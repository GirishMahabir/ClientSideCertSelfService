"""Flask application — Client-Side Certificate Self-Service Portal."""
import io
import logging
import logging.handlers
import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask, Blueprint, render_template, request, redirect, url_for,
    session, flash, send_file, abort,
)
from flask_wtf.csrf import CSRFProtect

from config import Config
import auth as ldap_auth
import cert_manager as cm
import database as db

csrf = CSRFProtect()

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    csrf.init_app(app)
    _setup_logging(app)
    db.init_db()
    cm.init_ca()

    app.register_blueprint(auth_bp)
    app.register_blueprint(client_bp)
    app.register_blueprint(admin_bp)

    @app.context_processor
    def inject_globals():
        return {"now": datetime.now(timezone.utc)}

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", code=403,
                               message="You don't have permission to access this page."), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404,
                               message="The page you're looking for doesn't exist."), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("error.html", code=500,
                               message="An internal server error occurred."), 500

    return app


def _setup_logging(app):
    Path(Config.LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
    level = getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler = logging.handlers.RotatingFileHandler(
        Config.LOG_PATH, maxBytes=10 * 1024 * 1024, backupCount=5
    )
    file_handler.setFormatter(fmt)
    file_handler.setLevel(level)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    stream_handler.setLevel(level)

    logging.root.setLevel(level)
    logging.root.addHandler(file_handler)
    logging.root.addHandler(stream_handler)


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def _current_user():
    return {
        "username": session.get("username"),
        "display_name": session.get("display_name"),
        "email": session.get("email"),
        "role": session.get("role"),
    }


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Auth blueprint
# ---------------------------------------------------------------------------

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/", methods=["GET"])
def index():
    if session.get("username"):
        return redirect(url_for("client.dashboard") if session.get("role") != "admin"
                        else url_for("admin.dashboard"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("username"):
        return redirect(url_for("auth.index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        result = ldap_auth.authenticate(username, password)

        if result.ok:
            session.clear()
            session.permanent = True
            session["username"] = username
            session["display_name"] = result.display_name
            session["email"] = result.email or ""
            session["role"] = result.role
            db.audit(username, "LOGIN", ip=request.remote_addr)
            logging.getLogger(__name__).info("Login: %s role=%s", username, result.role)

            next_url = request.args.get("next") or (
                url_for("admin.dashboard") if result.role == "admin"
                else url_for("client.dashboard")
            )
            # Guard open-redirect: only allow same-origin relative paths
            if not next_url.startswith("/"):
                next_url = url_for("auth.index")
            return redirect(next_url)
        else:
            error = result.error
            db.audit(username or "(blank)", "LOGIN_FAILED",
                     detail=error, ip=request.remote_addr)

    return render_template("login.html", error=error)


@auth_bp.route("/logout")
def logout():
    username = session.get("username", "(unknown)")
    db.audit(username, "LOGOUT", ip=request.remote_addr)
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


# ---------------------------------------------------------------------------
# Client blueprint
# ---------------------------------------------------------------------------

client_bp = Blueprint("client", __name__, url_prefix="/client")


@client_bp.route("/")
@login_required
def dashboard():
    user = _current_user()
    cert = db.get_cert_by_username(user["username"])
    expiry_days = None
    if cert:
        expiry_days = cm.days_until_expiry(cert["expires_at"])
    return render_template(
        "client/dashboard.html",
        user=user,
        cert=cert,
        expiry_days=expiry_days,
        warning_days=Config.EXPIRY_WARNING_DAYS,
    )


@client_bp.route("/generate", methods=["POST"])
@login_required
def generate():
    user = _current_user()
    existing = db.get_cert_by_username(user["username"])
    if existing:
        flash("You already have an active certificate. Contact an admin to renew it.", "warning")
        return redirect(url_for("client.dashboard"))

    try:
        cm.issue_client_cert(
            username=user["username"],
            display_name=user["display_name"] or user["username"],
            email=user["email"] or None,
        )
        flash("Certificate generated successfully. Download it below.", "success")
    except Exception as exc:
        logging.getLogger(__name__).exception("Cert generation failed for %s", user["username"])
        flash(f"Certificate generation failed: {exc}", "danger")

    return redirect(url_for("client.dashboard"))


@client_bp.route("/download", methods=["POST"])
@login_required
def download():
    user = _current_user()
    cert = db.get_cert_by_username(user["username"])
    if not cert:
        flash("No active certificate found. Generate one first.", "warning")
        return redirect(url_for("client.dashboard"))

    p12_password = request.form.get("p12_password", "").strip()
    if not p12_password:
        flash("You must enter a password to protect your certificate bundle.", "warning")
        return redirect(url_for("client.dashboard"))
    if len(p12_password) < 4:
        flash("Password must be at least 4 characters.", "warning")
        return redirect(url_for("client.dashboard"))

    try:
        p12_bytes = cm.build_pkcs12(cert, p12_password)
        db.audit(user["username"], "DOWNLOAD_CERT",
                 target=cert["serial"], ip=request.remote_addr)
        return send_file(
            io.BytesIO(p12_bytes),
            mimetype="application/x-pkcs12",
            as_attachment=True,
            download_name=f"{user['username']}-cert.p12",
        )
    except Exception as exc:
        logging.getLogger(__name__).exception("P12 build failed for %s", user["username"])
        flash(f"Download failed: {exc}", "danger")
        return redirect(url_for("client.dashboard"))


@client_bp.route("/download-ca")
@login_required
def download_ca():
    if not cm.ca_exists():
        abort(404)
    db.audit(session["username"], "DOWNLOAD_CA", ip=request.remote_addr)
    return send_file(
        Config.CA_CERT_PATH,
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name="company-ca.crt",
    )


# ---------------------------------------------------------------------------
# Admin blueprint
# ---------------------------------------------------------------------------

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
@admin_required
def dashboard():
    user = _current_user()
    certs = db.get_all_certs()

    total = len(certs)
    active = sum(1 for c in certs if c["status"] == "active")
    revoked = sum(1 for c in certs if c["status"] == "revoked")
    expiring_soon = sum(
        1 for c in certs
        if c["status"] == "active" and
        0 <= cm.days_until_expiry(c["expires_at"]) <= Config.EXPIRY_WARNING_DAYS
    )

    ca_info = cm.get_ca_info()
    audit_entries = db.get_audit_log(limit=50)

    return render_template(
        "admin/dashboard.html",
        user=user,
        certs=certs,
        stats=dict(total=total, active=active, revoked=revoked, expiring_soon=expiring_soon),
        ca_info=ca_info,
        audit_entries=audit_entries,
        expiry_fn=cm.days_until_expiry,
        warning_days=Config.EXPIRY_WARNING_DAYS,
    )


@admin_bp.route("/certs/<int:cert_id>/revoke", methods=["POST"])
@admin_required
def revoke(cert_id):
    reason = request.form.get("reason", "unspecified").strip() or "unspecified"
    try:
        cm.revoke_cert(cert_id, revoked_by=session["username"], reason=reason)
        flash("Certificate revoked and CRL updated.", "success")
    except ValueError as exc:
        flash(str(exc), "warning")
    except Exception as exc:
        logging.getLogger(__name__).exception("Revoke failed cert_id=%s", cert_id)
        flash(f"Revocation failed: {exc}", "danger")
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/certs/<int:cert_id>/renew", methods=["POST"])
@admin_required
def renew(cert_id):
    record = db.get_cert_by_id(cert_id)
    if not record:
        flash("Certificate not found.", "warning")
        return redirect(url_for("admin.dashboard"))

    try:
        if record["status"] == "active":
            cm.revoke_cert(cert_id, revoked_by=session["username"], reason="superseded")
        cm.issue_client_cert(
            username=record["username"],
            display_name=record["common_name"],
            email=record["email"] or None,
        )
        db.audit(session["username"], "RENEW_CERT",
                 target=record["serial"],
                 detail=f"for user {record['username']}")
        flash(f"Certificate renewed for {record['username']}.", "success")
    except Exception as exc:
        logging.getLogger(__name__).exception("Renew failed cert_id=%s", cert_id)
        flash(f"Renewal failed: {exc}", "danger")

    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/download-ca")
@admin_required
def download_ca():
    if not cm.ca_exists():
        abort(404)
    db.audit(session["username"], "ADMIN_DOWNLOAD_CA", ip=request.remote_addr)
    return send_file(
        Config.CA_CERT_PATH,
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name="company-ca.crt",
    )


@admin_bp.route("/download-crl")
@admin_required
def download_crl():
    if not os.path.isfile(Config.CRL_PATH):
        abort(404)
    db.audit(session["username"], "ADMIN_DOWNLOAD_CRL", ip=request.remote_addr)
    return send_file(
        Config.CRL_PATH,
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name="crl.pem",
    )


@admin_bp.route("/init-ca", methods=["POST"])
@admin_required
def init_ca_route():
    if cm.ca_exists():
        flash("CA already exists.", "info")
    else:
        cm.init_ca()
        flash("CA initialised successfully.", "success")
        db.audit(session["username"], "INIT_CA")
    return redirect(url_for("admin.dashboard"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

app = create_app()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
            host="0.0.0.0", port=5000)
