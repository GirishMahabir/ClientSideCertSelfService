"""REST API Blueprint — machine-to-machine access for CRL/CA polling."""
import os

from flask import Blueprint, send_file, jsonify

from api_key import require_scope
from config import Config
import cert_manager as cm

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


@api_bp.route("/health")
def health():
    """Unauthenticated liveness check."""
    return jsonify(status="ok")


@api_bp.route("/crl")
@require_scope("crl:read")
def get_crl():
    """Return the current CRL in PEM format."""
    if not os.path.isfile(Config.CRL_PATH):
        return jsonify(error="CRL not found — CA may not be initialised"), 404
    return send_file(
        Config.CRL_PATH,
        mimetype="application/x-pem-file",
        download_name="crl.pem",
    )


@api_bp.route("/ca")
@require_scope("ca:read")
def get_ca():
    """Return the CA certificate in PEM format."""
    if not cm.ca_exists():
        return jsonify(error="CA not found"), 404
    return send_file(
        Config.CA_CERT_PATH,
        mimetype="application/x-pem-file",
        download_name="ca.crt",
    )
