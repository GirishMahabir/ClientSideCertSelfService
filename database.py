import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from config import Config

logger = logging.getLogger(__name__)


def get_connection():
    conn = sqlite3.connect(Config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS certificates (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT NOT NULL,
                common_name TEXT NOT NULL,
                email       TEXT,
                serial      TEXT NOT NULL UNIQUE,
                issued_at   TEXT NOT NULL,
                expires_at  TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'active',
                cert_path   TEXT NOT NULL,
                key_path    TEXT NOT NULL,
                revoked_at  TEXT,
                revoked_by  TEXT,
                revoke_reason TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_certs_username ON certificates(username);
            CREATE INDEX IF NOT EXISTS idx_certs_status   ON certificates(status);
            CREATE INDEX IF NOT EXISTS idx_certs_serial   ON certificates(serial);

            CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT NOT NULL,
                username  TEXT NOT NULL,
                action    TEXT NOT NULL,
                target    TEXT,
                detail    TEXT,
                ip        TEXT
            );

            CREATE TABLE IF NOT EXISTS reminder_log (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                cert_serial    TEXT    NOT NULL,
                threshold_days INTEGER NOT NULL,
                sent_at        TEXT    NOT NULL,
                UNIQUE(cert_serial, threshold_days)
            );

            CREATE TABLE IF NOT EXISTS scheduler_heartbeat (
                id       INTEGER PRIMARY KEY CHECK (id = 1),
                last_run TEXT NOT NULL DEFAULT '1970-01-01T00:00:00+00:00'
            );
            INSERT OR IGNORE INTO scheduler_heartbeat(id, last_run)
                VALUES (1, '1970-01-01T00:00:00+00:00');
            """
        )
    logger.info("Database initialised at %s", Config.DB_PATH)


# ---------- certificate helpers ----------

def add_certificate(username, common_name, email, serial, issued_at, expires_at,
                    cert_path, key_path):
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO certificates
               (username, common_name, email, serial, issued_at, expires_at,
                status, cert_path, key_path)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (username, common_name, email, str(serial),
             issued_at.isoformat(), expires_at.isoformat(),
             "active", cert_path, key_path),
        )
    logger.info("Certificate recorded: serial=%s user=%s", serial, username)


def get_cert_by_username(username):
    """Return the most-recent active cert for a user, or None."""
    with get_connection() as conn:
        row = conn.execute(
            """SELECT * FROM certificates
               WHERE username=? AND status='active'
               ORDER BY id DESC LIMIT 1""",
            (username,),
        ).fetchone()
    return dict(row) if row else None


def get_all_certs():
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM certificates ORDER BY id DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_cert_by_id(cert_id):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM certificates WHERE id=?", (cert_id,)
        ).fetchone()
    return dict(row) if row else None


def get_cert_by_serial(serial):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM certificates WHERE serial=?", (str(serial),)
        ).fetchone()
    return dict(row) if row else None


def revoke_cert_by_id(cert_id, revoked_by, reason="unspecified"):
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            """UPDATE certificates
               SET status='revoked', revoked_at=?, revoked_by=?, revoke_reason=?
               WHERE id=?""",
            (now, revoked_by, reason, cert_id),
        )
    logger.info("Certificate id=%s revoked by %s (%s)", cert_id, revoked_by, reason)


def get_active_serials():
    """Return list of serial strings for all active certs (for CRL)."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT serial FROM certificates WHERE status='active'"
        ).fetchall()
    return [r["serial"] for r in rows]


def get_revoked_certs_for_crl():
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT serial, revoked_at FROM certificates WHERE status='revoked'"
        ).fetchall()
    return [dict(r) for r in rows]


# ---------- audit log ----------

def audit(username, action, target=None, detail=None, ip=None):
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO audit_log (ts, username, action, target, detail, ip) VALUES (?,?,?,?,?,?)",
            (now, username, action, target, detail, ip),
        )


def get_audit_log(limit=200):
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ---------- reminder helpers ----------

def get_certs_expiring_within(days: int) -> list[dict]:
    """Return active certs that expire between now and now+days (inclusive)."""
    now = datetime.now(timezone.utc)
    cutoff = (now + timedelta(days=days)).isoformat()
    now_iso = now.isoformat()
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT * FROM certificates
               WHERE status = 'active'
                 AND expires_at > :now
                 AND expires_at <= :cutoff
               ORDER BY expires_at ASC""",
            {"now": now_iso, "cutoff": cutoff},
        ).fetchall()
    return [dict(r) for r in rows]


def has_reminder_been_sent(serial: str, threshold_days: int) -> bool:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM reminder_log WHERE cert_serial=? AND threshold_days=?",
            (str(serial), threshold_days),
        ).fetchone()
    return row is not None


def record_reminder_sent(serial: str, threshold_days: int) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            """INSERT OR IGNORE INTO reminder_log(cert_serial, threshold_days, sent_at)
               VALUES (?, ?, ?)""",
            (str(serial), threshold_days, now),
        )


def try_acquire_scheduler_lock() -> bool:
    """Atomic single-row update; returns True if this call won the lock.

    Prevents duplicate reminder sends when multiple gunicorn workers each run
    their own APScheduler instance. The lock expires after 23 hours so the next
    daily run can proceed.
    """
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(hours=23)).isoformat()
    now_iso = now.isoformat()
    with get_connection() as conn:
        result = conn.execute(
            """UPDATE scheduler_heartbeat
               SET last_run = :now
               WHERE id = 1 AND last_run < :cutoff""",
            {"now": now_iso, "cutoff": cutoff},
        )
        conn.commit()
    return result.rowcount == 1
