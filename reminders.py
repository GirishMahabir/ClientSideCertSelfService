"""Expiry reminder emails — called by the embedded APScheduler job or send_reminders.py."""
import logging
from datetime import datetime, timezone

from config import Config
import database as db
import mailer

logger = logging.getLogger(__name__)


def send_expiry_reminders() -> None:
    if not Config.REMINDER_ENABLED:
        return
    if not mailer.smtp_available():
        logger.warning("REMINDER_ENABLED=true but SMTP_HOST is not set — skipping")
        return
    if not db.try_acquire_scheduler_lock():
        logger.debug("Reminder job: lock held by another worker, skipping")
        return

    now = datetime.now(timezone.utc)
    max_threshold = max(Config.REMINDER_DAYS)
    certs = db.get_certs_expiring_within(max_threshold)

    sent = skipped_already_sent = skipped_no_email = 0

    for cert in certs:
        expires = datetime.fromisoformat(cert["expires_at"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        days_left = (expires - now).days

        for threshold in sorted(Config.REMINDER_DAYS, reverse=True):
            if days_left > threshold:
                continue
            if db.has_reminder_been_sent(cert["serial"], threshold):
                skipped_already_sent += 1
                continue
            if not cert["email"]:
                logger.warning(
                    "No email stored for %s — skipping reminder (threshold=%dd)",
                    cert["username"], threshold,
                )
                db.record_reminder_sent(cert["serial"], threshold)
                skipped_no_email += 1
                continue
            _send_reminder(cert, days_left, threshold)
            db.record_reminder_sent(cert["serial"], threshold)
            sent += 1

    logger.info(
        "Reminder run complete: sent=%d already_sent=%d no_email=%d",
        sent, skipped_already_sent, skipped_no_email,
    )


def _send_reminder(cert: dict, days_left: int, threshold: int) -> None:
    plural = "s" if days_left != 1 else ""
    subject = f"[CertPortal] Your certificate expires in {days_left} day{plural}"
    body = (
        f"Hello {cert['common_name']},\n\n"
        f"Your client certificate (CN={cert['common_name']}) will expire in "
        f"{days_left} day{plural} (on {cert['expires_at'][:10]}).\n\n"
        f"Please log in to {Config.PORTAL_URL} to download a renewed certificate "
        f"once an administrator has renewed it for you.\n\n"
        f"If you need help, contact your IT administrator.\n"
    )
    try:
        mailer.send_plain(cert["email"], subject, body)
        logger.info(
            "Reminder sent to %s (threshold=%dd, days_left=%d)",
            cert["email"], threshold, days_left,
        )
    except Exception:
        logger.exception("Failed to send reminder to %s", cert["email"])
