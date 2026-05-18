"""Shared SMTP utility — used by reminders and cert delivery."""
import logging
import smtplib
from email.message import EmailMessage

from config import Config

logger = logging.getLogger(__name__)


def smtp_available() -> bool:
    return bool(Config.SMTP_HOST)


def _smtp_send(msg: EmailMessage) -> None:
    with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT) as s:
        if Config.SMTP_USE_TLS:
            s.starttls()
        if Config.SMTP_USER:
            s.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
        s.send_message(msg)


def send_plain(to: str, subject: str, body: str) -> None:
    """Plain-text email (used by expiry reminders)."""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = Config.SMTP_FROM
    msg["To"] = to
    msg.set_content(body)
    _smtp_send(msg)
    logger.info("Email sent to %s: %s", to, subject)


def send_cert_bundle(to: str, username: str, common_name: str,
                     p12_bytes: bytes, p12_password: str) -> None:
    """Email a PKCS#12 bundle as an attachment with the bundle password in the body."""
    subject = "[CertPortal] Your client certificate is ready"
    body = (
        f"Hello {common_name},\n\n"
        f"Your client certificate has been generated and is attached to this email.\n\n"
        f"Bundle password: {p12_password}\n\n"
        f"Import the attached .p12 file into your browser or operating system using\n"
        f"the password above. Installation instructions are available at:\n"
        f"{Config.PORTAL_URL}\n\n"
        f"Keep the password safe — it cannot be recovered from the portal.\n"
        f"You can request a new bundle at any time using the Resend button on the portal.\n"
    )
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = Config.SMTP_FROM
    msg["To"] = to
    msg.set_content(body)
    msg.add_attachment(
        p12_bytes,
        maintype="application",
        subtype="x-pkcs12",
        filename=f"{username}-cert.p12",
    )
    _smtp_send(msg)
    logger.info("Cert bundle emailed to %s for user %s", to, username)
