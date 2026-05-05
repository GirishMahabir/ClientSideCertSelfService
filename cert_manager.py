"""PKI operations: CA creation, client cert issuance, revocation, PKCS12 packaging."""
import os
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import ReasonFlags, CRLReason

from config import Config
import database as db

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _subject(cn, org=None, ou=None, country=None, state=None, locality=None,
             email=None):
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if ou:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    if country:
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    if state:
        attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if locality:
        attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
    if email:
        attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    return x509.Name(attrs)


def _gen_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def _save_key(key, path: Path, password: bytes | None = None):
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption,
    ))
    path.chmod(0o600)


def _load_ca():
    ca_cert = x509.load_pem_x509_certificate(
        Path(Config.CA_CERT_PATH).read_bytes()
    )
    ca_key = serialization.load_pem_private_key(
        Path(Config.CA_KEY_PATH).read_bytes(), password=None
    )
    return ca_cert, ca_key


# ---------------------------------------------------------------------------
# CA initialisation
# ---------------------------------------------------------------------------

def ca_exists() -> bool:
    return (
        os.path.isfile(Config.CA_CERT_PATH)
        and os.path.isfile(Config.CA_KEY_PATH)
    )


def init_ca():
    """Generate a self-signed CA.  Idempotent — skips if already present."""
    if ca_exists():
        logger.info("CA already exists, skipping generation")
        return

    Path(Config.CA_CERT_PATH).parent.mkdir(parents=True, exist_ok=True)

    key = _gen_key()
    now = datetime.now(timezone.utc)
    subject = issuer = _subject(
        cn=Config.CA_COMMON_NAME,
        org=Config.CA_ORGANIZATION,
        ou=Config.CA_ORG_UNIT,
        country=Config.CA_COUNTRY,
        state=Config.CA_STATE,
        locality=Config.CA_LOCALITY,
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=Config.CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )

    _save_key(key, Path(Config.CA_KEY_PATH))
    Path(Config.CA_CERT_PATH).write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )
    logger.info("CA created: %s", Config.CA_CERT_PATH)
    generate_crl()   # generate an empty CRL on creation


# ---------------------------------------------------------------------------
# Client certificate issuance
# ---------------------------------------------------------------------------

def issue_client_cert(username: str, display_name: str, email: str | None):
    """
    Generate a new client cert for *username*, sign it with the CA, persist
    the PEM files, record in the database, and return the cert record dict.
    """
    ca_cert, ca_key = _load_ca()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=Config.CLIENT_CERT_VALIDITY_DAYS)
    serial = x509.random_serial_number()

    client_key = _gen_key()
    cn = display_name or username
    subject = _subject(cn=cn, email=email,
                       org=Config.CA_ORGANIZATION, ou=Config.CA_ORG_UNIT)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )

    if email:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(email)]),
            critical=False,
        )

    client_cert = builder.sign(ca_key, hashes.SHA256())

    # Persist
    user_dir = Path(Config.CLIENTS_DIR) / username
    user_dir.mkdir(parents=True, exist_ok=True)

    cert_path = user_dir / "cert.pem"
    key_path = user_dir / "key.pem"
    cert_path.write_bytes(client_cert.public_bytes(serialization.Encoding.PEM))
    _save_key(client_key, key_path)

    db.add_certificate(
        username=username,
        common_name=cn,
        email=email or "",
        serial=serial,
        issued_at=now,
        expires_at=expires,
        cert_path=str(cert_path),
        key_path=str(key_path),
    )
    db.audit(username, "ISSUE_CERT", target=str(serial),
             detail=f"cn={cn} expires={expires.date()}")

    logger.info("Issued cert serial=%s for %s", serial, username)
    return db.get_cert_by_username(username)


# ---------------------------------------------------------------------------
# PKCS12 packaging (on-demand, not stored on disk)
# ---------------------------------------------------------------------------

def build_pkcs12(cert_record: dict, p12_password: str) -> bytes:
    """
    Create an in-memory PKCS12 bundle from a cert record row.
    Returns raw bytes suitable for streaming to the browser.
    """
    ca_cert_pem = Path(Config.CA_CERT_PATH).read_bytes()
    cert_pem = Path(cert_record["cert_path"]).read_bytes()
    key_pem = Path(cert_record["key_path"]).read_bytes()

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    client_cert = x509.load_pem_x509_certificate(cert_pem)
    client_key = serialization.load_pem_private_key(key_pem, password=None)

    name = cert_record["username"].encode()
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=name,
        key=client_key,
        cert=client_cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(
            p12_password.encode()
        ),
    )
    return p12_bytes


# ---------------------------------------------------------------------------
# Revocation & CRL
# ---------------------------------------------------------------------------

def revoke_cert(cert_id: int, revoked_by: str, reason: str = "unspecified"):
    """Mark a cert as revoked in the DB and regenerate the CRL."""
    record = db.get_cert_by_id(cert_id)
    if not record:
        raise ValueError(f"Certificate id={cert_id} not found")
    if record["status"] == "revoked":
        raise ValueError("Certificate is already revoked")

    db.revoke_cert_by_id(cert_id, revoked_by, reason)
    db.audit(revoked_by, "REVOKE_CERT", target=record["serial"],
             detail=f"reason={reason} username={record['username']}")
    generate_crl()


def generate_crl() -> None:
    """Build a fresh CRL from all revoked serials and write it to disk."""
    if not ca_exists():
        return

    ca_cert, ca_key = _load_ca()
    now = datetime.now(timezone.utc)
    next_update = now + timedelta(days=7)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(next_update)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )

    revoked_rows = db.get_revoked_certs_for_crl()
    for row in revoked_rows:
        revoked_at = datetime.fromisoformat(row["revoked_at"])
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(row["serial"]))
            .revocation_date(revoked_at)
            .add_extension(
                CRLReason(ReasonFlags.unspecified), critical=False
            )
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(ca_key, hashes.SHA256())
    Path(Config.CRL_PATH).write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    logger.info("CRL regenerated: %d revoked entries", len(revoked_rows))


# ---------------------------------------------------------------------------
# Info helpers
# ---------------------------------------------------------------------------

def get_ca_info() -> dict | None:
    if not ca_exists():
        return None
    cert = x509.load_pem_x509_certificate(Path(Config.CA_CERT_PATH).read_bytes())
    return {
        "subject": cert.subject.rfc4514_string(),
        "serial": str(cert.serial_number),
        "not_before": cert.not_valid_before_utc.date().isoformat(),
        "not_after": cert.not_valid_after_utc.date().isoformat(),
    }


def days_until_expiry(expires_at_str: str) -> int:
    expires = datetime.fromisoformat(expires_at_str)
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    delta = expires - datetime.now(timezone.utc)
    return delta.days
