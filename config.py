import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-key-in-production")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true"
    PERMANENT_SESSION_LIFETIME = timedelta(
        hours=int(os.environ.get("SESSION_LIFETIME_HOURS", "8"))
    )
    WTF_CSRF_TIME_LIMIT = 3600

    # LDAP
    LDAP_SERVER = os.environ.get("LDAP_SERVER", "ldap://localhost:389")
    LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "dc=example,dc=com")
    LDAP_USER_DN = os.environ.get("LDAP_USER_DN", "ou=users,dc=example,dc=com")
    LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", "")
    LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD", "")
    # {username} is substituted at runtime
    LDAP_USER_SEARCH_FILTER = os.environ.get(
        "LDAP_USER_SEARCH_FILTER", "(uid={username})"
    )
    LDAP_ADMIN_GROUP_DN = os.environ.get(
        "LDAP_ADMIN_GROUP_DN", "cn=cert-admins,ou=groups,dc=example,dc=com"
    )
    LDAP_USER_GROUP_DN = os.environ.get(
        "LDAP_USER_GROUP_DN", "cn=cert-users,ou=groups,dc=example,dc=com"
    )
    # Set to 'true' to skip LDAP and use LOCAL_USERS instead (dev/testing)
    LDAP_BYPASS = os.environ.get("LDAP_BYPASS", "false").lower() == "true"
    # Format: "user1:password1:user,user2:password2:admin"
    LOCAL_USERS = os.environ.get("LOCAL_USERS", "admin:admin:admin,user:user:user")

    # Paths
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    CERTS_DIR = os.path.join(BASE_DIR, os.environ.get("CERTS_DIR", "certs"))
    CA_CERT_PATH = os.path.join(CERTS_DIR, "ca", "ca.crt")
    CA_KEY_PATH = os.path.join(CERTS_DIR, "ca", "ca.key")
    CRL_PATH = os.path.join(CERTS_DIR, "ca", "crl.pem")
    CLIENTS_DIR = os.path.join(CERTS_DIR, "clients")
    DB_PATH = os.path.join(BASE_DIR, os.environ.get("DB_PATH", "cert_manager.db"))
    LOG_PATH = os.path.join(BASE_DIR, os.environ.get("LOG_PATH", "logs/app.log"))
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

    # CA subject
    CA_COMMON_NAME = os.environ.get("CA_COMMON_NAME", "Company Internal CA")
    CA_ORGANIZATION = os.environ.get("CA_ORGANIZATION", "My Company")
    CA_ORG_UNIT = os.environ.get("CA_ORG_UNIT", "IT Security")
    CA_COUNTRY = os.environ.get("CA_COUNTRY", "US")
    CA_STATE = os.environ.get("CA_STATE", "California")
    CA_LOCALITY = os.environ.get("CA_LOCALITY", "San Francisco")
    CA_VALIDITY_DAYS = int(os.environ.get("CA_VALIDITY_DAYS", "3650"))
    CRL_VALIDITY_DAYS = int(os.environ.get("CRL_VALIDITY_DAYS", "30"))

    # Client cert
    CLIENT_CERT_VALIDITY_DAYS = int(os.environ.get("CLIENT_CERT_VALIDITY_DAYS", "365"))
    # Warn when cert expires within this many days
    EXPIRY_WARNING_DAYS = int(os.environ.get("EXPIRY_WARNING_DAYS", "30"))
    # Validity options offered to admins in the renew dropdown (days)
    CERT_VALIDITY_OPTIONS = [
        int(d) for d in
        os.environ.get("CERT_VALIDITY_OPTIONS", "30,90,180,365,730").split(",")
    ]

    # SMTP / email reminders
    SMTP_HOST     = os.environ.get("SMTP_HOST", "")
    SMTP_PORT     = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USER     = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM     = os.environ.get("SMTP_FROM", "certportal@example.com")
    SMTP_USE_TLS  = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"

    REMINDER_ENABLED = os.environ.get("REMINDER_ENABLED", "false").lower() == "true"
    REMINDER_DAYS    = [
        int(d) for d in os.environ.get("REMINDER_DAYS", "30,7,1").split(",")
    ]
    PORTAL_URL = os.environ.get("PORTAL_URL", "http://localhost:5000")

    # When true: cert generation auto-emails the .p12 bundle; download form is hidden
    CERT_EMAIL_DELIVERY = os.environ.get("CERT_EMAIL_DELIVERY", "false").lower() == "true"
