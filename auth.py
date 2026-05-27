"""LDAP authentication with optional local-user bypass for development."""
import logging
from ldap3 import Server, Connection, ALL, SUBTREE, NTLM, SIMPLE
from ldap3.core.exceptions import LDAPException
from config import Config

logger = logging.getLogger(__name__)


class AuthResult:
    __slots__ = ("ok", "role", "display_name", "email", "error")

    def __init__(self, ok=False, role=None, display_name=None, email=None, error=None):
        self.ok = ok
        self.role = role            # "admin" | "user" | None
        self.display_name = display_name
        self.email = email
        self.error = error


def _local_auth(username: str, password: str) -> AuthResult:
    """Simple local user map for development/testing (LDAP_BYPASS=true)."""
    for entry in Config.LOCAL_USERS.split(","):
        parts = entry.strip().split(":")
        if len(parts) != 3:
            continue
        u, p, role = parts
        if u == username and p == password:
            return AuthResult(ok=True, role=role, display_name=username.capitalize(),
                              email=f"{username}@local.dev")
    return AuthResult(ok=False, error="Invalid username or password")


def authenticate(username: str, password: str) -> AuthResult:
    if not username or not password:
        return AuthResult(ok=False, error="Username and password are required")

    if Config.LDAP_BYPASS:
        logger.warning("LDAP bypass active — using local user list")
        return _local_auth(username, password)

    try:
        server = Server(Config.LDAP_SERVER, get_info=ALL)

        # Use a service account to look up the user's DN first
        bind_dn = Config.LDAP_BIND_DN or None
        bind_pw = Config.LDAP_BIND_PASSWORD or None

        with Connection(server, user=bind_dn, password=bind_pw,
                        authentication=SIMPLE if bind_dn else None,
                        auto_bind=True) as conn:
            search_filter = Config.LDAP_USER_SEARCH_FILTER.format(username=username)
            conn.search(
                search_base=Config.LDAP_USER_DN,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["cn", "mail", "memberOf"],
            )
            if not conn.entries:
                return AuthResult(ok=False, error="User not found in directory")

            entry = conn.entries[0]
            user_dn = entry.entry_dn
            display_name = str(entry.cn) if entry.cn else username
            email = str(entry.mail) if entry.mail else None
            member_of = [str(g) for g in entry.memberOf] if entry.memberOf else []

        # Verify the password by binding as the user
        with Connection(server, user=user_dn, password=password,
                        authentication=SIMPLE, auto_bind=True):
            pass  # raises if credentials are wrong

        # Determine role via group membership
        role = None
        if Config.LDAP_ADMIN_GROUP_DN in member_of:
            role = "admin"
        elif Config.LDAP_USER_GROUP_DN in member_of:
            role = "user"
        else:
            return AuthResult(ok=False,
                              error="You are not authorised to use this service")

        logger.info("Authenticated user=%s role=%s", username, role)
        return AuthResult(ok=True, role=role, display_name=display_name, email=email)

    except LDAPException as exc:
        logger.error("LDAP error for user %s: %s", username, exc)
        return AuthResult(ok=False, error="Authentication service error — please try again")
    except Exception as exc:
        logger.exception("Unexpected auth error for user %s", username)
        return AuthResult(ok=False, error="An unexpected error occurred")
