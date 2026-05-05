# CertPortal — Client-Side Certificate Self-Service

A lightweight internal web application that lets your users generate, download,
and manage their own TLS client certificates without involving IT for every
request.  Admins get a full management dashboard; users get a one-click
certificate generator.

Built with **Python 3 / Flask**, **LDAP authentication**, and the
**cryptography** library.  No external PKI infrastructure required — the app
runs its own internal CA.

---

## Features

| | |
|---|---|
| **Login** | LDAP authentication with admin/user group separation |
| **Client portal** | Generate a personal certificate, download as PKCS#12 (`.p12`), per-OS install guide |
| **Admin dashboard** | View all certificates, revoke with reason, one-click renew, CRL download |
| **PKI** | RSA-2048 internal CA, automatic CRL regeneration on every revocation |
| **Audit log** | Every login, cert issue, revocation, and download is recorded |
| **Storage** | SQLite database + PEM files on disk.  No external dependencies |
| **Security** | CSRF protection, HttpOnly/SameSite session cookies, 8-hour session timeout, open-redirect guard |

---

## Tech Stack

- **Python 3.11+**
- **Flask 3** — web framework
- **ldap3** — LDAP/Active Directory authentication
- **cryptography** — PKI (CA, client certs, PKCS12, CRL)
- **Flask-WTF** — CSRF protection
- **SQLite** — certificate records and audit log
- **Tailwind CSS** (CDN) + **Font Awesome** (CDN) — UI

---

## Prerequisites

- Python 3.11 or newer
- An LDAP / Active Directory server accessible from the host
- `pip` (comes with Python)
- Nginx (for deploying with client certificate enforcement — see [Nginx Configuration](#nginx-configuration))

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/your-org/clientsidecertselfservice.git
cd clientsidecertselfservice
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure the application

Copy the example environment file and edit it:

```bash
cp .env.example .env
```

Open `.env` and set **at minimum** these values:

```env
SECRET_KEY=<long-random-string>   # python3 -c "import secrets; print(secrets.token_hex(32))"
LDAP_SERVER=ldap://your-ldap-host:389
LDAP_BASE_DN=dc=example,dc=com
LDAP_USER_DN=ou=users,dc=example,dc=com
LDAP_ADMIN_GROUP_DN=cn=cert-admins,ou=groups,dc=example,dc=com
LDAP_USER_GROUP_DN=cn=cert-users,ou=groups,dc=example,dc=com
```

Full reference: [Configuration Reference](#configuration-reference)

> **Testing without LDAP?**  Set `LDAP_BYPASS=true` in `.env`.  The app will
> use a built-in local user list (`LOCAL_USERS`) instead.  Default accounts:
> `admin / admin` (role: admin) and `user / user` (role: user).

### 5. Initialise the CA and database

This creates the SQLite database, generates the internal CA key pair, and
writes an initial empty CRL.  Run it once:

```bash
python init_ca.py
```

Expected output:

```
CertPortal — Initialisation
========================================
  Directory: certs/ca
  Directory: certs/clients
  Directory: logs
  Database : cert_manager.db
  CA       : generated at certs/ca/ca.crt

  Subject  : CN=Company Internal CA,O=My Company,...
  Valid    : 2025-01-01  →  2035-01-01

Initialisation complete. Start the app with:
  python run.py
```

### 6. Start the application

```bash
python run.py
```

The portal is now available at `http://localhost:5000`.

For production, see [Production Deployment](#production-deployment).

---

## User Guide

### Admin users

1. Log in with an account that belongs to `LDAP_ADMIN_GROUP_DN`.
2. You are taken to the **Admin Dashboard**.
3. From here you can:
   - View every certificate ever issued — status, expiry, owner
   - **Revoke** a certificate (choose a reason; the CRL is regenerated instantly)
   - **Renew** a certificate (the old cert is revoked and a new one is issued)
   - Download the **CA certificate** to distribute to your infrastructure
   - Download the **CRL** to configure in Nginx
   - Browse the **audit log** (last 50 events)

### Regular users

1. Log in with an account that belongs to `LDAP_USER_GROUP_DN`.
2. You are taken to the **My Certificate** page.
3. If you have no certificate, click **Generate My Certificate**.
4. Once generated, enter a password and click **Download .p12**.
5. Install the `.p12` on your device using the on-screen guide (Windows,
   macOS, Linux, iOS tabs are provided).
6. Use the **Download CA** link to install the company CA so your device
   trusts it.

> The `.p12` password protects the bundle.  It is never stored by the portal —
> keep it somewhere safe.  You can re-download the same certificate at any time
> with a new password.

---

## Configuration Reference

All settings are read from the `.env` file (or real environment variables).

### Flask / Security

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `change-me-…` | Flask session signing key — **change in production** |
| `SESSION_LIFETIME_HOURS` | `8` | How long a login session stays valid |

### LDAP

| Variable | Default | Description |
|---|---|---|
| `LDAP_SERVER` | `ldap://localhost:389` | LDAP server URL (`ldaps://` for TLS) |
| `LDAP_BASE_DN` | `dc=example,dc=com` | Base DN for all searches |
| `LDAP_USER_DN` | `ou=users,dc=example,dc=com` | Where to search for users |
| `LDAP_BIND_DN` | _(empty)_ | Service account DN for initial user lookup (leave empty for anonymous bind) |
| `LDAP_BIND_PASSWORD` | _(empty)_ | Password for the service account |
| `LDAP_USER_SEARCH_FILTER` | `(uid={username})` | Filter used to find a user — `{username}` is substituted at runtime.  For Active Directory use `(sAMAccountName={username})` |
| `LDAP_ADMIN_GROUP_DN` | `cn=cert-admins,…` | Full DN of the admin group |
| `LDAP_USER_GROUP_DN` | `cn=cert-users,…` | Full DN of the user group |
| `LDAP_BYPASS` | `false` | Set to `true` to skip LDAP entirely (dev/testing) |
| `LOCAL_USERS` | `admin:admin:admin,user:user:user` | Local accounts when bypass is active — `username:password:role` |

### Certificate Authority

| Variable | Default | Description |
|---|---|---|
| `CA_COMMON_NAME` | `Company Internal CA` | CN field on the CA certificate |
| `CA_ORGANIZATION` | `My Company` | O field |
| `CA_ORG_UNIT` | `IT Security` | OU field |
| `CA_COUNTRY` | `US` | Two-letter country code |
| `CA_STATE` | `California` | State / province |
| `CA_LOCALITY` | `San Francisco` | City |
| `CA_VALIDITY_DAYS` | `3650` | CA certificate lifetime (10 years) |

### Client Certificates

| Variable | Default | Description |
|---|---|---|
| `CLIENT_CERT_VALIDITY_DAYS` | `365` | Client certificate lifetime |
| `EXPIRY_WARNING_DAYS` | `30` | Days before expiry to show a warning banner |

### Paths

| Variable | Default | Description |
|---|---|---|
| `CERTS_DIR` | `certs` | Root directory for all certificate files |
| `DB_PATH` | `cert_manager.db` | SQLite database file |
| `LOG_PATH` | `logs/app.log` | Rotating log file (10 MB, 5 backups) |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

---

## Nginx Configuration

After your users have installed their certificates, configure Nginx to require
them on the routes you want to protect.

### Step 1 — Copy the CA certificate to Nginx

```bash
sudo cp certs/ca/ca.crt /etc/nginx/ssl/company-ca.crt
```

### Step 2 — Configure Nginx

```nginx
server {
    listen 443 ssl;
    server_name yourapp.internal;

    ssl_certificate     /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;

    # Company CA — used to verify client certificates
    ssl_client_certificate /etc/nginx/ssl/company-ca.crt;

    # 'on'       — client cert is mandatory
    # 'optional' — client cert is requested but not required
    ssl_verify_client on;
    ssl_verify_depth  2;

    # Optional: serve the CRL so Nginx can check revocations
    # (requires nginx built with --with-http_ssl_module)
    # ssl_crl /etc/nginx/ssl/crl.pem;

    location / {
        # The verified client DN is available as a header if needed
        proxy_set_header X-SSL-Client-DN   $ssl_client_s_dn;
        proxy_set_header X-SSL-Client-Cert $ssl_client_cert;

        proxy_pass http://127.0.0.1:8080;
    }
}

# Redirect HTTP → HTTPS
server {
    listen 80;
    server_name yourapp.internal;
    return 301 https://$host$request_uri;
}
```

### Step 3 — Keep the CRL up to date

Every time a certificate is revoked in the portal, download the fresh CRL
from the Admin Dashboard and replace the file on your Nginx host, then reload:

```bash
sudo cp crl.pem /etc/nginx/ssl/crl.pem
sudo nginx -s reload
```

> **Tip:** automate this with a daily cron job that pulls the CRL from
> `https://certportal.internal/admin/download-crl` using a service account.

---

## Production Deployment

### Run behind Gunicorn

```bash
pip install gunicorn
gunicorn --workers 4 --bind 0.0.0.0:5000 "app:app"
```

### Systemd service

Create `/etc/systemd/system/certportal.service`:

```ini
[Unit]
Description=CertPortal
After=network.target

[Service]
User=certportal
WorkingDirectory=/opt/certportal
EnvironmentFile=/opt/certportal/.env
ExecStart=/opt/certportal/.venv/bin/gunicorn --workers 4 --bind 127.0.0.1:5000 "app:app"
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now certportal
```

### Security checklist for production

- [ ] Set a strong, random `SECRET_KEY` in `.env`
- [ ] Set `SESSION_COOKIE_SECURE=True` if serving over HTTPS (add to `config.py` or `.env`)
- [ ] Restrict filesystem permissions on `certs/ca/ca.key` (`chmod 600`)
- [ ] Put the portal itself behind Nginx (no client cert required on the portal — users need to reach it to get their cert)
- [ ] Set `FLASK_DEBUG=false`
- [ ] Rotate logs — the rotating file handler keeps 5 × 10 MB files by default
- [ ] Back up `cert_manager.db` and `certs/ca/` regularly

---

## Project Structure

```
.
├── app.py              # Flask app — all routes and blueprints
├── auth.py             # LDAP authentication
├── cert_manager.py     # PKI: CA init, cert issuance, revocation, CRL, PKCS12
├── config.py           # Configuration (reads from .env)
├── database.py         # SQLite helpers — certificates + audit log
├── init_ca.py          # One-time setup script
├── run.py              # Development entry point
├── requirements.txt
├── .env.example        # Copy to .env and fill in your values
│
├── certs/
│   ├── ca/             # CA certificate, key, and CRL (gitignored except .gitkeep)
│   └── clients/        # Per-user PEM files (gitignored)
│
├── templates/
│   ├── base.html       # Shared nav, flash messages
│   ├── login.html      # Standalone login page
│   ├── error.html      # 403 / 404 / 500 pages
│   ├── admin/
│   │   └── dashboard.html
│   └── client/
│       └── dashboard.html
│
├── static/
│   ├── css/style.css   # Component styles (glassmorphism dark theme)
│   └── js/app.js       # Toast auto-dismiss
│
├── logs/               # Rotating log file (gitignored)
└── cert_manager.db     # SQLite database (gitignored)
```

---

## License

Internal use.  Not for public distribution.
