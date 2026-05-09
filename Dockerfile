FROM python:3.11-slim

WORKDIR /app

# cryptography and ldap3 have pure-Python / pre-built wheels; no build tools needed.
# Install gunicorn alongside app dependencies.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn==21.2.0

COPY . .

# /data is the single persistence mount:
#   /data/certs        → CA key, CA cert, CRL, client PEM files
#   /data/cert_manager.db → SQLite database
#   /data/logs         → rotating log file
RUN mkdir -p /data

EXPOSE 5000

# Two workers is right-sized for an internal tool.
# The embedded APScheduler reminder job uses a DB lock so duplicate sends are
# prevented even when multiple workers each start a scheduler thread.
CMD ["gunicorn", \
     "--workers", "2", \
     "--bind", "0.0.0.0:5000", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]
