#!/usr/bin/env python3
"""
Stand-alone script to initialise the CA and database.
Run once before starting the app for the first time:
    python init_ca.py
"""
import os
import sys
from pathlib import Path

# Ensure the app root is on the path
sys.path.insert(0, os.path.dirname(__file__))

from config import Config
import database as db
import cert_manager as cm

def main():
    print("CertPortal — Initialisation")
    print("=" * 40)

    # Ensure directories exist
    for d in [Path(Config.CERTS_DIR) / "ca",
              Path(Config.CERTS_DIR) / "clients",
              Path(Config.LOG_PATH).parent]:
        d.mkdir(parents=True, exist_ok=True)
        print(f"  Directory: {d}")

    # Database
    db.init_db()
    print(f"  Database : {Config.DB_PATH}")

    # CA
    if cm.ca_exists():
        print(f"  CA       : already exists at {Config.CA_CERT_PATH}")
    else:
        cm.init_ca()
        print(f"  CA       : generated at {Config.CA_CERT_PATH}")

    print()
    info = cm.get_ca_info()
    if info:
        print(f"  Subject  : {info['subject']}")
        print(f"  Valid    : {info['not_before']}  →  {info['not_after']}")

    print()
    print("Initialisation complete. Start the app with:")
    print("  python run.py")
    print("  or: flask run --host 0.0.0.0 --port 5000")


if __name__ == "__main__":
    main()
