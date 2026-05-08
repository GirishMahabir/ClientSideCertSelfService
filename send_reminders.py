#!/usr/bin/env python3
"""Standalone reminder script — alternative to the embedded APScheduler job.

Run daily via cron or systemd timer when you prefer not to use the background
scheduler inside the Flask process:

    # crontab example — run every day at 07:00
    0 7 * * * /opt/certportal/.venv/bin/python /opt/certportal/send_reminders.py

Set REMINDER_ENABLED=true and configure SMTP_* vars in your .env before use.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from reminders import send_expiry_reminders

if __name__ == "__main__":
    with create_app().app_context():
        send_expiry_reminders()
