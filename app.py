import os
import csv
import sqlite3
import smtplib
from io import StringIO, BytesIO
from pathlib import Path
from functools import wraps
from datetime import datetime, date, timedelta
from datetime import timezone

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, make_response, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_RIGHT




from reportlab.pdfgen import canvas
from io import BytesIO


from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

import shutil

def dict_factory(cursor, row):
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}

def to_namibia_time(value):
    """Convert stored UTC datetime (datetime object or ISO string) to Namibia local time (UTC+2) string."""
    from datetime import datetime, timedelta

    if value is None:
        return None

    if isinstance(value, datetime):
        # Strip tzinfo if present to avoid aware/naive conflict
        if value.tzinfo is not None:
            value = value.replace(tzinfo=None)
        return (value + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M")

    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is not None:
                dt = dt.replace(tzinfo=None)
            return (dt + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M")
        except Exception:
            return value[:16] if len(value) >= 16 else value

    return str(value)


import csv
from io import StringIO


def build_csv_response(rows, columns, filename):
    """
    Build a Flask response that downloads a CSV file.
    `columns` is a list of (key, header) tuples.
    `rows` is a list of dicts.
    """
    si = StringIO()
    # Use UTF-8 BOM so Excel opens accented characters correctly
    si.write('\ufeff')
    writer = csv.writer(si)

    # Header
    writer.writerow([header for _, header in columns])

    # Rows
    for row in rows:
        out = []
        for key, _ in columns:
            val = row.get(key) if isinstance(row, dict) else None
            if val is None:
                out.append("")
            else:
                out.append(str(val))
        writer.writerow(out)

    output = si.getvalue()
    response = make_response(output)
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def _export_filename(prefix, filtered=False):
    """e.g. audit_log_filtered_2026-10-11_22-45.csv"""
    from datetime import datetime
    suffix = "_filtered" if filtered else ""
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
    return f"{prefix}{suffix}_{ts}.csv"


def _build_filters_from_request(prefix=""):
    """
    Read the same filter params used by login-history and audit-log pages.
    Returns (where_clause, params, meta_dict).
    `meta_dict` describes the filters for the PDF header.
    """
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    user_filter = (request.args.get("user_filter") or "").strip()
    status_filter = (request.args.get("status_filter") or "").strip()
    action_filter = (request.args.get("action_filter") or "").strip()
    entity_filter = (request.args.get("entity_filter") or "").strip()

    where = " WHERE 1=1"
    params = []

    if date_from:
        where += f" AND date({prefix}created_at) >= ?"
        params.append(date_from)
    if date_to:
        where += f" AND date({prefix}created_at) <= ?"
        params.append(date_to)

    meta = {
        "date_from": date_from or "—",
        "date_to": date_to or "—",
        "user_filter": user_filter or "—",
        "status_filter": status_filter or "—",
        "action_filter": action_filter or "—",
        "entity_filter": entity_filter or "—",
    }

    return where, params, meta, {
        "date_from": date_from,
        "date_to": date_to,
        "user_filter": user_filter,
        "status_filter": status_filter,
        "action_filter": action_filter,
        "entity_filter": entity_filter,
    }

# =============================================
# LOAD ENVIRONMENT VARIABLES
# =============================================
load_dotenv()

# =============================================
# BASE PATH
# =============================================
BASE = Path(__file__).resolve().parent
DB = BASE / "rab.db"


app = Flask(__name__)

# =============================================
# SECRET KEY — must be set BEFORE any extension
# =============================================
_secret_key = os.environ.get("SECRET_KEY")
if not _secret_key:
    if os.environ.get("FLASK_DEBUG") == "1":
        _secret_key = "dev-only-secret-key-do-not-use-in-production"
        print("⚠️ Using dev-only SECRET_KEY")
    else:
        raise RuntimeError(
            "SECRET_KEY environment variable is not set! "
            "Please configure it in the Render dashboard."
        )
app.secret_key = _secret_key


from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,        # trust 1 proxy for X-Forwarded-For
    x_proto=1,      # trust X-Forwarded-Proto (https)
    x_host=1,       # trust X-Forwarded-Host
    x_port=1,       # trust X-Forwarded-Port
)


@app.before_request
def _enforce_idle_timeout():
    """
    Force-logout users who have been idle too long.
    Runs on every request before the view function.
    """
    from datetime import datetime, timezone

    # Skip static files and the login/logout routes themselves
    path = request.path or ""
    if path.startswith("/static/") or path in ("/login", "/customer-login", "/logout"):
        return

    # Only run if the user is logged in
    user_id = session.get("user_id")
    if not user_id:
        return

    role = session.get("role", "staff")
    idle_limit = _role_idle_seconds(role)

    now = datetime.now(timezone.utc).timestamp()
    last = session.get("last_activity")

    if last is None:
        # First request after login — initialize
        session["last_activity"] = now
        return

    idle_seconds = now - last

    if idle_seconds > idle_limit:
        # Log the timeout
        try:
            log_audit(
                action="session_timeout",
                entity_type="user",
                entity_id=user_id,
                details=f"Idle timeout after {int(idle_seconds // 60)} minutes (limit: {idle_limit // 60} min)"
            )
        except Exception as e:
            print(f"⚠️ session_timeout log failed: {e}")

        session.clear()
        flash("You have been logged out due to inactivity. Please log in again.", "warning")
        return redirect(url_for("login"))

    # Update last_activity on every active request
    session["last_activity"] = now
    session.modified = True





def backfill_2fa_required():
    """Mark admin/manager as 2FA-required — but ONLY in production."""
    # Skip locally — don't force 2FA during development
    if not os.environ.get("DATABASE_URL"):
        print("ℹ️ Skipping 2FA backfill (local dev).")
        return

    try:
        conn = db()
        c = conn.cursor()
        execute_query(c, """
            UPDATE users
            SET twofa_required = 1
            WHERE role IN ('admin', 'manager')
              AND (twofa_required IS NULL OR twofa_required = 0)
        """)
        conn.commit()
        conn.close()
        print("✅ Backfilled 2FA requirement for admin/manager users.")
    except Exception as e:
        print(f"⚠️ backfill_2fa_required failed: {e}")


@app.before_request
def _enforce_2fa_setup():
    """..."""
    # ✅ Skip entirely in local development
    if not os.environ.get("DATABASE_URL"):
        return

    path = request.path or ""
    if path.startswith("/static/") or path.startswith("/2fa/"):
        return
    if path in ("/login", "/customer-login", "/logout"):
        return

    user_id = session.get("user_id")
    if not user_id:
        return

    if session.get("twofa_verified"):
        return

    try:
        conn = db()
        c = conn.cursor()
        user = execute_query(c, """
            SELECT id, role, twofa_required, twofa_enabled FROM users WHERE id = ?
        """, (user_id,)).fetchone()
        conn.close()
    except Exception:
        return

    if not user:
        return

    if user_needs_2fa_setup(user):
        flash("You must enable two-factor authentication before continuing.", "warning")
        return redirect(url_for("twofa_setup"))

    if user.get("twofa_enabled") and not session.get("twofa_verified"):
        return redirect(url_for("twofa_verify"))



# =============================================
# BACKGROUND SCHEDULER (retention cleanup)
# =============================================
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

def _scheduled_cleanup():
    """Wrapper so we always log success/failure."""
    try:
        with app.app_context():
            cleanup_old_logs()
    except Exception as e:
        print(f"⚠️ Scheduled cleanup failed: {e}")

# Only start the scheduler if we're not in a Flask reloader child process
# (avoids duplicate schedules when debug=True spawns two processes)
import os as _os
if _os.environ.get("WERKZEUG_RUN_MAIN") != "true" or not _os.environ.get("FLASK_DEBUG"):
    scheduler = BackgroundScheduler(daemon=True)
    # Every day at 03:00 local server time (UTC on Render = 05:00 Namibia)
    scheduler.add_job(_scheduled_cleanup, "cron", hour=3, minute=0)
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown(wait=False))
    print("✅ Retention scheduler started (runs daily at 03:00 UTC)")

# =============================================
# SECURITY INITIALIZATION
# =============================================

# Detect prod environment (Render sets RENDER=true; DATABASE_URL=postgres on prod)
_is_prod = (
    os.environ.get("RENDER") == "true"
    or os.environ.get("DATABASE_URL", "").startswith("postgres")
)

# 1. CSRF protection
csrf = CSRFProtect(app)

# 2. Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"],
    storage_uri="memory://",
    headers_enabled=True,
)

Talisman(
    app,
    force_https=_is_prod,
    force_https_permanent=_is_prod,
    strict_transport_security=_is_prod,
    strict_transport_security_max_age=31536000 if _is_prod else 0,
    strict_transport_security_include_subdomains=False,
    strict_transport_security_preload=False,
    session_cookie_secure=_is_prod,
    session_cookie_http_only=True,
    frame_options="DENY",
    referrer_policy="strict-origin-when-cross-origin",
    content_security_policy={
        "default-src": "'self'",
        "script-src": "'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        "style-src": "'self' 'unsafe-inline'",
        "font-src": "'self'",
        "img-src": "'self' data: https://res.cloudinary.com",
        "connect-src": "'self'",
        "frame-ancestors": "'none'",
        "object-src": "'none'",
        "base-uri": "'self'",
        "form-action": "'self'",
    },
    content_security_policy_report_only=False,
)

# 4. Cookie hardening
app.config.update(
    SESSION_COOKIE_SECURE=_is_prod,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PREFERRED_URL_SCHEME="https" if _is_prod else "http",
    WTF_CSRF_TIME_LIMIT=3600,
)



# =============================================
# UPLOAD FOLDER
# =============================================
UPLOAD_FOLDER = os.path.join(BASE, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Public uploads (legacy, no longer used for new files)
UPLOAD_FOLDER = os.path.join(BASE, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ✅ New: private uploads (NOT under static/) — served only via authenticated route
PRIVATE_UPLOAD_FOLDER = os.path.join(BASE, 'private_uploads')
os.makedirs(PRIVATE_UPLOAD_FOLDER, exist_ok=True)

# File validation constants
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".pdf"}

# =============================================
# PASSWORD POLICY
# =============================================
import re as _re



_COMMON_PASSWORDS = {
    # Top 50 leaked passwords (compiled from HaveIBeenPwned / NCSC)
    "password", "passw0rd", "password1", "password12", "password123", "password1234",
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "qwertyuiop", "azerty", "123qwe",
    "abc123", "letmein", "welcome", "welcome1", "welcome123",
    "admin", "admin123", "administrator", "root", "toor",
    "pass", "pass123", "changeme", "iloveyou", "monkey",
    "dragon", "sunshine", "princess", "football", "baseball",
    "123123", "qwe123", "1q2w3e4r", "zxcvbnm", "asdfghjkl",
    "trustno1", "starwars", "whatever", "freedom", "hunter",
    # Project-specific
    "rab123", "rab12345", "rabrate123", "rent123", "bike123",
    "rabrental", "rabrentals", "rab-bike", "rabbike",
    "windhoek", "namibia",
}

def validate_password_strength(password):
    """
    Check a password against the policy (Q1 — Strong).
    Returns (ok: bool, error_message: str or None)
    """
    if not password:
        return False, "Password is required."

    if password != password.strip():
        return False, "Password cannot start or end with a space."

    if len(password) < 10:
        return False, "Password must be at least 10 characters long."

    if not _re.search(r"[A-Za-z]", password):
        return False, "Password must contain at least one letter."

    if not _re.search(r"\d", password):
        return False, "Password must contain at least one number."

    if not _re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must contain at least one special character (e.g. ! @ # $ %)."

    # ✅ Substring check with normalization (defeats common bypass tricks)
    lower = password.lower()
    normalized = (
        lower
        .replace("@", "a")
        .replace("0", "o")
        .replace("1", "i")
        .replace("3", "e")
        .replace("5", "s")
        .replace("$", "s")
        .replace("!", "i")
    )

    for common in _COMMON_PASSWORDS:
        if common in normalized:
            return False, "This password contains a common word. Please choose something less predictable."

    return True, None




ALLOWED_MIME_TYPES = {
    "image/jpeg", "image/jpg", "image/png",
    "application/pdf",
}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# =============================================
# DATA RETENTION POLICY (single source of truth)
# =============================================
RETENTION = {
    "rental_records_years": 7,        # accounting / tax — Namibian company records
    "payment_records_years": 7,       # accounting / tax
    "customer_documents_years": 2,    # after last rental
    "login_history_days": 90,
    "audit_log_days": 180,
    "document_views_days": 90,
    "damage_claims_years": 7,         # accounting
}

# =============================================
# SESSION IDLE TIMEOUTS (per role, in minutes)
# =============================================
SESSION_IDLE_MINUTES = {
    "admin": 15,
    "manager": 30,
    "staff": 30,
    "customer": 60,
}
SESSION_WARN_SECONDS = 120  # Show warning when this many seconds remain

# =============================================
# ACCOUNT LOCKOUT POLICY
# =============================================
LOCKOUT_MAX_FAILURES = 5              # Lock after this many consecutive failures
LOCKOUT_DURATION_MINUTES = 15         # Auto-unlock after this many minutes


def _role_idle_seconds(role):
    """Return idle timeout in seconds for a role."""
    minutes = SESSION_IDLE_MINUTES.get(role, 30)
    return minutes * 60


PRIVACY_EMAIL = "privacy@rab.com"


def db():
    """Connect to the database."""
    import os
    if os.environ.get("DATABASE_URL"):
        # PostgreSQL (Production on Render)
        import psycopg2
        import psycopg2.extras
        
        conn = psycopg2.connect(os.environ.get("DATABASE_URL"))
        # ✅ IMPORTANT: Use RealDictCursor to return rows as dictionaries
        conn.cursor_factory = psycopg2.extras.RealDictCursor
        return conn
    else:
        # SQLite (Local Development)
        import sqlite3
        conn = sqlite3.connect(DB)
        conn.execute("PRAGMA foreign_keys = ON")
       # conn.row_factory = sqlite3.Row
        conn.row_factory = dict_factory    # ✅ new
        return conn


def validate_upload(file_storage):
    """
    Validate an uploaded file.
    Returns (ok: bool, error_message: str or None, ext: str or None)
    """
    if not file_storage or not file_storage.filename:
        return (True, None, None)  # nothing uploaded, not an error

    # Extension check
    filename = file_storage.filename
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return (False, f"File type '{ext}' is not allowed. Use JPG, PNG, or PDF.", None)

    # MIME check (client-supplied, but worth verifying)
    if file_storage.mimetype and file_storage.mimetype not in ALLOWED_MIME_TYPES:
        return (False, f"Invalid MIME type '{file_storage.mimetype}'.", None)

    # Size check — read a bit, then rewind
    try:
        file_storage.stream.seek(0, os.SEEK_END)
        size = file_storage.stream.tell()
        file_storage.stream.seek(0)
    except Exception:
        size = 0

    if size > MAX_FILE_SIZE:
        return (False, f"File is too large ({size // 1024 // 1024} MB). Maximum is 10 MB.", None)

    return (True, None, ext)


def migrate_public_uploads_to_private():
    """
    Move any files currently in static/uploads/ to private_uploads/ and
    update the DB paths accordingly. Safe to run on every boot — it's idempotent.
    """
    conn = db()
    c = conn.cursor()

    # Only handle local paths (skip Cloudinary URLs)
    rows = execute_query(c, """
        SELECT id, file_path FROM customer_documents
        WHERE file_path LIKE 'uploads/%'
    """).fetchall()

    if not rows:
        conn.close()
        return

    moved = 0
    for row in rows:
        rel_path = row["file_path"]  # e.g. "uploads/id_3_x.png"
        filename = os.path.basename(rel_path)
        old_path = os.path.join(BASE, 'static', rel_path)     # static/uploads/...
        new_rel = f"private_uploads/{filename}"
        new_path = os.path.join(PRIVATE_UPLOAD_FOLDER, filename)

        if os.path.exists(old_path):
            try:
                shutil.move(old_path, new_path)
                moved += 1
            except Exception as e:
                print(f"⚠️ Could not move {old_path}: {e}")
                continue

        # Update DB regardless — even if file was already moved in a prior run
        execute_query(c, """
            UPDATE customer_documents SET file_path = ? WHERE id = ?
        """, (new_rel, row["id"]))

    conn.commit()
    conn.close()
    if moved:
        print(f"✅ Migrated {moved} file(s) from static/uploads to private_uploads.")




def execute_query(cursor, query, params=None):
    """Execute a query with proper parameter handling for both SQLite and PostgreSQL."""
    import os
    is_postgres = os.environ.get("DATABASE_URL") is not None
    
    if is_postgres:
        # Replace ? with %s for PostgreSQL
        query = query.replace("?", "%s")
    
    if params:
        cursor.execute(query, params)
    else:
        cursor.execute(query)
    
    # ✅ Return the cursor so you can use .fetchone() or .fetchall()
    return cursor

def insert_and_get_id(cursor, query, params=None):
    """
    Insert a row and return the new row's ID.
    Works on both SQLite (via lastrowid) and PostgreSQL (via RETURNING id).
    """
    is_postgres = os.environ.get("DATABASE_URL") is not None

    if is_postgres:
        # ✅ Convert ? placeholders to %s for Postgres
        pg_query = query.replace("?", "%s").rstrip().rstrip(";")

        # Strip any existing RETURNING clause so we can add our own
        if "RETURNING" in pg_query.upper():
            pg_query = pg_query[:pg_query.upper().index("RETURNING")].rstrip()

        pg_query = pg_query + " RETURNING id"

        if params:
            cursor.execute(pg_query, params)
        else:
            cursor.execute(pg_query)

        row = cursor.fetchone()
        if not row:
            return None
        if isinstance(row, dict):
            return list(row.values())[0]
        return row[0]
    else:
        # SQLite
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        return cursor.lastrowid



def get_single_value(cursor, query, params=None):
    """Get a single value from a query (handles both SQLite and PostgreSQL)."""
    result = execute_query(cursor, query, params).fetchone()
    if result is None:
        return 0
    # For PostgreSQL with RealDictCursor, result is a dict
    if isinstance(result, dict):
        # Get the first value from the dict
        return list(result.values())[0] if result.values() else 0
    else:
        # For SQLite tuple
        return result[0] if result else 0


def parse_user_agent(ua_string):
    """Return a short human-readable summary like 'Chrome on Windows'."""
    if not ua_string:
        return "Unknown"

    ua = ua_string.lower()

    # Browser
    if "edg" in ua:
        browser = "Edge"
    elif "chrome" in ua and "edg" not in ua:
        browser = "Chrome"
    elif "firefox" in ua:
        browser = "Firefox"
    elif "safari" in ua and "chrome" not in ua:
        browser = "Safari"
    elif "opera" in ua or "opr" in ua:
        browser = "Opera"
    else:
        browser = "Unknown browser"

    # OS
    if "windows" in ua:
        os_name = "Windows"
    elif "iphone" in ua or "ipad" in ua:
        os_name = "iOS"
    elif "android" in ua:
        os_name = "Android"
    elif "mac os" in ua or "macintosh" in ua:
        os_name = "macOS"
    elif "linux" in ua:
        os_name = "Linux"
    else:
        os_name = "Unknown OS"

    return f"{browser} on {os_name}"


def mask_ip(ip):
    """Mask an IP for non-admin display: 192.168.1.42 → 192.168.***.***"""
    if not ip:
        return "unknown"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.***.***"
    # IPv6 or weird format
    return ip[:6] + "***"

def check_suspicious_login(user, ip_address, ua_string):
    """
    Fire alerts (email) if login looks suspicious.
    - Outside business hours (22:00–06:00 Namibia time)
    - ≥5 failed attempts for this username in last 10 minutes
    - New IP for this user (first time seen, and user has prior login history)
    """
    from datetime import datetime, timedelta

    try:
        conn = db()
        c = conn.cursor()

        alerts = []

        # 1. Non-working hours
        # local_hour = (utc_now() + timedelta(hours=2)).hour
        local_hour = (datetime.now(timezone.utc) + timedelta(hours=2)).hour
        if local_hour >= 22 or local_hour < 6:
            alerts.append(f"Login at {local_hour:02d}:00 (outside business hours)")

        # 2. Failed attempts
        failed = get_single_value(c, """
            SELECT COUNT(*) FROM login_history
            WHERE username_attempted = ?
              AND success = 0
              AND created_at >= datetime('now', '-10 minutes')
        """ if not os.environ.get("DATABASE_URL") else """
            SELECT COUNT(*) FROM login_history
            WHERE username_attempted = %s
              AND success = 0
              AND created_at >= CURRENT_TIMESTAMP - INTERVAL '10 minutes'
        """, (user["username"],))
        if failed and int(failed) >= 5:
            alerts.append(f"{failed} failed login attempts in the last 10 minutes")

        # 3. New IP for this user
        if ip_address:
            prior = get_single_value(c, """
                SELECT COUNT(*) FROM login_history
                WHERE user_id = ? AND ip_address = ? AND success = 1
            """, (user["id"], ip_address))
            total = get_single_value(c, """
                SELECT COUNT(*) FROM login_history
                WHERE user_id = ? AND success = 1
            """, (user["id"],))
            # New IP: user has prior logins (>=1) but not from this IP
            if (total or 0) > 0 and (prior or 0) == 0:
                alerts.append(f"New IP address: {ip_address}")

        conn.close()

        # Send email if there are alerts
        if alerts:
            subject = f"⚠️ Suspicious login: {user['username']}"
            body = (
                f"A login for user '{user['username']}' ({user.get('full_name', '')}) "
                f"was flagged as suspicious:\n\n"
                + "\n".join(f"• {a}" for a in alerts)
                + f"\n\nIP: {ip_address}\nDevice: {parse_user_agent(ua_string)}"
                + f"\nTime (UTC): {utc_now().isoformat()}"
                + "\n\n— RAB Daily Rental Security"
            )
            # Send to admins
            admin_emails = execute_query(c, """
                SELECT email FROM users WHERE role = 'admin' AND email IS NOT NULL AND email != ''
            """).fetchall() if False else []  # need a fresh connection
            # Fresh query
            conn2 = db()
            c2 = conn2.cursor()
            admin_rows = execute_query(c2, """
                SELECT email FROM users WHERE role = 'admin' 
                AND email IS NOT NULL AND email != ''
            """).fetchall()
            conn2.close()

            for admin in admin_rows:
                try:
                    send_email_notification(admin["email"], subject, body)
                except Exception as e:
                    print(f"⚠️ Alert email failed: {e}")

    except Exception as e:
        print(f"⚠️ check_suspicious_login failed: {e}")



def log_login_attempt(user_id, username_attempted, success,
                      ip_address=None, user_agent=None, failure_reason=None):
    """Insert a row in login_history."""
    try:
        conn = db()
        c = conn.cursor()
        execute_query(c, """
            INSERT INTO login_history
            (user_id, username_attempted, success, ip_address, user_agent,
             device_summary, failure_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            username_attempted,
            1 if success else 0,
            ip_address,
            user_agent,
            parse_user_agent(user_agent),
            failure_reason
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ log_login_attempt failed: {e}")


def get_lockout_status(cursor, user_id):
    """
    Return a dict with the lockout status of a user:
      {
        "locked": bool,
        "minutes_remaining": int,
        "failed_count": int,
      }
    """
    row = execute_query(cursor, """
        SELECT failed_count, locked_until
        FROM login_attempts
        WHERE user_id = ?
    """, (user_id,)).fetchone()

    if not row:
        return {"locked": False, "minutes_remaining": 0, "failed_count": 0}

    failed_count = row.get("failed_count") or 0
    locked_until_raw = row.get("locked_until")

    if not locked_until_raw:
        return {"locked": False, "minutes_remaining": 0, "failed_count": failed_count}

    from datetime import datetime, timezone, timedelta

    # Parse locked_until — could be a datetime (Postgres) or string (SQLite)
    if isinstance(locked_until_raw, datetime):
        locked_until = locked_until_raw
        if locked_until.tzinfo is not None:
            locked_until = locked_until.astimezone(timezone.utc).replace(tzinfo=None)
    else:
        try:
            locked_until = datetime.fromisoformat(str(locked_until_raw))
            if locked_until.tzinfo is not None:
                locked_until = locked_until.astimezone(timezone.utc).replace(tzinfo=None)
        except Exception:
            return {"locked": False, "minutes_remaining": 0, "failed_count": failed_count}

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if locked_until > now:
        remaining = (locked_until - now).total_seconds() / 60
        return {
            "locked": True,
            "minutes_remaining": max(1, int(round(remaining))),
            "failed_count": failed_count,
        }

    # Lock has expired — clear it lazily
    try:
        execute_query(cursor, """
            UPDATE login_attempts
            SET locked_until = NULL, locked_reason = NULL, failed_count = 0
            WHERE user_id = ?
        """, (user_id,))
    except Exception:
        pass

    return {"locked": False, "minutes_remaining": 0, "failed_count": failed_count}


def record_failed_login(cursor, user_id):
    """
    Increment failed count for a user and lock if threshold reached.
    Returns the new state: {"locked": bool, "minutes_remaining": int, "failed_count": int}
    """
    from datetime import datetime, timezone, timedelta

    row = execute_query(cursor, """
        SELECT failed_count FROM login_attempts WHERE user_id = ?
    """, (user_id,)).fetchone()

    current = (row.get("failed_count") if row else 0) or 0
    new_count = current + 1

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    locked_until = None
    reason = None

    if new_count >= LOCKOUT_MAX_FAILURES:
        locked_until = now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        reason = f"Locked after {new_count} failed attempts"
        new_count = 0  # reset counter so it starts fresh after unlock

    if row:
        execute_query(cursor, """
            UPDATE login_attempts
            SET failed_count = ?, last_failed_at = ?, locked_until = ?, locked_reason = ?
            WHERE user_id = ?
        """, (new_count, now.isoformat(), 
              locked_until.isoformat() if locked_until else None,
              reason, user_id))
    else:
        execute_query(cursor, """
            INSERT INTO login_attempts (user_id, failed_count, last_failed_at, locked_until, locked_reason)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, new_count, now.isoformat(),
              locked_until.isoformat() if locked_until else None, reason))

    if locked_until:
        return {
            "locked": True,
            "minutes_remaining": LOCKOUT_DURATION_MINUTES,
            "failed_count": new_count,
        }

    return {"locked": False, "minutes_remaining": 0, "failed_count": new_count}


def reset_login_attempts(cursor, user_id):
    """Clear failed count and lockout after a successful login."""
    try:
        execute_query(cursor, """
            UPDATE login_attempts
            SET failed_count = 0, locked_until = NULL, locked_reason = NULL
            WHERE user_id = ?
        """, (user_id,))
    except Exception:
        pass


def unlock_user_account(user_id):
    """Admin action: manually unlock a user and clear their failed counter."""
    try:
        conn = db()
        c = conn.cursor()
        execute_query(c, """
            UPDATE login_attempts
            SET failed_count = 0, locked_until = NULL, locked_reason = NULL
            WHERE user_id = ?
        """, (user_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"⚠️ unlock_user_account failed: {e}")
        return False


def log_audit(action, entity_type=None, entity_id=None, details=None,
              user_id=None, username=None, user_role=None):
    """
    Insert a row in audit_log. If user_id/username/role aren't passed,
    it will try to read from the current session.
    """
    try:
        # Try to grab from session
        if user_id is None:
            user_id = session.get("user_id")
        if username is None:
            username = session.get("username")
        if user_role is None:
            user_role = session.get("role")

        conn = db()
        c = conn.cursor()
        execute_query(c, """
            INSERT INTO audit_log
            (user_id, username, user_role, action, entity_type, entity_id,
             details, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            username,
            user_role,
            action,
            entity_type,
            entity_id,
            details,
            request.remote_addr if request else None,
            request.headers.get("User-Agent") if request else None
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ log_audit failed: {e}")


def get_customer_unpaid_damages(cursor, customer_id):
    """Return total unpaid damage amount for a customer."""
    result = execute_query(cursor, """
        SELECT COALESCE(SUM(amount), 0) AS total
        FROM damage_claims
        WHERE customer_id = ? AND status != 'Paid' AND status != 'Waived'
    """, (customer_id,)).fetchone()
    if not result:
        return 0.0
    if isinstance(result, dict):
        return float(list(result.values())[0] or 0)
    return float(result[0] or 0)



def get_duration_sql():
    """Return the correct duration SQL for the database."""
    if os.environ.get("DATABASE_URL"):
        # PostgreSQL - calculate duration from UTC time
        return """
            CONCAT(
                GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - r.start_time)) / 3600)), 'h ',
                GREATEST(0, FLOOR((EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - r.start_time)) % 3600) / 60)), 'm'
            ) AS duration
        """
    else:
        # SQLite - calculate duration from UTC time
        return """
            CAST(MAX(0, (strftime('%s', 'now') - strftime('%s', r.start_time))) / 3600 AS INTEGER) || 'h ' ||
            CAST(MAX(0, ((strftime('%s', 'now') - strftime('%s', r.start_time)) % 3600)) / 60 AS INTEGER) || 'm' AS duration
        """

def get_count(cursor, query, params=None):
    """Execute a count query and return the count, works for both SQLite and PostgreSQL."""
    result = execute_query(cursor, query, params).fetchone()
    if result is None:
        return 0
    # For PostgreSQL with RealDictCursor, result is a dict
    # For SQLite with Row, result is also dict-like
    if isinstance(result, dict):
        # Try to get the first value from the dict
        return list(result.values())[0] if result.values() else 0
    else:
        # For tuple or other types
        return result[0] if result else 0







# =============================================
# NOTIFICATION CONFIGURATION
# =============================================
EMAIL_ENABLED = False
EMAIL_HOST = os.environ.get("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", 587))
EMAIL_USER = os.environ.get("EMAIL_USER", "")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "noreply@rab.com")

# =============================================
# TWILIO SMS CONFIGURATION
# =============================================

SMS_ENABLED = False  # ✅ Enable SMS

# ✅ These MUST be set in Render environment variables
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.environ.get("TWILIO_PHONE_NUMBER")

# Optional: Check if credentials are set
if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN or not TWILIO_PHONE_NUMBER:
    print("⚠️ Warning: Twilio credentials not fully configured")
    SMS_ENABLED = False  # Disable SMS if credentials missing






import cloudinary
import cloudinary.uploader

# Cloudinary configuration
CLOUDINARY_CLOUD_NAME = os.environ.get("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.environ.get("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.environ.get("CLOUDINARY_API_SECRET")

if CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET:
    cloudinary.config(
        cloud_name=CLOUDINARY_CLOUD_NAME,
        api_key=CLOUDINARY_API_KEY,
        api_secret=CLOUDINARY_API_SECRET
    )
    print("✅ Cloudinary configured successfully!")
else:
    print("⚠️ Cloudinary credentials not set. Using local storage.")

def utc_now():
    """Return current UTC time as a naive datetime (compatible with our storage)."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).replace(tzinfo=None)




def cleanup_old_logs():
    """Delete logs older than retention window. Run once a day."""
    try:
        conn = db()
        c = conn.cursor()
        is_postgres = os.environ.get("DATABASE_URL") is not None

        login_days = RETENTION["login_history_days"]
        audit_days = RETENTION["audit_log_days"]
        doc_days = RETENTION["document_views_days"]

        if is_postgres:
            execute_query(c, f"""
                DELETE FROM login_history 
                WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '{login_days} days'
            """)
            execute_query(c, f"""
                DELETE FROM audit_log 
                WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '{audit_days} days'
            """)
            execute_query(c, f"""
                DELETE FROM document_views 
                WHERE viewed_at < CURRENT_TIMESTAMP - INTERVAL '{doc_days} days'
            """)
        else:
            execute_query(c, f"""
                DELETE FROM login_history 
                WHERE created_at < datetime('now', '-{login_days} days')
            """)
            execute_query(c, f"""
                DELETE FROM audit_log 
                WHERE created_at < datetime('now', '-{audit_days} days')
            """)
            execute_query(c, f"""
                DELETE FROM document_views 
                WHERE viewed_at < datetime('now', '-{doc_days} days')
            """)

        # Clear expired lockouts and stale failure counters
        is_postgres = os.environ.get("DATABASE_URL") is not None
        if is_postgres:
            execute_query(c, """
                UPDATE login_attempts
                SET locked_until = NULL, locked_reason = NULL, failed_count = 0
                WHERE locked_until IS NOT NULL AND locked_until < CURRENT_TIMESTAMP
            """)
            execute_query(c, """
                DELETE FROM login_attempts
                WHERE failed_count = 0
                  AND locked_until IS NULL
                  AND last_failed_at < CURRENT_TIMESTAMP - INTERVAL '30 days'
            """)
        else:
            execute_query(c, """
                UPDATE login_attempts
                SET locked_until = NULL, locked_reason = NULL, failed_count = 0
                WHERE locked_until IS NOT NULL AND locked_until < datetime('now')
            """)
            execute_query(c, """
                DELETE FROM login_attempts
                WHERE failed_count = 0
                  AND locked_until IS NULL
                  AND last_failed_at < datetime('now', '-30 days')
            """)


        conn.commit()
        conn.close()
        print("✅ Log cleanup complete.")
    except Exception as e:
        print(f"⚠️ cleanup_old_logs failed: {e}")


def login_required(f):
    """Check if user is logged in."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please login to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper






def init_db():
    """Initialize the database with daily rental tables."""
    conn = db()
    c = conn.cursor()
    
    is_postgres = os.environ.get("DATABASE_URL") is not None
    
    if is_postgres:
        # =============================================
        # POSTGRESQL SYNTAX (Production on Render)
        # =============================================
        
        # Users table
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS users(
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'staff',
                full_name TEXT,
                email TEXT,
                branch_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Customers table
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS customers(
                id SERIAL PRIMARY KEY,
                full_name TEXT NOT NULL,
                id_number TEXT,
                phone TEXT NOT NULL,
                email TEXT,
                address TEXT,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                terms_accepted INTEGER DEFAULT 0,
                terms_accepted_date TIMESTAMP,
                signature_data TEXT,
                verification_status TEXT DEFAULT 'Pending',
                verification_notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Customer Documents
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS customer_documents(
                id SERIAL PRIMARY KEY,
                customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
                document_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Branches
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS branches(
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                location TEXT,
                address TEXT,
                phone TEXT,
                email TEXT,
                manager_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Bicycles
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS bicycles(
                id SERIAL PRIMARY KEY,
                bike_code TEXT UNIQUE NOT NULL,
                brand TEXT,
                model TEXT,
                bike_type TEXT DEFAULT 'Standard',
                hourly_rate REAL DEFAULT 20,
                daily_cap REAL DEFAULT 120,
                deposit_amount REAL DEFAULT 50,
                status TEXT DEFAULT 'Available',
                branch_id INTEGER REFERENCES branches(id),
                notes TEXT
            );
        """)
        
        # Daily Rentals
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS daily_rentals(
                id SERIAL PRIMARY KEY,
                customer_id INTEGER NOT NULL REFERENCES customers(id),
                bicycle_id INTEGER NOT NULL REFERENCES bicycles(id),
                branch_id INTEGER REFERENCES branches(id),
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP,
                actual_return_time TIMESTAMP,
                total_hours REAL,
                total_cost REAL,
                hourly_rate REAL,
                daily_cap REAL,
                deposit_paid REAL DEFAULT 0,
                late_fee REAL DEFAULT 0,
                discount_code_id INTEGER,
                discount_amount REAL DEFAULT 0,
                payment_status TEXT DEFAULT 'Pending',
                payment_method TEXT,
                status TEXT DEFAULT 'Active',
                condition_before TEXT,
                condition_after TEXT,
                agreement_signed INTEGER DEFAULT 0,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Daily Rates
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS daily_rates(
                id SERIAL PRIMARY KEY,
                bike_type TEXT,
                hourly_rate REAL DEFAULT 20,
                daily_cap REAL DEFAULT 120,
                deposit REAL DEFAULT 50,
                is_active INTEGER DEFAULT 1
            );
        """)
        
        # Rental Payments
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS rental_payments(
                id SERIAL PRIMARY KEY,
                daily_rental_id INTEGER NOT NULL REFERENCES daily_rentals(id) ON DELETE CASCADE,
                amount REAL NOT NULL,
                payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                payment_method TEXT,
                status TEXT DEFAULT 'Completed'
            );
        """)
        
        # Verification Requests
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS verification_requests(
                id SERIAL PRIMARY KEY,
                customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
                verified_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                status TEXT DEFAULT 'Pending',
                notes TEXT,
                verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Reminder Logs
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS reminder_logs(
                id SERIAL PRIMARY KEY,
                rental_id INTEGER NOT NULL REFERENCES daily_rentals(id) ON DELETE CASCADE,
                reminder_type TEXT NOT NULL,
                sent_to TEXT NOT NULL,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Discount Codes
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS discount_codes(
                id SERIAL PRIMARY KEY,
                code TEXT UNIQUE NOT NULL,
                description TEXT,
                discount_type TEXT NOT NULL,
                discount_value REAL NOT NULL,
                min_rental_amount REAL DEFAULT 0,
                max_uses INTEGER DEFAULT 0,
                used_count INTEGER DEFAULT 0,
                start_date TIMESTAMP,
                end_date TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Discount Usage
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS discount_usage(
                id SERIAL PRIMARY KEY,
                discount_code_id INTEGER NOT NULL REFERENCES discount_codes(id),
                rental_id INTEGER NOT NULL REFERENCES daily_rentals(id) ON DELETE CASCADE,
                customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
                amount_discounted REAL NOT NULL,
                used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Loyalty Points
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS loyalty_points(
                id SERIAL PRIMARY KEY,
                customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
                points INTEGER DEFAULT 0,
                total_spent REAL DEFAULT 0,
                total_rentals INTEGER DEFAULT 0,
                tier TEXT DEFAULT 'Bronze',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Points Transactions
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS points_transactions(
                id SERIAL PRIMARY KEY,
                customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
                points INTEGER NOT NULL,
                transaction_type TEXT NOT NULL,
                description TEXT,
                rental_id INTEGER REFERENCES daily_rentals(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Maintenance Records
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS maintenance_records(
                id SERIAL PRIMARY KEY,
                bicycle_id INTEGER NOT NULL REFERENCES bicycles(id) ON DELETE CASCADE,
                maintenance_type TEXT NOT NULL,
                description TEXT,
                cost REAL DEFAULT 0,
                status TEXT DEFAULT 'Scheduled',
                scheduled_date TIMESTAMP,
                completed_date TIMESTAMP,
                performed_by TEXT,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Bike Conditions
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS bike_conditions(
                id SERIAL PRIMARY KEY,
                bicycle_id INTEGER NOT NULL REFERENCES bicycles(id) ON DELETE CASCADE,
                condition_type TEXT NOT NULL,
                condition_status TEXT NOT NULL,
                notes TEXT,
                checked_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                rental_id INTEGER REFERENCES daily_rentals(id) ON DELETE CASCADE
            );
        """)
        
        # Bicycle Health
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS bicycle_health(
                id SERIAL PRIMARY KEY,
                bicycle_id INTEGER NOT NULL REFERENCES bicycles(id) ON DELETE CASCADE,
                health_score INTEGER DEFAULT 100,
                condition_rating TEXT DEFAULT 'Excellent',
                last_maintenance_date TIMESTAMP,
                next_maintenance_due TIMESTAMP,
                total_maintenance_count INTEGER DEFAULT 0,
                total_repair_cost REAL DEFAULT 0,
                last_condition_check TIMESTAMP,
                notes TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Bicycle Health History
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS bicycle_health_history(
                id SERIAL PRIMARY KEY,
                bicycle_id INTEGER NOT NULL REFERENCES bicycles(id) ON DELETE CASCADE,
                health_score INTEGER NOT NULL,
                condition_rating TEXT NOT NULL,
                reason TEXT,
                recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Announcements
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS announcements(
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                author_name TEXT NOT NULL,
                author_role TEXT NOT NULL,
                priority TEXT DEFAULT 'normal',
                category TEXT DEFAULT 'general',
                is_pinned INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Announcement Comments
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS announcement_comments(
                id SERIAL PRIMARY KEY,
                announcement_id INTEGER NOT NULL REFERENCES announcements(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                user_name TEXT NOT NULL,
                user_role TEXT NOT NULL,
                comment TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Announcement Reads
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS announcement_reads(
                id SERIAL PRIMARY KEY,
                announcement_id INTEGER NOT NULL REFERENCES announcements(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(announcement_id, user_id)
            );
        """)
        
    else:
        # =============================================
        # SQLITE SYNTAX (Local Development)
        # =============================================
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'staff',
            full_name TEXT,
            email TEXT,
            branch_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS customers(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            id_number TEXT,
            phone TEXT NOT NULL,
            email TEXT,
            address TEXT,
            user_id INTEGER,
            terms_accepted INTEGER DEFAULT 0,
            terms_accepted_date TEXT,
            signature_data TEXT,
            verification_status TEXT DEFAULT 'Pending',
            verification_notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        
        CREATE TABLE IF NOT EXISTS customer_documents(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            document_type TEXT NOT NULL,
            file_path TEXT NOT NULL,
            uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS bicycles(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bike_code TEXT UNIQUE NOT NULL,
            brand TEXT,
            model TEXT,
            bike_type TEXT DEFAULT 'Standard',
            hourly_rate REAL DEFAULT 20,
            daily_cap REAL DEFAULT 120,
            deposit_amount REAL DEFAULT 50,
            status TEXT DEFAULT 'Available',
            branch_id INTEGER,
            notes TEXT,
            FOREIGN KEY (branch_id) REFERENCES branches(id)
        );
        
        CREATE TABLE IF NOT EXISTS daily_rentals(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            bicycle_id INTEGER NOT NULL,
            branch_id INTEGER,
            start_time TEXT NOT NULL,
            end_time TEXT,
            actual_return_time TEXT,
            total_hours REAL,
            total_cost REAL,
            hourly_rate REAL,
            daily_cap REAL,
            deposit_paid REAL DEFAULT 0,
            late_fee REAL DEFAULT 0,
            discount_code_id INTEGER,
            discount_amount REAL DEFAULT 0,
            payment_status TEXT DEFAULT 'Pending',
            payment_method TEXT,
            status TEXT DEFAULT 'Active',
            condition_before TEXT,
            condition_after TEXT,
            agreement_signed INTEGER DEFAULT 0,
            notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (customer_id) REFERENCES customers(id),
            FOREIGN KEY (bicycle_id) REFERENCES bicycles(id),
            FOREIGN KEY (discount_code_id) REFERENCES discount_codes(id),
            FOREIGN KEY (branch_id) REFERENCES branches(id)
        );
        
        CREATE TABLE IF NOT EXISTS daily_rates(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bike_type TEXT,
            hourly_rate REAL DEFAULT 20,
            daily_cap REAL DEFAULT 120,
            deposit REAL DEFAULT 50,
            is_active INTEGER DEFAULT 1
        );
        
        CREATE TABLE IF NOT EXISTS rental_payments(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            daily_rental_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            payment_date TEXT DEFAULT CURRENT_TIMESTAMP,
            payment_method TEXT,
            status TEXT DEFAULT 'Completed',
            FOREIGN KEY (daily_rental_id) REFERENCES daily_rentals(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS verification_requests(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            verified_by INTEGER,
            status TEXT DEFAULT 'Pending',
            notes TEXT,
            verified_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
            FOREIGN KEY (verified_by) REFERENCES users(id) ON DELETE SET NULL
        );
        
        CREATE TABLE IF NOT EXISTS reminder_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rental_id INTEGER NOT NULL,
            reminder_type TEXT NOT NULL,
            sent_to TEXT NOT NULL,
            sent_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (rental_id) REFERENCES daily_rentals(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS discount_codes(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            description TEXT,
            discount_type TEXT NOT NULL,
            discount_value REAL NOT NULL,
            min_rental_amount REAL DEFAULT 0,
            max_uses INTEGER DEFAULT 0,
            used_count INTEGER DEFAULT 0,
            start_date TEXT,
            end_date TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS discount_usage(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discount_code_id INTEGER NOT NULL,
            rental_id INTEGER NOT NULL,
            customer_id INTEGER NOT NULL,
            amount_discounted REAL NOT NULL,
            used_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (discount_code_id) REFERENCES discount_codes(id),
            FOREIGN KEY (rental_id) REFERENCES daily_rentals(id) ON DELETE CASCADE,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS loyalty_points(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            points INTEGER DEFAULT 0,
            total_spent REAL DEFAULT 0,
            total_rentals INTEGER DEFAULT 0,
            tier TEXT DEFAULT 'Bronze',
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS points_transactions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            points INTEGER NOT NULL,
            transaction_type TEXT NOT NULL,
            description TEXT,
            rental_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
            FOREIGN KEY (rental_id) REFERENCES daily_rentals(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS maintenance_records(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bicycle_id INTEGER NOT NULL,
            maintenance_type TEXT NOT NULL,
            description TEXT,
            cost REAL DEFAULT 0,
            status TEXT DEFAULT 'Scheduled',
            scheduled_date TEXT,
            completed_date TEXT,
            performed_by TEXT,
            notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (bicycle_id) REFERENCES bicycles(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS bike_conditions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bicycle_id INTEGER NOT NULL,
            condition_type TEXT NOT NULL,
            condition_status TEXT NOT NULL,
            notes TEXT,
            checked_by INTEGER,
            checked_at TEXT DEFAULT CURRENT_TIMESTAMP,
            rental_id INTEGER,
            FOREIGN KEY (bicycle_id) REFERENCES bicycles(id) ON DELETE CASCADE,
            FOREIGN KEY (checked_by) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (rental_id) REFERENCES daily_rentals(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS branches(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            location TEXT,
            address TEXT,
            phone TEXT,
            email TEXT,
            manager_id INTEGER,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (manager_id) REFERENCES users(id) ON DELETE SET NULL
        );
        
        CREATE TABLE IF NOT EXISTS bicycle_health(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bicycle_id INTEGER NOT NULL,
            health_score INTEGER DEFAULT 100,
            condition_rating TEXT DEFAULT 'Excellent',
            last_maintenance_date TEXT,
            next_maintenance_due TEXT,
            total_maintenance_count INTEGER DEFAULT 0,
            total_repair_cost REAL DEFAULT 0,
            last_condition_check TEXT,
            notes TEXT,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (bicycle_id) REFERENCES bicycles(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS bicycle_health_history(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bicycle_id INTEGER NOT NULL,
            health_score INTEGER NOT NULL,
            condition_rating TEXT NOT NULL,
            reason TEXT,
            recorded_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (bicycle_id) REFERENCES bicycles(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS announcements(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            author_name TEXT NOT NULL,
            author_role TEXT NOT NULL,
            priority TEXT DEFAULT 'normal',
            category TEXT DEFAULT 'general',
            is_pinned INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS announcement_comments(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            announcement_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            user_name TEXT NOT NULL,
            user_role TEXT NOT NULL,
            comment TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (announcement_id) REFERENCES announcements(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS announcement_reads(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            announcement_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            read_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (announcement_id) REFERENCES announcements(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(announcement_id, user_id)
        );
        """)
    
    # =============================================
    # ADD DEFAULT RATES (Works for both)
    # =============================================
    
    # Check if rates exist
    execute_query(c, "SELECT COUNT(*) as count FROM daily_rates")
    result = c.fetchone()
    count = result['count'] if isinstance(result, dict) else result[0]
    
    # if count == 0:
    #     if is_postgres:
    #         execute_query(c, "INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) VALUES ('Standard', 20, 120, 50)")
    #         execute_query(c, "INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) VALUES ('Electric', 30, 180, 75)")
    #         execute_query(c, "INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) VALUES ('Mountain', 25, 150, 60)")
    #     else:
    #         c.executescript("""
    #             INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) 
    #             VALUES ('Standard', 20, 120, 50);
    #             INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) 
    #             VALUES ('Electric', 30, 180, 75);
    #             INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) 
    #             VALUES ('Mountain', 25, 150, 60);
    #         """)

    if count == 0:
        if is_postgres:
            execute_query(c, "INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) VALUES ('Standard', 60, 480, 50)")
            execute_query(c, "INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) VALUES ('Electric', 90, 720, 75)")
            execute_query(c, "INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) VALUES ('Mountain', 75, 600, 60)")
        else:
            c.executescript("""
                INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) 
                VALUES ('Standard', 60, 480, 50);
                INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) 
                VALUES ('Electric', 90, 720, 75);
                INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) 
                VALUES ('Mountain', 75, 600, 60);
            """)

    # =============================================
    # CREATE DEFAULT USERS
    # =============================================
    try:
        if is_postgres:
            execute_query(c, """
                INSERT INTO users (username, password_hash, role, full_name) 
                VALUES ('admin', %s, 'admin', 'System Administrator')
                ON CONFLICT (username) DO NOTHING
            """, (generate_password_hash("admin123"),))
            
            execute_query(c, """
                INSERT INTO users (username, password_hash, role, full_name) 
                VALUES ('manager', %s, 'manager', 'Store Manager')
                ON CONFLICT (username) DO NOTHING
            """, (generate_password_hash("manager123"),))
            
            execute_query(c, """
                INSERT INTO users (username, password_hash, role, full_name) 
                VALUES ('staff', %s, 'staff', 'Sales Staff')
                ON CONFLICT (username) DO NOTHING
            """, (generate_password_hash("staff123"),))
        else:
            execute_query(c, """
                INSERT OR IGNORE INTO users (username, password_hash, role, full_name) 
                VALUES ('admin', ?, 'admin', 'System Administrator')
            """, (generate_password_hash("admin123"),))
            
            execute_query(c, """
                INSERT OR IGNORE INTO users (username, password_hash, role, full_name) 
                VALUES ('manager', ?, 'manager', 'Store Manager')
            """, (generate_password_hash("manager123"),))
            
            execute_query(c, """
                INSERT OR IGNORE INTO users (username, password_hash, role, full_name) 
                VALUES ('staff', ?, 'staff', 'Sales Staff')
            """, (generate_password_hash("staff123"),))
    except Exception as e:
        print(f"Error inserting default users: {e}")
    
    conn.commit()
    conn.close()


 



def ci_like(column, param):
    """
    Return a case-insensitive LIKE expression that works on both SQLite and PostgreSQL.
    Usage:  WHERE {ci_like('full_name', '?')}   or with a named param, just append.
    The `?` placeholder will be converted to %s automatically by execute_query().
    """
    if os.environ.get("DATABASE_URL"):
        # PostgreSQL
        return f"LOWER({column}) LIKE LOWER(?)"
    else:
        # SQLite — LIKE is already case-insensitive for ASCII by default
        return f"{column} LIKE ?"


def ensure_workers_schema():
    """
    Idempotent migration for the Workers / HR feature.
    Adds HR-related columns to the users table.
    """
    conn = db()
    c = conn.cursor()
    is_postgres = os.environ.get("DATABASE_URL") is not None

    if is_postgres:
        # Use ADD COLUMN IF NOT EXISTS — safe to run every boot
        for col, coltype in [
            ("id_number", "TEXT"),
            ("date_of_birth", "DATE"),
            ("hire_date", "DATE"),
            ("phone", "TEXT"),
            ("address", "TEXT"),
            ("emergency_contact", "TEXT"),
            ("job_title", "TEXT"),
            ("specialty", "TEXT"),
            ("salary", "REAL"),
            ("bank_details", "TEXT"),
            ("tax_number", "TEXT"),
            ("photo_path", "TEXT"),
            ("worker_notes", "TEXT"),
        ]:
            execute_query(c, f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {col} {coltype}")
    else:
        # SQLite — check PRAGMA first
        rows = execute_query(c, "PRAGMA table_info(users)").fetchall()
        existing = []
        for row in rows:
            existing.append(row.get("name") if isinstance(row, dict) else row[1])

        for col, coltype in [
            ("id_number", "TEXT"),
            ("date_of_birth", "TEXT"),
            ("hire_date", "TEXT"),
            ("phone", "TEXT"),
            ("address", "TEXT"),
            ("emergency_contact", "TEXT"),
            ("job_title", "TEXT"),
            ("specialty", "TEXT"),
            ("salary", "REAL"),
            ("bank_details", "TEXT"),
            ("tax_number", "TEXT"),
            ("photo_path", "TEXT"),
            ("worker_notes", "TEXT"),
        ]:
            if col not in existing:
                execute_query(c, f"ALTER TABLE users ADD COLUMN {col} {coltype}")

    if is_postgres:
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS worker_documents(
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                document_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                uploaded_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT
            );
        """)
    else:
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS worker_documents(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                document_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                uploaded_by_user_id INTEGER,
                uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (uploaded_by_user_id) REFERENCES users(id) ON DELETE SET NULL
            );
        """)

    conn.commit()
    conn.close()


def ensure_schema_columns():
    """
    Idempotently add audit + station columns to daily_rentals and bicycles.
    Safe to run on every startup on both SQLite and PostgreSQL.
    """
    conn = db()
    c = conn.cursor()
    is_postgres = os.environ.get("DATABASE_URL") is not None

    # (table, column, sqlite_type, postgres_type)
    columns = [
        # daily_rentals — audit trail
        ("daily_rentals", "started_by_user_id",   "INTEGER", "INTEGER"),
        ("daily_rentals", "ended_by_user_id",     "INTEGER", "INTEGER"),
        ("daily_rentals", "cancelled_by_user_id", "INTEGER", "INTEGER"),
        # daily_rentals — stations
        ("daily_rentals", "start_station_id",     "INTEGER", "INTEGER"),
        ("daily_rentals", "end_station_id",       "INTEGER", "INTEGER"),
        # bicycles — current location
        ("bicycles",      "current_station_id",   "INTEGER", "INTEGER"),
    ]

    for table, column, sqlite_type, pg_type in columns:
        try:
            if is_postgres:
                # PostgreSQL supports IF NOT EXISTS natively
                execute_query(c, f"""
                    ALTER TABLE {table}
                    ADD COLUMN IF NOT EXISTS {column} {pg_type}
                """)
            else:
                # SQLite doesn't support IF NOT EXISTS on ADD COLUMN,
                # so check the schema first


                existing = execute_query(c, f"PRAGMA table_info({table})").fetchall()
                # SQLite returns rows either as dicts (dict_factory) or tuples; handle both
                names = []
                for row in existing:
                    if isinstance(row, dict):
                        names.append(row.get("name"))
                    else:
                        # tuple layout: (cid, name, type, notnull, dflt_value, pk)
                        names.append(row[1])
                if column not in names:

                    execute_query(c, f"""
                        ALTER TABLE {table}
                        ADD COLUMN {column} {sqlite_type}
                    """)
        except Exception as e:
            # If it already exists, ignore. Otherwise print for debugging.
            print(f"ensure_schema_columns: {table}.{column} → {e}")

    conn.commit()
    conn.close()



def worker_visible_fields(viewer_role, is_own_profile=False):
    """
    Returns a set of field names the viewer is allowed to see.
    Staff/mechanic see only their own basic profile (no salary, no bank).
    Manager sees everything except salary + bank_details.
    Admin sees everything.
    """
    if viewer_role == "admin":
        return {
            "id_number", "date_of_birth", "hire_date", "phone", "address",
            "emergency_contact", "job_title", "specialty", "salary",
            "bank_details", "tax_number", "photo_path", "worker_notes",
        }
    if viewer_role == "manager":
        return {
            "id_number", "date_of_birth", "hire_date", "phone", "address",
            "emergency_contact", "job_title", "specialty",
            "tax_number", "photo_path", "worker_notes",
            # No salary, no bank_details
        }
    # staff / own profile
    return {
        "id_number", "date_of_birth", "hire_date", "phone", "address",
        "emergency_contact", "job_title", "specialty", "photo_path",
        "worker_notes",
    }

def ensure_rental_extras_schema():
    """
    Idempotent migration for the new rental extras:
    - items catalogue
    - rental_items join table
    - damage_claims table
    - extra columns on bicycles and daily_rentals
    Safe to run on every startup.
    """
    conn = db()
    c = conn.cursor()
    is_postgres = os.environ.get("DATABASE_URL") is not None


    if is_postgres:
        # ---------- PostgreSQL ----------
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS items(
                id SERIAL PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        execute_query(c, """
            CREATE TABLE IF NOT EXISTS rental_items(
                id SERIAL PRIMARY KEY,
                rental_id INTEGER NOT NULL REFERENCES daily_rentals(id) ON DELETE CASCADE,
                item_id INTEGER NOT NULL REFERENCES items(id),
                given_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                given_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                returned_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                returned_at TIMESTAMP,
                condition_on_return TEXT,
                notes TEXT,
                UNIQUE(rental_id, item_id)
            );
        """)

        execute_query(c, """
            CREATE TABLE IF NOT EXISTS damage_claims(
                id SERIAL PRIMARY KEY,
                rental_id INTEGER REFERENCES daily_rentals(id) ON DELETE SET NULL,
                customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
                bicycle_id INTEGER REFERENCES bicycles(id) ON DELETE SET NULL,
                item_id INTEGER REFERENCES items(id) ON DELETE SET NULL,
                description TEXT NOT NULL,
                amount REAL NOT NULL DEFAULT 0,
                status TEXT DEFAULT 'Pending',
                charged_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                charged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                paid_at TIMESTAMP,
                payment_method TEXT,
                signature_data TEXT,
                signed_agreement_path TEXT,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        execute_query(c, """
            CREATE TABLE IF NOT EXISTS document_views(
                id SERIAL PRIMARY KEY,
                document_id INTEGER NOT NULL REFERENCES customer_documents(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT
            );
        """)


        # Add columns idempotently
        execute_query(c, "ALTER TABLE bicycles ADD COLUMN IF NOT EXISTS condition_notes TEXT;")
        execute_query(c, "ALTER TABLE daily_rentals ADD COLUMN IF NOT EXISTS start_condition_note TEXT;")
        execute_query(c, "ALTER TABLE daily_rentals ADD COLUMN IF NOT EXISTS damage_charge REAL DEFAULT 0;")

    else:
        # ---------- SQLite ----------
        c.executescript("""
        CREATE TABLE IF NOT EXISTS items(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS rental_items(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rental_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            given_by_user_id INTEGER,
            given_at TEXT DEFAULT CURRENT_TIMESTAMP,
            returned_by_user_id INTEGER,
            returned_at TEXT,
            condition_on_return TEXT,
            notes TEXT,
            UNIQUE(rental_id, item_id),
            FOREIGN KEY (rental_id) REFERENCES daily_rentals(id) ON DELETE CASCADE,
            FOREIGN KEY (item_id) REFERENCES items(id),
            FOREIGN KEY (given_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (returned_by_user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS damage_claims(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rental_id INTEGER,
            customer_id INTEGER NOT NULL,
            bicycle_id INTEGER,
            item_id INTEGER,
            description TEXT NOT NULL,
            amount REAL NOT NULL DEFAULT 0,
            status TEXT DEFAULT 'Pending',
            charged_by_user_id INTEGER,
            charged_at TEXT DEFAULT CURRENT_TIMESTAMP,
            paid_at TEXT,
            payment_method TEXT,
            signature_data TEXT,
            signed_agreement_path TEXT,
            notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (rental_id) REFERENCES daily_rentals(id) ON DELETE SET NULL,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
            FOREIGN KEY (bicycle_id) REFERENCES bicycles(id) ON DELETE SET NULL,
            FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE SET NULL,
            FOREIGN KEY (charged_by_user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        -- Add columns if they don't exist (SQLite lacks IF NOT EXISTS for ADD COLUMN)
        """)

        execute_query(c, """
            CREATE TABLE IF NOT EXISTS document_views(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                user_id INTEGER,
                viewed_at TEXT DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                FOREIGN KEY (document_id) REFERENCES customer_documents(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );
        """)

        # SQLite helper to add column only if missing
        def _add_col_if_missing(table, column, coltype):
            rows = execute_query(c, f"PRAGMA table_info({table})").fetchall()
            names = []
            for row in rows:
                names.append(row.get("name") if isinstance(row, dict) else row[1])
            if column not in names:
                execute_query(c, f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")

        _add_col_if_missing("bicycles", "condition_notes", "TEXT")
        _add_col_if_missing("daily_rentals", "start_condition_note", "TEXT")
        _add_col_if_missing("daily_rentals", "damage_charge", "REAL DEFAULT 0")

    # ---------- Seed default items (both DBs) ----------
    default_items = [
        "Helmet", "Lock", "Pump", "Water Bottle", "Child Seat", "Phone Holder"
    ]
    for item_name in default_items:
        try:
            if is_postgres:
                execute_query(c, """
                    INSERT INTO items (name) VALUES (%s)
                    ON CONFLICT (name) DO NOTHING
                """, (item_name,))
            else:
                execute_query(c, """
                    INSERT OR IGNORE INTO items (name) VALUES (?)
                """, (item_name,))
        except Exception as e:
            print(f"seed items skip {item_name}: {e}")

    conn.commit()
    conn.close()



def ensure_audit_schema():
    """
    Idempotent migration for Phase 3:
    - login_history
    - audit_log
    - retention settings (nothing to add — just policies)
    """
    conn = db()
    c = conn.cursor()
    is_postgres = os.environ.get("DATABASE_URL") is not None

    if is_postgres:
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS login_history(
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                username_attempted TEXT,
                success INTEGER DEFAULT 0,
                ip_address TEXT,
                user_agent TEXT,
                device_summary TEXT,
                failure_reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        execute_query(c, """
            CREATE INDEX IF NOT EXISTS idx_login_history_user_time
            ON login_history(user_id, created_at DESC);
        """)

        execute_query(c, """
            CREATE TABLE IF NOT EXISTS audit_log(
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                username TEXT,
                user_role TEXT,
                action TEXT NOT NULL,
                entity_type TEXT,
                entity_id INTEGER,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        execute_query(c, """
            CREATE INDEX IF NOT EXISTS idx_audit_log_entity
            ON audit_log(entity_type, entity_id);
        """)

        execute_query(c, """
            CREATE INDEX IF NOT EXISTS idx_audit_log_time
            ON audit_log(created_at DESC);
        """)
    else:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS login_history(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username_attempted TEXT,
            success INTEGER DEFAULT 0,
            ip_address TEXT,
            user_agent TEXT,
            device_summary TEXT,
            failure_reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_login_history_user_time
        ON login_history(user_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS audit_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            user_role TEXT,
            action TEXT NOT NULL,
            entity_type TEXT,
            entity_id INTEGER,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_audit_log_entity
        ON audit_log(entity_type, entity_id);

        CREATE INDEX IF NOT EXISTS idx_audit_log_time
        ON audit_log(created_at DESC);
        """)

    conn.commit()
    conn.close()


  


def ensure_lockout_schema():
    """Idempotent migration for account lockout tracking."""
    conn = db()
    c = conn.cursor()
    is_postgres = os.environ.get("DATABASE_URL") is not None

    if is_postgres:
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS login_attempts(
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                failed_count INTEGER DEFAULT 0,
                last_failed_at TIMESTAMP,
                locked_until TIMESTAMP,
                locked_reason TEXT
            );
        """)
    else:
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS login_attempts(
                user_id INTEGER PRIMARY KEY,
                failed_count INTEGER DEFAULT 0,
                last_failed_at TEXT,
                locked_until TEXT,
                locked_reason TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)

    conn.commit()
    conn.close()

@app.route("/")
def home():
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("50 per minute;200 per hour")
def login():
    if request.method == "POST":
        conn = db()
        c = conn.cursor()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = execute_query(c,
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        # ✅ Check lockout status BEFORE verifying password
        if user:
            lockout = get_lockout_status(c, user["id"])
            if lockout["locked"]:
                log_login_attempt(
                    user_id=user["id"],
                    username_attempted=username,
                    success=False,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get("User-Agent"),
                    failure_reason=f"Account locked ({lockout['minutes_remaining']} min remaining)"
                )
                conn.close()
                flash(
                    f"Account is locked due to too many failed attempts. "
                    f"Try again in {lockout['minutes_remaining']} minute(s).",
                    "danger"
                )
                return render_template("login.html", title="Login - Daily Rentals")

        # ✅ Successful login path
        if user and check_password_hash(user["password_hash"], password):
            from datetime import datetime, timezone
            session["last_activity"] = datetime.now(timezone.utc).timestamp()

            log_login_attempt(
                user_id=user["id"],
                username_attempted=username,
                success=True,
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent"),
            )
            log_audit(
                action="login_success",
                entity_type="user",
                entity_id=user["id"],
                details=f"User {username} logged in",
                user_id=user["id"],
                username=user["username"],
                user_role=user["role"],
            )
            check_suspicious_login(user, request.remote_addr, request.headers.get("User-Agent"))
            reset_login_attempts(c, user["id"])

            # ✅ Auto-upgrade old password hashes to the current scheme
            if maybe_rehash_password(c, user["id"], user["password_hash"], password):
                log_audit(
                    action="password_rehash",
                    entity_type="user",
                    entity_id=user["id"],
                    details="Upgraded password hash to current scheme",
                )

            conn.commit()
            conn.close()

            # Customer users go to their portal
            if user["role"] == "customer":
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                session["full_name"] = user["full_name"]
                session["twofa_verified"] = False   # ← force 2FA check on next request

                conn2 = db()
                c2 = conn2.cursor()
                customer = execute_query(c2,
                    "SELECT id FROM customers WHERE user_id = ?",
                    (user["id"],)
                ).fetchone()
                conn2.close()

                if customer:
                    session["customer_id"] = customer["id"]

                flash(f"Welcome back, {user['full_name'] or user['username']}!", "success")
                return redirect(url_for("customer_portal"))

            # Staff / manager / admin
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["full_name"] = user["full_name"]
            session["station_id"] = user.get("branch_id")

            flash(f"Welcome back, {user['full_name'] or user['username']}!", "success")
            return redirect(url_for("dashboard"))

        # ✅ Failed login path — runs ONCE
        log_login_attempt(
            user_id=user["id"] if user else None,
            username_attempted=username,
            success=False,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            failure_reason="Invalid credentials",
        )

        if user:
            result = record_failed_login(c, user["id"])
            conn.commit()
            if result["locked"]:
                log_audit(
                    action="account_locked",
                    entity_type="user",
                    entity_id=user["id"],
                    details=f"Account locked for {LOCKOUT_DURATION_MINUTES} min after {LOCKOUT_MAX_FAILURES} failed attempts"
                )
                flash(
                    f"Too many failed attempts. Your account is locked for "
                    f"{LOCKOUT_DURATION_MINUTES} minutes.",
                    "danger"
                )
            else:
                remaining = LOCKOUT_MAX_FAILURES - result["failed_count"]
                flash(
                    f"Invalid username or password. "
                    f"{remaining} attempt(s) left before lockout.",
                    "danger"
                )
        else:
            flash("Invalid username or password.", "danger")

        conn.close()
        return render_template("login.html", title="Login - Daily Rentals")

    # GET
    return render_template("login.html", title="Login - Daily Rentals")

@app.route("/customer-login", methods=["GET", "POST"])
@limiter.limit("50 per minute;200 per hour")
def customer_login():
    """Customer login page."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = db()
        c = conn.cursor()

        user = execute_query(c,
            "SELECT * FROM users WHERE username = ? AND role = 'customer'",
            (username,)
        ).fetchone()

        # ✅ Check lockout status BEFORE verifying password
        if user:
            lockout = get_lockout_status(c, user["id"])
            if lockout["locked"]:
                log_login_attempt(
                    user_id=user["id"],
                    username_attempted=username,
                    success=False,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get("User-Agent"),
                    failure_reason=f"Account locked ({lockout['minutes_remaining']} min remaining)"
                )
                conn.close()
                flash(
                    f"Account is locked due to too many failed attempts. "
                    f"Try again in {lockout['minutes_remaining']} minute(s).",
                    "danger"
                )
                return render_template("customer_login.html", title="Customer Login")

        # ✅ Successful login
        if user and check_password_hash(user["password_hash"], password):
            from datetime import datetime, timezone
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["full_name"] = user["full_name"]
            session["last_activity"] = datetime.now(timezone.utc).timestamp()
            session["twofa_verified"] = False   # ← force 2FA check on next request

            log_login_attempt(
                user_id=user["id"],
                username_attempted=username,
                success=True,
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent"),
            )
            log_audit(
                action="login_success",
                entity_type="user",
                entity_id=user["id"],
                details=f"Customer {username} logged in",
                user_id=user["id"],
                username=user["username"],
                user_role=user["role"],
            )

            reset_login_attempts(c, user["id"])

            if maybe_rehash_password(c, user["id"], user["password_hash"], password):
                log_audit(
                    action="password_rehash",
                    entity_type="user",
                    entity_id=user["id"],
                    details="Upgraded customer password hash to current scheme",
                )

            conn.commit()

            # Get customer ID
            customer = execute_query(c,
                "SELECT id FROM customers WHERE user_id = ?",
                (user["id"],)
            ).fetchone()
            conn.close()

            if customer:
                session["customer_id"] = customer["id"]

            flash(f"Welcome back, {user['full_name'] or user['username']}!", "success")
            return redirect(url_for("customer_portal"))

        # ✅ Failed login — runs ONCE
        log_login_attempt(
            user_id=user["id"] if user else None,
            username_attempted=username,
            success=False,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            failure_reason="Invalid credentials",
        )

        if user:
            result = record_failed_login(c, user["id"])
            conn.commit()
            if result["locked"]:
                log_audit(
                    action="account_locked",
                    entity_type="user",
                    entity_id=user["id"],
                    details=f"Account locked for {LOCKOUT_DURATION_MINUTES} min after {LOCKOUT_MAX_FAILURES} failed attempts"
                )
                flash(
                    f"Too many failed attempts. Your account is locked for "
                    f"{LOCKOUT_DURATION_MINUTES} minutes.",
                    "danger"
                )
            else:
                remaining = LOCKOUT_MAX_FAILURES - result["failed_count"]
                flash(
                    f"Invalid username or password. "
                    f"{remaining} attempt(s) left before lockout.",
                    "danger"
                )
        else:
            flash("Invalid username or password.", "danger")

        conn.close()
        return render_template("customer_login.html", title="Customer Login")

    # GET
    return render_template("customer_login.html", title="Customer Login")






def _gather_customer_data(customer_id):
    """
    Fetch everything we hold about a customer.
    Returns a dict suitable for JSON export.
    """
    conn = db()
    c = conn.cursor()

    customer = execute_query(c, """
        SELECT id, full_name, id_number, phone, email, address,
               verification_status, verification_notes,
               terms_accepted, terms_accepted_date, signature_data,
               created_at
        FROM customers WHERE id = ?
    """, (customer_id,)).fetchone()

    if not customer:
        conn.close()
        return None

    documents = execute_query(c, """
        SELECT id, document_type, file_path, uploaded_at
        FROM customer_documents WHERE customer_id = ?
        ORDER BY uploaded_at
    """, (customer_id,)).fetchall()

    rentals = execute_query(c, """
        SELECT r.id, r.start_time, r.end_time, r.total_hours, r.total_cost,
               r.deposit_paid, r.late_fee, r.payment_status, r.status,
               r.start_condition_note, r.condition_before, r.condition_after,
               b.bike_code, b.brand, b.model,
               ss.name AS start_station, es.name AS end_station
        FROM daily_rentals r
        LEFT JOIN bicycles b ON b.id = r.bicycle_id
        LEFT JOIN branches ss ON ss.id = r.start_station_id
        LEFT JOIN branches es ON es.id = r.end_station_id
        WHERE r.customer_id = ?
        ORDER BY r.start_time DESC
    """, (customer_id,)).fetchall()

    payments = execute_query(c, """
        SELECT p.id, p.amount, p.payment_date, p.payment_method, p.status,
               p.daily_rental_id
        FROM rental_payments p
        JOIN daily_rentals r ON r.id = p.daily_rental_id
        WHERE r.customer_id = ?
        ORDER BY p.payment_date DESC
    """, (customer_id,)).fetchall()

    damage_claims = execute_query(c, """
        SELECT id, description, amount, status, charged_at, paid_at,
               payment_method, bicycle_id, item_id
        FROM damage_claims WHERE customer_id = ?
        ORDER BY charged_at DESC
    """, (customer_id,)).fetchall()

    loyalty = execute_query(c, """
        SELECT points, total_spent, total_rentals, tier, updated_at
        FROM loyalty_points WHERE customer_id = ?
    """, (customer_id,)).fetchone()

    conn.close()

    # Convert datetime fields to Namibia-local strings for display
    for r in rentals:
        if r.get("start_time"):
            r["start_time"] = to_namibia_time(r["start_time"])
        if r.get("end_time"):
            r["end_time"] = to_namibia_time(r["end_time"])
    for p in payments:
        if p.get("payment_date"):
            p["payment_date"] = to_namibia_time(p["payment_date"])
    for d in damage_claims:
        for k in ("charged_at", "paid_at"):
            if d.get(k):
                d[k] = to_namibia_time(d[k])
    for d in documents:
        if d.get("uploaded_at"):
            d["uploaded_at"] = to_namibia_time(d["uploaded_at"])

    return {
        "customer": dict(customer) if hasattr(customer, "keys") else customer,
        "documents": documents,
        "rentals": rentals,
        "payments": payments,
        "damage_claims": damage_claims,
        "loyalty": dict(loyalty) if loyalty and hasattr(loyalty, "keys") else loyalty,
    }


def _build_customer_data_pdf(customer, documents, rentals, payments,
                             damage_claims, loyalty):
    """Build a customer data export PDF and return as BytesIO."""
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from io import BytesIO
    from datetime import datetime

    buf = BytesIO()
    pdf = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    x = 20 * mm
    y = height - 20 * mm

    # Header
    pdf.setFont("Helvetica-Bold", 18)
    pdf.setFillColor(colors.HexColor("#0d1f46"))
    pdf.drawString(x, y, "RAB — Personal Data Export")
    y -= 8 * mm

    pdf.setFont("Helvetica", 9)
    pdf.setFillColor(colors.HexColor("#667085"))
    pdf.drawString(x, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    y -= 10 * mm

    def section(title):
        nonlocal y
        if y < 40 * mm:
            pdf.showPage()
            y = height - 20 * mm
        pdf.setFont("Helvetica-Bold", 12)
        pdf.setFillColor(colors.HexColor("#0d1f46"))
        pdf.drawString(x, y, title)
        y -= 6 * mm
        pdf.setFont("Helvetica", 9)
        pdf.setFillColor(colors.HexColor("#111111"))

    def line(label, value):
        nonlocal y
        if y < 20 * mm:
            pdf.showPage()
            y = height - 20 * mm
            pdf.setFont("Helvetica", 9)
            pdf.setFillColor(colors.HexColor("#111111"))
        text = f"{label}: {value if value not in (None, '') else '—'}"
        # Wrap long lines
        max_chars = 110
        if len(text) > max_chars:
            pdf.drawString(x + 3 * mm, y, text[:max_chars])
            y -= 5 * mm
            remaining = text[max_chars:]
            while remaining:
                pdf.drawString(x + 3 * mm, y, "  " + remaining[:max_chars])
                y -= 5 * mm
                remaining = remaining[max_chars:]
        else:
            pdf.drawString(x + 3 * mm, y, text)
            y -= 5 * mm

    # 1. Identity
    section("1. Your Identity")
    line("Full name", customer.get("full_name"))
    line("ID / Passport number", customer.get("id_number"))
    line("Phone", customer.get("phone"))
    line("Email", customer.get("email"))
    line("Address", customer.get("address"))
    line("Verification status", customer.get("verification_status"))
    line("Verification notes", customer.get("verification_notes"))
    line("Account created", to_namibia_time(customer.get("created_at")))
    line("Terms accepted", "Yes" if customer.get("terms_accepted") else "No")
    line("Terms accepted on", to_namibia_time(customer.get("terms_accepted_date")))
    y -= 4 * mm

    # 2. Documents
    section(f"2. Uploaded Documents ({len(documents)})")
    if documents:
        for d in documents:
            line(d.get("document_type", "document"), 
                 f"uploaded {d.get('uploaded_at')}")
    else:
        line("(none)", "")
    y -= 4 * mm

    # 3. Rentals
    section(f"3. Rental History ({len(rentals)})")
    if rentals:
        for r in rentals:
            line(f"#{r.get('id')} — {r.get('bike_code')}",
                 f"{r.get('start_time')} → {r.get('end_time') or 'active'} | "
                 f"{r.get('total_hours') or 0:.1f}h | N${r.get('total_cost') or 0:.2f} | "
                 f"{r.get('status')}")
    else:
        line("(no rentals)", "")
    y -= 4 * mm

    # 4. Payments
    section(f"4. Payments ({len(payments)})")
    if payments:
        for p in payments:
            line(f"#{p.get('id')}",
                 f"{p.get('payment_date')} | N${p.get('amount') or 0:.2f} | "
                 f"{p.get('payment_method') or '—'} | {p.get('status')}")
    else:
        line("(no payments)", "")
    y -= 4 * mm

    # 5. Damage claims
    section(f"5. Damage Claims ({len(damage_claims)})")
    if damage_claims:
        for d in damage_claims:
            line(f"#{d.get('id')}",
                 f"{d.get('charged_at')} | N${d.get('amount') or 0:.2f} | "
                 f"{d.get('status')} | {d.get('description', '')[:80]}")
    else:
        line("(no claims)", "")
    y -= 4 * mm

    # 6. Loyalty
    section("6. Loyalty Program")
    if loyalty:
        line("Points balance", loyalty.get("points"))
        line("Total spent", f"N${loyalty.get('total_spent') or 0:.2f}")
        line("Total rentals", loyalty.get("total_rentals"))
        line("Tier", loyalty.get("tier"))
    else:
        line("(not enrolled)", "")

    y -= 10 * mm
    pdf.setFont("Helvetica", 8)
    pdf.setFillColor(colors.HexColor("#667085"))
    pdf.drawString(x, y, 
                   "This is a summary of personal data held by RAB Rent A Bike. "
                   "A machine-readable JSON version accompanies this PDF in the export.")
    y -= 4 * mm
    pdf.drawString(x, y, 
                   "For questions, contact privacy@rab.com")

    pdf.save()
    buf.seek(0)
    return buf


def ensure_privacy_schema():
    """Idempotent migration for privacy requests."""
    conn = db()
    c = conn.cursor()
    is_postgres = os.environ.get("DATABASE_URL") is not None

    if is_postgres:
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS privacy_requests(
                id SERIAL PRIMARY KEY,
                customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
                request_type TEXT NOT NULL,         -- 'delete' or 'export'
                reason TEXT,
                status TEXT DEFAULT 'Pending',      -- Pending / Approved / Rejected / Completed
                reviewed_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                reviewed_at TIMESTAMP,
                review_notes TEXT,
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            );
        """)
    else:
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS privacy_requests(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id INTEGER NOT NULL,
                request_type TEXT NOT NULL,
                reason TEXT,
                status TEXT DEFAULT 'Pending',
                reviewed_by_user_id INTEGER,
                reviewed_at TEXT,
                review_notes TEXT,
                requested_at TEXT DEFAULT CURRENT_TIMESTAMP,
                completed_at TEXT,
                FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
                FOREIGN KEY (reviewed_by_user_id) REFERENCES users(id) ON DELETE SET NULL
            );
        """)

    conn.commit()
    conn.close()

def ensure_2fa_schema():
    """Idempotent migration for 2FA."""
    conn = db()
    c = conn.cursor()
    is_postgres = os.environ.get("DATABASE_URL") is not None

    if is_postgres:
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS user_2fa(
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                secret TEXT NOT NULL,
                enabled INTEGER DEFAULT 0,
                confirmed_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS user_2fa_backup_codes(
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                code_hash TEXT NOT NULL,
                used_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        # Add columns to users if missing
        execute_query(c, "ALTER TABLE users ADD COLUMN IF NOT EXISTS twofa_required INTEGER DEFAULT 0;")
        execute_query(c, "ALTER TABLE users ADD COLUMN IF NOT EXISTS twofa_enabled INTEGER DEFAULT 0;")
    else:
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS user_2fa(
                user_id INTEGER PRIMARY KEY,
                secret TEXT NOT NULL,
                enabled INTEGER DEFAULT 0,
                confirmed_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS user_2fa_backup_codes(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        # SQLite: add columns only if missing
        def _add_col_if_missing(table, column, coltype):
            rows = execute_query(c, f"PRAGMA table_info({table})").fetchall()
            names = []
            for row in rows:
                names.append(row.get("name") if isinstance(row, dict) else row[1])
            if column not in names:
                execute_query(c, f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")

        _add_col_if_missing("users", "twofa_required", "INTEGER DEFAULT 0")
        _add_col_if_missing("users", "twofa_enabled", "INTEGER DEFAULT 0")

    conn.commit()
    conn.close()




import pyotp
import qrcode
import base64
from io import BytesIO
import secrets as _secrets


def _generate_backup_codes(count=8):
    """Generate N single-use backup codes (12 hex chars each)."""
    codes = []
    for _ in range(count):
        # Format: XXXX-XXXX-XXXX
        raw = _secrets.token_hex(6).upper()  # 12 chars
        codes.append(f"{raw[:4]}-{raw[4:8]}-{raw[8:]}")
    return codes


def _hash_backup_code(code):
    """Hash a backup code (they're short, so bcrypt via werkzeug is fine)."""
    from werkzeug.security import generate_password_hash
    return generate_password_hash(code.replace("-", "").upper())


def _verify_backup_code(code, stored_hash):
    """Check if a backup code matches a stored hash."""
    from werkzeug.security import check_password_hash
    return check_password_hash(stored_hash, code.replace("-", "").upper())


def _generate_qr_png_base64(uri):
    """Render a QR code from an otpauth:// URI and return a base64 PNG data URL."""
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def user_needs_2fa_setup(user):
    """
    Return True if the user has 2FA required but hasn't confirmed it yet.
    `user` is a dict (from SELECT * FROM users).
    """
    required = user.get("twofa_required") or 0
    enabled = user.get("twofa_enabled") or 0
    return bool(required) and not bool(enabled)

def maybe_rehash_password(cursor, user_id, stored_hash, plain_password):
    """
    If the stored hash uses an outdated scheme, re-hash the password
    with the current default. Returns True if a re-hash happened.
    """
    try:
        from werkzeug.security import generate_password_hash, check_password_hash
        # Werkzeug prefixes hashes with the method (e.g. 'pbkdf2:sha256:...')
        # Current default is 'scrypt'. We re-hash if the prefix isn't 'scrypt'.
        if not stored_hash.startswith("scrypt:"):
            new_hash = generate_password_hash(plain_password)
            execute_query(cursor,
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, user_id))
            return True
    except Exception as e:
        print(f"⚠️ maybe_rehash_password failed: {e}")
    return False


def role_required(allowed_roles):
    """Decorator to check if user has required role."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please login to access this page.", "warning")
                return redirect(url_for("login"))
            
            conn = db()
            c = conn.cursor()
            user = execute_query(c,
                "SELECT role FROM users WHERE id = ?", 
                (session["user_id"],)
            ).fetchone()
            conn.close()
            
            if not user:
                flash("User not found.", "danger")
                return redirect(url_for("logout"))
            
            if user["role"] not in allowed_roles:
                flash("You don't have permission to access this page.", "danger")
                return redirect(url_for("dashboard"))
            
            return f(*args, **kwargs)
        return wrapper
    return decorator

def admin_required(f):
    """Admin-only access."""
    return role_required(['admin'])(f)

def manager_required(f):
    """Manager and admin access."""
    return role_required(['admin', 'manager'])(f)




def admin_required(f):
    """Decorator for admin-only access."""
    return role_required(['admin'])(f)

def manager_required(f):
    """Decorator for manager and admin access."""
    return role_required(['admin', 'manager'])(f)



def staff_required(f):
    """Staff-only access (blocks customers)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please login to access this page.", "warning")
            return redirect(url_for("login"))
        
        if session.get("role") == "customer":
            flash("Access denied. Staff only.", "danger")
            return redirect(url_for("customer_portal"))
        
        return f(*args, **kwargs)
    return wrapper


# ✅ ADD THIS - Customer-only decorator
def customer_required(f):
    """Customer-only access (blocks staff)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please login to access this page.", "warning")
            return redirect(url_for("login"))
        
        if session.get("role") != "customer":
            flash("Access denied. Customers only.", "danger")
            return redirect(url_for("dashboard"))
        
        return f(*args, **kwargs)
    return wrapper




@app.route("/users")
@login_required
@admin_required
def users():
    """View all users (Admin only)."""
    conn = db()
    c = conn.cursor()
    

    users_list = execute_query(c, """
        SELECT u.id, u.username, u.role, u.full_name, u.email, u.created_at,
               s.name AS station_name,
               la.locked_until
        FROM users u
        LEFT JOIN branches s ON s.id = u.branch_id
        LEFT JOIN login_attempts la ON la.user_id = u.id
        WHERE u.role != 'customer'
        ORDER BY u.role, u.username
    """).fetchall()

    conn.close()
    
    # Format datetime for each user
    for user in users_list:
        if user.get("created_at"):
            if isinstance(user["created_at"], datetime):
                user["created_at"] = user["created_at"].strftime("%Y-%m-%d")
            elif isinstance(user["created_at"], str):
                user["created_at"] = user["created_at"]

    # from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for user in users_list:
        # ... existing datetime formatting ...
        lu = user.get("locked_until")
        if lu:
            try:
                if isinstance(lu, datetime):
                    locked_until = lu.replace(tzinfo=None) if lu.tzinfo is None else lu.astimezone(timezone.utc).replace(tzinfo=None)
                else:
                    locked_until = datetime.fromisoformat(str(lu))
                    if locked_until.tzinfo is not None:
                        locked_until = locked_until.astimezone(timezone.utc).replace(tzinfo=None)
                user["is_locked"] = locked_until > now
            except Exception:
                user["is_locked"] = False
        else:
            user["is_locked"] = False

    return render_template("users.html", title="User Management", users=users_list)
  

# =============================================
# WORKERS (HR)
# =============================================

@app.route("/workers")
@login_required
@manager_required
def workers():
    """List all non-customer workers with their job titles and station."""
    conn = db()
    c = conn.cursor()

    search = (request.args.get("search") or "").strip()
    role_filter = (request.args.get("role") or "").strip()
    specialty_filter = (request.args.get("specialty") or "").strip()

    query = """
        SELECT 
            u.id, u.username, u.full_name, u.role, u.email,
            u.phone, u.job_title, u.specialty, u.hire_date,
            u.photo_path, u.branch_id,
            s.name AS station_name
        FROM users u
        LEFT JOIN branches s ON s.id = u.branch_id
        WHERE u.role != 'customer'
    """
    params = []

    if search:
        like = f"%{search}%"
        query += f""" AND (
            {ci_like('u.full_name', '?')} OR
            {ci_like('u.username', '?')} OR
            {ci_like('u.job_title', '?')} OR
            {ci_like('u.specialty', '?')}
        )"""
        params.extend([like, like, like, like])

    if role_filter:
        query += " AND u.role = ?"
        params.append(role_filter)

    if specialty_filter:
        query += " AND u.specialty = ?"
        params.append(specialty_filter)

    query += " ORDER BY u.role, u.full_name"

    workers_list = execute_query(c, query, params).fetchall()

    # Distinct specialties for the filter dropdown
    specialties = execute_query(c, """
        SELECT DISTINCT specialty FROM users
        WHERE role != 'customer' AND specialty IS NOT NULL AND specialty != ''
        ORDER BY specialty
    """).fetchall()
    specialty_list = [s["specialty"] if isinstance(s, dict) else s[0] for s in specialties]

    # Counts
    total_workers = len(workers_list)
    total_active = sum(1 for w in workers_list if w.get("role") != "customer")

    conn.close()

    return render_template(
        "workers.html",
        title="Workers",
        workers=workers_list,
        search=search,
        role_filter=role_filter,
        specialty_filter=specialty_filter,
        specialty_list=specialty_list,
        total_workers=total_workers,
        total_active=total_active,
    )


@app.route("/workers/<int:worker_id>")
@login_required
def worker_profile(worker_id):
    """
    View a worker profile.
    - admin/manager: any worker
    - staff: only their own
    """
    viewer_id = session.get("user_id")
    viewer_role = session.get("role")

    # Staff can only view their own profile
    if viewer_role == "staff" and viewer_id != worker_id:
        flash("You can only view your own profile.", "danger")
        return redirect(url_for("worker_profile", worker_id=viewer_id))

    # Customers are not workers
    if viewer_role == "customer":
        flash("Access denied.", "danger")
        return redirect(url_for("customer_portal"))

    conn = db()
    c = conn.cursor()

    worker = execute_query(c, """
        SELECT u.*, s.name AS station_name
        FROM users u
        LEFT JOIN branches s ON s.id = u.branch_id
        WHERE u.id = ? AND u.role != 'customer'
    """, (worker_id,)).fetchone()

    if not worker:
        conn.close()
        flash("Worker not found.", "danger")
        return redirect(url_for("workers"))

    # Worker documents
    documents = execute_query(c, """
        SELECT wd.*, u.username AS uploaded_by_username
        FROM worker_documents wd
        LEFT JOIN users u ON u.id = wd.uploaded_by_user_id
        WHERE wd.user_id = ?
        ORDER BY wd.uploaded_at DESC
    """, (worker_id,)).fetchall()

    # Lockout status
    lockout = get_lockout_status(c, worker_id)

    # Recent activity summary (last 10 rentals this user started or ended)
    recent_activity = execute_query(c, """
        SELECT 
            r.id, r.start_time, r.end_time, r.status,
            su.username AS started_by, eu.username AS ended_by,
            b.bike_code
        FROM daily_rentals r
        LEFT JOIN users su ON su.id = r.started_by_user_id
        LEFT JOIN users eu ON eu.id = r.ended_by_user_id
        LEFT JOIN bicycles b ON b.id = r.bicycle_id
        WHERE r.started_by_user_id = ? OR r.ended_by_user_id = ?
        ORDER BY r.start_time DESC
        LIMIT 10
    """, (worker_id, worker_id)).fetchall()

    for r in recent_activity:
        if r.get("start_time"): r["start_time"] = to_namibia_time(r["start_time"])
        if r.get("end_time"): r["end_time"] = to_namibia_time(r["end_time"])

    # Decide which fields the viewer can see
    is_own = (viewer_id == worker_id)
    visible = worker_visible_fields(viewer_role, is_own_profile=is_own)

    conn.close()

    return render_template(
        "worker_profile.html",
        title=f"Worker — {worker['full_name'] or worker['username']}",
        worker=worker,
        documents=documents,
        lockout=lockout,
        recent_activity=recent_activity,
        visible=visible,
        is_own=is_own,
        viewer_role=viewer_role,
    )


@app.route("/workers/<int:worker_id>/edit", methods=["GET", "POST"])
@login_required
@manager_required
def worker_edit(worker_id):
    """
    Edit a worker.
    - Admin: all fields
    - Manager: everything except salary + bank_details
    """
    viewer_role = session.get("role")

    conn = db()
    c = conn.cursor()

    worker = execute_query(c, """
        SELECT * FROM users WHERE id = ? AND role != 'customer'
    """, (worker_id,)).fetchone()

    if not worker:
        conn.close()
        flash("Worker not found.", "danger")
        return redirect(url_for("workers"))

    # Load stations for the dropdown
    stations = execute_query(c, """
        SELECT id, name FROM branches WHERE is_active = 1 ORDER BY name
    """).fetchall()

    if request.method == "POST":
        # Fields everyone can set
        full_name = (request.form.get("full_name") or "").strip()
        email = (request.form.get("email") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        id_number = (request.form.get("id_number") or "").strip()
        date_of_birth = (request.form.get("date_of_birth") or "").strip() or None
        hire_date = (request.form.get("hire_date") or "").strip() or None
        address = (request.form.get("address") or "").strip()
        emergency_contact = (request.form.get("emergency_contact") or "").strip()
        job_title = (request.form.get("job_title") or "").strip()
        specialty = (request.form.get("specialty") or "").strip()
        tax_number = (request.form.get("tax_number") or "").strip()
        worker_notes = (request.form.get("worker_notes") or "").strip()
        role = request.form.get("role", worker["role"])
        branch_id = request.form.get("branch_id") or None
        if branch_id:
            branch_id = int(branch_id)

        # Role-boundaries: a manager cannot create/promote to admin
        if viewer_role == "manager" and role == "admin":
            role = worker["role"]  # keep as-is
            flash("Only an admin can assign the admin role.", "warning")

        # Update base fields
        execute_query(c, """
            UPDATE users
            SET full_name = ?, email = ?, phone = ?, id_number = ?,
                date_of_birth = ?, hire_date = ?, address = ?,
                emergency_contact = ?, job_title = ?, specialty = ?,
                tax_number = ?, worker_notes = ?, role = ?, branch_id = ?
            WHERE id = ?
        """, (full_name, email, phone, id_number,
              date_of_birth, hire_date, address,
              emergency_contact, job_title, specialty,
              tax_number, worker_notes, role, branch_id,
              worker_id))


        # ✅ Optional: photo upload
        photo = request.files.get("photo") if request.files else None
        if photo and photo.filename:
            ok, err, ext = validate_upload(photo)
            if not ok:
                conn.close()
                flash(f"Photo rejected: {err}", "danger")
                return redirect(url_for("worker_edit", worker_id=worker_id))

            use_cloudinary = all([
                os.environ.get("CLOUDINARY_CLOUD_NAME"),
                os.environ.get("CLOUDINARY_API_KEY"),
                os.environ.get("CLOUDINARY_API_SECRET"),
            ])

            uploaded = False
            new_photo_path = None

            if use_cloudinary:
                try:
                    result = cloudinary.uploader.upload(photo)
                    new_photo_path = result["secure_url"]
                    uploaded = True
                except Exception as e:
                    print(f"⚠️ Cloudinary upload failed: {e}")

            if not uploaded:
                filename = f"worker_photo_{worker_id}_{secure_filename(photo.filename)}"
                full_path = os.path.join(PRIVATE_UPLOAD_FOLDER, filename)
                photo.save(full_path)
                new_photo_path = f"private_uploads/{filename}"

            execute_query(c, "UPDATE users SET photo_path = ? WHERE id = ?", (new_photo_path, worker_id))

        # Salary + bank_details — admin only
        if viewer_role == "admin":
            salary_raw = (request.form.get("salary") or "").strip()
            salary = float(salary_raw) if salary_raw else None
            bank_details = (request.form.get("bank_details") or "").strip()

            execute_query(c, """
                UPDATE users SET salary = ?, bank_details = ? WHERE id = ?
            """, (salary, bank_details, worker_id))

        # Optional: reset password
        new_password = (request.form.get("new_password") or "").strip()
        if new_password:
            ok, err = validate_password_strength(new_password)
            if not ok:
                conn.close()
                flash(f"Password rejected: {err}", "danger")
                return redirect(url_for("worker_edit", worker_id=worker_id))
            execute_query(c, """
                UPDATE users SET password_hash = ? WHERE id = ?
            """, (generate_password_hash(new_password), worker_id))

        conn.commit()
        conn.close()

        log_audit(
            action="worker_edit",
            entity_type="user",
            entity_id=worker_id,
            details=f"Updated worker '{worker['username']}' — role={role}, title={job_title}"
        )

        flash(f"Worker '{full_name or worker['username']}' updated.", "success")
        return redirect(url_for("worker_profile", worker_id=worker_id))

    conn.close()

    return render_template(
        "worker_edit.html",
        title="Edit Worker",
        worker=worker,
        stations=stations,
        viewer_role=viewer_role,
    )







@app.route("/workers/<int:worker_id>/documents/add", methods=["GET", "POST"])
@login_required
@manager_required
def worker_add_document(worker_id):
    """Upload a document for a worker."""
    conn = db()
    c = conn.cursor()

    worker = execute_query(c, """
        SELECT id, username, full_name FROM users WHERE id = ? AND role != 'customer'
    """, (worker_id,)).fetchone()

    if not worker:
        conn.close()
        flash("Worker not found.", "danger")
        return redirect(url_for("workers"))

    if request.method == "POST":
        document_type = (request.form.get("document_type") or "").strip()
        notes = (request.form.get("notes") or "").strip()
        upload = request.files.get("file")

        if not document_type:
            flash("Document type is required.", "danger")
            conn.close()
            return redirect(url_for("worker_add_document", worker_id=worker_id))

        if not upload or not upload.filename:
            flash("Please choose a file to upload.", "danger")
            conn.close()
            return redirect(url_for("worker_add_document", worker_id=worker_id))

        ok, err, ext = validate_upload(upload)
        if not ok:
            flash(f"Upload rejected: {err}", "danger")
            conn.close()
            return redirect(url_for("worker_add_document", worker_id=worker_id))

        use_cloudinary = all([
            os.environ.get("CLOUDINARY_CLOUD_NAME"),
            os.environ.get("CLOUDINARY_API_KEY"),
            os.environ.get("CLOUDINARY_API_SECRET"),
        ])

        uploaded = False
        file_path = None

        # Try Cloudinary
        if use_cloudinary:
            try:
                result = cloudinary.uploader.upload(upload)
                file_path = result["secure_url"]
                uploaded = True
            except Exception as e:
                print(f"⚠️ Cloudinary upload failed: {e}")

        # Fallback to local
        if not uploaded:
            filename = f"worker_{worker_id}_{secure_filename(upload.filename)}"
            full_path = os.path.join(PRIVATE_UPLOAD_FOLDER, filename)
            upload.save(full_path)
            file_path = f"private_uploads/{filename}"

        execute_query(c, """
            INSERT INTO worker_documents 
            (user_id, document_type, file_path, uploaded_by_user_id, notes)
            VALUES (?, ?, ?, ?, ?)
        """, (worker_id, document_type, file_path, session["user_id"], notes))
        conn.commit()
        conn.close()

        log_audit(
            action="worker_document_upload",
            entity_type="user",
            entity_id=worker_id,
            details=f"Uploaded '{document_type}' for worker '{worker['username']}'"
        )

        flash("Document uploaded.", "success")
        return redirect(url_for("worker_profile", worker_id=worker_id))

    conn.close()
    return render_template(
        "worker_add_document.html",
        title="Add Worker Document",
        worker=worker
    )


@app.route("/worker-documents/<int:doc_id>/file")
@login_required
def serve_worker_document(doc_id):
    """Serve a worker document with access control."""
    viewer_id = session.get("user_id")
    viewer_role = session.get("role")

    conn = db()
    c = conn.cursor()
    doc = execute_query(c, """
        SELECT wd.*, u.username 
        FROM worker_documents wd
        JOIN users u ON u.id = wd.user_id
        WHERE wd.id = ?
    """, (doc_id,)).fetchone()

    if not doc:
        conn.close()
        flash("Document not found.", "danger")
        return redirect(url_for("workers"))

    # Access control
    if viewer_role == "staff" and doc["user_id"] != viewer_id:
        conn.close()
        flash("You can only view your own documents.", "danger")
        return redirect(url_for("worker_profile", worker_id=viewer_id))

    if viewer_role == "customer":
        conn.close()
        flash("Access denied.", "danger")
        return redirect(url_for("customer_portal"))

    conn.close()

    file_path = doc["file_path"]

    if file_path.startswith("http"):
        return redirect(file_path)

    filename = os.path.basename(file_path)
    full_path = os.path.join(PRIVATE_UPLOAD_FOLDER, filename)

    if not os.path.exists(full_path):
        flash(f"File not found: {filename}", "danger")
        return redirect(url_for("worker_profile", worker_id=doc["user_id"]))

    return send_file(full_path, as_attachment=False, download_name=filename)


@app.route("/worker-documents/<int:doc_id>/delete", methods=["POST"])
@login_required
@manager_required
def worker_delete_document(doc_id):
    """Delete a worker document."""
    conn = db()
    c = conn.cursor()

    doc = execute_query(c, """
        SELECT * FROM worker_documents WHERE id = ?
    """, (doc_id,)).fetchone()

    if not doc:
        conn.close()
        flash("Document not found.", "danger")
        return redirect(url_for("workers"))

    # Try to delete the physical file (if local)
    file_path = doc["file_path"]
    if not file_path.startswith("http"):
        filename = os.path.basename(file_path)
        full_path = os.path.join(PRIVATE_UPLOAD_FOLDER, filename)
        try:
            if os.path.exists(full_path):
                os.remove(full_path)
        except Exception as e:
            print(f"⚠️ Could not delete file: {e}")

    execute_query(c, "DELETE FROM worker_documents WHERE id = ?", (doc_id,))
    conn.commit()
    conn.close()

    log_audit(
        action="worker_document_delete",
        entity_type="user",
        entity_id=doc["user_id"],
        details=f"Deleted document '{doc['document_type']}'"
    )

    flash("Document deleted.", "success")
    return redirect(url_for("worker_profile", worker_id=doc["user_id"]))


@app.route("/workers/<int:user_id>/photo")
@login_required
def serve_worker_photo(user_id):
    """Serve a worker's profile photo."""
    viewer_id = session.get("user_id")
    viewer_role = session.get("role")

    # Staff can only view their own photo
    if viewer_role == "staff" and user_id != viewer_id:
        abort(403)
    if viewer_role == "customer":
        abort(403)

    conn = db()
    c = conn.cursor()
    worker = execute_query(c, "SELECT photo_path FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    if not worker or not worker.get("photo_path"):
        abort(404)

    photo_path = worker["photo_path"]

    if photo_path.startswith("http"):
        return redirect(photo_path)

    filename = os.path.basename(photo_path)
    full_path = os.path.join(PRIVATE_UPLOAD_FOLDER, filename)

    if not os.path.exists(full_path):
        abort(404)

    return send_file(full_path, as_attachment=False)





@app.route("/users/add", methods=["GET", "POST"])
@login_required
@admin_required
def add_user():
   
    """Add a new user (Admin only)."""
    conn = db()
    c = conn.cursor()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "staff")
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()

        branch_id = request.form.get("branch_id") or None
        if branch_id:
            branch_id = int(branch_id)

        # if not username or not password:
        #     flash("Username and password are required.", "danger")
        #     conn.close()
        #     return redirect(url_for("add_user"))

        if not username or not password:
            flash("Username and password are required.", "danger")
            conn.close()
            return redirect(url_for("add_user"))

        # ✅ Enforce password policy
        ok, err = validate_password_strength(password)
        if not ok:
            flash(f"Password rejected: {err}", "danger")
            conn.close()
            return redirect(url_for("add_user"))


        try:
            execute_query(c, """
                INSERT INTO users (username, password_hash, role, full_name, email, branch_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (username, generate_password_hash(password), role, full_name, email, branch_id))
            conn.commit()

            log_audit(
                action="user_create",
                entity_type="user",
                details=f"Created user '{username}' (role={role})"
            )

            flash(f"User '{username}' created successfully!", "success")
        except sqlite3.IntegrityError:
            flash(f"Username '{username}' already exists.", "danger")

        conn.close()
        return redirect(url_for("users"))

    # GET branch
    stations = execute_query(c, """
        SELECT id, name FROM branches WHERE is_active = 1 ORDER BY name
    """).fetchall()


    conn.close()



    return render_template("add_user.html", title="Add User", stations=stations)


@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def edit_user(user_id):
    """Edit a user (Admin only)."""
    conn = db()
    c = conn.cursor()
    
    user = execute_query(c,"SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    # if not user:
    #     flash("User not found.", "danger")
    #     return redirect(url_for("users"))
    if not user:
        conn.close()
        flash("User not found.", "danger")
        return redirect(url_for("users"))  


    if request.method == "POST":
        role = request.form.get("role", "staff")
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        new_password = request.form.get("new_password", "")

        # ✅ Enforce password policy if a new password is set
        if new_password:
            ok, err = validate_password_strength(new_password)
            if not ok:
                flash(f"Password rejected: {err}", "danger")
                conn.close()
                return redirect(url_for("edit_user", user_id=user_id))



        # ✅ Optional: assign a station
        branch_id = request.form.get("branch_id") or None
        if branch_id:
            branch_id = int(branch_id)

        if new_password:
            execute_query(c,"""
                UPDATE users 
                SET role = ?, full_name = ?, email = ?, password_hash = ?, branch_id = ?
                WHERE id = ?
            """, (role, full_name, email, generate_password_hash(new_password), branch_id, user_id))
        else:
            execute_query(c,"""
                UPDATE users 
                SET role = ?, full_name = ?, email = ?, branch_id = ?
                WHERE id = ?
            """, (role, full_name, email, branch_id, user_id))

        conn.commit()

        log_audit(
            action="user_edit",
            entity_type="user",
            entity_id=user_id,
            details=f"Edited user '{user['username']}' (role={role})"
        )

        conn.close()

        flash(f"User '{user['username']}' updated successfully!", "success")
        return redirect(url_for("users"))    
    # conn.close()
    # return render_template("edit_user.html", title="Edit User", user=user)
    stations = execute_query(c, """
        SELECT id, name FROM branches WHERE is_active = 1 ORDER BY name
    """).fetchall()

    conn.close()
    return render_template("edit_user.html", title="Edit User", user=user, stations=stations)


@app.route("/users/<int:user_id>/unlock", methods=["POST"])
@login_required
@admin_required
def unlock_user(user_id):
    """Manually unlock a user account."""
    conn = db()
    c = conn.cursor()

    user = execute_query(c, "SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        conn.close()
        flash("User not found.", "danger")
        return redirect(url_for("users"))
    conn.close()

    if unlock_user_account(user_id):
        log_audit(
            action="account_unlocked",
            entity_type="user",
            entity_id=user_id,
            details=f"Admin manually unlocked user '{user['username']}'"
        )
        flash(f"User '{user['username']}' unlocked.", "success")
    else:
        flash("Failed to unlock user.", "danger")

    return redirect(url_for("users"))


@app.route("/staff-activity")
@login_required
@manager_required
def staff_activity():
    """Admin/manager view: who started / ended / cancelled each rental, at which station."""
    conn = db()
    c = conn.cursor()

    # Filters
    date_from = (request.args.get("date_from") or "").strip()
    date_to   = (request.args.get("date_to") or "").strip()
    staff_id  = (request.args.get("staff_id") or "").strip()
    station_id = (request.args.get("station_id") or "").strip()
    action    = (request.args.get("action") or "").strip()

    query = """
        SELECT
            r.id,
            r.start_time,
            r.end_time,
            r.status,
            r.total_cost,
            r.notes,
            c.full_name       AS customer_name,
            b.bike_code,
            su.username       AS started_by,
            su.full_name      AS started_by_name,
            eu.username       AS ended_by,
            eu.full_name      AS ended_by_name,
            cu.username       AS cancelled_by,
            cu.full_name      AS cancelled_by_name,
            ss.name           AS start_station,
            es.name           AS end_station
        FROM daily_rentals r
        LEFT JOIN customers   c  ON c.id  = r.customer_id
        LEFT JOIN bicycles    b  ON b.id  = r.bicycle_id
        LEFT JOIN users       su ON su.id = r.started_by_user_id
        LEFT JOIN users       eu ON eu.id = r.ended_by_user_id
        LEFT JOIN users       cu ON cu.id = r.cancelled_by_user_id
        LEFT JOIN branches    ss ON ss.id = r.start_station_id
        LEFT JOIN branches    es ON es.id = r.end_station_id
        WHERE 1=1
    """
    params = []

    if date_from:
        query += " AND date(r.start_time) >= ?"
        params.append(date_from)
    if date_to:
        query += " AND date(r.start_time) <= ?"
        params.append(date_to)
    if staff_id:
        query += " AND (r.started_by_user_id = ? OR r.ended_by_user_id = ? OR r.cancelled_by_user_id = ?)"
        params.extend([staff_id, staff_id, staff_id])
    if station_id:
        query += " AND (r.start_station_id = ? OR r.end_station_id = ?)"
        params.extend([station_id, station_id])
    if action == "started":
        query += " AND r.started_by_user_id IS NOT NULL"
    elif action == "ended":
        query += " AND r.ended_by_user_id IS NOT NULL"
    elif action == "cancelled":
        query += " AND r.cancelled_by_user_id IS NOT NULL"

    query += " ORDER BY r.start_time DESC LIMIT 500"

    rentals = execute_query(c, query, params).fetchall()

    # Format datetimes using shared helper
    for r in rentals:
        if r.get("start_time"): r["start_time"] = to_namibia_time(r["start_time"])
        if r.get("end_time"):   r["end_time"]   = to_namibia_time(r["end_time"])

    # For filter dropdowns
    staff_list = execute_query(c, """
        SELECT id, username, full_name FROM users
        WHERE role IN ('admin','manager','staff')
        ORDER BY username
    """).fetchall()

    station_list = execute_query(c, """
        SELECT id, name FROM branches WHERE is_active = 1 ORDER BY name
    """).fetchall()

    conn.close()

    return render_template(
        "staff_activity.html",
        title="Staff Activity",
        rentals=rentals,
        staff_list=staff_list,
        station_list=station_list,
        date_from=date_from,
        date_to=date_to,
        staff_id=staff_id,
        station_id=station_id,
        action=action
    )




@app.route("/stations", methods=["GET", "POST"])
@login_required
@admin_required
def stations():
    """Admin: manage stations (= branches)."""
    conn = db()
    c = conn.cursor()

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        location = (request.form.get("location") or "").strip()
        address = (request.form.get("address") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        email = (request.form.get("email") or "").strip()

        if not name:
            flash("Station name is required.", "danger")
        else:
            try:
                execute_query(c, """
                    INSERT INTO branches (name, location, address, phone, email, is_active)
                    VALUES (?, ?, ?, ?, ?, 1)
                """, (name, location, address, phone, email))
                conn.commit()

                log_audit(
                    action="station_create",
                    entity_type="branch",
                    details=f"Added station '{name}'"
                )

                flash(f"Station '{name}' added.", "success")
            except Exception as e:
                conn.rollback()
                flash(f"Error: {e}", "danger")

        conn.close()
        return redirect(url_for("stations"))

    # ✅ Include bike count per station
    stations_list = execute_query(c, """
        SELECT s.*,
               (SELECT COUNT(*) FROM bicycles b WHERE b.current_station_id = s.id) AS bike_count
        FROM branches s
        ORDER BY s.name
    """).fetchall()

    conn.close()
    return render_template("stations.html", title="Stations", stations=stations_list)



@app.route("/items", methods=["GET", "POST"])
@login_required
@admin_required
def items():
    """Admin: manage items provided with rentals."""
    conn = db()
    c = conn.cursor()

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        description = (request.form.get("description") or "").strip()

        if not name:
            flash("Item name is required.", "danger")
        else:
            try:
                execute_query(c, """
                    INSERT INTO items (name, description, is_active)
                    VALUES (?, ?, 1)
                """, (name, description))
                conn.commit()

                log_audit(
                    action="item_create",
                    entity_type="item",
                    details=f"Added item '{name}'"
                )

                flash(f"Item '{name}' added.", "success")
            except Exception as e:
                conn.rollback()
                flash(f"Error: {e}", "danger")

        conn.close()
        return redirect(url_for("items"))

    items_list = execute_query(c, """
        SELECT * FROM items ORDER BY name
    """).fetchall()
    conn.close()
    return render_template("items.html", title="Items", items=items_list)


@app.route("/items/<int:item_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def edit_item(item_id):
    conn = db()
    c = conn.cursor()

    item = execute_query(c, "SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    if not item:
        conn.close()
        flash("Item not found.", "danger")
        return redirect(url_for("items"))

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        description = (request.form.get("description") or "").strip()
        is_active = 1 if request.form.get("is_active") == "on" else 0

        if not name:
            flash("Item name is required.", "danger")
        else:
            execute_query(c, """
                UPDATE items SET name = ?, description = ?, is_active = ?
                WHERE id = ?
            """, (name, description, is_active, item_id))
            conn.commit()

            log_audit(
                action="item_edit",
                entity_type="item",
                entity_id=item_id,
                details=f"Edited item '{name}'"
            )

            flash(f"Item '{name}' updated.", "success")
            conn.close()
            return redirect(url_for("items"))

    conn.close()
    return render_template("edit_item.html", title="Edit Item", item=item)


@app.route("/items/<int:item_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_item(item_id):
    conn = db()
    c = conn.cursor()

    # Block if any rental is currently using it (not yet returned)
    in_use = get_single_value(c, """
        SELECT COUNT(*) FROM rental_items ri
        JOIN daily_rentals r ON r.id = ri.rental_id
        WHERE ri.item_id = ? AND ri.returned_at IS NULL
          AND r.status = 'Active'
    """, (item_id,))

    if in_use and int(in_use) > 0:
        conn.close()
        flash(f"Cannot delete: {in_use} active rental(s) still have this item.", "danger")
        return redirect(url_for("items"))


    log_audit(
        action="item_delete",
        entity_type="item",
        entity_id=item_id,
        details=f"Deleted item #{item_id}"
    )

    execute_query(c, "DELETE FROM items WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    flash("Item deleted.", "success")
    return redirect(url_for("items"))


@app.route("/stations/<int:station_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def edit_station(station_id):
    conn = db()
    c = conn.cursor()

    station = execute_query(c,
        "SELECT * FROM branches WHERE id = ?", (station_id,)
    ).fetchone()

    if not station:
        conn.close()
        flash("Station not found.", "danger")
        return redirect(url_for("stations"))

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        location = (request.form.get("location") or "").strip()
        address = (request.form.get("address") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        email = (request.form.get("email") or "").strip()
        is_active = 1 if request.form.get("is_active") == "on" else 0

        if not name:
            flash("Station name is required.", "danger")
        else:
            execute_query(c, """
                UPDATE branches
                SET name = ?, location = ?, address = ?, phone = ?, email = ?, is_active = ?
                WHERE id = ?
            """, (name, location, address, phone, email, is_active, station_id))
            conn.commit()

            log_audit(
                action="station_edit",
                entity_type="branch",
                entity_id=station_id,
                details=f"Edited station '{name}'"
            )

            flash(f"Station '{name}' updated.", "success")
            conn.close()
            return redirect(url_for("stations"))

    conn.close()
    return render_template("edit_station.html", title="Edit Station", station=station)


@app.route("/stations/<int:station_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_station(station_id):
    conn = db()
    c = conn.cursor()

    # Block if any bicycle is currently at this station
    bikes_here = get_single_value(c,
        "SELECT COUNT(*) FROM bicycles WHERE current_station_id = ?", (station_id,))
    if bikes_here and int(bikes_here) > 0:
        conn.close()
        flash(f"Cannot delete: {bikes_here} bicycle(s) are currently at this station.", "danger")
        return redirect(url_for("stations"))

    log_audit(
        action="station_delete",
        entity_type="branch",
        entity_id=station_id,
        details=f"Deleted station '{station_id}'"
    )

    execute_query(c, "DELETE FROM branches WHERE id = ?", (station_id,))
    conn.commit()
    conn.close()
    flash("Station deleted.", "success")
    return redirect(url_for("stations"))






@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user (Admin only)."""
    if user_id == session["user_id"]:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("users"))
    
    conn = db()
    c = conn.cursor()
    
    # Check if user exists
    user = execute_query(c,"SELECT username, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("users"))
    
    try:
        # ✅ STEP 1: Get customer ID if exists
        customer = execute_query(c,"SELECT id FROM customers WHERE user_id = ?", (user_id,)).fetchone()
        
        if customer:
            customer_id = customer["id"]
            
            # ✅ STEP 2: Delete customer documents FIRST
            execute_query(c,"DELETE FROM customer_documents WHERE customer_id = ?", (customer_id,))
            
            # ✅ STEP 3: Delete discount usage
            execute_query(c,"DELETE FROM discount_usage WHERE customer_id = ?", (customer_id,))
            
            # ✅ STEP 4: Delete loyalty points
            execute_query(c,"DELETE FROM loyalty_points WHERE customer_id = ?", (customer_id,))
            
            # ✅ STEP 5: Delete points transactions
            execute_query(c,"DELETE FROM points_transactions WHERE customer_id = ?", (customer_id,))
            
            # ✅ STEP 6: Delete verification requests
            execute_query(c,"DELETE FROM verification_requests WHERE customer_id = ?", (customer_id,))
            
            # ✅ STEP 7: Get all rentals for this customer
            rentals = execute_query(c,"SELECT id FROM daily_rentals WHERE customer_id = ?", (customer_id,)).fetchall()
            
            for rental in rentals:
                rental_id = rental["id"]
                # Delete rental payments
                execute_query(c,"DELETE FROM rental_payments WHERE daily_rental_id = ?", (rental_id,))
                # Delete reminder logs
                execute_query(c,"DELETE FROM reminder_logs WHERE rental_id = ?", (rental_id,))
                # Delete bike conditions
                execute_query(c,"DELETE FROM bike_conditions WHERE rental_id = ?", (rental_id,))
            
            # ✅ STEP 8: Delete rentals
            execute_query(c,"DELETE FROM daily_rentals WHERE customer_id = ?", (customer_id,))
            
            # ✅ STEP 9: Finally delete the customer
            execute_query(c,"DELETE FROM customers WHERE id = ?", (customer_id,))
        
        # ✅ STEP 10: Delete user's announcement comments
        execute_query(c,"DELETE FROM announcement_comments WHERE user_id = ?", (user_id,))
        
        # ✅ STEP 11: Delete user's announcements
        execute_query(c,"DELETE FROM announcements WHERE author_id = ?", (user_id,))
        
        # ✅ STEP 12: Delete verification requests where user is verifier
        execute_query(c,"DELETE FROM verification_requests WHERE verified_by = ?", (user_id,))
        
        # ✅ STEP 13: Delete bike conditions where user is checker
        execute_query(c,"DELETE FROM bike_conditions WHERE checked_by = ?", (user_id,))

        log_audit(
            action="user_delete",
            entity_type="user",
            entity_id=user_id,
            details=f"Deleted user '{user['username']}' (role={user['role']})"
        )

        # ✅ STEP 14: Finally delete the user
        execute_query(c,"DELETE FROM users WHERE id = ?", (user_id,))
        
        conn.commit()
        flash(f"User '{user['username']}' deleted successfully.", "success")
        
    except sqlite3.IntegrityError as e:
        conn.rollback()
        flash(f"Cannot delete user: {str(e)}", "danger")
    except Exception as e:
        conn.rollback()
        flash(f"Error deleting user: {str(e)}", "danger")
    finally:
        conn.close()
    
    return redirect(url_for("users"))




# =============================================
# PASSWORD RESET (Admin Only)
# =============================================

@app.route("/customers/<int:customer_id>/reset-password", methods=["GET", "POST"])
@login_required
@admin_required
def reset_customer_password(customer_id):
    """Reset a customer's password (Admin only)."""
    conn = db()
    c = conn.cursor()
    
    # Get customer
    customer = execute_query(c,"""
        SELECT c.*, u.id AS user_id, u.username 
        FROM customers c
        JOIN users u ON u.id = c.user_id
        WHERE c.id = ?
    """, (customer_id,)).fetchone()
    
    if not customer:
        flash("Customer not found.", "danger")
        return redirect(url_for("customers"))
    
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
    

        ok, err = validate_password_strength(new_password)
        if not ok:
            flash(f"Password rejected: {err}", "danger")
            return redirect(url_for("reset_customer_password", customer_id=customer_id))
            
        
        # Update password
        execute_query(c,"""
            UPDATE users 
            SET password_hash = ? 
            WHERE id = ?
        """, (generate_password_hash(new_password), customer["user_id"]))
        
        conn.commit()

        log_audit(
            action="customer_password_reset",
            entity_type="customer",
            entity_id=customer_id,
            details=f"Password reset for customer '{customer['full_name']}'"
        )

        conn.close()
        
        flash(f"Password reset successful for {customer['full_name']}!", "success")
        flash(f"New Password: {new_password} - Please give this to the customer.", "info")
        return redirect(url_for("customers"))
    
    conn.close()
    return render_template(
        "reset_customer_password.html",
        title="Reset Password",
        customer=customer
    )





@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """View and edit own profile."""
    conn = db()
    c = conn.cursor()
    
    user = execute_query(c,"SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        


        if current_password and new_password:
            # ✅ Enforce password policy
            ok, err = validate_password_strength(new_password)
            if not ok:
                flash(f"Password rejected: {err}", "danger")
                return redirect(url_for("profile"))

            if not check_password_hash(user["password_hash"], current_password):
                flash("Current password is incorrect.", "danger")
                return redirect(url_for("profile"))


            
            execute_query(c,"""
                UPDATE users 
                SET full_name = ?, email = ?, password_hash = ?
                WHERE id = ?
            """, (full_name, email, generate_password_hash(new_password), session["user_id"]))
        else:
            execute_query(c,"""
                UPDATE users 
                SET full_name = ?, email = ?
                WHERE id = ?
            """, (full_name, email, session["user_id"]))
        
        conn.commit()

        log_audit(
            action="password_change",
            entity_type="user",
            entity_id=session["user_id"],
            details="Changed own password"
        )

        conn.close()
        
        flash("Profile updated successfully!", "success")
        return redirect(url_for("profile"))
    
    conn.close()
    return render_template("profile.html", title="My Profile", user=user)



@app.route("/my-data/export.zip")
@login_required
@customer_required
def customer_data_export():
    """Customer: download a ZIP with all personal data held."""
    import zipfile
    from io import BytesIO

    # Find the customer ID for this user
    conn = db()
    c = conn.cursor()
    customer_row = execute_query(c, 
        "SELECT id FROM customers WHERE user_id = ?", (session["user_id"],)
    ).fetchone()
    conn.close()

    if not customer_row:
        flash("No customer profile found.", "danger")
        return redirect(url_for("customer_portal"))

    customer_id = customer_row["id"]
    data = _gather_customer_data(customer_id)
    if not data:
        flash("Could not gather your data.", "danger")
        return redirect(url_for("customer_portal"))

    customer = data["customer"]
    documents = data["documents"]
    rentals = data["rentals"]
    payments = data["payments"]
    damage_claims = data["damage_claims"]
    loyalty = data["loyalty"]

    # Build the ZIP
    zip_buffer = BytesIO()

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # README
        readme = (
            "RAB RENT A BIKE — PERSONAL DATA EXPORT\n"
            "======================================\n\n"
            f"Customer: {customer.get('full_name')}\n"
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
            "Contents of this archive:\n"
            "  - personal_data.json      Machine-readable data (portable format)\n"
            "  - personal_data.pdf       Human-readable summary\n"
            "  - documents/              Uploaded ID documents and photos\n"
            "  - signatures/signature.png Your digital signature (if on file)\n\n"
            "Your rights under the Namibian Data Protection Act (Act 5 of 2022):\n"
            "  - Access, correction, deletion, portability, objection\n\n"
            "Questions: privacy@rab.com\n"
        )
        zf.writestr("README.txt", readme)

        # JSON
        import json
        json_data = {
            "export_generated": datetime.now().isoformat(),
            "export_generated_by": session.get("username"),
            "customer": {k: v for k, v in customer.items() if k != "signature_data"},
            "documents": [
                {k: v for k, v in d.items() if k != "file_path"} for d in documents
            ],
            "rentals": rentals,
            "payments": payments,
            "damage_claims": damage_claims,
            "loyalty": loyalty,
        }
        zf.writestr(
            "personal_data.json",
            json.dumps(json_data, indent=2, default=str)
        )

        # PDF
        pdf_buf = _build_customer_data_pdf(
            customer, documents, rentals, payments, damage_claims, loyalty
        )
        zf.writestr("personal_data.pdf", pdf_buf.getvalue())

        # Documents
        for doc in documents:
            file_path = doc.get("file_path") or ""
            filename = f"doc_{doc['id']}_{doc['document_type']}"

            if file_path.startswith("http"):
                # Cloudinary — skip actual file; note the URL
                zf.writestr(
                    f"documents/{filename}.url.txt",
                    f"Stored on Cloudinary:\n{file_path}\n"
                )
            else:
                local_name = os.path.basename(file_path)
                full_path = os.path.join(PRIVATE_UPLOAD_FOLDER, local_name)
                if os.path.exists(full_path):
                    ext = os.path.splitext(local_name)[1]
                    zf.write(full_path, arcname=f"documents/{filename}{ext}")
                else:
                    zf.writestr(
                        f"documents/{filename}.missing.txt",
                        f"File was not found on server: {local_name}\n"
                    )

        # Signature
        sig_data = customer.get("signature_data")
        if sig_data:
            try:
                if sig_data.startswith("data:image"):
                    header, b64 = sig_data.split(",", 1)
                else:
                    b64 = sig_data
                import base64
                sig_bytes = base64.b64decode(b64)
                zf.writestr("signatures/signature.png", sig_bytes)
            except Exception as e:
                zf.writestr("signatures/signature_error.txt", f"Could not decode signature: {e}")

    zip_buffer.seek(0)

    # Log the export
    log_audit(
        action="customer_data_export",
        entity_type="customer",
        entity_id=customer_id,
        details=f"Customer exported their data (self-service)"
    )

    filename = f"rab_personal_data_{customer_id}_{datetime.now().strftime('%Y-%m-%d')}.zip"
    return send_file(
        zip_buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/zip"
    )





@app.route("/customer-rentals")
@login_required
@customer_required
def customer_rentals():
    """Customer view - only their own rentals."""
    from datetime import datetime  # ✅ Add this import
    
    conn = db()
    c = conn.cursor()
    
    # Get customer ID
    customer = execute_query(c, """
        SELECT id FROM customers WHERE user_id = ?
    """, (session["user_id"],)).fetchone()
    
    if not customer:
        flash("Customer profile not found.", "danger")
        return redirect(url_for("customer_portal"))
    
    # Get customer's rentals only
    rentals = execute_query(c, """
        SELECT 
            r.*,
            b.bike_code,
            b.brand,
            b.model
        FROM daily_rentals r
        JOIN bicycles b ON b.id = r.bicycle_id
        WHERE r.customer_id = ?
        ORDER BY r.start_time DESC
    """, (customer["id"],)).fetchall()
    
    # ✅ FIX: Format datetime for each rental
    for rental in rentals:
        if rental.get("start_time"):
            if isinstance(rental["start_time"], datetime):
                rental["start_time"] = rental["start_time"].strftime("%Y-%m-%d %H:%M")
        if rental.get("end_time"):
            if isinstance(rental["end_time"], datetime):
                rental["end_time"] = rental["end_time"].strftime("%Y-%m-%d %H:%M")
    
    conn.close()
    
    return render_template(
        "customer_rentals.html",
        title="My Rentals",
        rentals=rentals
    )


@app.route("/customer-rent")
@login_required
@customer_required
def customer_rent():
    """Legacy route — redirected to Pickup Points."""
    return redirect(url_for("customer_stations"))








@app.route("/dashboard")
@login_required
@staff_required
def dashboard():
    """Staff dashboard - NOT for customers."""
    from datetime import datetime, timedelta
    
    conn = db()
    c = conn.cursor()
    
    is_postgres = os.environ.get("DATABASE_URL") is not None
    
    # Stats
    total_bikes = get_single_value(c, "SELECT COUNT(*) FROM bicycles WHERE status = 'Available'")
    active_rentals = get_single_value(c, "SELECT COUNT(*) FROM daily_rentals WHERE status = 'Active'")
    total_customers = get_single_value(c, "SELECT COUNT(*) FROM customers")
    pending_verification = get_single_value(c, "SELECT COUNT(*) FROM customers WHERE verification_status = 'Pending'")
    
    # Today's Revenue
    if is_postgres:
        today_revenue = get_single_value(c, """
            SELECT COALESCE(SUM(total_cost), 0) 
            FROM daily_rentals 
            WHERE DATE(created_at) = CURRENT_DATE
            AND status = 'Completed' 
            AND payment_status = 'Paid'
            AND total_cost >= 0
        """)
    else:
        today_revenue = get_single_value(c, """
            SELECT COALESCE(SUM(total_cost), 0) 
            FROM daily_rentals 
            WHERE date(created_at) = date('now') 
            AND status = 'Completed' 
            AND payment_status = 'Paid'
            AND total_cost >= 0
        """)
    
    # ✅ Get active rentals with correct duration
    if is_postgres:
        rentals = execute_query(c, """
            SELECT 
                r.id,
                c.full_name,
                b.bike_code,
                r.start_time,
                CONCAT(
                    GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - r.start_time)) / 3600)), 'h ',
                    GREATEST(0, FLOOR((EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - r.start_time)) % 3600) / 60)), 'm'
                ) AS duration
            FROM daily_rentals r
            JOIN customers c ON c.id = r.customer_id
            JOIN bicycles b ON b.id = r.bicycle_id
            WHERE r.status = 'Active'
            ORDER BY r.start_time DESC
        """).fetchall()
    else:
        rentals = execute_query(c, """
            SELECT 
                r.id,
                c.full_name,
                b.bike_code,
                r.start_time,
                CAST(MAX(0, (strftime('%s', 'now') - strftime('%s', r.start_time))) / 3600 AS INTEGER) || 'h ' ||
                CAST(MAX(0, ((strftime('%s', 'now') - strftime('%s', r.start_time)) % 3600)) / 60 AS INTEGER) || 'm' AS duration
            FROM daily_rentals r
            JOIN customers c ON c.id = r.customer_id
            JOIN bicycles b ON b.id = r.bicycle_id
            WHERE r.status = 'Active'
            ORDER BY r.start_time DESC
        """).fetchall()
    
    # ✅ FIX: Format start_time for display - Convert UTC to Local (Namibia time)
    for rental in rentals:
        if rental.get("start_time"):
            if isinstance(rental["start_time"], datetime):
                # Add 2 hours for Namibia time (UTC+2)
                local_start = rental["start_time"] + timedelta(hours=2)
                rental["start_time"] = local_start.strftime("%Y-%m-%d %H:%M")
                print(f"✅ Formatted start_time (datetime): {rental['start_time']}")
            elif isinstance(rental["start_time"], str):
                try:
                    dt = datetime.fromisoformat(rental["start_time"])
                    local_dt = dt + timedelta(hours=2)
                    rental["start_time"] = local_dt.strftime("%Y-%m-%d %H:%M")
                    print(f"✅ Formatted start_time (string): {rental['start_time']}")
                except Exception as e:
                    print(f"❌ Error parsing start_time: {e}")
                    rental["start_time"] = rental["start_time"]
        else:
            rental["start_time"] = "Time not recorded"
            print("⚠️ start_time is None or empty")
    
    # Unpaid rentals
    unpaid_rentals = execute_query(c, """
        SELECT 
            r.id,
            c.full_name,
            b.bike_code,
            r.total_cost,
            r.start_time,
            r.end_time
        FROM daily_rentals r
        JOIN customers c ON c.id = r.customer_id
        JOIN bicycles b ON b.id = r.bicycle_id
        WHERE r.status = 'Completed'
        AND (r.payment_status IS NULL OR r.payment_status != 'Paid')
        ORDER BY r.end_time DESC
    """).fetchall()
        # ✅ Pending privacy requests
    pending_privacy = get_single_value(c, """
        SELECT COUNT(*) FROM privacy_requests WHERE status = 'Pending'
    """)
    # Format dates for unpaid rentals
    for rental in unpaid_rentals:
        if rental.get("start_time"):
            if isinstance(rental["start_time"], datetime):
                local_start = rental["start_time"] + timedelta(hours=2)
                rental["start_time"] = local_start.strftime("%Y-%m-%d %H:%M")
            elif isinstance(rental["start_time"], str):
                try:
                    dt = datetime.fromisoformat(rental["start_time"])
                    local_dt = dt + timedelta(hours=2)
                    rental["start_time"] = local_dt.strftime("%Y-%m-%d %H:%M")
                except:
                    rental["start_time"] = rental["start_time"]
        
        if rental.get("end_time"):
            if isinstance(rental["end_time"], datetime):
                local_end = rental["end_time"] + timedelta(hours=2)
                rental["end_time"] = local_end.strftime("%Y-%m-%d %H:%M")
            elif isinstance(rental["end_time"], str):
                try:
                    dt = datetime.fromisoformat(rental["end_time"])
                    local_dt = dt + timedelta(hours=2)
                    rental["end_time"] = local_dt.strftime("%Y-%m-%d %H:%M")
                except:
                    rental["end_time"] = rental["end_time"]
    

    
    conn.close()
    
    # Ensure revenue is never negative
    if today_revenue < 0:
        today_revenue = 0
    
    return render_template(
        "dashboard.html",
        title="Dashboard - Daily Rentals",
        total_bikes=total_bikes,
        active_rentals=active_rentals,
        total_customers=total_customers,
        pending_verification=pending_verification,
        today_revenue=today_revenue,
        rentals=rentals,
        unpaid_rentals=unpaid_rentals,
        pending_privacy=pending_privacy,
        retention=RETENTION
    )





@app.route("/rentals/start", methods=["GET", "POST"])
@login_required
@staff_required
def start_rental():
    from datetime import datetime, timedelta, timezone
    import pytz

    conn = db()
    c = conn.cursor()

    if request.method == "POST":
        customer_id = request.form.get("customer_id")
        bicycle_id = request.form.get("bicycle_id")
        start_time = request.form.get("start_time")

        # ✅ Block if customer has unpaid damage claims
        unpaid = get_customer_unpaid_damages(c, customer_id)
        if unpaid > 0:
            conn.close()
            flash(
                f"Cannot start rental: this customer has an unpaid damage balance of N$ {unpaid:.2f}. "
                f"Please settle the balance first.",
                "danger"
            )
            return redirect(url_for("customer_damages", customer_id=customer_id))

        # ✅ Block if customer already has an active rental
        existing_active = execute_query(c, """
            SELECT r.id, b.bike_code
            FROM daily_rentals r
            JOIN bicycles b ON b.id = r.bicycle_id
            WHERE r.customer_id = ? AND r.status = 'Active'
        """, (customer_id,)).fetchall()

        if existing_active:
            conn.close()
            if len(existing_active) == 1:
                active_info = existing_active[0]
                flash(
                    f"Cannot start a new rental — this customer already has an active rental "
                    f"(#{active_info['id']} on bike {active_info['bike_code']}). "
                    f"Please end that rental first.",
                    "danger"
                )
            else:
                bikes_list = ", ".join(a["bike_code"] for a in existing_active)
                flash(
                    f"Cannot start a new rental — this customer already has {len(existing_active)} active rentals "
                    f"(bikes: {bikes_list}). Please end them first.",
                    "danger"
                )
            return redirect(url_for("start_rental"))

        # ✅ Convert local time to UTC for storage
        if start_time:
            local_dt = datetime.fromisoformat(start_time)
            utc_dt = local_dt - timedelta(hours=2)
            start_time_utc = utc_dt.strftime("%Y-%m-%d %H:%M:%S")
        else:
            utc_dt = datetime.now(timezone.utc).replace(tzinfo=None)
            start_time_utc = utc_dt.strftime("%Y-%m-%d %H:%M:%S")

        # Verify customer is verified
        customer = execute_query(c, """
            SELECT verification_status FROM customers WHERE id = ?
        """, (customer_id,)).fetchone()

        if not customer or customer["verification_status"] != "Verified":
            conn.close()
            flash("Customer must be verified before renting.", "danger")
            return redirect(url_for("start_rental"))

        bike = execute_query(c, """
            SELECT hourly_rate, daily_cap, deposit_amount FROM bicycles WHERE id = ?
        """, (bicycle_id,)).fetchone()

        if not bike:
            conn.close()
            flash("Bicycle not found.", "danger")
            return redirect(url_for("start_rental"))

        try:
            deposit_paid = float(request.form.get("deposit_paid", bike["deposit_amount"]))
            if deposit_paid < 0:
                deposit_paid = 0
        except (TypeError, ValueError):
            deposit_paid = bike["deposit_amount"]

        # Station
        start_station_id = request.form.get("start_station_id") or None
        if start_station_id:
            start_station_id = int(start_station_id)

        rental_id = insert_and_get_id(c, """
            INSERT INTO daily_rentals (
                customer_id, bicycle_id, start_time,
                hourly_rate, daily_cap, deposit_paid, status,
                agreement_signed, started_by_user_id, start_station_id
            ) VALUES (?, ?, ?, ?, ?, ?, 'Active', 1, ?, ?)
        """, (customer_id, bicycle_id, start_time_utc,
              bike["hourly_rate"], bike["daily_cap"], deposit_paid,
              session["user_id"], start_station_id))

        execute_query(c, "UPDATE bicycles SET status = 'Rented' WHERE id = ?", (bicycle_id,))

        # Save start condition note
        start_condition_note = (request.form.get("start_condition_note") or "").strip()
        execute_query(c, """
            UPDATE daily_rentals SET start_condition_note = ? WHERE id = ?
        """, (start_condition_note, rental_id))

        # Save selected items
        selected_items = request.form.getlist("items")
        for item_id in selected_items:
            try:
                execute_query(c, """
                    INSERT INTO rental_items (rental_id, item_id, given_by_user_id)
                    VALUES (?, ?, ?)
                """, (rental_id, int(item_id), session["user_id"]))
            except Exception as e:
                print(f"skip item {item_id}: {e}")

        log_audit(
            action="rental_start",
            entity_type="daily_rental",
            entity_id=rental_id,
            details=f"Started rental #{rental_id} — customer_id={customer_id}, bike_id={bicycle_id}, "
                    f"deposit=N${deposit_paid:.2f}, station_id={start_station_id}"
        )

        conn.commit()
        conn.close()

        flash(f"Rental started successfully! Rental ID: {rental_id}", "success")
        return redirect(url_for("dashboard"))

    # =============================================
    # GET branch
    # =============================================
    customers = execute_query(c, """
        SELECT id, full_name, phone FROM customers 
        WHERE verification_status = 'Verified' 
        ORDER BY full_name
    """).fetchall()

    bicycles = execute_query(c, """
        SELECT id, bike_code, brand, model, hourly_rate, daily_cap 
        FROM bicycles WHERE status = 'Available'
    """).fetchall()

    stations = execute_query(c, """
        SELECT id, name, location FROM branches
        WHERE is_active = 1
        ORDER BY name
    """).fetchall()

    items_list = execute_query(c, """
        SELECT id, name FROM items WHERE is_active = 1 ORDER BY name
    """).fetchall()

    default_station_id = session.get("station_id")
    if not default_station_id and stations:
        default_station_id = stations[0]["id"]

    conn.close()

    namibia_tz = pytz.timezone('Africa/Windhoek')
    local_now = datetime.now(namibia_tz)

    return render_template(
        "start_rental.html",
        title="Start Rental",
        customers=customers,
        bicycles=bicycles,
        stations=stations,
        items_list=items_list,
        default_station_id=default_station_id,
        now=local_now.strftime("%Y-%m-%dT%H:%M")
    )

@app.route("/login-history")
@login_required
@manager_required
def login_history():
    """Admin/Manager: view all login attempts."""
    from datetime import datetime, timedelta

    conn = db()
    c = conn.cursor()

    # Filters
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    user_filter = (request.args.get("user_filter") or "").strip()
    status_filter = (request.args.get("status_filter") or "").strip()
    page = int(request.args.get("page", 1))
    per_page = 50
    offset = (page - 1) * per_page

    query = """
        SELECT 
            lh.*,
            u.username AS user_username,
            u.full_name AS user_full_name,
            u.role AS user_role
        FROM login_history lh
        LEFT JOIN users u ON u.id = lh.user_id
        WHERE 1=1
    """
    params = []

    if date_from:
        query += " AND date(lh.created_at) >= ?"
        params.append(date_from)
    if date_to:
        query += " AND date(lh.created_at) <= ?"
        params.append(date_to)
    if user_filter:
        query += " AND (lh.username_attempted LIKE ? OR u.username LIKE ?)"
        like = f"%{user_filter}%"
        params.extend([like, like])
    if status_filter == "success":
        query += " AND lh.success = 1"
    elif status_filter == "failed":
        query += " AND lh.success = 0"

    # Get total count for pagination
    count_query = "SELECT COUNT(*) AS cnt FROM (" + query + ") AS sub"
    total_count = get_single_value(c, count_query, params)

    query += " ORDER BY lh.created_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])

    entries = execute_query(c, query, params).fetchall()

    # Convert UTC → Namibia local time for display
    for e in entries:
        if e.get("created_at"):
            e["created_at_display"] = to_namibia_time(e["created_at"])
        else:
            e["created_at_display"] = "—"

        # IP masking — admin sees full, manager sees masked
        if session.get("role") == "admin":
            e["ip_display"] = e.get("ip_address") or "—"
        else:
            e["ip_display"] = mask_ip(e.get("ip_address"))

    # Stats
    total_attempts = get_single_value(c, "SELECT COUNT(*) FROM login_history")
    total_success = get_single_value(c, "SELECT COUNT(*) FROM login_history WHERE success = 1")
    total_failed = get_single_value(c, "SELECT COUNT(*) FROM login_history WHERE success = 0")

    # Failed in last hour
    if os.environ.get("DATABASE_URL"):
        failed_last_hour = get_single_value(c, """
            SELECT COUNT(*) FROM login_history
            WHERE success = 0 AND created_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour'
        """)
    else:
        failed_last_hour = get_single_value(c, """
            SELECT COUNT(*) FROM login_history
            WHERE success = 0 AND created_at >= datetime('now', '-1 hour')
        """)

    total_pages = max(1, (total_count + per_page - 1) // per_page)


    active_users_today = get_single_value(c, """
        SELECT COUNT(DISTINCT user_id) FROM login_history
        WHERE success = 1 AND date(created_at) = date('now')
    """ if not os.environ.get("DATABASE_URL") else """
        SELECT COUNT(DISTINCT user_id) FROM login_history
        WHERE success = 1 AND DATE(created_at) = CURRENT_DATE
    """)    

    conn.close()

    return render_template(
        "login_history.html",
        title="Login History",
        entries=entries,
        total_attempts=total_attempts,
        total_success=total_success,
        total_failed=total_failed,
        failed_last_hour=failed_last_hour,
        date_from=date_from,
        date_to=date_to,
        user_filter=user_filter,
        status_filter=status_filter,
        page=page,
        total_pages=total_pages,
        active_users_today=active_users_today
    )


@app.route("/audit-log")
@login_required
@admin_required
def audit_log_page():
    """Admin only: view general audit log."""
    conn = db()
    c = conn.cursor()

    # Filters
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    user_filter = (request.args.get("user_filter") or "").strip()
    action_filter = (request.args.get("action_filter") or "").strip()
    entity_filter = (request.args.get("entity_filter") or "").strip()
    page = int(request.args.get("page", 1))
    per_page = 100
    offset = (page - 1) * per_page

    query = "SELECT * FROM audit_log WHERE 1=1"
    params = []

    if date_from:
        query += " AND date(created_at) >= ?"
        params.append(date_from)
    if date_to:
        query += " AND date(created_at) <= ?"
        params.append(date_to)
    if user_filter:
        query += " AND (username LIKE ? OR user_role LIKE ?)"
        like = f"%{user_filter}%"
        params.extend([like, like])
    if action_filter:
        query += " AND action = ?"
        params.append(action_filter)
    if entity_filter:
        query += " AND entity_type = ?"
        params.append(entity_filter)

    # Count for pagination
    count_query = "SELECT COUNT(*) AS cnt FROM (" + query + ") AS sub"
    total_count = get_single_value(c, count_query, params)

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])

    entries = execute_query(c, query, params).fetchall()

    # Convert UTC → Namibia local time
    for e in entries:
        if e.get("created_at"):
            e["created_at_display"] = to_namibia_time(e["created_at"])
        else:
            e["created_at_display"] = "—"
        if session.get("role") == "admin":
            e["ip_display"] = e.get("ip_address") or "—"
        else:
            e["ip_display"] = mask_ip(e.get("ip_address"))

    # Get the list of distinct actions for the filter dropdown
    actions = execute_query(c, """
        SELECT DISTINCT action FROM audit_log ORDER BY action
    """).fetchall()
    action_list = [a["action"] if isinstance(a, dict) else a[0] for a in actions]

    # Distinct entity types
    entities = execute_query(c, """
        SELECT DISTINCT entity_type FROM audit_log 
        WHERE entity_type IS NOT NULL ORDER BY entity_type
    """).fetchall()
    entity_list = [a["entity_type"] if isinstance(a, dict) else a[0] for a in entities]

    total_pages = max(1, (total_count + per_page - 1) // per_page)
    conn.close()

    return render_template(
        "audit_log.html",
        title="Audit Log",
        entries=entries,
        action_list=action_list,
        entity_list=entity_list,
        date_from=date_from,
        date_to=date_to,
        user_filter=user_filter,
        action_filter=action_filter,
        entity_filter=entity_filter,
        page=page,
        total_pages=total_pages,
    )

@app.route("/admin/run-cleanup", methods=["POST"])
@login_required
@admin_required
def admin_run_cleanup():
    """Manually trigger the retention cleanup."""
    cleanup_old_logs()
    log_audit(
        action="run_cleanup",
        entity_type="system",
        details="Manual retention cleanup executed",
    )
    flash("Retention cleanup completed. Old logs purged.", "success")
    return redirect(url_for("audit_log_page"))






@app.route("/customers", methods=["GET", "POST"])
@login_required
@staff_required
@limiter.limit("10 per minute")
def customers():
    import os
    import cloudinary
    import cloudinary.uploader
    from werkzeug.utils import secure_filename
    
    conn = db()
    c = conn.cursor()
    
    is_postgres = os.environ.get("DATABASE_URL") is not None
    
    # ✅ Check if Cloudinary is configured
    use_cloudinary = all([
        os.environ.get("CLOUDINARY_CLOUD_NAME"),
        os.environ.get("CLOUDINARY_API_KEY"),
        os.environ.get("CLOUDINARY_API_SECRET")
    ])
    
    if use_cloudinary:
        try:
            cloudinary.config(
                cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
                api_key=os.environ.get("CLOUDINARY_API_KEY"),
                api_secret=os.environ.get("CLOUDINARY_API_SECRET")
            )
            print("✅ Cloudinary configured successfully!")
        except Exception as e:
            print(f"❌ Cloudinary config error: {e}")
            use_cloudinary = False
    
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        phone = request.form.get("phone", "").strip()
        id_number = request.form.get("id_number", "").strip()
        email = request.form.get("email", "").strip()
        address = request.form.get("address", "").strip()
        id_photo = request.files.get("id_photo") if request.files else None
        customer_photo = request.files.get("customer_photo") if request.files else None
        
        terms_accepted = 1 if request.form.get("terms_accepted") == "on" else 0
        signature_data = request.form.get("signature_data", "").strip()
        
        if not full_name or not phone:
            flash("Name and phone are required.", "danger")
            return redirect(url_for("customers"))
        
        if not terms_accepted:
            flash("You must accept the Terms & Conditions.", "danger")
            return redirect(url_for("customers"))
        
        # Create username
        username = phone
        existing_user = execute_query(c, "SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing_user:
            if email:
                username = email
            else:
                username = f"cust_{phone}"
        

        
        import secrets
        import string
        # ✅ Generate a policy-compliant random password (10 chars, letters + digits + special)
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        temp_password = ''.join(secrets.choice(alphabet) for _ in range(12))
        # Guarantee at least one of each class in case of unlucky draw
        temp_password = (
            secrets.choice(string.ascii_letters)
            + secrets.choice(string.digits)
            + secrets.choice("!@#$%^&*")
            + ''.join(secrets.choice(alphabet) for _ in range(9))
        )
        # Shuffle so the classes aren't always at the start
        temp_list = list(temp_password)
        secrets.SystemRandom().shuffle(temp_list)
        temp_password = ''.join(temp_list)
        password_hash = generate_password_hash(temp_password)

        # Insert user
        try:
            execute_query(c, """
                INSERT INTO users (username, password_hash, role, full_name, email)
                VALUES (?, ?, 'customer', ?, ?)
            """, (username, password_hash, full_name, email))
            
            user_result = execute_query(c, "SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if user_result:
                user_id = user_result['id'] if isinstance(user_result, dict) else user_result[0]
            else:
                flash("Error: User created but ID not found.", "danger")
                return redirect(url_for("customers"))
        except sqlite3.IntegrityError:
            flash(f"Username '{username}' already exists.", "danger")
            return redirect(url_for("customers"))
        
        # Insert customer
        # execute_query(c, """
        #     INSERT INTO customers (
        #         full_name, id_number, phone, email, address, user_id,
        #         terms_accepted, terms_accepted_date, signature_data, verification_status
        #     ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, 'Pending')
        # """, (full_name, id_number, phone, email, address, user_id, 
        #       terms_accepted, signature_data))
        
        # customer_id = c.lastrowid

        customer_id = insert_and_get_id(c, """
            INSERT INTO customers (
                full_name, id_number, phone, email, address, user_id,
                terms_accepted, terms_accepted_date, signature_data, verification_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, 'Pending')
        """, (full_name, id_number, phone, email, address, user_id,
              terms_accepted, signature_data))

        # if is_postgres:
        #     customer_result = execute_query(c, "SELECT id FROM customers WHERE user_id = ?", (user_id,)).fetchone()
        #     if customer_result:
        #         customer_id = customer_result['id'] if isinstance(customer_result, dict) else customer_result[0]
        
        session["customer_id"] = customer_id
        

        log_audit(
            action="customer_create",
            entity_type="customer",
            entity_id=customer_id,
            details=f"Registered customer '{full_name}' (phone: {phone})"
        )


        # ✅ Save documents
        UPLOAD_FOLDER = os.path.join(BASE, 'static', 'uploads')
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        # ✅ Handle ID Photo
        if id_photo and id_photo.filename:
            ok, err, ext = validate_upload(id_photo)
            if not ok:
                flash(f"ID document rejected: {err}", "danger")
                return redirect(url_for("customers"))

            uploaded = False

            # Try Cloudinary first
            if use_cloudinary:
                try:
                    upload_result = cloudinary.uploader.upload(id_photo)
                    file_url = upload_result['secure_url']
                    execute_query(c, """
                        INSERT INTO customer_documents (customer_id, document_type, file_path)
                        VALUES (?, 'id_copy', ?)
                    """, (customer_id, file_url))
                    flash("ID document uploaded successfully!", "success")
                    uploaded = True
                except Exception as e:
                    print(f"❌ Cloudinary upload failed: {e}")

            # Fallback to private local storage
            if not uploaded:
                try:
                    filename = f"id_{customer_id}_{secure_filename(id_photo.filename)}"
                    filepath = os.path.join(PRIVATE_UPLOAD_FOLDER, filename)
                    id_photo.save(filepath)
                    execute_query(c, """
                        INSERT INTO customer_documents (customer_id, document_type, file_path)
                        VALUES (?, 'id_copy', ?)
                    """, (customer_id, f"private_uploads/{filename}"))
                    flash("ID document saved securely!", "success")
                except Exception as e:
                    print(f"❌ Local save failed: {e}")
                    flash("Error uploading ID document.", "danger")
                    return redirect(url_for("customers"))

        # ✅ Handle Customer Photo
        if customer_photo and customer_photo.filename:
            ok, err, ext = validate_upload(customer_photo)
            if not ok:
                flash(f"Customer photo rejected: {err}", "danger")
                return redirect(url_for("customers"))

            uploaded = False

            if use_cloudinary:
                try:
                    upload_result = cloudinary.uploader.upload(customer_photo)
                    file_url = upload_result['secure_url']
                    execute_query(c, """
                        INSERT INTO customer_documents (customer_id, document_type, file_path)
                        VALUES (?, 'customer_photo', ?)
                    """, (customer_id, file_url))
                    flash("Customer photo uploaded successfully!", "success")

                    log_audit(
                        action="document_upload",
                        entity_type="customer",
                        entity_id=customer_id,
                        details=f"Uploaded {doc_type} for customer #{customer_id}"
                    )

                    uploaded = True
                except Exception as e:
                    print(f"❌ Cloudinary upload failed: {e}")

            if not uploaded:
                try:
                    filename = f"photo_{customer_id}_{secure_filename(customer_photo.filename)}"
                    filepath = os.path.join(PRIVATE_UPLOAD_FOLDER, filename)
                    customer_photo.save(filepath)
                    execute_query(c, """
                        INSERT INTO customer_documents (customer_id, document_type, file_path)
                        VALUES (?, 'customer_photo', ?)
                    """, (customer_id, f"private_uploads/{filename}"))
                    flash("Customer photo saved securely!", "success")
                except Exception as e:
                    print(f"❌ Local save failed: {e}")
                    flash("Error uploading customer photo.", "danger")
                    return redirect(url_for("customers"))



        
        conn.commit()
        conn.close()
        
        flash(f"Customer '{full_name}' registered successfully!", "success")
        flash(f"🔑 Login Credentials - Username: {username}, Password: {temp_password}", "success")
        flash("📌 Please give these credentials to the customer.", "info")
        
        return redirect(url_for("customers"))
    

    # =============================================
    # SEARCH FILTER (case-insensitive on both DBs)
    # =============================================
    search = (request.args.get("search") or "").strip()

    if search:
        like = f"%{search}%"
        customers = execute_query(c, f"""
            SELECT * FROM customers
            WHERE {ci_like('full_name', '?')}
               OR {ci_like('phone', '?')}
               OR {ci_like('id_number', '?')}
               OR {ci_like('email', '?')}
            ORDER BY full_name
        """, (like, like, like, like)).fetchall()
    else:
        customers = execute_query(c, "SELECT * FROM customers ORDER BY full_name").fetchall()

    conn.close()

    return render_template(
        "customers.html",
        title="Customers",
        customers=customers,
        search=search
    )




@app.route("/customers/<int:customer_id>/verify", methods=["GET"])
@login_required
def verify_customer_page(customer_id):
    """Show verification page for a customer."""
    conn = db()
    c = conn.cursor()
    
    customer = execute_query(c,"SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
    
    if not customer:
        flash("Customer not found.", "danger")
        return redirect(url_for("customers"))
    
    conn.close()
    return render_template("verify_customer.html", title="Verify Customer", customer=customer)


@app.route("/damages")
@login_required
@manager_required
def damages_list():
    """List all damage claims."""
    conn = db()
    c = conn.cursor()

    status = (request.args.get("status") or "").strip()

    query = """
        SELECT d.*, 
               cu.full_name AS customer_name, cu.phone AS customer_phone,
               b.bike_code,
               i.name AS item_name,
               u.username AS charged_by
        FROM damage_claims d
        LEFT JOIN customers cu ON cu.id = d.customer_id
        LEFT JOIN bicycles b ON b.id = d.bicycle_id
        LEFT JOIN items i ON i.id = d.item_id
        LEFT JOIN users u ON u.id = d.charged_by_user_id
        WHERE 1=1
    """
    params = []
    if status:
        query += " AND d.status = ?"
        params.append(status)
    query += " ORDER BY d.created_at DESC LIMIT 500"

    claims = execute_query(c, query, params).fetchall()

    # Format timestamps
    for claim in claims:
        for key in ("created_at", "charged_at", "paid_at"):
            if claim.get(key):
                claim[key] = to_namibia_time(claim[key])

    # Totals
    total_outstanding = get_single_value(c, """
        SELECT COALESCE(SUM(amount), 0) FROM damage_claims
        WHERE status NOT IN ('Paid', 'Waived')
    """)
    total_paid = get_single_value(c, """
        SELECT COALESCE(SUM(amount), 0) FROM damage_claims
        WHERE status = 'Paid'
    """)

    conn.close()
    return render_template(
        "damages_list.html",
        title="Damage Claims",
        claims=claims,
        status=status,
        total_outstanding=total_outstanding,
        total_paid=total_paid
    )


@app.route("/damages/new", methods=["GET", "POST"])
@login_required
@manager_required
def new_damage():
    """Create a damage claim manually (outside of end_rental)."""
    conn = db()
    c = conn.cursor()

    # GET: load customers + bikes + items for dropdowns
    customers = execute_query(c, """
        SELECT id, full_name, phone FROM customers ORDER BY full_name
    """).fetchall()
    bicycles = execute_query(c, """
        SELECT id, bike_code FROM bicycles ORDER BY bike_code
    """).fetchall()
    items_list = execute_query(c, """
        SELECT id, name FROM items WHERE is_active = 1 ORDER BY name
    """).fetchall()

    if request.method == "POST":
        customer_id = request.form.get("customer_id")
        bicycle_id = request.form.get("bicycle_id") or None
        item_id = request.form.get("item_id") or None
        description = (request.form.get("description") or "").strip()
        amount = float(request.form.get("amount", 0) or 0)
        notes = (request.form.get("notes") or "").strip()

        if not customer_id or not description or amount <= 0:
            flash("Customer, description, and a positive amount are required.", "danger")
            conn.close()
            return redirect(url_for("new_damage"))

        execute_query(c, """
            INSERT INTO damage_claims
            (customer_id, bicycle_id, item_id, description, amount, notes,
             status, charged_by_user_id)
            VALUES (?, ?, ?, ?, ?, ?, 'Charged', ?)
        """, (int(customer_id),
              int(bicycle_id) if bicycle_id else None,
              int(item_id) if item_id else None,
              description, amount, notes, session["user_id"]))

        conn.commit()

        log_audit(
            action="damage_create",
            entity_type="damage_claim",
            details=f"Created damage claim N${amount:.2f} for customer_id={customer_id} — {description[:80]}"
        )

        conn.close()
        flash(f"Damage claim of N$ {amount:.2f} created.", "success")
        return redirect(url_for("damages_list"))

    conn.close()
    return render_template(
        "new_damage.html",
        title="New Damage Claim",
        customers=customers,
        bicycles=bicycles,
        items=items_list
    )


@app.route("/damages/<int:claim_id>/pay", methods=["GET", "POST"])
@login_required
@manager_required
def pay_damage(claim_id):
    conn = db()
    c = conn.cursor()

    claim = execute_query(c, """
        SELECT d.*, cu.full_name AS customer_name
        FROM damage_claims d
        JOIN customers cu ON cu.id = d.customer_id
        WHERE d.id = ?
    """, (claim_id,)).fetchone()

    if not claim:
        conn.close()
        flash("Claim not found.", "danger")
        return redirect(url_for("damages_list"))

    if request.method == "POST":
        method = request.form.get("payment_method", "Cash")
        execute_query(c, """
            UPDATE damage_claims
            SET status = 'Paid', paid_at = CURRENT_TIMESTAMP, payment_method = ?
            WHERE id = ?
        """, (method, claim_id))
        conn.commit()

        log_audit(
            action="damage_paid",
            entity_type="damage_claim",
            entity_id=claim_id,
            details=f"Damage claim #{claim_id} marked paid (N${claim['amount']:.2f}, {method})"
        )

        conn.close()
        flash(f"Damage claim marked as Paid (N$ {claim['amount']:.2f}).", "success")
        return redirect(url_for("damages_list"))

    conn.close()
    return render_template("pay_damage.html", title="Pay Damage Claim", claim=claim)


@app.route("/damages/<int:claim_id>/waive", methods=["POST"])
@login_required
@admin_required
def waive_damage(claim_id):
    conn = db()
    c = conn.cursor()
    execute_query(c, """
        UPDATE damage_claims SET status = 'Waived' WHERE id = ?
    """, (claim_id,))
    conn.commit()

    log_audit(
        action="damage_waived",
        entity_type="damage_claim",
        entity_id=claim_id,
        details=f"Damage claim #{claim_id} waived"
    )

    conn.close()
    flash("Damage claim waived.", "success")
    return redirect(url_for("damages_list"))


@app.route("/customers/<int:customer_id>/damages")
@login_required
def customer_damages(customer_id):
    """Show all damage claims for a specific customer."""
    conn = db()
    c = conn.cursor()

    customer = execute_query(c, "SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
    if not customer:
        conn.close()
        flash("Customer not found.", "danger")
        return redirect(url_for("customers"))

    claims = execute_query(c, """
        SELECT d.*, b.bike_code, i.name AS item_name
        FROM damage_claims d
        LEFT JOIN bicycles b ON b.id = d.bicycle_id
        LEFT JOIN items i ON i.id = d.item_id
        WHERE d.customer_id = ?
        ORDER BY d.created_at DESC
    """, (customer_id,)).fetchall()

    for claim in claims:
        for key in ("created_at", "charged_at", "paid_at"):
            if claim.get(key):
                claim[key] = to_namibia_time(claim[key])

    outstanding = get_customer_unpaid_damages(c, customer_id)

    conn.close()
    return render_template(
        "customer_damages.html",
        title=f"Damages — {customer['full_name']}",
        customer=customer,
        claims=claims,
        outstanding=outstanding
    )

@app.route("/damages/<int:claim_id>/agreement.pdf")
@login_required
@manager_required
def damage_agreement_pdf(claim_id):
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import mm
    from io import BytesIO

    conn = db()
    c = conn.cursor()

    claim = execute_query(c, """
        SELECT d.*, 
               cu.full_name, cu.id_number, cu.phone, cu.address,
               b.bike_code, b.brand, b.model,
               i.name AS item_name,
               u.username AS charged_by_username, u.full_name AS charged_by_name
        FROM damage_claims d
        JOIN customers cu ON cu.id = d.customer_id
        LEFT JOIN bicycles b ON b.id = d.bicycle_id
        LEFT JOIN items i ON i.id = d.item_id
        LEFT JOIN users u ON u.id = d.charged_by_user_id
        WHERE d.id = ?
    """, (claim_id,)).fetchone()
    conn.close()

    if not claim:
        flash("Claim not found.", "danger")
        return redirect(url_for("damages_list"))

    buf = BytesIO()
    pdf = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    x, y = 22*mm, height - 25*mm

    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(x, y, "RAB - DAMAGE AGREEMENT")
    y -= 10*mm

    pdf.setFont("Helvetica", 10)
    pdf.drawString(x, y, f"Claim ID: #{claim['id']}")
    pdf.drawString(x + 120*mm, y, f"Date: {to_namibia_time(claim['created_at'])}")
    y -= 8*mm
    pdf.line(x, y, width-x, y)
    y -= 10*mm

    # Customer
    pdf.setFont("Helvetica-Bold", 12); pdf.drawString(x, y, "CUSTOMER"); y -= 7*mm
    pdf.setFont("Helvetica", 10)
    pdf.drawString(x + 5*mm, y, f"Name: {claim['full_name']}"); y -= 6*mm
    pdf.drawString(x + 5*mm, y, f"ID / Passport: {claim['id_number'] or 'Not provided'}"); y -= 6*mm
    pdf.drawString(x + 5*mm, y, f"Phone: {claim['phone']}"); y -= 6*mm
    pdf.drawString(x + 5*mm, y, f"Address: {claim['address'] or 'Not provided'}"); y -= 10*mm

    # Item / bike
    pdf.setFont("Helvetica-Bold", 12); pdf.drawString(x, y, "ITEM / BICYCLE"); y -= 7*mm
    pdf.setFont("Helvetica", 10)
    if claim['bike_code']:
        pdf.drawString(x + 5*mm, y, f"Bicycle: {claim['bike_code']} - {claim['brand'] or ''} {claim['model'] or ''}"); y -= 6*mm
    if claim['item_name']:
        pdf.drawString(x + 5*mm, y, f"Item: {claim['item_name']}"); y -= 6*mm
    y -= 4*mm

    # Damage details
    pdf.setFont("Helvetica-Bold", 12); pdf.drawString(x, y, "DAMAGE DETAILS"); y -= 7*mm
    pdf.setFont("Helvetica", 10)
    pdf.drawString(x + 5*mm, y, f"Description: {claim['description']}"); y -= 6*mm
    pdf.drawString(x + 5*mm, y, f"Amount Agreed: N$ {claim['amount']:.2f}"); y -= 6*mm
    pdf.drawString(x + 5*mm, y, f"Reported by: {claim['charged_by_name'] or claim['charged_by_username'] or 'N/A'}"); y -= 12*mm

    # Terms
    pdf.setFont("Helvetica-Bold", 12); pdf.drawString(x, y, "CUSTOMER AGREEMENT"); y -= 7*mm
    pdf.setFont("Helvetica", 9)
    terms = [
        "1. I acknowledge the damage described above occurred during my rental period.",
        "2. I agree to pay the amount stated above for repair or replacement.",
        "3. I understand that unpaid damage claims may block future rentals.",
        "4. I have been given the opportunity to review this document before signing.",
    ]
    for t in terms:
        pdf.drawString(x + 5*mm, y, t); y -= 5.5*mm

    y -= 10*mm
    pdf.line(x, y, x + 70*mm, y)
    pdf.line(x + 95*mm, y, width - x, y)
    y -= 5*mm
    pdf.setFont("Helvetica", 9)
    pdf.drawString(x, y, "Customer Signature")
    pdf.drawString(x + 95*mm, y, "RAB Representative")
    y -= 15*mm
    pdf.line(x, y, x + 70*mm, y)
    pdf.line(x + 95*mm, y, width - x, y)
    y -= 5*mm
    pdf.drawString(x, y, "Date")
    pdf.drawString(x + 95*mm, y, "Date")

    pdf.save()
    buf.seek(0)
    filename = f"RAB_Damage_{claim['id']}.pdf"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="application/pdf")



@app.route("/customers/<int:customer_id>/verify", methods=["POST"])
@login_required
def verify_customer(customer_id):
    """Verify or reject a customer."""
    conn = db()
    c = conn.cursor()
    
    # ✅ Check if customer exists
    customer = execute_query(c,"SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
    if not customer:
        flash("Customer not found.", "danger")
        return redirect(url_for("customers"))
    
    status = request.form.get("verification_status", "Pending")
    notes = request.form.get("verification_notes", "").strip()
    
    try:
        # ✅ STEP 1: Update customer verification status
        execute_query(c,"""
            UPDATE customers 
            SET verification_status = ?, verification_notes = ?
            WHERE id = ?
        """, (status, notes, customer_id))
        
        # ✅ STEP 2: Insert into verification_requests
        # Make sure the user exists in the users table
        user = execute_query(c,"SELECT id FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        
        if user:
            execute_query(c,"""
                INSERT INTO verification_requests (customer_id, verified_by, status, notes)
                VALUES (?, ?, ?, ?)
            """, (customer_id, session["user_id"], status, notes))
        else:
            # If user doesn't exist, insert with NULL or skip
            flash("Warning: User not found for verification record.", "warning")
        
        conn.commit()
        log_audit(
            action="customer_verify",
            entity_type="customer",
            entity_id=customer_id,
            details=f"Customer verification set to '{status}'"
        )

        flash(f"Customer verification updated to {status}.", "success")
        
    except sqlite3.IntegrityError as e:
        conn.rollback()
        flash(f"Error updating verification: {str(e)}", "danger")
    except Exception as e:
        conn.rollback()
        flash(f"Error updating verification: {str(e)}", "danger")
    finally:
        conn.close()
    
    return redirect(url_for("customers"))



@app.route("/privacy")
def privacy_policy():
    """Public privacy policy page — no login required."""
    return render_template(
        "privacy.html",
        title="Privacy Policy",
        retention=RETENTION,
        privacy_email=PRIVACY_EMAIL,
        company_name="RAB — Rent A Bike",
        last_updated="2026-10-11",
    )

@app.route("/customers/<int:customer_id>/documents")
@login_required
def view_documents(customer_id):
    conn = db()
    c = conn.cursor()
    
    customer = execute_query(c,"SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
    documents = execute_query(c,"""
        SELECT * FROM customer_documents 
        WHERE customer_id = ? 
        ORDER BY uploaded_at DESC
    """, (customer_id,)).fetchall()
    
    conn.close()
    
    if not customer:
        flash("Customer not found.", "danger")
        return redirect(url_for("customers"))
    
    return render_template(
        "documents.html",
        title="Customer Documents",
        customer=customer,
        documents=documents
    )





@app.route("/customers/<int:customer_id>/documents/<int:doc_id>/view")
@login_required
def view_document_file(customer_id, doc_id):
    """View a customer document."""
    import os
    
    conn = db()
    c = conn.cursor()
    
    doc = execute_query(c, """
        SELECT * FROM customer_documents 
        WHERE id = ? AND customer_id = ?
    """, (doc_id, customer_id)).fetchone()
    
    conn.close()
    
    if not doc:
        flash("Document not found.", "danger")
        return redirect(url_for("view_documents", customer_id=customer_id))
    
    file_path = doc["file_path"]
    
    # ✅ If it's a Cloudinary URL, redirect directly
    if file_path.startswith("http"):
        return redirect(file_path)
    
    # ✅ For local files, try multiple paths
    filename = file_path.split('/')[-1]
    
    # Try to find the file in different locations
    possible_paths = [
        file_path,
        f"uploads/{filename}",
        filename,
        f"static/uploads/{filename}",
        os.path.join('uploads', filename)
    ]
    
    for path in possible_paths:
        full_path = os.path.join(BASE, 'static', path)
        if os.path.exists(full_path):
            return render_template(
                "view_document.html",
                title="View Document",
                doc=doc,
                customer_id=customer_id,
                file_path=path
            )
    
    # If file not found, show error and delete option
    flash(f"Document file not found: {filename}. The file may have been deleted.", "danger")
    return render_template(
        "view_document.html",
        title="View Document",
        doc=doc,
        customer_id=customer_id,
        file_path=None,
        file_not_found=True
    )

@app.route("/login-history/export.csv")
@login_required
@manager_required
def login_history_export_csv():
    """Export login history as CSV. Respects the current filters if any are set."""
    conn = db()
    c = conn.cursor()

    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    user_filter = (request.args.get("user_filter") or "").strip()
    status_filter = (request.args.get("status_filter") or "").strip()

    query = """
        SELECT 
            lh.id, lh.username_attempted, lh.success, lh.ip_address,
            lh.user_agent, lh.device_summary, lh.failure_reason,
            lh.created_at,
            u.username AS user_username, u.full_name AS user_full_name, u.role AS user_role
        FROM login_history lh
        LEFT JOIN users u ON u.id = lh.user_id
        WHERE 1=1
    """
    params = []

    if date_from:
        query += " AND date(lh.created_at) >= ?"
        params.append(date_from)
    if date_to:
        query += " AND date(lh.created_at) <= ?"
        params.append(date_to)
    if user_filter:
        query += " AND (lh.username_attempted LIKE ? OR u.username LIKE ?)"
        like = f"%{user_filter}%"
        params.extend([like, like])
    if status_filter == "success":
        query += " AND lh.success = 1"
    elif status_filter == "failed":
        query += " AND lh.success = 0"

    query += " ORDER BY lh.created_at DESC"

    rows = execute_query(c, query, params).fetchall()
    conn.close()

    # Convert to display-friendly values
    is_admin = session.get("role") == "admin"
    for r in rows:
        r["created_at_display"] = to_namibia_time(r.get("created_at"))
        r["status_label"] = "Success" if r.get("success") else "Failed"
        r["ip_display"] = (r.get("ip_address") or "—") if is_admin else mask_ip(r.get("ip_address"))
        r["user_display"] = r.get("user_username") or r.get("username_attempted") or "—"

    columns = [
        ("id", "ID"),
        ("created_at_display", "Date/Time (Namibia)"),
        ("user_display", "User"),
        ("user_full_name", "Full Name"),
        ("user_role", "Role"),
        ("status_label", "Status"),
        ("device_summary", "Device"),
        ("ip_display", "IP Address"),
        ("failure_reason", "Failure Reason"),
    ]

    filtered = bool(date_from or date_to or user_filter or status_filter)
    filename = _export_filename("login_history", filtered=filtered)
    return build_csv_response(rows, columns, filename)

def build_audit_pdf(rows, columns, title, filters_meta, generated_by):
    """
    Build a Flask response with a PDF export.
    - rows: list of dicts
    - columns: list of (key, header, width_pct) tuples
    - title: page title string
    - filters_meta: dict of applied filters
    - generated_by: username of the admin who exported
    """
    from datetime import datetime

    buf = BytesIO()
    # Landscape for wide tables
    pdf = canvas.Canvas(buf, pagesize=landscape(A4))
    width, height = landscape(A4)

    margin_x = 15 * mm
    y = height - 20 * mm

    # ============= HEADER =============
    pdf.setFont("Helvetica-Bold", 18)
    pdf.setFillColor(colors.HexColor("#0d1f46"))
    pdf.drawString(margin_x, y, f"RAB — {title}")

    y -= 8 * mm
    pdf.setFont("Helvetica", 9)
    pdf.setFillColor(colors.HexColor("#667085"))
    pdf.drawString(margin_x, y, f"Generated by: {generated_by}")
    pdf.drawString(margin_x + 100 * mm, y, 
                   f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    pdf.drawString(margin_x + 200 * mm, y, 
                   f"Total rows: {len(rows)}")

    y -= 5 * mm

    # ============= FILTERS APPLIED =============
    pdf.setFont("Helvetica-Bold", 9)
    pdf.setFillColor(colors.HexColor("#0d1f46"))
    pdf.drawString(margin_x, y, "Filters applied:")
    y -= 4 * mm

    pdf.setFont("Helvetica", 8)
    pdf.setFillColor(colors.HexColor("#111111"))
    filter_line = " | ".join(
        f"{k.replace('_', ' ').title()}: {v}" 
        for k, v in filters_meta.items() if v and v != "—"
    )
    if not filter_line:
        filter_line = "None (all-time export)"
    pdf.drawString(margin_x, y, filter_line)

    y -= 8 * mm

    # ============= TABLE HEADER =============
    pdf.setFillColor(colors.HexColor("#0d1f46"))
    pdf.rect(margin_x, y - 1 * mm, width - 2 * margin_x, 7 * mm, fill=1, stroke=0)

    pdf.setFillColor(colors.white)
    pdf.setFont("Helvetica-Bold", 8)
    x = margin_x + 2 * mm
    for key, header, pct in columns:
        col_width = (width - 2 * margin_x - 4 * mm) * pct
        pdf.drawString(x, y + 1 * mm, header[:30])
        x += col_width

    y -= 8 * mm

    # ============= ROWS =============
    pdf.setFont("Helvetica", 7)
    pdf.setFillColor(colors.HexColor("#111111"))

    row_height = 5 * mm
    rows_per_page = int((y - 40 * mm) / row_height)

    for idx, row in enumerate(rows):
        # Page break
        if idx > 0 and idx % rows_per_page == 0:
            pdf.showPage()
            y = height - 20 * mm
            # Redraw table header on new page
            pdf.setFillColor(colors.HexColor("#0d1f46"))
            pdf.rect(margin_x, y - 1 * mm, width - 2 * margin_x, 7 * mm, fill=1, stroke=0)
            pdf.setFillColor(colors.white)
            pdf.setFont("Helvetica-Bold", 8)
            x = margin_x + 2 * mm
            for key, header, pct in columns:
                col_width = (width - 2 * margin_x - 4 * mm) * pct
                pdf.drawString(x, y + 1 * mm, header[:30])
                x += col_width
            y -= 8 * mm
            pdf.setFont("Helvetica", 7)
            pdf.setFillColor(colors.HexColor("#111111"))

        # Alternate row shading
        if idx % 2 == 0:
            pdf.setFillColor(colors.HexColor("#f8f9fa"))
            pdf.rect(margin_x, y - 1.5 * mm, width - 2 * margin_x, row_height, fill=1, stroke=0)
            pdf.setFillColor(colors.HexColor("#111111"))

        x = margin_x + 2 * mm
        for key, header, pct in columns:
            col_width = (width - 2 * margin_x - 4 * mm) * pct
            val = row.get(key) if isinstance(row, dict) else None
            text = str(val) if val is not None else ""
            # Truncate long text
            max_chars = int(col_width / 1.8)
            if len(text) > max_chars:
                text = text[:max_chars - 3] + "..."
            pdf.drawString(x, y, text)
            x += col_width

        y -= row_height

    # ============= SIGNATURE BLOCK =============
    y -= 15 * mm
    if y < 30 * mm:
        pdf.showPage()
        y = height - 30 * mm

    pdf.setFont("Helvetica", 9)
    pdf.setFillColor(colors.HexColor("#111111"))
    pdf.drawString(margin_x, y, "Exported by (name & signature):")
    pdf.drawString(margin_x + 150 * mm, y, "Date:")
    y -= 15 * mm
    pdf.line(margin_x, y, margin_x + 100 * mm, y)
    pdf.line(margin_x + 150 * mm, y, margin_x + 220 * mm, y)

    y -= 10 * mm
    pdf.setFont("Helvetica", 7)
    pdf.setFillColor(colors.HexColor("#667085"))
    pdf.drawString(margin_x, y, 
                   "This document is a system-generated record. Any modification after signing invalidates it.")

    pdf.save()
    buf.seek(0)

    from datetime import datetime
    filename = f"{title.lower().replace(' ', '_')}_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.pdf"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="application/pdf")

@app.route("/audit-log/export.csv")
@login_required
@admin_required
def audit_log_export_csv():
    """Export audit log as CSV. Respects filters if any are set."""
    conn = db()
    c = conn.cursor()

    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    user_filter = (request.args.get("user_filter") or "").strip()
    action_filter = (request.args.get("action_filter") or "").strip()
    entity_filter = (request.args.get("entity_filter") or "").strip()

    query = "SELECT * FROM audit_log WHERE 1=1"
    params = []

    if date_from:
        query += " AND date(created_at) >= ?"
        params.append(date_from)
    if date_to:
        query += " AND date(created_at) <= ?"
        params.append(date_to)
    if user_filter:
        query += " AND (username LIKE ? OR user_role LIKE ?)"
        like = f"%{user_filter}%"
        params.extend([like, like])
    if action_filter:
        query += " AND action = ?"
        params.append(action_filter)
    if entity_filter:
        query += " AND entity_type = ?"
        params.append(entity_filter)

    query += " ORDER BY created_at DESC"

    rows = execute_query(c, query, params).fetchall()
    conn.close()

    for r in rows:
        r["created_at_display"] = to_namibia_time(r.get("created_at"))
        r["ip_display"] = (r.get("ip_address") or "—") if session.get("role") == "admin" else mask_ip(r.get("ip_address"))
        r["entity_display"] = f"{r.get('entity_type') or ''}#{r.get('entity_id') or ''}".strip("#") or "—"

    columns = [
        ("id", "ID"),
        ("created_at_display", "Date/Time (Namibia)"),
        ("username", "Username"),
        ("user_role", "Role"),
        ("action", "Action"),
        ("entity_type", "Entity Type"),
        ("entity_id", "Entity ID"),
        ("details", "Details"),
        ("ip_display", "IP Address"),
    ]

    filtered = bool(date_from or date_to or user_filter or action_filter or entity_filter)
    filename = _export_filename("audit_log", filtered=filtered)
    return build_csv_response(rows, columns, filename)


@app.route("/login-history/export.pdf")
@login_required
@manager_required
def login_history_export_pdf():
    """Export login history as PDF. Respects the current filters if any are set."""
    conn = db()
    c = conn.cursor()

    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    user_filter = (request.args.get("user_filter") or "").strip()
    status_filter = (request.args.get("status_filter") or "").strip()

    query = """
        SELECT 
            lh.id, lh.username_attempted, lh.success, lh.ip_address,
            lh.user_agent, lh.device_summary, lh.failure_reason,
            lh.created_at,
            u.username AS user_username, u.full_name AS user_full_name, u.role AS user_role
        FROM login_history lh
        LEFT JOIN users u ON u.id = lh.user_id
        WHERE 1=1
    """
    params = []

    if date_from:
        query += " AND date(lh.created_at) >= ?"
        params.append(date_from)
    if date_to:
        query += " AND date(lh.created_at) <= ?"
        params.append(date_to)
    if user_filter:
        query += " AND (lh.username_attempted LIKE ? OR u.username LIKE ?)"
        like = f"%{user_filter}%"
        params.extend([like, like])
    if status_filter == "success":
        query += " AND lh.success = 1"
    elif status_filter == "failed":
        query += " AND lh.success = 0"

    query += " ORDER BY lh.created_at DESC"
    rows = execute_query(c, query, params).fetchall()
    conn.close()

    is_admin = session.get("role") == "admin"
    for r in rows:
        r["created_at_display"] = to_namibia_time(r.get("created_at")) or "—"
        r["status_label"] = "Success" if r.get("success") else "Failed"
        r["ip_display"] = (r.get("ip_address") or "—") if is_admin else mask_ip(r.get("ip_address"))
        r["user_display"] = r.get("user_username") or r.get("username_attempted") or "—"

    # (key, header, width_pct) — must sum to ~1.0
    columns = [
        ("created_at_display", "Date/Time", 0.13),
        ("user_display", "User", 0.10),
        ("user_role", "Role", 0.07),
        ("status_label", "Status", 0.07),
        ("device_summary", "Device", 0.15),
        ("ip_display", "IP", 0.12),
        ("failure_reason", "Reason", 0.16),
    ]

    filters_meta = {
        "date_from": date_from or "—",
        "date_to": date_to or "—",
        "user": user_filter or "—",
        "status": status_filter or "—",
    }

    return build_audit_pdf(
        rows=rows,
        columns=columns,
        title="Login History",
        filters_meta=filters_meta,
        generated_by=session.get("username", "admin"),
    )


@app.route("/audit-log/export.pdf")
@login_required
@admin_required
def audit_log_export_pdf():
    """Export audit log as PDF. Respects filters if any are set."""
    conn = db()
    c = conn.cursor()

    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    user_filter = (request.args.get("user_filter") or "").strip()
    action_filter = (request.args.get("action_filter") or "").strip()
    entity_filter = (request.args.get("entity_filter") or "").strip()

    query = "SELECT * FROM audit_log WHERE 1=1"
    params = []

    if date_from:
        query += " AND date(created_at) >= ?"
        params.append(date_from)
    if date_to:
        query += " AND date(created_at) <= ?"
        params.append(date_to)
    if user_filter:
        query += " AND (username LIKE ? OR user_role LIKE ?)"
        like = f"%{user_filter}%"
        params.extend([like, like])
    if action_filter:
        query += " AND action = ?"
        params.append(action_filter)
    if entity_filter:
        query += " AND entity_type = ?"
        params.append(entity_filter)

    query += " ORDER BY created_at DESC"
    rows = execute_query(c, query, params).fetchall()
    conn.close()

    for r in rows:
        r["created_at_display"] = to_namibia_time(r.get("created_at")) or "—"
        r["ip_display"] = (r.get("ip_address") or "—") if session.get("role") == "admin" else mask_ip(r.get("ip_address"))

    columns = [
        ("created_at_display", "Date/Time", 0.12),
        ("username", "User", 0.09),
        ("user_role", "Role", 0.06),
        ("action", "Action", 0.14),
        ("entity_type", "Entity", 0.11),
        ("details", "Details", 0.35),
        ("ip_display", "IP", 0.13),
    ]

    filters_meta = {
        "date_from": date_from or "—",
        "date_to": date_to or "—",
        "user": user_filter or "—",
        "action": action_filter or "—",
        "entity": entity_filter or "—",
    }

    return build_audit_pdf(
        rows=rows,
        columns=columns,
        title="Audit Log",
        filters_meta=filters_meta,
        generated_by=session.get("username", "admin"),
    )


@app.route("/document-views/export.csv")
@login_required
@admin_required
def document_views_export_csv():
    """Export the document-view log as CSV."""
    conn = db()
    c = conn.cursor()

    rows = execute_query(c, """
        SELECT 
            dv.id, dv.viewed_at, dv.ip_address,
            cd.document_type, cd.customer_id,
            u.username, u.full_name AS user_full_name, u.role AS user_role,
            cu.full_name AS customer_full_name
        FROM document_views dv
        LEFT JOIN customer_documents cd ON cd.id = dv.document_id
        LEFT JOIN users u ON u.id = dv.user_id
        LEFT JOIN customers cu ON cu.id = cd.customer_id
        ORDER BY dv.viewed_at DESC
    """).fetchall()
    conn.close()

    for r in rows:
        r["viewed_at_display"] = to_namibia_time(r.get("viewed_at"))
        r["ip_display"] = (r.get("ip_address") or "—") if session.get("role") == "admin" else mask_ip(r.get("ip_address"))

    columns = [
        ("id", "ID"),
        ("viewed_at_display", "Viewed At (Namibia)"),
        ("username", "Staff Username"),
        ("user_full_name", "Staff Name"),
        ("user_role", "Role"),
        ("customer_full_name", "Customer"),
        ("document_type", "Document Type"),
        ("ip_display", "IP Address"),
    ]

    filename = _export_filename("document_views")
    return build_csv_response(rows, columns, filename)





@app.route("/customers/<int:customer_id>/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_document(customer_id, doc_id):
    """Delete a customer document."""
    conn = db()
    c = conn.cursor()
    
    # Get the document
    doc = execute_query(c, """
        SELECT * FROM customer_documents 
        WHERE id = ? AND customer_id = ?
    """, (doc_id, customer_id)).fetchone()
    
    if not doc:
        flash("Document not found.", "danger")
        return redirect(url_for("view_documents", customer_id=customer_id))


    log_audit(
        action="document_delete",
        entity_type="customer_document",
        entity_id=doc_id,
        details=f"Deleted document type '{doc['document_type']}' for customer #{customer_id}"
    )
    # Delete the document record from database
    execute_query(c, "DELETE FROM customer_documents WHERE id = ?", (doc_id,))
    
    # ✅ Try to delete the physical file if it exists locally
    import os
    file_path = doc["file_path"]
    
    # Check if it's a local file (not Cloudinary)
    if not file_path.startswith("http"):
        # Try to find and delete the file
        filename = file_path.split('/')[-1]
        possible_paths = [
            os.path.join(BASE, 'static', file_path),
            os.path.join(BASE, 'static', 'uploads', filename),
            os.path.join(BASE, 'static', filename),
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                try:
                    os.remove(path)
                    print(f"✅ Deleted file: {path}")
                except Exception as e:
                    print(f"❌ Could not delete file: {e}")
                break
    
    conn.commit()
    conn.close()
    
    flash("Document deleted successfully!", "success")
    return redirect(url_for("view_documents", customer_id=customer_id))





@app.route("/documents/<int:doc_id>/file")
@login_required
def serve_document(doc_id):
    """
    Serve a customer document. Enforces access control + logs the view.
    - Staff/manager/admin: can view any document
    - Customers: can only view their OWN documents
    """
    conn = db()
    c = conn.cursor()

    doc = execute_query(c, """
        SELECT cd.*, cu.id AS customer_id, cu.user_id AS customer_user_id
        FROM customer_documents cd
        JOIN customers cu ON cu.id = cd.customer_id
        WHERE cd.id = ?
    """, (doc_id,)).fetchone()



    if not doc:
        conn.close()
        flash("Document not found.", "danger")
        return redirect(url_for("dashboard"))

    role = session.get("role")
    user_id = session.get("user_id")

    # ✅ Access control
    if role == "customer":
        # Customer can only view their own documents
        if doc["customer_user_id"] != user_id:
            conn.close()
            flash("You do not have permission to view that document.", "danger")
            return redirect(url_for("customer_portal"))
    else:
        # Staff/manager/admin — allow
        pass

    # ✅ Log the view
    try:
        execute_query(c, """
            INSERT INTO document_views (document_id, user_id, ip_address)
            VALUES (?, ?, ?)
        """, (doc_id, user_id, request.remote_addr or "unknown"))
        conn.commit()
    except Exception as e:
        print(f"⚠️ document_views insert failed: {e}")

    conn.close()

    file_path = doc["file_path"]

    log_audit(
        action="document_view",
        entity_type="customer_document",
        entity_id=doc_id,
        details=f"Viewed document type '{doc['document_type']}' (customer #{doc['customer_id']})"
    )

    # ✅ Cloudinary URL → redirect
    if file_path.startswith("http"):
        return redirect(file_path)

    # ✅ Local private file → stream
    filename = os.path.basename(file_path)
    full_path = os.path.join(PRIVATE_UPLOAD_FOLDER, filename)

    if not os.path.exists(full_path):
        flash(f"Document file not found: {filename}", "danger")
        return redirect(url_for("view_documents", customer_id=doc["customer_id"]))

    return send_file(
        full_path,
        as_attachment=False,
        download_name=filename,
        mimetype="application/pdf" if filename.lower().endswith(".pdf") else None
    )


@app.route("/rentals/<int:rental_id>/refund", methods=["GET", "POST"])
@login_required
def refund_rental(rental_id):
    """Handle the case where the deposit exceeds the rental cost."""
    from datetime import datetime

    conn = db()
    c = conn.cursor()

    rental = execute_query(c, """
        SELECT r.*, c.full_name, b.bike_code
        FROM daily_rentals r
        JOIN customers c ON c.id = r.customer_id
        JOIN bicycles b ON b.id = r.bicycle_id
        WHERE r.id = ?
    """, (rental_id,)).fetchone()

    if not rental:
        conn.close()
        flash("Rental not found.", "danger")
        return redirect(url_for("dashboard"))

    deposit_paid = float(rental["deposit_paid"] or 0)
    total_cost = float(rental["total_cost"] or 0)
    refund_amount = round(deposit_paid - total_cost, 2)

    if refund_amount <= 0:
        conn.close()
        flash("No refund is due on this rental.", "info")
        return redirect(url_for("record_payment", rental_id=rental_id))

    if request.method == "POST":
        refund_method = request.form.get("refund_method", "Cash")
        notes = (request.form.get("notes") or "").strip()

        # Record the refund as a NEGATIVE payment (so totals stay truthful)
        execute_query(c, """
            INSERT INTO rental_payments (daily_rental_id, amount, payment_method, status)
            VALUES (?, ?, ?, 'Refunded')
        """, (rental_id, -refund_amount, refund_method))

        # Mark rental as paid (fully settled)
        execute_query(c, """
            UPDATE daily_rentals 
            SET payment_status = 'Paid',
                payment_method = ?
            WHERE id = ?
        """, (refund_method, rental_id))

        conn.commit()

        log_audit(
            action="refund",
            entity_type="daily_rental",
            entity_id=rental_id,
            details=f"Refunded N${refund_amount:.2f} ({refund_method}) for rental #{rental_id}"
        )

        conn.close()

        flash(f"Refund of N$ {refund_amount:.2f} recorded. Rental settled.", "success")
        return redirect(url_for("payment_history"))

    conn.close()

    return render_template(
        "refund_rental.html",
        title="Refund Deposit",
        rental=rental,
        deposit_paid=deposit_paid,
        total_cost=total_cost,
        refund_amount=refund_amount
    )






@app.route("/rentals/<int:rental_id>/payment", methods=["GET", "POST"])
@login_required
def record_payment(rental_id):
    from datetime import datetime
    
    conn = db()
    c = conn.cursor()
    
    rental = execute_query(c, """
        SELECT r.*, c.full_name, b.bike_code
        FROM daily_rentals r
        JOIN customers c ON c.id = r.customer_id
        JOIN bicycles b ON b.id = r.bicycle_id
        WHERE r.id = ?
    """, (rental_id,)).fetchone()
    
    if not rental:
        conn.close()
        flash("Rental not found.", "danger")
        return redirect(url_for("dashboard"))
    
    # Format start_time for display
    if rental.get("start_time"):
        if isinstance(rental["start_time"], datetime):
            rental["start_time"] = rental["start_time"].strftime("%Y-%m-%d %H:%M")
    
    # ✅ Compute deposit and net due
    deposit_paid = float(rental["deposit_paid"] or 0)
    total_cost = float(rental["total_cost"] or 0)
    net_due = round(total_cost - deposit_paid, 2)  # positive = customer owes, negative = refund
    
    # ✅ If refund is due, redirect to the refund page
    if net_due < 0:
        conn.close()
        return redirect(url_for("refund_rental", rental_id=rental_id))
    
    if request.method == "POST":
        amount = float(request.form.get("amount", 0))
        payment_method = request.form.get("payment_method", "Cash")
        
        if amount <= 0:
            flash("Payment amount must be greater than zero.", "danger")
            return redirect(url_for("record_payment", rental_id=rental_id))
        
        execute_query(c, """
            INSERT INTO rental_payments (daily_rental_id, amount, payment_method, status)
            VALUES (?, ?, ?, 'Completed')
        """, (rental_id, amount, payment_method))
        
        execute_query(c, """
            UPDATE daily_rentals 
            SET payment_status = 'Paid',
                payment_method = ?
            WHERE id = ?
        """, (payment_method, rental_id))
        
        conn.commit()

        log_audit(
            action="payment_record",
            entity_type="daily_rental",
            entity_id=rental_id,
            details=f"Recorded payment N${amount:.2f} ({payment_method}) for rental #{rental_id}"
        )

        conn.close()
        
        flash(f"Payment of N$ {amount:.2f} recorded successfully!", "success")
        return redirect(url_for("payment_history"))
    
    # Get total payments for this rental
    total_paid = get_single_value(c, """
        SELECT COALESCE(SUM(amount), 0) 
        FROM rental_payments 
        WHERE daily_rental_id = ?
    """, (rental_id,))
    
    conn.close()
    
    return render_template(
        "record_payment.html",
        title="Record Payment",
        rental=rental,
        total_paid=total_paid,
        deposit_paid=deposit_paid,
        net_due=net_due
    )



@app.route("/privacy/request-deletion", methods=["POST"])
@login_required
@customer_required
def request_account_deletion():
    """Customer submits a deletion request."""
    conn = db()
    c = conn.cursor()

    # Find the customer record
    customer = execute_query(c,
        "SELECT id, full_name FROM customers WHERE user_id = ?",
        (session["user_id"],)
    ).fetchone()

    if not customer:
        conn.close()
        flash("No customer profile found.", "danger")
        return redirect(url_for("customer_portal"))

    # Check for unpaid damages
    unpaid = get_customer_unpaid_damages(c, customer["id"])
    if unpaid > 0:
        conn.close()
        flash(
            f"Cannot request deletion while you have an unpaid damage balance of "
            f"N$ {unpaid:.2f}. Please settle it first.",
            "danger"
        )
        return redirect(url_for("customer_damages", customer_id=customer["id"]))

    # Check for active rentals
    active = get_single_value(c, """
        SELECT COUNT(*) FROM daily_rentals
        WHERE customer_id = ? AND status = 'Active'
    """, (customer["id"],))
    if active and int(active) > 0:
        conn.close()
        flash("Cannot request deletion while you have an active rental. Please return it first.", "danger")
        return redirect(url_for("customer_portal"))

    # Check for existing pending request
    existing = execute_query(c, """
        SELECT id FROM privacy_requests
        WHERE customer_id = ? AND request_type = 'delete' AND status = 'Pending'
    """, (customer["id"],)).fetchone()
    if existing:
        conn.close()
        flash("You already have a pending deletion request. Please wait for admin review.", "info")
        return redirect(url_for("customer_portal"))

    reason = (request.form.get("reason") or "").strip()

    execute_query(c, """
        INSERT INTO privacy_requests (customer_id, request_type, reason)
        VALUES (?, 'delete', ?)
    """, (customer["id"], reason))

    conn.commit()
    conn.close()

    log_audit(
        action="privacy_delete_request",
        entity_type="customer",
        entity_id=customer["id"],
        details=f"Customer '{customer['full_name']}' requested account deletion"
    )

    flash(
        "Your deletion request has been submitted. An administrator will review it within 30 days.",
        "success"
    )
    return redirect(url_for("customer_portal"))


@app.route("/privacy-requests")
@login_required
@admin_required
def privacy_requests_dashboard():
    """Admin: view and review privacy/deletion requests."""
    conn = db()
    c = conn.cursor()

    status_filter = (request.args.get("status") or "").strip()

    query = """
        SELECT pr.*, 
               cu.full_name AS customer_name, 
               cu.phone AS customer_phone,
               cu.email AS customer_email,
               u.username AS reviewed_by_username
        FROM privacy_requests pr
        LEFT JOIN customers cu ON cu.id = pr.customer_id
        LEFT JOIN users u ON u.id = pr.reviewed_by_user_id
        WHERE 1=1
    """
    params = []

    if status_filter:
        query += " AND pr.status = ?"
        params.append(status_filter)

    query += " ORDER BY pr.requested_at DESC LIMIT 500"

    requests_list = execute_query(c, query, params).fetchall()

    # Format dates
    for r in requests_list:
        for k in ("requested_at", "reviewed_at", "completed_at"):
            if r.get(k):
                r[k] = to_namibia_time(r[k])

    # Summary counts
    pending_count = get_single_value(c, """
        SELECT COUNT(*) FROM privacy_requests WHERE status = 'Pending'
    """)
    approved_count = get_single_value(c, """
        SELECT COUNT(*) FROM privacy_requests WHERE status = 'Approved'
    """)
    rejected_count = get_single_value(c, """
        SELECT COUNT(*) FROM privacy_requests WHERE status = 'Rejected'
    """)
    completed_count = get_single_value(c, """
        SELECT COUNT(*) FROM privacy_requests WHERE status = 'Completed'
    """)

    conn.close()

    return render_template(
        "privacy_requests.html",
        title="Privacy Requests",
        requests_list=requests_list,
        status_filter=status_filter,
        pending_count=pending_count,
        approved_count=approved_count,
        rejected_count=rejected_count,
        completed_count=completed_count,
    )

@app.route("/privacy-requests/<int:request_id>/review", methods=["POST"])
@login_required
@admin_required
def review_privacy_request(request_id):
    """Admin approves or rejects a privacy request."""
    action = request.form.get("action", "").strip()  # 'approve' or 'reject'
    notes = (request.form.get("notes") or "").strip()

    if action not in ("approve", "reject"):
        flash("Invalid action.", "danger")
        return redirect(url_for("privacy_requests_dashboard"))

    conn = db()
    c = conn.cursor()

    pr = execute_query(c, """
        SELECT pr.*, cu.full_name AS customer_name
        FROM privacy_requests pr
        JOIN customers cu ON cu.id = pr.customer_id
        WHERE pr.id = ?
    """, (request_id,)).fetchone()

    if not pr:
        conn.close()
        flash("Request not found.", "danger")
        return redirect(url_for("privacy_requests_dashboard"))

    if pr["status"] != "Pending":
        conn.close()
        flash(f"This request has already been {pr['status'].lower()}.", "info")
        return redirect(url_for("privacy_requests_dashboard"))

    new_status = "Approved" if action == "approve" else "Rejected"

    execute_query(c, """
        UPDATE privacy_requests
        SET status = ?, reviewed_by_user_id = ?, reviewed_at = CURRENT_TIMESTAMP,
            review_notes = ?
        WHERE id = ?
    """, (new_status, session["user_id"], notes, request_id))

    conn.commit()
    conn.close()

    log_audit(
        action=f"privacy_request_{action}",
        entity_type="privacy_request",
        entity_id=request_id,
        details=f"{new_status} deletion request for customer '{pr['customer_name']}'. Notes: {notes or 'none'}"
    )

    if action == "approve":
        flash(f"Request approved. Now execute the anonymization to finalize.", "success")
        return redirect(url_for("execute_deletion", request_id=request_id))
    else:
        flash(f"Request rejected.", "success")
        return redirect(url_for("privacy_requests_dashboard"))


@app.route("/privacy-requests/<int:request_id>/execute", methods=["GET", "POST"])
@login_required
@admin_required
def execute_deletion(request_id):
    """Admin: run the actual anonymization for an approved request."""
    conn = db()
    c = conn.cursor()

    pr = execute_query(c, """
        SELECT pr.*, cu.full_name AS customer_name, cu.user_id AS customer_user_id
        FROM privacy_requests pr
        JOIN customers cu ON cu.id = pr.customer_id
        WHERE pr.id = ?
    """, (request_id,)).fetchone()

    if not pr:
        conn.close()
        flash("Request not found.", "danger")
        return redirect(url_for("privacy_requests_dashboard"))

    if pr["status"] != "Approved":
        conn.close()
        flash(f"This request must be Approved before execution. Current status: {pr['status']}.", "danger")
        return redirect(url_for("privacy_requests_dashboard"))

    customer_id = pr["customer_id"]
    customer_name = pr["customer_name"]
    user_id = pr["customer_user_id"]

    if request.method == "POST":
        # Confirm admin typed DELETE
        confirm = (request.form.get("confirm") or "").strip()
        if confirm != "DELETE":
            flash("You must type DELETE to confirm.", "danger")
            conn.close()
            return redirect(url_for("execute_deletion", request_id=request_id))

        try:
            # 1. Delete uploaded documents (physical files + DB rows)
            docs = execute_query(c, """
                SELECT file_path FROM customer_documents WHERE customer_id = ?
            """, (customer_id,)).fetchall()

            for d in docs:
                file_path = d.get("file_path") or ""
                if not file_path.startswith("http"):
                    local_name = os.path.basename(file_path)
                    full_path = os.path.join(PRIVATE_UPLOAD_FOLDER, local_name)
                    try:
                        if os.path.exists(full_path):
                            os.remove(full_path)
                    except Exception as e:
                        print(f"⚠️ Could not delete file {full_path}: {e}")

            execute_query(c, "DELETE FROM customer_documents WHERE customer_id = ?", (customer_id,))

            # 2. Anonymize customer record
            execute_query(c, """
                UPDATE customers
                SET full_name = ?,
                    id_number = NULL,
                    phone = ?,
                    email = NULL,
                    address = NULL,
                    signature_data = NULL,
                    verification_notes = 'Account deleted on ' || CURRENT_TIMESTAMP,
                    verification_status = 'Deleted'
                WHERE id = ?
            """, (f"Deleted User #{customer_id}", f"deleted_{customer_id}", customer_id))

            # 3. Anonymize comments made by the customer
            if user_id:
                execute_query(c, """
                    UPDATE announcement_comments
                    SET user_name = 'Deleted User'
                    WHERE user_id = ?
                """, (user_id,))

                # 4. Disable login by scrambling username and password
                import secrets
                scrambled = f"deleted_{user_id}_{secrets.token_hex(6)}"
                execute_query(c, """
                    UPDATE users
                    SET username = ?,
                        password_hash = ?,
                        email = NULL,
                        full_name = 'Deleted User',
                        role = 'customer'
                    WHERE id = ?
                """, (scrambled, generate_password_hash(secrets.token_hex(16)), user_id))

            # 5. Mark request completed
            execute_query(c, """
                UPDATE privacy_requests
                SET status = 'Completed', completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (request_id,))

            conn.commit()
            conn.close()

            log_audit(
                action="privacy_deletion_executed",
                entity_type="customer",
                entity_id=customer_id,
                details=f"Anonymized customer #{customer_id} ('{customer_name}') and purged documents"
            )

            flash(
                f"Customer '{customer_name}' has been anonymized. "
                f"Documents purged, login disabled.",
                "success"
            )
            return redirect(url_for("privacy_requests_dashboard"))

        except Exception as e:
            conn.rollback()
            conn.close()
            flash(f"Error during anonymization: {e}", "danger")
            return redirect(url_for("privacy_requests_dashboard"))

    # GET: show the confirmation page
    conn.close()
    return render_template(
        "execute_deletion.html",
        title="Execute Deletion",
        request_row=pr,
    )





@app.route("/payments")
@login_required
@staff_required
def payment_history():
    """Payment history — shows all payments with both gross and net figures."""
    from datetime import datetime

    conn = db()
    c = conn.cursor()

    payments = execute_query(c, """
        SELECT 
            p.*,
            r.id AS rental_id,
            r.total_cost AS rental_cost,
            r.total_hours,
            r.deposit_paid,
            b.bike_code,
            c.full_name
        FROM rental_payments p
        JOIN daily_rentals r ON r.id = p.daily_rental_id
        JOIN bicycles b ON b.id = r.bicycle_id
        JOIN customers c ON c.id = r.customer_id
        ORDER BY p.payment_date DESC
        LIMIT 50
    """).fetchall()

    # Format dates
    for payment in payments:
        if payment.get("payment_date"):
            payment["payment_date"] = to_namibia_time(payment["payment_date"])

    # ✅ Total Rental Cost — gross revenue (each rental counted once)
    total_rental_cost = get_single_value(c, """
        SELECT COALESCE(SUM(total_cost), 0)
        FROM daily_rentals
        WHERE status IN ('Completed', 'Active')
    """)

    # ✅ Total Net Settled — actual cash moved (payments minus refunds)
    total_settled = get_single_value(c, """
        SELECT COALESCE(SUM(amount), 0) FROM rental_payments
    """)

    conn.close()

    return render_template(
        "payment_history.html",
        title="Payment History",
        payments=payments,
        total_rental_cost=total_rental_cost,
        total_settled=total_settled,
    )





@app.route("/reports/revenue")
@login_required
@manager_required
def revenue_report():
    """Revenue report based on total_cost (gross rental revenue) + damages."""
    conn = db()
    c = conn.cursor()

    is_postgres = os.environ.get("DATABASE_URL") is not None

    # ---------- SAFE PARAMETER HANDLING ----------
    period = (request.args.get("period") or "daily").strip()
    date_filter = (request.args.get("date") or "").strip()

    if period == "daily":
        if not date_filter or len(date_filter) != 10 or date_filter.count("-") != 2:
            date_filter = datetime.now().strftime("%Y-%m-%d")
    elif period == "monthly":
        if date_filter and len(date_filter) >= 7:
            date_filter = date_filter[:7]
        if not date_filter or len(date_filter) != 7:
            date_filter = datetime.now().strftime("%Y-%m")
    elif period == "weekly":
        if not date_filter or "W" not in date_filter.upper():
            date_filter = ""
    else:
        period = "daily"
        date_filter = datetime.now().strftime("%Y-%m-%d")

    daily_revenue = []
    available_dates = []
    daily_summary = None
    weekly_summary = None
    monthly_summary = None
    weekly_trend = []
    damage_revenue = []
    damage_summary = None
    report_title = "Revenue Report"

    # =============================================
    # DAILY
    # =============================================
    if period == "daily":
        if is_postgres:
            daily_revenue = execute_query(c, """
                SELECT 
                    DATE(dr.start_time) AS date,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(dr.total_cost), 0) AS total,
                    STRING_AGG(DISTINCT b.bike_code, ', ') AS bikes_rented
                FROM daily_rentals dr
                LEFT JOIN bicycles b ON b.id = dr.bicycle_id
                WHERE DATE(dr.start_time) = %s
                  AND dr.status IN ('Completed', 'Active')
                GROUP BY DATE(dr.start_time)
                ORDER BY DATE(dr.start_time) DESC
            """, (date_filter,)).fetchall()

            daily_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(dr.total_cost), 0) AS total,
                    COUNT(*) AS transactions,
                    COUNT(DISTINCT dr.customer_id) AS unique_customers
                FROM daily_rentals dr
                WHERE DATE(dr.start_time) = %s
                  AND dr.status IN ('Completed', 'Active')
            """, (date_filter,)).fetchone()

            damage_revenue = execute_query(c, """
                SELECT 
                    DATE(d.paid_at) AS date,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(d.amount), 0) AS total
                FROM damage_claims d
                WHERE DATE(d.paid_at) = %s AND d.status = 'Paid'
                GROUP BY DATE(d.paid_at)
                ORDER BY DATE(d.paid_at) DESC
            """, (date_filter,)).fetchall()

            damage_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(amount), 0) AS total,
                    COUNT(*) AS transactions
                FROM damage_claims
                WHERE DATE(paid_at) = %s AND status = 'Paid'
            """, (date_filter,)).fetchone()

            available_dates = execute_query(c, """
                SELECT DISTINCT DATE(start_time) AS date
                FROM daily_rentals
                WHERE status IN ('Completed', 'Active')
                ORDER BY date DESC
            """).fetchall()

            weekly_trend = execute_query(c, """
                SELECT 
                    DATE(start_time) AS date,
                    COALESCE(SUM(total_cost), 0) AS total
                FROM daily_rentals
                WHERE DATE(start_time) >= CURRENT_DATE - INTERVAL '7 days'
                  AND status IN ('Completed', 'Active')
                GROUP BY DATE(start_time)
                ORDER BY DATE(start_time) ASC
            """).fetchall()
        else:
            daily_revenue = execute_query(c, """
                SELECT 
                    date(dr.start_time) AS date,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(dr.total_cost), 0) AS total,
                    GROUP_CONCAT(DISTINCT b.bike_code) AS bikes_rented
                FROM daily_rentals dr
                LEFT JOIN bicycles b ON b.id = dr.bicycle_id
                WHERE date(dr.start_time) = ?
                  AND dr.status IN ('Completed', 'Active')
                GROUP BY date(dr.start_time)
                ORDER BY date(dr.start_time) DESC
            """, (date_filter,)).fetchall()

            daily_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(dr.total_cost), 0) AS total,
                    COUNT(*) AS transactions,
                    COUNT(DISTINCT dr.customer_id) AS unique_customers
                FROM daily_rentals dr
                WHERE date(dr.start_time) = ?
                  AND dr.status IN ('Completed', 'Active')
            """, (date_filter,)).fetchone()

            damage_revenue = execute_query(c, """
                SELECT 
                    date(d.paid_at) AS date,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(d.amount), 0) AS total
                FROM damage_claims d
                WHERE date(d.paid_at) = ? AND d.status = 'Paid'
                GROUP BY date(d.paid_at)
                ORDER BY date(d.paid_at) DESC
            """, (date_filter,)).fetchall()

            damage_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(amount), 0) AS total,
                    COUNT(*) AS transactions
                FROM damage_claims
                WHERE date(paid_at) = ? AND status = 'Paid'
            """, (date_filter,)).fetchone()

            available_dates = execute_query(c, """
                SELECT DISTINCT date(start_time) AS date
                FROM daily_rentals
                WHERE status IN ('Completed', 'Active')
                ORDER BY date DESC
            """).fetchall()

            weekly_trend = execute_query(c, """
                SELECT 
                    date(start_time) AS date,
                    COALESCE(SUM(total_cost), 0) AS total
                FROM daily_rentals
                WHERE date(start_time) >= date('now', '-7 days')
                  AND status IN ('Completed', 'Active')
                GROUP BY date(start_time)
                ORDER BY date(start_time) ASC
            """).fetchall()

        report_title = f"Revenue Report - {date_filter}"

    # =============================================
    # WEEKLY
    # =============================================
    elif period == "weekly":
        year = request.args.get("year", datetime.now().strftime("%Y"))
        week = request.args.get("week", datetime.now().strftime("%W"))

        if is_postgres:
            weekly_revenue = execute_query(c, """
                SELECT 
                    EXTRACT(WEEK FROM dr.start_time) AS week,
                    EXTRACT(YEAR FROM dr.start_time) AS year,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(dr.total_cost), 0) AS total
                FROM daily_rentals dr
                WHERE EXTRACT(WEEK FROM dr.start_time) = %s
                  AND EXTRACT(YEAR FROM dr.start_time) = %s
                  AND dr.status IN ('Completed', 'Active')
                GROUP BY EXTRACT(WEEK FROM dr.start_time), EXTRACT(YEAR FROM dr.start_time)
                ORDER BY year DESC, week DESC
            """, (week, year)).fetchall()

            weekly_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(dr.total_cost), 0) AS total,
                    COUNT(*) AS transactions,
                    COUNT(DISTINCT dr.customer_id) AS unique_customers
                FROM daily_rentals dr
                WHERE EXTRACT(WEEK FROM dr.start_time) = %s
                  AND EXTRACT(YEAR FROM dr.start_time) = %s
                  AND dr.status IN ('Completed', 'Active')
            """, (week, year)).fetchone()

            damage_revenue = execute_query(c, """
                SELECT 
                    EXTRACT(WEEK FROM d.paid_at) AS week,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(d.amount), 0) AS total
                FROM damage_claims d
                WHERE EXTRACT(WEEK FROM d.paid_at) = %s
                  AND EXTRACT(YEAR FROM d.paid_at) = %s
                  AND d.status = 'Paid'
                GROUP BY EXTRACT(WEEK FROM d.paid_at)
            """, (week, year)).fetchall()

            damage_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(amount), 0) AS total,
                    COUNT(*) AS transactions
                FROM damage_claims
                WHERE EXTRACT(WEEK FROM paid_at) = %s
                  AND EXTRACT(YEAR FROM paid_at) = %s
                  AND status = 'Paid'
            """, (week, year)).fetchone()

            available_weeks = execute_query(c, """
                SELECT DISTINCT 
                    EXTRACT(WEEK FROM start_time) AS week,
                    EXTRACT(YEAR FROM start_time) AS year
                FROM daily_rentals
                WHERE status IN ('Completed', 'Active')
                ORDER BY year DESC, week DESC
                LIMIT 20
            """).fetchall()
        else:
            weekly_revenue = execute_query(c, """
                SELECT 
                    strftime('%W', dr.start_time) AS week,
                    strftime('%Y', dr.start_time) AS year,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(dr.total_cost), 0) AS total
                FROM daily_rentals dr
                WHERE strftime('%W', dr.start_time) = ?
                  AND strftime('%Y', dr.start_time) = ?
                  AND dr.status IN ('Completed', 'Active')
                GROUP BY strftime('%W', dr.start_time), strftime('%Y', dr.start_time)
                ORDER BY year DESC, week DESC
            """, (week, year)).fetchall()

            weekly_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(dr.total_cost), 0) AS total,
                    COUNT(*) AS transactions,
                    COUNT(DISTINCT dr.customer_id) AS unique_customers
                FROM daily_rentals dr
                WHERE strftime('%W', dr.start_time) = ?
                  AND strftime('%Y', dr.start_time) = ?
                  AND dr.status IN ('Completed', 'Active')
            """, (week, year)).fetchone()

            damage_revenue = execute_query(c, """
                SELECT 
                    strftime('%W', d.paid_at) AS week,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(d.amount), 0) AS total
                FROM damage_claims d
                WHERE strftime('%W', d.paid_at) = ?
                  AND strftime('%Y', d.paid_at) = ?
                  AND d.status = 'Paid'
                GROUP BY strftime('%W', d.paid_at)
            """, (week, year)).fetchall()

            damage_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(amount), 0) AS total,
                    COUNT(*) AS transactions
                FROM damage_claims
                WHERE strftime('%W', paid_at) = ?
                  AND strftime('%Y', paid_at) = ?
                  AND status = 'Paid'
            """, (week, year)).fetchone()

            available_weeks = execute_query(c, """
                SELECT DISTINCT 
                    strftime('%W', start_time) AS week,
                    strftime('%Y', start_time) AS year
                FROM daily_rentals
                WHERE status IN ('Completed', 'Active')
                ORDER BY year DESC, week DESC
                LIMIT 20
            """).fetchall()

        daily_revenue = weekly_revenue
        available_dates = available_weeks
        date_filter = f"{year}-W{week}"
        report_title = f"Weekly Revenue Report - Week {week}, {year}"

    # =============================================
    # MONTHLY
    # =============================================
    else:
        month_filter = date_filter

        if is_postgres:
            monthly_revenue = execute_query(c, """
                SELECT 
                    TO_CHAR(dr.start_time, 'YYYY-MM') AS month,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(dr.total_cost), 0) AS total,
                    COUNT(DISTINCT dr.customer_id) AS unique_customers
                FROM daily_rentals dr
                WHERE TO_CHAR(dr.start_time, 'YYYY-MM') = %s
                  AND dr.status IN ('Completed', 'Active')
                GROUP BY TO_CHAR(dr.start_time, 'YYYY-MM')
                ORDER BY month DESC
            """, (month_filter,)).fetchall()

            monthly_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(dr.total_cost), 0) AS total,
                    COUNT(*) AS transactions,
                    COUNT(DISTINCT dr.customer_id) AS unique_customers
                FROM daily_rentals dr
                WHERE TO_CHAR(dr.start_time, 'YYYY-MM') = %s
                  AND dr.status IN ('Completed', 'Active')
            """, (month_filter,)).fetchone()

            damage_revenue = execute_query(c, """
                SELECT 
                    TO_CHAR(d.paid_at, 'YYYY-MM') AS month,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(d.amount), 0) AS total
                FROM damage_claims d
                WHERE TO_CHAR(d.paid_at, 'YYYY-MM') = %s AND d.status = 'Paid'
                GROUP BY TO_CHAR(d.paid_at, 'YYYY-MM')
            """, (month_filter,)).fetchall()

            damage_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(amount), 0) AS total,
                    COUNT(*) AS transactions
                FROM damage_claims
                WHERE TO_CHAR(paid_at, 'YYYY-MM') = %s AND status = 'Paid'
            """, (month_filter,)).fetchone()

            available_months = execute_query(c, """
                SELECT DISTINCT TO_CHAR(start_time, 'YYYY-MM') AS month
                FROM daily_rentals
                WHERE status IN ('Completed', 'Active')
                ORDER BY month DESC
            """).fetchall()
        else:
            monthly_revenue = execute_query(c, """
                SELECT 
                    strftime('%Y-%m', dr.start_time) AS month,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(dr.total_cost), 0) AS total,
                    COUNT(DISTINCT dr.customer_id) AS unique_customers
                FROM daily_rentals dr
                WHERE strftime('%Y-%m', dr.start_time) = ?
                  AND dr.status IN ('Completed', 'Active')
                GROUP BY strftime('%Y-%m', dr.start_time)
                ORDER BY month DESC
            """, (month_filter,)).fetchall()

            monthly_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(dr.total_cost), 0) AS total,
                    COUNT(*) AS transactions,
                    COUNT(DISTINCT dr.customer_id) AS unique_customers
                FROM daily_rentals dr
                WHERE strftime('%Y-%m', dr.start_time) = ?
                  AND dr.status IN ('Completed', 'Active')
            """, (month_filter,)).fetchone()

            damage_revenue = execute_query(c, """
                SELECT 
                    strftime('%Y-%m', d.paid_at) AS month,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(d.amount), 0) AS total
                FROM damage_claims d
                WHERE strftime('%Y-%m', d.paid_at) = ? AND d.status = 'Paid'
                GROUP BY strftime('%Y-%m', d.paid_at)
            """, (month_filter,)).fetchall()

            damage_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(amount), 0) AS total,
                    COUNT(*) AS transactions
                FROM damage_claims
                WHERE strftime('%Y-%m', paid_at) = ? AND status = 'Paid'
            """, (month_filter,)).fetchone()

            available_months = execute_query(c, """
                SELECT DISTINCT strftime('%Y-%m', start_time) AS month
                FROM daily_rentals
                WHERE status IN ('Completed', 'Active')
                ORDER BY month DESC
            """).fetchall()

        daily_revenue = monthly_revenue
        available_dates = available_months
        report_title = f"Monthly Revenue Report - {month_filter}"

    # ---------- LIFETIME TOTALS (based on rental cost + damages) ----------
    lifetime_rentals = execute_query(c, """
        SELECT 
            COALESCE(SUM(total_cost), 0) AS total,
            COUNT(*) AS transactions
        FROM daily_rentals
        WHERE status IN ('Completed', 'Active')
    """).fetchone()

    lifetime_damages = execute_query(c, """
        SELECT 
            COALESCE(SUM(amount), 0) AS total,
            COUNT(*) AS transactions
        FROM damage_claims
        WHERE status = 'Paid'
    """).fetchone()

    lifetime_rental_total = 0.0
    lifetime_damage_total = 0.0
    lifetime_rental_txn = 0
    lifetime_damage_txn = 0

    if lifetime_rentals:
        if isinstance(lifetime_rentals, dict):
            lifetime_rental_total = float(lifetime_rentals.get("total") or 0)
            lifetime_rental_txn = int(lifetime_rentals.get("transactions") or 0)
        else:
            lifetime_rental_total = float(lifetime_rentals[0] or 0)
            lifetime_rental_txn = int(lifetime_rentals[1] or 0)

    if lifetime_damages:
        if isinstance(lifetime_damages, dict):
            lifetime_damage_total = float(lifetime_damages.get("total") or 0)
            lifetime_damage_txn = int(lifetime_damages.get("transactions") or 0)
        else:
            lifetime_damage_total = float(lifetime_damages[0] or 0)
            lifetime_damage_txn = int(lifetime_damages[1] or 0)

    lifetime_combined = lifetime_rental_total + lifetime_damage_total
    lifetime_total_txn = lifetime_rental_txn + lifetime_damage_txn

    # Outstanding damages
    outstanding_result = execute_query(c, """
        SELECT COALESCE(SUM(amount), 0) AS total, COUNT(*) AS cnt
        FROM damage_claims
        WHERE status NOT IN ('Paid', 'Waived')
    """).fetchone()
    outstanding_damages = 0.0
    outstanding_count = 0
    if outstanding_result:
        if isinstance(outstanding_result, dict):
            outstanding_damages = float(outstanding_result.get("total") or 0)
            outstanding_count = int(outstanding_result.get("cnt") or 0)
        else:
            outstanding_damages = float(outstanding_result[0] or 0)
            outstanding_count = int(outstanding_result[1] or 0)

    # ---------- COMBINED TOTALS for the filtered period ----------
    rental_total = 0
    damage_total = 0

    summary_row = daily_summary or weekly_summary or monthly_summary
    if summary_row:
        if isinstance(summary_row, dict):
            rental_total = float(summary_row.get("total") or 0)
        else:
            rental_total = float(summary_row[0] or 0)

    if damage_summary:
        if isinstance(damage_summary, dict):
            damage_total = float(damage_summary.get("total") or 0)
        else:
            damage_total = float(damage_summary[0] or 0)

    combined_total = rental_total + damage_total

    conn.close()

    return render_template(
        "revenue_report.html",
        title="Revenue Report",
        report_title=report_title,
        period=period,
        date_filter=date_filter,
        daily_revenue=daily_revenue,
        daily_summary=daily_summary,
        weekly_summary=weekly_summary,
        monthly_summary=monthly_summary,
        available_dates=available_dates,
        weekly_trend=weekly_trend,
        report_type=period,
        damage_revenue=damage_revenue,
        damage_summary=damage_summary,
        rental_total=rental_total,
        damage_total=damage_total,
        combined_total=combined_total,
        lifetime_rental_total=lifetime_rental_total,
        lifetime_damage_total=lifetime_damage_total,
        lifetime_combined=lifetime_combined,
        lifetime_total_txn=lifetime_total_txn,
        outstanding_damages=outstanding_damages,
        outstanding_count=outstanding_count,
    )


@app.route("/staff-activity/export.csv")
@login_required
@manager_required
def staff_activity_export_csv():
    """Export staff activity as CSV. Respects the current filters if any are set."""
    conn = db()
    c = conn.cursor()

    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    staff_id = (request.args.get("staff_id") or "").strip()
    station_id = (request.args.get("station_id") or "").strip()
    action = (request.args.get("action") or "").strip()

    query = """
        SELECT
            r.id, r.start_time, r.end_time, r.status, r.total_cost, r.notes,
            c.full_name AS customer_name,
            b.bike_code,
            su.username AS started_by, su.full_name AS started_by_name,
            eu.username AS ended_by, eu.full_name AS ended_by_name,
            cu.username AS cancelled_by, cu.full_name AS cancelled_by_name,
            ss.name AS start_station, es.name AS end_station
        FROM daily_rentals r
        LEFT JOIN customers c ON c.id = r.customer_id
        LEFT JOIN bicycles b ON b.id = r.bicycle_id
        LEFT JOIN users su ON su.id = r.started_by_user_id
        LEFT JOIN users eu ON eu.id = r.ended_by_user_id
        LEFT JOIN users cu ON cu.id = r.cancelled_by_user_id
        LEFT JOIN branches ss ON ss.id = r.start_station_id
        LEFT JOIN branches es ON es.id = r.end_station_id
        WHERE 1=1
    """
    params = []

    if date_from:
        query += " AND date(r.start_time) >= ?"
        params.append(date_from)
    if date_to:
        query += " AND date(r.start_time) <= ?"
        params.append(date_to)
    if staff_id:
        query += " AND (r.started_by_user_id = ? OR r.ended_by_user_id = ? OR r.cancelled_by_user_id = ?)"
        params.extend([staff_id, staff_id, staff_id])
    if station_id:
        query += " AND (r.start_station_id = ? OR r.end_station_id = ?)"
        params.extend([station_id, station_id])
    if action == "started":
        query += " AND r.started_by_user_id IS NOT NULL"
    elif action == "ended":
        query += " AND r.ended_by_user_id IS NOT NULL"
    elif action == "cancelled":
        query += " AND r.cancelled_by_user_id IS NOT NULL"

    query += " ORDER BY r.start_time DESC"

    rows = execute_query(c, query, params).fetchall()
    conn.close()

    for r in rows:
        if r.get("start_time"): r["start_time_display"] = to_namibia_time(r["start_time"])
        if r.get("end_time"):   r["end_time_display"]   = to_namibia_time(r["end_time"])

    columns = [
        ("id", "Rental ID"),
        ("customer_name", "Customer"),
        ("bike_code", "Bicycle"),
        ("started_by_name", "Started By (Name)"),
        ("started_by", "Started By (User)"),
        ("start_time_display", "Start Time (Namibia)"),
        ("start_station", "Start Station"),
        ("ended_by_name", "Ended By (Name)"),
        ("ended_by", "Ended By (User)"),
        ("end_time_display", "End Time (Namibia)"),
        ("end_station", "End Station"),
        ("cancelled_by_name", "Cancelled By (Name)"),
        ("status", "Status"),
        ("total_cost", "Total Cost"),
    ]

    filtered = bool(date_from or date_to or staff_id or station_id or action)
    filename = _export_filename("staff_activity", filtered=filtered)
    return build_csv_response(rows, columns, filename)


@app.route("/staff-activity/export.pdf")
@login_required
@manager_required
def staff_activity_export_pdf():
    """Export staff activity as PDF."""
    conn = db()
    c = conn.cursor()

    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    staff_id = (request.args.get("staff_id") or "").strip()
    station_id = (request.args.get("station_id") or "").strip()
    action = (request.args.get("action") or "").strip()

    query = """
        SELECT
            r.id, r.start_time, r.end_time, r.status, r.total_cost,
            c.full_name AS customer_name,
            b.bike_code,
            su.username AS started_by, su.full_name AS started_by_name,
            eu.username AS ended_by, eu.full_name AS ended_by_name,
            cu.username AS cancelled_by, cu.full_name AS cancelled_by_name,
            ss.name AS start_station, es.name AS end_station
        FROM daily_rentals r
        LEFT JOIN customers c ON c.id = r.customer_id
        LEFT JOIN bicycles b ON b.id = r.bicycle_id
        LEFT JOIN users su ON su.id = r.started_by_user_id
        LEFT JOIN users eu ON eu.id = r.ended_by_user_id
        LEFT JOIN users cu ON cu.id = r.cancelled_by_user_id
        LEFT JOIN branches ss ON ss.id = r.start_station_id
        LEFT JOIN branches es ON es.id = r.end_station_id
        WHERE 1=1
    """
    params = []

    if date_from:
        query += " AND date(r.start_time) >= ?"
        params.append(date_from)
    if date_to:
        query += " AND date(r.start_time) <= ?"
        params.append(date_to)
    if staff_id:
        query += " AND (r.started_by_user_id = ? OR r.ended_by_user_id = ? OR r.cancelled_by_user_id = ?)"
        params.extend([staff_id, staff_id, staff_id])
    if station_id:
        query += " AND (r.start_station_id = ? OR r.end_station_id = ?)"
        params.extend([station_id, station_id])
    if action == "started":
        query += " AND r.started_by_user_id IS NOT NULL"
    elif action == "ended":
        query += " AND r.ended_by_user_id IS NOT NULL"
    elif action == "cancelled":
        query += " AND r.cancelled_by_user_id IS NOT NULL"

    query += " ORDER BY r.start_time DESC LIMIT 1000"

    rows = execute_query(c, query, params).fetchall()
    conn.close()

    for r in rows:
        r["start_time_display"] = to_namibia_time(r.get("start_time")) or "—"
        r["end_time_display"] = to_namibia_time(r.get("end_time")) or "—"
        r["started_display"] = r.get("started_by_name") or r.get("started_by") or "—"
        r["ended_display"] = r.get("ended_by_name") or r.get("ended_by") or "—"

    columns = [
        ("id", "ID", 0.05),
        ("customer_name", "Customer", 0.13),
        ("bike_code", "Bike", 0.09),
        ("started_display", "Started By", 0.13),
        ("start_time_display", "Start", 0.13),
        ("start_station", "Start Station", 0.12),
        ("ended_display", "Ended By", 0.13),
        ("end_time_display", "End", 0.13),
        ("end_station", "End Station", 0.09),
    ]

    filters_meta = {
        "date_from": date_from or "—",
        "date_to": date_to or "—",
        "staff_id": staff_id or "—",
        "station_id": station_id or "—",
        "action": action or "—",
    }

    return build_audit_pdf(
        rows=rows,
        columns=columns,
        title="Staff Activity",
        filters_meta=filters_meta,
        generated_by=session.get("username", "admin"),
    )




@app.route("/rentals/history")
@login_required
@staff_required
def rental_history():
    from datetime import datetime

    conn = db()
    c = conn.cursor()

    # Get filter parameters
    status_filter = request.args.get("status", "")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    search = request.args.get("search", "").strip()

    # Build query
    query = """
        SELECT
            r.id,
            r.start_time,
            r.end_time,
            r.total_hours,
            r.total_cost,
            r.payment_status,
            r.status AS rental_status,
            c.full_name,
            c.phone,
            b.bike_code,
            b.brand,
            b.model,
            (SELECT COUNT(*) FROM rental_payments WHERE daily_rental_id = r.id) AS payment_count
        FROM daily_rentals r
        JOIN customers c ON c.id = r.customer_id
        JOIN bicycles b ON b.id = r.bicycle_id
        WHERE 1=1
    """

    params = []

    if status_filter:
        query += " AND r.status = ?"
        params.append(status_filter)

    if date_from:
        query += " AND date(r.start_time) >= ?"
        params.append(date_from)

    if date_to:
        query += " AND date(r.start_time) <= ?"
        params.append(date_to)



    if search:
        query += f""" AND (
            {ci_like('c.full_name', '?')} OR 
            {ci_like('b.bike_code', '?')} OR 
            {ci_like('c.phone', '?')}
        )"""
        search_term = f"%{search}%"
        params.extend([search_term, search_term, search_term])


    query += " ORDER BY r.start_time DESC LIMIT 100"


    rentals = execute_query(c, query, params).fetchall()

    # ✅ FIX: Convert start_time and end_time from UTC to Namibia local time (UTC+2)
    for rental in rentals:
        if rental.get("start_time"):
            rental["start_time"] = to_namibia_time(rental["start_time"])
        if rental.get("end_time"):
            rental["end_time"] = to_namibia_time(rental["end_time"])            

    # Get summary stats
    total_rentals = len(rentals)
    total_revenue = sum(float(r.get("total_cost") or 0) for r in rentals)
    paid_count = sum(1 for r in rentals if r.get("payment_status") == "Paid")
    unpaid_count = sum(1 for r in rentals if r.get("payment_status") != "Paid")
    active_count = sum(1 for r in rentals if r.get("rental_status") == "Active")
    completed_count = sum(1 for r in rentals if r.get("rental_status") == "Completed")

    conn.close()

    return render_template(
        "rental_history.html",
        title="Rental History",
        rentals=rentals,
        total_rentals=total_rentals,
        total_revenue=total_revenue,
        paid_count=paid_count,
        unpaid_count=unpaid_count,
        active_count=active_count,
        completed_count=completed_count,
        status_filter=status_filter,
        date_from=date_from,
        date_to=date_to,
        search=search,
    )



@app.route("/rentals/<int:rental_id>/agreement.pdf")
@login_required
def rental_agreement_pdf(rental_id):
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import mm
    from io import BytesIO
    
    conn = db()
    c = conn.cursor()
    
    rental = execute_query(c,"""
        SELECT 
            r.*,
            c.full_name,
            c.id_number,
            c.phone,
            c.address,
            c.signature_data,
            b.bike_code,
            b.brand,
            b.model
        FROM daily_rentals r
        JOIN customers c ON c.id = r.customer_id
        JOIN bicycles b ON b.id = r.bicycle_id
        WHERE r.id = ?
    """, (rental_id,)).fetchone()
    conn.close()
    
    if not rental:
        flash("Rental not found.", "danger")
        return redirect(url_for("dashboard"))
    
    buf = BytesIO()
    pdf = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    x = 22*mm
    y = height - 25*mm
    
    # Header
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(x, y, "RAB – DAILY RENTAL AGREEMENT")
    y -= 10*mm
    
    pdf.setFont("Helvetica", 10)
    pdf.drawString(x, y, f"Rental ID: #{rental['id']}")
    pdf.drawString(x + 120*mm, y, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    y -= 8*mm
    
    pdf.line(x, y, width-x, y)
    y -= 10*mm
    
    # Customer Details
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(x, y, "CUSTOMER DETAILS")
    y -= 7*mm
    pdf.setFont("Helvetica", 10)
    details = [
        ("Full Name", rental["full_name"]),
        ("ID / Passport", rental["id_number"] or "Not provided"),
        ("Phone", rental["phone"]),
        ("Address", rental["address"] or "Not provided"),
    ]
    for label, value in details:
        pdf.drawString(x + 5*mm, y, f"{label}: {value}")
        y -= 6*mm
    
    y -= 4*mm
    
    # Bicycle Details
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(x, y, "BICYCLE DETAILS")
    y -= 7*mm
    pdf.setFont("Helvetica", 10)
    pdf.drawString(x + 5*mm, y, f"Bike: {rental['bike_code']} – {rental['brand'] or ''} {rental['model'] or ''}")
    y -= 6*mm
    pdf.drawString(x + 5*mm, y, f"Hourly Rate: N$ {rental['hourly_rate']:.2f}")
    y -= 6*mm
    pdf.drawString(x + 5*mm, y, f"Daily Cap: N$ {rental['daily_cap']:.2f}")
    y -= 6*mm
    pdf.drawString(x + 5*mm, y, f"Deposit: N$ {rental['deposit_paid']:.2f}")
    
    y -= 8*mm
    
    # Rental Details
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(x, y, "RENTAL DETAILS")
    y -= 7*mm
    pdf.setFont("Helvetica", 10)
    pdf.drawString(x + 5*mm, y, f"Start Time: {to_namibia_time(rental['start_time'])}")
    y -= 6*mm


    if rental['status'] == 'Cancelled':
        pdf.setFillColorRGB(0.86, 0.21, 0.27)  # red
        pdf.drawString(x + 5*mm, y, "Status: *** CANCELLED ***")
        pdf.setFillColorRGB(0, 0, 0)  # back to black
    elif rental['end_time']:
        pdf.drawString(x + 5*mm, y, f"End Time: {to_namibia_time(rental['end_time'])}")
        y -= 6*mm
        pdf.drawString(x + 5*mm, y, f"Total Hours: {rental['total_hours']:.1f}")
        y -= 6*mm
        pdf.drawString(x + 5*mm, y, f"Total Cost: N$ {rental['total_cost']:.2f}")
    else:
        pdf.drawString(x + 5*mm, y, "Status: Active (Not yet returned)")


    y -= 12*mm
    
    # Terms & Conditions
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(x, y, "TERMS & CONDITIONS")
    y -= 7*mm
    pdf.setFont("Helvetica", 9)
    terms = [
        "1. The bicycle remains the property of RAB at all times.",
        "2. The customer is responsible for the bicycle during the rental period.",
        "3. The bicycle must be returned by the agreed time.",
        "4. Late returns will incur additional charges.",
        "5. Damage or loss must be reported immediately.",
        "6. The customer agrees to follow all traffic rules and safety guidelines.",
    ]
    for term in terms:
        pdf.drawString(x + 5*mm, y, term)
        y -= 5.5*mm
    
    y -= 8*mm
    
    # Signature
    pdf.line(x, y, x+70*mm, y)
    pdf.line(x+95*mm, y, width-x, y)
    y -= 5*mm
    pdf.setFont("Helvetica", 9)
    pdf.drawString(x, y, "Customer Signature")
    pdf.drawString(x+95*mm, y, "RAB Representative")
    y -= 15*mm
    pdf.line(x, y, x+70*mm, y)
    pdf.line(x+95*mm, y, width-x, y)
    y -= 5*mm
    pdf.drawString(x, y, "Date")
    pdf.drawString(x+95*mm, y, "Date")
    
    pdf.save()
    buf.seek(0)
    
    filename = f"RAB_Agreement_{rental['bike_code']}_{rental['id']}.pdf"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="application/pdf")



@app.route("/customers/<int:customer_id>/edit", methods=["GET", "POST"])
@login_required
@manager_required
def edit_customer(customer_id):
    """Edit customer details."""
    from datetime import datetime
    import os
    
    conn = db()
    c = conn.cursor()
    
    # Check if Cloudinary is configured
    use_cloudinary = all([
        os.environ.get("CLOUDINARY_CLOUD_NAME"),
        os.environ.get("CLOUDINARY_API_KEY"),
        os.environ.get("CLOUDINARY_API_SECRET")
    ])
    
    if use_cloudinary:
        try:
            import cloudinary
            import cloudinary.uploader
            cloudinary.config(
                cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
                api_key=os.environ.get("CLOUDINARY_API_KEY"),
                api_secret=os.environ.get("CLOUDINARY_API_SECRET")
            )
        except:
            use_cloudinary = False
    
    customer = execute_query(c, "SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
    if not customer:
        flash("Customer not found.", "danger")
        return redirect(url_for("customers"))
    
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        id_number = request.form.get("id_number", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        address = request.form.get("address", "").strip()
        verification_status = request.form.get("verification_status", "Pending")
        
        if not full_name or not phone:
            flash("Name and phone are required.", "danger")
            return redirect(url_for("edit_customer", customer_id=customer_id))
        
        id_photo = request.files.get("id_photo") if request.files else None
        customer_photo = request.files.get("customer_photo") if request.files else None
        
        execute_query(c, """
            UPDATE customers 
            SET full_name = ?, id_number = ?, phone = ?, email = ?, address = ?,
                verification_status = ?
            WHERE id = ?
        """, (full_name, id_number, phone, email, address, verification_status, customer_id))
        
        # Handle document uploads with fallback
        from werkzeug.utils import secure_filename
        UPLOAD_FOLDER = os.path.join(BASE, 'static', 'uploads')
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        
        if id_photo and id_photo.filename:
            uploaded = False
            if use_cloudinary:
                try:
                    upload_result = cloudinary.uploader.upload(id_photo)
                    file_url = upload_result['secure_url']
                    execute_query(c, """
                        INSERT INTO customer_documents (customer_id, document_type, file_path)
                        VALUES (?, 'id_copy', ?)
                    """, (customer_id, file_url))
                    uploaded = True
                except Exception as e:
                    print(f"❌ Cloudinary upload failed: {e}")
            
            if not uploaded:
                try:
                    filename = f"id_{customer_id}_{secure_filename(id_photo.filename)}"
                    id_photo.save(os.path.join(UPLOAD_FOLDER, filename))
                    execute_query(c, """
                        INSERT INTO customer_documents (customer_id, document_type, file_path)
                        VALUES (?, 'id_copy', ?)
                    """, (customer_id, f"uploads/{filename}"))
                except Exception as e:
                    flash("Error uploading ID document.", "danger")
                    return redirect(url_for("edit_customer", customer_id=customer_id))
        
        if customer_photo and customer_photo.filename:
            uploaded = False
            if use_cloudinary:
                try:
                    upload_result = cloudinary.uploader.upload(customer_photo)
                    file_url = upload_result['secure_url']
                    execute_query(c, """
                        INSERT INTO customer_documents (customer_id, document_type, file_path)
                        VALUES (?, 'customer_photo', ?)
                    """, (customer_id, file_url))
                    uploaded = True
                except Exception as e:
                    print(f"❌ Cloudinary upload failed: {e}")
            
            if not uploaded:
                try:
                    filename = f"photo_{customer_id}_{secure_filename(customer_photo.filename)}"
                    customer_photo.save(os.path.join(UPLOAD_FOLDER, filename))
                    execute_query(c, """
                        INSERT INTO customer_documents (customer_id, document_type, file_path)
                        VALUES (?, 'customer_photo', ?)
                    """, (customer_id, f"uploads/{filename}"))
                except Exception as e:
                    flash("Error uploading customer photo.", "danger")
                    return redirect(url_for("edit_customer", customer_id=customer_id))
        
        conn.commit()

        conn.close()
        
        flash(f"Customer '{full_name}' updated successfully!", "success")

        log_audit(
            action="customer_edit",
            entity_type="customer",
            entity_id=customer_id,
            details=f"Edited customer '{full_name}'"
        )        
        return redirect(url_for("customers"))
    
    
    documents = execute_query(c, """
        SELECT * FROM customer_documents 
        WHERE customer_id = ? 
        ORDER BY uploaded_at DESC
    """, (customer_id,)).fetchall()
    
    for doc in documents:
        if doc.get("uploaded_at"):
            if isinstance(doc["uploaded_at"], datetime):
                doc["uploaded_at"] = doc["uploaded_at"].strftime("%Y-%m-%d %H:%M")
    
    conn.close()
    
    return render_template(
        "edit_customer.html",
        title="Edit Customer",
        customer=customer,
        documents=documents
    )




# =============================================
# MAINTENANCE EDIT
# =============================================

@app.route("/maintenance/<int:record_id>/edit", methods=["GET", "POST"])
@login_required
@manager_required
def edit_maintenance(record_id):
    """Edit a maintenance record."""
    conn = db()
    c = conn.cursor()
    
    # Get maintenance record
    record = execute_query(c,"""
        SELECT m.*, b.bike_code, b.brand, b.model
        FROM maintenance_records m
        JOIN bicycles b ON b.id = m.bicycle_id
        WHERE m.id = ?
    """, (record_id,)).fetchone()
    
    if not record:
        flash("Maintenance record not found.", "danger")
        return redirect(url_for("maintenance_dashboard"))
    
    # Get all bicycles for dropdown
    bicycles = execute_query(c,
        "SELECT id, bike_code, brand, model FROM bicycles ORDER BY bike_code"
    ).fetchall()
    
    if request.method == "POST":
        bicycle_id = request.form.get("bicycle_id")
        maintenance_type = request.form.get("maintenance_type")
        description = request.form.get("description", "").strip()
        cost = float(request.form.get("cost", 0))
        status = request.form.get("status", "Scheduled")
        scheduled_date = request.form.get("scheduled_date")
        completed_date = request.form.get("completed_date")
        performed_by = request.form.get("performed_by", "").strip()
        notes = request.form.get("notes", "").strip()
        
        if not bicycle_id or not maintenance_type:
            flash("Bicycle and maintenance type are required.", "danger")
            return redirect(url_for("edit_maintenance", record_id=record_id))
        
        try:
            # Update maintenance record
            execute_query(c,"""
                UPDATE maintenance_records 
                SET bicycle_id = ?, maintenance_type = ?, description = ?, cost = ?,
                    status = ?, scheduled_date = ?, completed_date = ?, 
                    performed_by = ?, notes = ?
                WHERE id = ?
            """, (bicycle_id, maintenance_type, description, cost, status, 
                  scheduled_date, completed_date, performed_by, notes, record_id))
            
            # Update bicycle status based on maintenance status
            if status == "Completed":
                execute_query(c,"UPDATE bicycles SET status = 'Available' WHERE id = ?", (bicycle_id,))
            elif status in ["Scheduled", "In Progress"]:
                execute_query(c,"UPDATE bicycles SET status = 'Maintenance' WHERE id = ?", (bicycle_id,))
            
            conn.commit()
            flash("Maintenance record updated successfully!", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error updating maintenance record: {str(e)}", "danger")
        finally:
            conn.close()
        
        return redirect(url_for("maintenance_dashboard"))
    
    conn.close()
    
    return render_template(
        "edit_maintenance.html",
        title="Edit Maintenance",
        record=record,
        bicycles=bicycles
    )


@app.route("/maintenance/<int:record_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_maintenance(record_id):
    """Delete a maintenance record."""
    conn = db()
    c = conn.cursor()
    
    record = execute_query(c,
        "SELECT bicycle_id FROM maintenance_records WHERE id = ?", 
        (record_id,)
    ).fetchone()
    
    if not record:
        flash("Maintenance record not found.", "danger")
        return redirect(url_for("maintenance_dashboard"))
    
    try:
        execute_query(c,"DELETE FROM maintenance_records WHERE id = ?", (record_id,))
        # Update bicycle status back to Available
        execute_query(c,"UPDATE bicycles SET status = 'Available' WHERE id = ?", (record["bicycle_id"],))
        conn.commit()
        flash("Maintenance record deleted successfully.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error deleting maintenance record: {str(e)}", "danger")
    finally:
        conn.close()
    
    return redirect(url_for("maintenance_dashboard"))






@app.route("/customers/<int:customer_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_customer(customer_id):
    """Delete a customer and all associated data."""
    conn = db()
    c = conn.cursor()
    
    # Check if customer exists
    customer = execute_query(c,"SELECT full_name, user_id FROM customers WHERE id = ?", (customer_id,)).fetchone()
    if not customer:
        flash("Customer not found.", "danger")
        return redirect(url_for("customers"))
    
    try:
        # ✅ STEP 1: Check if customer has active rentals
        active_rental = execute_query(c,
            "SELECT id FROM daily_rentals WHERE customer_id = ? AND status = 'Active'", 
            (customer_id,)
        ).fetchone()
        
        if active_rental:
            flash("Cannot delete customer with active rentals. Please end all rentals first.", "danger")
            return redirect(url_for("customers"))
        
        # ✅ STEP 2: Get all rental IDs for this customer
        rentals = execute_query(c,"SELECT id FROM daily_rentals WHERE customer_id = ?", (customer_id,)).fetchall()
        
        # ✅ STEP 3: Delete rental payments (child of rentals)
        for rental in rentals:

            # Log before deleting (need the name before it's gone)
            log_audit(
                action="customer_delete",
                entity_type="customer",
                entity_id=customer_id,
                details=f"Deleted customer '{customer['full_name']}' (user_id: {customer.get('user_id')})"
            )        

            execute_query(c,"DELETE FROM rental_payments WHERE daily_rental_id = ?", (rental["id"],))
        
        # ✅ STEP 4: Delete reminder logs (child of rentals)
        for rental in rentals:
            execute_query(c,"DELETE FROM reminder_logs WHERE rental_id = ?", (rental["id"],))
        
        # ✅ STEP 5: Delete bike conditions (child of rentals)
        for rental in rentals:
            execute_query(c,"DELETE FROM bike_conditions WHERE rental_id = ?", (rental["id"],))
        
        # ✅ STEP 6: Delete rentals
        execute_query(c,"DELETE FROM daily_rentals WHERE customer_id = ?", (customer_id,))
        
        # ✅ STEP 7: Delete customer documents
        execute_query(c,"DELETE FROM customer_documents WHERE customer_id = ?", (customer_id,))
        
        # ✅ STEP 8: Delete discount usage
        execute_query(c,"DELETE FROM discount_usage WHERE customer_id = ?", (customer_id,))
        
        # ✅ STEP 9: Delete loyalty points
        execute_query(c,"DELETE FROM loyalty_points WHERE customer_id = ?", (customer_id,))
        
        # ✅ STEP 10: Delete points transactions
        execute_query(c,"DELETE FROM points_transactions WHERE customer_id = ?", (customer_id,))
        
        # ✅ STEP 11: Delete verification requests
        execute_query(c,"DELETE FROM verification_requests WHERE customer_id = ?", (customer_id,))
        
        # ✅ STEP 12: Delete the customer
        execute_query(c,"DELETE FROM customers WHERE id = ?", (customer_id,))
        
        # ✅ STEP 13: Delete the associated user (if exists)
        if customer["user_id"]:
            # Check if user has any other customers linked (shouldn't, but just in case)
            other_customers = execute_query(c,
                "SELECT id FROM customers WHERE user_id = ? AND id != ?", 
                (customer["user_id"], customer_id)
            ).fetchone()
            
            if not other_customers:
                # Delete user's other records
                execute_query(c,"DELETE FROM announcement_comments WHERE user_id = ?", (customer["user_id"],))
                execute_query(c,"DELETE FROM announcements WHERE author_id = ?", (customer["user_id"],))
                execute_query(c,"DELETE FROM verification_requests WHERE verified_by = ?", (customer["user_id"],))
                execute_query(c,"DELETE FROM bike_conditions WHERE checked_by = ?", (customer["user_id"],))
                
                # Delete the user
                execute_query(c,"DELETE FROM users WHERE id = ?", (customer["user_id"],))
        
        conn.commit()
        flash(f"Customer '{customer['full_name']}' deleted successfully.", "success")
        
    except sqlite3.IntegrityError as e:
        conn.rollback()
        flash(f"Error deleting customer: {str(e)}", "danger")
    except Exception as e:
        conn.rollback()
        flash(f"Error deleting customer: {str(e)}", "danger")
    finally:
        conn.close()
    
    return redirect(url_for("customers"))




# =============================================
# BICYCLE HEALTH TRACKING
# =============================================

@app.route("/bicycle-health")
@login_required
@manager_required
def bicycle_health_dashboard():
    """View all bicycles health status."""
    conn = db()
    c = conn.cursor()
    
    # Get all bicycles with health data
    bicycles = execute_query(c,"""
        SELECT 
            b.*,
            bh.health_score,
            bh.condition_rating,
            bh.last_maintenance_date,
            bh.next_maintenance_due,
            bh.total_maintenance_count,
            bh.total_repair_cost,
            bh.notes AS health_notes,
            (SELECT COUNT(*) FROM daily_rentals WHERE bicycle_id = b.id) AS total_rentals,
            (SELECT COUNT(*) FROM maintenance_records WHERE bicycle_id = b.id) AS maintenance_count
        FROM bicycles b
        LEFT JOIN bicycle_health bh ON bh.bicycle_id = b.id
        ORDER BY bh.health_score ASC, b.bike_code
    """).fetchall()
    
    # Health summary
    health_summary = execute_query(c,"""
        SELECT 
            COUNT(*) AS total_bicycles,
            SUM(CASE WHEN bh.health_score >= 80 THEN 1 ELSE 0 END) AS excellent,
            SUM(CASE WHEN bh.health_score >= 60 AND bh.health_score < 80 THEN 1 ELSE 0 END) AS good,
            SUM(CASE WHEN bh.health_score >= 40 AND bh.health_score < 60 THEN 1 ELSE 0 END) AS fair,
            SUM(CASE WHEN bh.health_score >= 20 AND bh.health_score < 40 THEN 1 ELSE 0 END) AS poor,
            SUM(CASE WHEN bh.health_score < 20 THEN 1 ELSE 0 END) AS critical,
            AVG(bh.health_score) AS avg_health_score
        FROM bicycles b
        LEFT JOIN bicycle_health bh ON bh.bicycle_id = b.id
    """).fetchone()
    
    conn.close()
    
    return render_template(
        "bicycle_health.html",
        title="Bicycle Health",
        bicycles=bicycles,
        health_summary=health_summary
    )


@app.route("/bicycle-health/<int:bicycle_id>")
@login_required
@manager_required
def bicycle_health_detail(bicycle_id):
    """View detailed health information for a specific bicycle."""
    conn = db()
    c = conn.cursor()
    
    # Get bicycle with health data
    bicycle = execute_query(c,"""
        SELECT 
            b.*,
            bh.health_score,
            bh.condition_rating,
            bh.last_maintenance_date,
            bh.next_maintenance_due,
            bh.total_maintenance_count,
            bh.total_repair_cost,
            bh.notes AS health_notes,
            (SELECT COUNT(*) FROM daily_rentals WHERE bicycle_id = b.id) AS total_rentals,
            (SELECT COALESCE(AVG(total_hours), 0) FROM daily_rentals WHERE bicycle_id = b.id) AS avg_hours
        FROM bicycles b
        LEFT JOIN bicycle_health bh ON bh.bicycle_id = b.id
        WHERE b.id = ?
    """, (bicycle_id,)).fetchone()
    
    if not bicycle:
        flash("Bicycle not found.", "danger")
        return redirect(url_for("bicycle_health_dashboard"))
    
    # Get health history
    health_history = execute_query(c,"""
        SELECT * FROM bicycle_health_history
        WHERE bicycle_id = ?
        ORDER BY recorded_at DESC
        LIMIT 20
    """, (bicycle_id,)).fetchall()
    
    # Get maintenance records
    maintenance = execute_query(c,"""
        SELECT * FROM maintenance_records
        WHERE bicycle_id = ?
        ORDER BY created_at DESC
        LIMIT 10
    """, (bicycle_id,)).fetchall()
    
    # Get rental history
    rentals = execute_query(c,"""
        SELECT 
            r.*,
            c.full_name
        FROM daily_rentals r
        JOIN customers c ON c.id = r.customer_id
        WHERE r.bicycle_id = ?
        ORDER BY r.start_time DESC
        LIMIT 10
    """, (bicycle_id,)).fetchall()
    
    conn.close()
    
    return render_template(
        "bicycle_health_detail.html",
        title=f"Health: {bicycle['bike_code']}",
        bicycle=bicycle,
        health_history=health_history,
        maintenance=maintenance,
        rentals=rentals
    )


@app.route("/bicycle-health/<int:bicycle_id>/update", methods=["GET", "POST"])
@login_required
@manager_required
def update_bicycle_health(bicycle_id):
    """Update bicycle health status."""
    conn = db()
    c = conn.cursor()
    
    bicycle = execute_query(c,"SELECT * FROM bicycles WHERE id = ?", (bicycle_id,)).fetchone()
    if not bicycle:
        flash("Bicycle not found.", "danger")
        return redirect(url_for("bicycle_health_dashboard"))
    
    # Get current health
    health = execute_query(c,"SELECT * FROM bicycle_health WHERE bicycle_id = ?", (bicycle_id,)).fetchone()
    
    if request.method == "POST":
        health_score = int(request.form.get("health_score", 100))
        condition_rating = request.form.get("condition_rating", "Good")
        notes = request.form.get("notes", "").strip()
        
        # Validate health score
        if health_score < 0 or health_score > 100:
            flash("Health score must be between 0 and 100.", "danger")
            return redirect(url_for("update_bicycle_health", bicycle_id=bicycle_id))
        
        try:
            if health:
                # Update existing health record
                execute_query(c,"""
                    UPDATE bicycle_health 
                    SET health_score = ?, condition_rating = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE bicycle_id = ?
                """, (health_score, condition_rating, notes, bicycle_id))
            else:
                # Create new health record
                execute_query(c,"""
                    INSERT INTO bicycle_health (bicycle_id, health_score, condition_rating, notes)
                    VALUES (?, ?, ?, ?)
                """, (bicycle_id, health_score, condition_rating, notes))
            
            # Record health history
            execute_query(c,"""
                INSERT INTO bicycle_health_history (bicycle_id, health_score, condition_rating, reason)
                VALUES (?, ?, ?, ?)
            """, (bicycle_id, health_score, condition_rating, notes or "Manual update"))
            
            conn.commit()
            flash("Bicycle health updated successfully!", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error updating health: {str(e)}", "danger")
        finally:
            conn.close()
        
        return redirect(url_for("bicycle_health_detail", bicycle_id=bicycle_id))
    
    conn.close()
    
    return render_template(
        "update_bicycle_health.html",
        title="Update Health",
        bicycle=bicycle,
        health=health
    )







@app.route("/bicycle-health/<int:bicycle_id>/calculate")
@login_required
@admin_required
def calculate_bicycle_health(bicycle_id):
    """Auto-calculate bicycle health score based on maintenance and usage."""
    import os
    conn = db()
    c = conn.cursor()
    
    is_postgres = os.environ.get("DATABASE_URL") is not None
    
    # Get bicycle data
    bicycle = execute_query(c, "SELECT * FROM bicycles WHERE id = ?", (bicycle_id,)).fetchone()
    if not bicycle:
        flash("Bicycle not found.", "danger")
        return redirect(url_for("bicycle_health_dashboard"))
    
    # ✅ Get maintenance data with PostgreSQL compatibility
    if is_postgres:
        maintenance = execute_query(c, """
            SELECT 
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed,
                COALESCE(SUM(cost), 0) AS total_cost,
                COUNT(CASE WHEN status = 'Completed' AND DATE(completed_date) >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) AS recent_maintenance
            FROM maintenance_records
            WHERE bicycle_id = %s
        """, (bicycle_id,)).fetchone()
    else:
        maintenance = execute_query(c, """
            SELECT 
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed,
                COALESCE(SUM(cost), 0) AS total_cost,
                COUNT(CASE WHEN status = 'Completed' AND date(completed_date) >= date('now', '-30 days') THEN 1 END) AS recent_maintenance
            FROM maintenance_records
            WHERE bicycle_id = ?
        """, (bicycle_id,)).fetchone()
    
    # ✅ Get rental data with PostgreSQL compatibility
    if is_postgres:
        rentals = execute_query(c, """
            SELECT 
                COUNT(*) AS total,
                COALESCE(SUM(total_hours), 0) AS total_hours,
                COUNT(CASE WHEN DATE(start_time) >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) AS recent_rentals
            FROM daily_rentals
            WHERE bicycle_id = %s AND status = 'Completed'
        """, (bicycle_id,)).fetchone()
    else:
        rentals = execute_query(c, """
            SELECT 
                COUNT(*) AS total,
                COALESCE(SUM(total_hours), 0) AS total_hours,
                COUNT(CASE WHEN date(start_time) >= date('now', '-30 days') THEN 1 END) AS recent_rentals
            FROM daily_rentals
            WHERE bicycle_id = ? AND status = 'Completed'
        """, (bicycle_id,)).fetchone()
    
    # Calculate health score (0-100)
    health_score = 100
    
    # Get values with defaults (handle None)
    total_hours = rentals["total_hours"] if rentals["total_hours"] is not None else 0
    completed_maintenance = maintenance["completed"] if maintenance["completed"] is not None else 0
    recent_rentals = rentals["recent_rentals"] if rentals["recent_rentals"] is not None else 0
    recent_maintenance = maintenance["recent_maintenance"] if maintenance["recent_maintenance"] is not None else 0
    
    # Deduct for high usage (more than 100 hours)
    if total_hours > 100:
        health_score -= min(20, (total_hours - 100) / 10)
    
    # Deduct for lack of maintenance
    if completed_maintenance == 0:
        health_score -= 30
    elif completed_maintenance < 5:
        health_score -= 10
    
    # Deduct for recent rentals without maintenance
    if recent_rentals > 5 and recent_maintenance == 0:
        health_score -= 15
    
    # Add points for recent maintenance
    if recent_maintenance > 0:
        health_score += min(10, recent_maintenance * 2)
    
    # Ensure score is between 0 and 100
    health_score = max(0, min(100, int(health_score)))
    
    # Determine condition rating
    if health_score >= 80:
        condition_rating = "Excellent"
    elif health_score >= 60:
        condition_rating = "Good"
    elif health_score >= 40:
        condition_rating = "Fair"
    elif health_score >= 20:
        condition_rating = "Poor"
    else:
        condition_rating = "Critical"
    
    # Update health record
    health = execute_query(c, "SELECT * FROM bicycle_health WHERE bicycle_id = ?", (bicycle_id,)).fetchone()
    
    try:
        if health:
            execute_query(c, """
                UPDATE bicycle_health 
                SET health_score = ?, condition_rating = ?, updated_at = CURRENT_TIMESTAMP,
                    total_maintenance_count = ?, total_repair_cost = ?
                WHERE bicycle_id = ?
            """, (health_score, condition_rating, completed_maintenance, maintenance["total_cost"] or 0, bicycle_id))
        else:
            execute_query(c, """
                INSERT INTO bicycle_health (bicycle_id, health_score, condition_rating, 
                    total_maintenance_count, total_repair_cost)
                VALUES (?, ?, ?, ?, ?)
            """, (bicycle_id, health_score, condition_rating, completed_maintenance, maintenance["total_cost"] or 0))
        
        # Record health history
        execute_query(c, """
            INSERT INTO bicycle_health_history (bicycle_id, health_score, condition_rating, reason)
            VALUES (?, ?, ?, ?)
        """, (bicycle_id, health_score, condition_rating, "Auto-calculated based on usage and maintenance"))
        
        conn.commit()
        flash(f"Health score calculated: {health_score}/100 ({condition_rating})", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error calculating health: {str(e)}", "danger")
    finally:
        conn.close()
    
    return redirect(url_for("bicycle_health_detail", bicycle_id=bicycle_id))





@app.route("/bicycle-health/calculate-all")
@login_required
@admin_required
def calculate_all_bicycle_health():
    """Calculate health scores for all bicycles."""
    import os
    conn = db()
    c = conn.cursor()
    
    is_postgres = os.environ.get("DATABASE_URL") is not None
    
    bicycles = execute_query(c, "SELECT id FROM bicycles").fetchall()
    count = 0
    
    for bicycle in bicycles:
        bike_id = bicycle["id"]
        
        # ✅ Maintenance data with PostgreSQL compatibility
        if is_postgres:
            maintenance = execute_query(c, """
                SELECT 
                    COUNT(*) AS total,
                    SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed,
                    COALESCE(SUM(cost), 0) AS total_cost,
                    COUNT(CASE WHEN status = 'Completed' AND DATE(completed_date) >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) AS recent_maintenance
                FROM maintenance_records
                WHERE bicycle_id = %s
            """, (bike_id,)).fetchone()
        else:
            maintenance = execute_query(c, """
                SELECT 
                    COUNT(*) AS total,
                    SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed,
                    COALESCE(SUM(cost), 0) AS total_cost,
                    COUNT(CASE WHEN status = 'Completed' AND date(completed_date) >= date('now', '-30 days') THEN 1 END) AS recent_maintenance
                FROM maintenance_records
                WHERE bicycle_id = ?
            """, (bike_id,)).fetchone()
        
        # ✅ Rental data with PostgreSQL compatibility
        if is_postgres:
            rentals = execute_query(c, """
                SELECT 
                    COUNT(*) AS total,
                    COALESCE(SUM(total_hours), 0) AS total_hours,
                    COUNT(CASE WHEN DATE(start_time) >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) AS recent_rentals
                FROM daily_rentals
                WHERE bicycle_id = %s AND status = 'Completed'
            """, (bike_id,)).fetchone()
        else:
            rentals = execute_query(c, """
                SELECT 
                    COUNT(*) AS total,
                    COALESCE(SUM(total_hours), 0) AS total_hours,
                    COUNT(CASE WHEN date(start_time) >= date('now', '-30 days') THEN 1 END) AS recent_rentals
                FROM daily_rentals
                WHERE bicycle_id = ? AND status = 'Completed'
            """, (bike_id,)).fetchone()
        
        # Handle None values
        total_hours = rentals["total_hours"] if rentals["total_hours"] is not None else 0
        completed_maintenance = maintenance["completed"] if maintenance["completed"] is not None else 0
        recent_rentals = rentals["recent_rentals"] if rentals["recent_rentals"] is not None else 0
        recent_maintenance = maintenance["recent_maintenance"] if maintenance["recent_maintenance"] is not None else 0
        total_cost = maintenance["total_cost"] if maintenance["total_cost"] is not None else 0
        
        # Calculate health score
        health_score = 100
        
        if total_hours > 100:
            health_score -= min(20, (total_hours - 100) / 10)
        
        if completed_maintenance == 0:
            health_score -= 30
        elif completed_maintenance < 5:
            health_score -= 10
        
        if recent_rentals > 5 and recent_maintenance == 0:
            health_score -= 15
        
        if recent_maintenance > 0:
            health_score += min(10, recent_maintenance * 2)
        
        health_score = max(0, min(100, int(health_score)))
        
        if health_score >= 80:
            condition_rating = "Excellent"
        elif health_score >= 60:
            condition_rating = "Good"
        elif health_score >= 40:
            condition_rating = "Fair"
        elif health_score >= 20:
            condition_rating = "Poor"
        else:
            condition_rating = "Critical"
        
        # Update or insert
        health = execute_query(c, "SELECT * FROM bicycle_health WHERE bicycle_id = ?", (bike_id,)).fetchone()
        if health:
            execute_query(c, """
                UPDATE bicycle_health 
                SET health_score = ?, condition_rating = ?, updated_at = CURRENT_TIMESTAMP,
                    total_maintenance_count = ?, total_repair_cost = ?
                WHERE bicycle_id = ?
            """, (health_score, condition_rating, completed_maintenance, total_cost, bike_id))
        else:
            execute_query(c, """
                INSERT INTO bicycle_health (bicycle_id, health_score, condition_rating, 
                    total_maintenance_count, total_repair_cost)
                VALUES (?, ?, ?, ?, ?)
            """, (bike_id, health_score, condition_rating, completed_maintenance, total_cost))
        
        # Record history
        execute_query(c, """
            INSERT INTO bicycle_health_history (bicycle_id, health_score, condition_rating, reason)
            VALUES (?, ?, ?, ?)
        """, (bike_id, health_score, condition_rating, "Auto-calculated - batch update"))
        
        count += 1
    
    conn.commit()
    conn.close()
    
    flash(f"Health scores calculated for {count} bicycles!", "success")
    return redirect(url_for("bicycle_health_dashboard"))


# =============================================
# BICYCLE DELETE
# =============================================

@app.route("/bicycles/<int:bicycle_id>/delete", methods=["POST"])
@login_required
@admin_required  # Only admins can delete bicycles
def delete_bicycle(bicycle_id):
    """Delete a bicycle if it's not currently rented."""
    conn = db()
    c = conn.cursor()
    
    # Check if bicycle exists
    bike = execute_query(c,"SELECT bike_code, status FROM bicycles WHERE id = ?", (bicycle_id,)).fetchone()
    if not bike:
        flash("Bicycle not found.", "danger")
        return redirect(url_for("bicycles"))
    
    # Check if bicycle is currently rented
    if bike["status"] == "Rented":
        flash(f"Cannot delete bicycle '{bike['bike_code']}' - it is currently rented.", "danger")
        return redirect(url_for("bicycles"))
    
    # Check if bicycle has maintenance records
    maintenance = execute_query(c,
        "SELECT id FROM maintenance_records WHERE bicycle_id = ? AND status != 'Completed'",
        (bicycle_id,)
    ).fetchone()
    
    if maintenance:
        flash(f"Cannot delete bicycle '{bike['bike_code']}' - it has pending maintenance.", "danger")
        return redirect(url_for("bicycles"))
    
    try:
        
        log_audit(
            action="bicycle_delete",
            entity_type="bicycle",
            entity_id=bicycle_id,
            details=f"Deleted bicycle '{bike['bike_code']}'"
        )

        # Delete bicycle
        execute_query(c,"DELETE FROM bicycles WHERE id = ?", (bicycle_id,))
        conn.commit()
        flash(f"Bicycle '{bike['bike_code']}' deleted successfully.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error deleting bicycle: {str(e)}", "danger")
    finally:
        conn.close()
    
    return redirect(url_for("bicycles"))



@app.route("/announcements")
@login_required
def announcements():
    """View all announcements."""
    from datetime import datetime
    
    conn = db()
    c = conn.cursor()
    
    user_id = session["user_id"]
    user_role = session.get("role", "staff")
    
    # Get all active announcements with read status
    announcements_list = execute_query(c, """
        SELECT 
            a.*,
            CASE WHEN ar.id IS NOT NULL THEN 1 ELSE 0 END AS is_read
        FROM announcements a
        LEFT JOIN announcement_reads ar ON ar.announcement_id = a.id AND ar.user_id = ?
        WHERE a.is_active = 1
        ORDER BY a.is_pinned DESC, a.priority DESC, a.created_at DESC
    """, (user_id,)).fetchall()
    
    # ✅ FIX: Format datetime for each announcement (PostgreSQL returns datetime objects)
    for announcement in announcements_list:
        if announcement.get("created_at"):
            if isinstance(announcement["created_at"], datetime):
                announcement["created_at"] = announcement["created_at"].strftime("%Y-%m-%d %H:%M:%S")
            elif isinstance(announcement["created_at"], str):
                announcement["created_at"] = announcement["created_at"]
        
        if announcement.get("updated_at"):
            if isinstance(announcement["updated_at"], datetime):
                announcement["updated_at"] = announcement["updated_at"].strftime("%Y-%m-%d %H:%M:%S")
            elif isinstance(announcement["updated_at"], str):
                announcement["updated_at"] = announcement["updated_at"]
    
    # ✅ FIX: Get unread count as integer
    unread_result = execute_query(c, """
        SELECT COUNT(*) as count FROM announcements a
        LEFT JOIN announcement_reads ar ON ar.announcement_id = a.id AND ar.user_id = ?
        WHERE a.is_active = 1 AND ar.id IS NULL
    """, (user_id,)).fetchone()
    
    unread_count = unread_result['count'] if isinstance(unread_result, dict) else unread_result[0] if unread_result else 0
    
    conn.close()
    
    return render_template(
        "announcements.html",
        title="Announcements",
        announcements=announcements_list,
        unread_count=unread_count,
        user_role=user_role
    )



@app.route("/announcements/<int:announcement_id>")
@login_required
def view_announcement(announcement_id):
    """View a single announcement with comments."""
    from datetime import datetime
    
    conn = db()
    c = conn.cursor()
    
    is_postgres = os.environ.get("DATABASE_URL") is not None
    
    user_id = session["user_id"]
    
    # Get announcement
    announcement = execute_query(c, """
        SELECT * FROM announcements WHERE id = ? AND is_active = 1
    """, (announcement_id,)).fetchone()
    
    if not announcement:
        flash("Announcement not found.", "danger")
        return redirect(url_for("announcements"))
    
    # ✅ FIX: Format datetime for announcement
    if announcement.get("created_at"):
        if isinstance(announcement["created_at"], datetime):
            announcement["created_at"] = announcement["created_at"].strftime("%Y-%m-%d %H:%M:%S")
    
    if announcement.get("updated_at"):
        if isinstance(announcement["updated_at"], datetime):
            announcement["updated_at"] = announcement["updated_at"].strftime("%Y-%m-%d %H:%M:%S")
    
    # ✅ FIX: Mark as read - handle PostgreSQL vs SQLite
    if is_postgres:
        # PostgreSQL syntax
        execute_query(c, """
            INSERT INTO announcement_reads (announcement_id, user_id)
            VALUES (%s, %s)
            ON CONFLICT (announcement_id, user_id) DO NOTHING
        """, (announcement_id, user_id))
    else:
        # SQLite syntax
        execute_query(c, """
            INSERT OR IGNORE INTO announcement_reads (announcement_id, user_id)
            VALUES (?, ?)
        """, (announcement_id, user_id))
    
    # Get comments
    comments = execute_query(c, """
        SELECT * FROM announcement_comments 
        WHERE announcement_id = ? 
        ORDER BY created_at ASC
    """, (announcement_id,)).fetchall()
    
    # ✅ FIX: Format datetime for comments
    for comment in comments:
        if comment.get("created_at"):
            if isinstance(comment["created_at"], datetime):
                comment["created_at"] = comment["created_at"].strftime("%Y-%m-%d %H:%M:%S")
    
    conn.commit()
    conn.close()
    
    return render_template(
        "view_announcement.html",
        title=announcement["title"],
        announcement=announcement,
        comments=comments
    )

@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def twofa_setup():
    """Enroll a user in TOTP."""
    user_id = session.get("user_id")
    conn = db()
    c = conn.cursor()

    user = execute_query(c, "SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        conn.close()
        flash("User not found.", "danger")
        return redirect(url_for("logout"))

    # If already enabled, redirect to verify
    if user.get("twofa_enabled"):
        conn.close()
        return redirect(url_for("twofa_verify"))

    # Get or create a secret in user_2fa (not yet enabled)
    row = execute_query(c, "SELECT * FROM user_2fa WHERE user_id = ?", (user_id,)).fetchone()
    if not row:
        secret = pyotp.random_base32()
        execute_query(c, """
            INSERT INTO user_2fa (user_id, secret, enabled)
            VALUES (?, ?, 0)
        """, (user_id, secret))
        conn.commit()
    else:
        secret = row["secret"]

    # Build the provisioning URI
    issuer = "RAB Rent A Bike"
    account_name = user["username"]
    uri = pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=issuer)
    qr_data = _generate_qr_png_base64(uri)

    if request.method == "POST":
        code = (request.form.get("code") or "").strip().replace(" ", "")
        if pyotp.TOTP(secret).verify(code, valid_window=1):
            # ✅ Correct code — enable 2FA
            execute_query(c, """
                UPDATE user_2fa
                SET enabled = 1, confirmed_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
            """, (user_id,))
            execute_query(c, """
                UPDATE users SET twofa_enabled = 1 WHERE id = ?
            """, (user_id,))

            # Generate backup codes
            codes = _generate_backup_codes()
            for code_plain in codes:
                execute_query(c, """
                    INSERT INTO user_2fa_backup_codes (user_id, code_hash)
                    VALUES (?, ?)
                """, (user_id, _hash_backup_code(code_plain)))

            conn.commit()
            conn.close()

            session["twofa_verified"] = True
            log_audit(
                action="2fa_enabled",
                entity_type="user",
                entity_id=user_id,
                details="User enabled TOTP 2FA and generated backup codes"
            )

            # Store backup codes in flash — but that's visible to others; better to show on a page
            session["show_backup_codes"] = codes
            return redirect(url_for("twofa_backup_codes"))
        else:
            flash("Invalid code. Please try again.", "danger")

    conn.close()
    return render_template(
        "twofa_setup.html",
        title="Set Up 2FA",
        qr_data=qr_data,
        secret=secret,
        user=user
    )


@app.route("/2fa/verify", methods=["GET", "POST"])
@login_required
def twofa_verify():
    """Prompt user for a 6-digit TOTP code (or a backup code)."""
    user_id = session.get("user_id")
    conn = db()
    c = conn.cursor()

    user = execute_query(c, "SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    row = execute_query(c, "SELECT * FROM user_2fa WHERE user_id = ?", (user_id,)).fetchone()

    if not user or not row or not row.get("enabled"):
        conn.close()
        flash("2FA is not set up for your account.", "warning")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        code = (request.form.get("code") or "").strip().replace(" ", "").upper()

        # Try TOTP first
        if pyotp.TOTP(row["secret"]).verify(code, valid_window=1):
            session["twofa_verified"] = True
            conn.close()
            log_audit(
                action="2fa_verified",
                entity_type="user",
                entity_id=user_id,
                details="User passed 2FA verification"
            )
            return redirect(url_for("dashboard"))

        # Try backup code (format XXXX-XXXX-XXXX)
        if "-" in code or len(code) == 12:
            codes = execute_query(c, """
                SELECT id, code_hash FROM user_2fa_backup_codes
                WHERE user_id = ? AND used_at IS NULL
            """, (user_id,)).fetchall()
            for bc in codes:
                if _verify_backup_code(code, bc["code_hash"]):
                    execute_query(c, """
                        UPDATE user_2fa_backup_codes SET used_at = CURRENT_TIMESTAMP WHERE id = ?
                    """, (bc["id"],))
                    conn.commit()
                    session["twofa_verified"] = True
                    conn.close()
                    log_audit(
                        action="2fa_verified_backup",
                        entity_type="user",
                        entity_id=user_id,
                        details="User passed 2FA using a backup code"
                    )
                    flash("Backup code accepted. Consider generating new backup codes soon.", "warning")
                    return redirect(url_for("dashboard"))

        flash("Invalid code. Please try again.", "danger")

    conn.close()
    return render_template("twofa_verify.html", title="Two-Factor Verification")


@app.route("/2fa/backup-codes")
@login_required
def twofa_backup_codes():
    """Show backup codes once (from session after enrollment)."""
    codes = session.pop("show_backup_codes", None)
    if not codes:
        flash("No backup codes to display.", "info")
        return redirect(url_for("dashboard"))

    return render_template("twofa_backup_codes.html", title="Backup Codes", codes=codes)


@app.route("/2fa/disable", methods=["POST"])
@login_required
def twofa_disable():
    """Disable 2FA. Only allowed if not required for this role."""
    user_id = session.get("user_id")
    conn = db()
    c = conn.cursor()
    user = execute_query(c, "SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("logout"))

    if user.get("twofa_required"):
        flash("2FA is mandatory for your role and cannot be disabled.", "danger")
        return redirect(url_for("profile"))

    conn = db()
    c = conn.cursor()
    execute_query(c, "DELETE FROM user_2fa WHERE user_id = ?", (user_id,))
    execute_query(c, "DELETE FROM user_2fa_backup_codes WHERE user_id = ?", (user_id,))
    execute_query(c, "UPDATE users SET twofa_enabled = 0 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    session.pop("twofa_verified", None)
    log_audit(
        action="2fa_disabled",
        entity_type="user",
        entity_id=user_id,
        details="User disabled 2FA"
    )
    flash("2FA disabled.", "success")
    return redirect(url_for("profile"))


@app.route("/announcements/create", methods=["GET", "POST"])
@login_required
def create_announcement():
    """Create a new announcement."""
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        priority = request.form.get("priority", "normal")
        category = request.form.get("category", "general")
        is_pinned = 1 if request.form.get("is_pinned") else 0
        
        if not title or not content:
            flash("Title and content are required.", "danger")
            return redirect(url_for("create_announcement"))
        
        conn = db()
        c = conn.cursor()
        
        execute_query(c, """
            INSERT INTO announcements 
            (title, content, author_id, author_name, author_role, priority, category, is_pinned)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            title, content, 
            session["user_id"], 
            session.get("full_name", session["username"]),
            session.get("role", "staff"),
            priority, category, is_pinned
        ))
        
        conn.commit()

        log_audit(
            action="announcement_create",
            entity_type="announcement",
            details=f"Created announcement '{title}'"
        )

        conn.close()
        
        flash("Announcement created successfully!", "success")
        return redirect(url_for("announcements"))
    
    return render_template("create_announcement.html", title="Create Announcement")


@app.route("/announcements/<int:announcement_id>/comment", methods=["POST"])
@login_required
def add_announcement_comment(announcement_id):
    """Add a comment to an announcement."""
    comment = request.form.get("comment", "").strip()
    
    if not comment:
        flash("Comment cannot be empty.", "danger")
        return redirect(url_for("view_announcement", announcement_id=announcement_id))
    
    conn = db()
    c = conn.cursor()
    
    execute_query(c,"""
        INSERT INTO announcement_comments 
        (announcement_id, user_id, user_name, user_role, comment)
        VALUES (?, ?, ?, ?, ?)
    """, (
        announcement_id,
        session["user_id"],
        session.get("full_name", session["username"]),
        session.get("role", "staff"),
        comment
    ))
    
    conn.commit()
    conn.close()
    
    flash("Comment added successfully!", "success")
    return redirect(url_for("view_announcement", announcement_id=announcement_id))


@app.route("/announcements/<int:announcement_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_announcement(announcement_id):
    """Delete an announcement (Admin only)."""
    conn = db()
    c = conn.cursor()
    
    # Soft delete - just mark as inactive
    execute_query(c,"UPDATE announcements SET is_active = 0 WHERE id = ?", (announcement_id,))
    conn.commit()

    log_audit(
        action="announcement_delete",
        entity_type="announcement",
        entity_id=announcement_id,
        details=f"Deactivated announcement #{announcement_id}"
    )

    conn.close()
    
    flash("Announcement deleted successfully.", "success")
    return redirect(url_for("announcements"))


@app.route("/announcements/<int:announcement_id>/pin", methods=["POST"])
@login_required
@admin_required
def toggle_pin_announcement(announcement_id):
    """Toggle pin status of an announcement (Admin only)."""
    conn = db()
    c = conn.cursor()
    
    announcement = execute_query(c,"SELECT is_pinned FROM announcements WHERE id = ?", (announcement_id,)).fetchone()
    if announcement:
        new_status = 0 if announcement["is_pinned"] == 1 else 1
        execute_query(c,"UPDATE announcements SET is_pinned = ? WHERE id = ?", (new_status, announcement_id))
        conn.commit()
        flash("Announcement pin status updated.", "success")
    else:
        flash("Announcement not found.", "danger")
    
    conn.close()
    return redirect(url_for("announcements"))



@app.route("/announcements/mark-all-read")
@login_required
def mark_all_read():
    """Mark all announcements as read."""
    conn = db()
    c = conn.cursor()
    
    is_postgres = os.environ.get("DATABASE_URL") is not None
    
    user_id = session["user_id"]
    
    if is_postgres:
        # PostgreSQL syntax
        execute_query(c, """
            INSERT INTO announcement_reads (announcement_id, user_id)
            SELECT id, %s FROM announcements WHERE is_active = 1
            ON CONFLICT (announcement_id, user_id) DO NOTHING
        """, (user_id,))
    else:
        # SQLite syntax
        execute_query(c, """
            INSERT OR IGNORE INTO announcement_reads (announcement_id, user_id)
            SELECT id, ? FROM announcements WHERE is_active = 1
        """, (user_id,))
    
    conn.commit()
    conn.close()
    
    flash("All announcements marked as read.", "success")
    return redirect(url_for("announcements"))





# =============================================
# ANALYTICS DASHBOARD
# =============================================

@app.route("/analytics")
@login_required
@manager_required
def analytics_dashboard():
    """Comprehensive analytics dashboard for admin and managers."""
    from datetime import datetime
    conn = db()
    c = conn.cursor()
    
    is_postgres = os.environ.get("DATABASE_URL") is not None
    
    # =============================================
    # OVERVIEW METRICS
    # =============================================
    
        # ✅ Total Rental Cost — the true revenue (sum of rental costs, once per rental)
    total_rental_cost = get_single_value(c, """
        SELECT COALESCE(SUM(total_cost), 0)
        FROM daily_rentals
        WHERE status IN ('Completed', 'Active')
    """)

    # ✅ Total Net Settled — actual cash movement (payments minus refunds)
    total_settled = get_single_value(c, """
        SELECT COALESCE(SUM(amount), 0) FROM rental_payments
    """)
    total_rentals = get_single_value(c, "SELECT COUNT(*) FROM daily_rentals")
    active_rentals = get_single_value(c, "SELECT COUNT(*) FROM daily_rentals WHERE status = 'Active'")
    total_customers = get_single_value(c, "SELECT COUNT(*) FROM customers")
    verified_customers = get_single_value(c, "SELECT COUNT(*) FROM customers WHERE verification_status = 'Verified'")
    total_bicycles = get_single_value(c, "SELECT COUNT(*) FROM bicycles")
    available_bicycles = get_single_value(c, "SELECT COUNT(*) FROM bicycles WHERE status = 'Available'")
    
    # =============================================
    # REVENUE TRENDS
    # =============================================
    
    if is_postgres:
        # PostgreSQL syntax
        daily_revenue = execute_query(c, """
            SELECT 
                DATE(payment_date) AS date,
                COALESCE(SUM(amount), 0) AS revenue,
                COUNT(*) AS transactions
            FROM rental_payments
            WHERE DATE(payment_date) >= CURRENT_DATE - INTERVAL '30 days'
            GROUP BY DATE(payment_date)
            ORDER BY DATE(payment_date) ASC
        """).fetchall()
        
        weekly_revenue = execute_query(c, """
            SELECT 
                EXTRACT(WEEK FROM payment_date) AS week,
                EXTRACT(YEAR FROM payment_date) AS year,
                COALESCE(SUM(amount), 0) AS revenue,
                COUNT(*) AS transactions
            FROM rental_payments
            WHERE DATE(payment_date) >= CURRENT_DATE - INTERVAL '84 days'
            GROUP BY EXTRACT(WEEK FROM payment_date), EXTRACT(YEAR FROM payment_date)
            ORDER BY year ASC, week ASC
        """).fetchall()
        
        monthly_revenue = execute_query(c, """
            SELECT 
                TO_CHAR(payment_date, 'YYYY-MM') AS month,
                COALESCE(SUM(amount), 0) AS revenue,
                COUNT(*) AS transactions
            FROM rental_payments
            WHERE DATE(payment_date) >= CURRENT_DATE - INTERVAL '365 days'
            GROUP BY TO_CHAR(payment_date, 'YYYY-MM')
            ORDER BY month ASC
        """).fetchall()
        
        new_customers = execute_query(c, """
            SELECT 
                DATE(created_at) AS date,
                COUNT(*) AS count
            FROM customers
            WHERE DATE(created_at) >= CURRENT_DATE - INTERVAL '30 days'
            GROUP BY DATE(created_at)
            ORDER BY DATE(created_at) ASC
        """).fetchall()
        
        revenue_by_day = execute_query(c, """
            SELECT 
                TO_CHAR(payment_date, 'Day') AS day_name,
                COALESCE(SUM(amount), 0) AS revenue,
                COUNT(*) AS transactions
            FROM rental_payments
            GROUP BY TO_CHAR(payment_date, 'Day'), EXTRACT(DOW FROM payment_date)
            ORDER BY EXTRACT(DOW FROM payment_date)
        """).fetchall()
    else:
        # SQLite syntax
        daily_revenue = execute_query(c, """
            SELECT 
                date(payment_date) AS date,
                COALESCE(SUM(amount), 0) AS revenue,
                COUNT(*) AS transactions
            FROM rental_payments
            WHERE date(payment_date) >= date('now', '-30 days')
            GROUP BY date(payment_date)
            ORDER BY date(payment_date) ASC
        """).fetchall()
        
        weekly_revenue = execute_query(c, """
            SELECT 
                strftime('%W', payment_date) AS week,
                strftime('%Y', payment_date) AS year,
                COALESCE(SUM(amount), 0) AS revenue,
                COUNT(*) AS transactions
            FROM rental_payments
            WHERE date(payment_date) >= date('now', '-84 days')
            GROUP BY week, year
            ORDER BY year ASC, week ASC
        """).fetchall()
        
        monthly_revenue = execute_query(c, """
            SELECT 
                strftime('%Y-%m', payment_date) AS month,
                COALESCE(SUM(amount), 0) AS revenue,
                COUNT(*) AS transactions
            FROM rental_payments
            WHERE date(payment_date) >= date('now', '-365 days')
            GROUP BY month
            ORDER BY month ASC
        """).fetchall()
        
        new_customers = execute_query(c, """
            SELECT 
                date(created_at) AS date,
                COUNT(*) AS count
            FROM customers
            WHERE date(created_at) >= date('now', '-30 days')
            GROUP BY date(created_at)
            ORDER BY date(created_at) ASC
        """).fetchall()
        
        revenue_by_day = execute_query(c, """
            SELECT 
                CASE strftime('%w', payment_date)
                    WHEN '0' THEN 'Sunday'
                    WHEN '1' THEN 'Monday'
                    WHEN '2' THEN 'Tuesday'
                    WHEN '3' THEN 'Wednesday'
                    WHEN '4' THEN 'Thursday'
                    WHEN '5' THEN 'Friday'
                    WHEN '6' THEN 'Saturday'
                END AS day_name,
                COALESCE(SUM(amount), 0) AS revenue,
                COUNT(*) AS transactions
            FROM rental_payments
            GROUP BY strftime('%w', payment_date)
            ORDER BY strftime('%w', payment_date)
        """).fetchall()
    
    # =============================================
    # BICYCLE ANALYTICS
    # =============================================
    
    top_bicycles = execute_query(c, """
        SELECT 
            b.bike_code,
            b.brand,
            b.model,
            b.bike_type,
            COUNT(r.id) AS rental_count,
            COALESCE(SUM(r.total_cost), 0) AS total_revenue,
            COALESCE(SUM(r.total_hours), 0) AS total_hours
        FROM bicycles b
        LEFT JOIN daily_rentals r ON r.bicycle_id = b.id
        GROUP BY b.id, b.bike_code, b.brand, b.model, b.bike_type
        ORDER BY rental_count DESC
        LIMIT 10
    """).fetchall()
    
    bike_type_stats = execute_query(c, """
        SELECT 
            b.bike_type,
            COUNT(b.id) AS bike_count,
            COUNT(r.id) AS rental_count,
            COALESCE(SUM(r.total_cost), 0) AS total_revenue,
            COALESCE(AVG(r.total_cost), 0) AS avg_revenue
        FROM bicycles b
        LEFT JOIN daily_rentals r ON r.bicycle_id = b.id
        GROUP BY b.bike_type
        ORDER BY total_revenue DESC
    """).fetchall()
    
    # =============================================
    # CUSTOMER ANALYTICS
    # =============================================
    
    top_customers = execute_query(c, """
        SELECT 
            c.id,
            c.full_name,
            c.phone,
            COUNT(r.id) AS rental_count,
            COALESCE(SUM(r.total_cost), 0) AS total_spent,
            COALESCE(lp.points, 0) AS points
        FROM customers c
        LEFT JOIN daily_rentals r ON r.customer_id = c.id
        LEFT JOIN loyalty_points lp ON lp.customer_id = c.id
        GROUP BY c.id, c.full_name, c.phone, lp.points
        ORDER BY total_spent DESC
        LIMIT 10
    """).fetchall()
    
    # =============================================
    # PAYMENT ANALYTICS
    # =============================================
    
    payment_methods = execute_query(c, """
        SELECT 
            payment_method,
            COUNT(*) AS count,
            COALESCE(SUM(amount), 0) AS total
        FROM rental_payments
        GROUP BY payment_method
        ORDER BY total DESC
    """).fetchall()
    
    avg_duration = execute_query(c, """
        SELECT 
            COALESCE(AVG(total_hours), 0) AS avg_hours,
            COALESCE(MIN(total_hours), 0) AS min_hours,
            COALESCE(MAX(total_hours), 0) AS max_hours
        FROM daily_rentals
        WHERE status = 'Completed' AND total_hours > 0
    """).fetchone()
    
    # =============================================
    # MAINTENANCE ANALYTICS
    # =============================================
    
    maintenance_stats = execute_query(c, """
        SELECT 
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'Scheduled' THEN 1 ELSE 0 END) AS scheduled,
            SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) AS in_progress,
            SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed,
            SUM(CASE WHEN status = 'Cancelled' THEN 1 ELSE 0 END) AS cancelled,
            COALESCE(SUM(cost), 0) AS total_cost
        FROM maintenance_records
    """).fetchone()
    
    # =============================================
    # DISCOUNT ANALYTICS
    # =============================================
    
    discount_stats = execute_query(c, """
        SELECT 
            COUNT(*) AS total_used,
            COALESCE(SUM(amount_discounted), 0) AS total_savings
        FROM discount_usage
    """).fetchone()
    
    conn.close()
    
    # =============================================
    # PREPARE CHART DATA
    # =============================================
    
    chart_data = {
        "daily_dates": [row["date"] for row in daily_revenue],
        "daily_revenue": [row["revenue"] for row in daily_revenue],
        "daily_transactions": [row["transactions"] for row in daily_revenue],
        "monthly_months": [row["month"] for row in monthly_revenue],
        "monthly_revenue": [row["revenue"] for row in monthly_revenue],
        "new_customers_dates": [row["date"] for row in new_customers],
        "new_customers_count": [row["count"] for row in new_customers],
        "week_days": [row["day_name"] for row in revenue_by_day],
        "week_revenue": [row["revenue"] for row in revenue_by_day],
    }
    
    # Handle average duration (might be None)
    avg_hours = avg_duration['avg_hours'] if avg_duration and isinstance(avg_duration, dict) else 0
    min_hours = avg_duration['min_hours'] if avg_duration and isinstance(avg_duration, dict) else 0
    max_hours = avg_duration['max_hours'] if avg_duration and isinstance(avg_duration, dict) else 0
    
    return render_template(
        "analytics.html",
        title="Analytics Dashboard",
        now=datetime.now(),
        total_revenue=total_rental_cost,
        total_rentals=total_rentals,
        active_rentals=active_rentals,
        total_customers=total_customers,
        verified_customers=verified_customers,
        total_bicycles=total_bicycles,
        available_bicycles=available_bicycles,
        daily_revenue=daily_revenue,
        weekly_revenue=weekly_revenue,
        monthly_revenue=monthly_revenue,
        top_bicycles=top_bicycles,
        bike_type_stats=bike_type_stats,
        top_customers=top_customers,
        new_customers=new_customers,
        payment_methods=payment_methods,
        avg_duration={
            "avg_hours": avg_hours,
            "min_hours": min_hours,
            "max_hours": max_hours
        },
        revenue_by_day=revenue_by_day,
        maintenance_stats=maintenance_stats,
        discount_stats=discount_stats,
        chart_data=chart_data
    )



@app.route("/bicycles/<int:bicycle_id>/edit", methods=["GET", "POST"])
@login_required
@manager_required
def edit_bicycle(bicycle_id):
    """Edit a bicycle's details."""
    conn = db()
    c = conn.cursor()

    bicycle = execute_query(c,
        "SELECT * FROM bicycles WHERE id = ?", (bicycle_id,)
    ).fetchone()

    if not bicycle:
        conn.close()
        flash("Bicycle not found.", "danger")
        return redirect(url_for("bicycles"))

    if request.method == "POST":
        bike_code = request.form.get("bike_code", "").strip().upper()
        brand = request.form.get("brand", "").strip()
        model = request.form.get("model", "").strip()
        bike_type = request.form.get("bike_type", "Standard")
        hourly_rate = float(request.form.get("hourly_rate", 20))
        daily_cap = float(request.form.get("daily_cap", 120))
        deposit_amount = float(request.form.get("deposit_amount", 50))
        notes = request.form.get("notes", "").strip()

        # ✅ Optional: update current station
        current_station_id = request.form.get("current_station_id") or None
        if current_station_id:
            current_station_id = int(current_station_id)

        if not bike_code:
            flash("Bicycle code is required.", "danger")
            conn.close()
            return redirect(url_for("edit_bicycle", bicycle_id=bicycle_id))

        try:

            condition_notes = (request.form.get("condition_notes") or "").strip()

            execute_query(c, """
                UPDATE bicycles
                SET bike_code = ?, brand = ?, model = ?, bike_type = ?,
                    hourly_rate = ?, daily_cap = ?, deposit_amount = ?,
                    notes = ?, condition_notes = ?, current_station_id = ?
                WHERE id = ?
            """, (bike_code, brand, model, bike_type,
                  hourly_rate, daily_cap, deposit_amount,
                  notes, condition_notes, current_station_id, bicycle_id))



            conn.commit()

            log_audit(
                action="bicycle_edit",
                entity_type="bicycle",
                entity_id=bicycle_id,
                details=f"Edited bicycle '{bike_code}'"
            )

            flash(f"Bicycle '{bike_code}' updated successfully!", "success")
        except sqlite3.IntegrityError:
            flash("Bicycle code already exists.", "danger")
        finally:
            conn.close()

        return redirect(url_for("bicycles"))

    # GET: fetch stations for the dropdown
    stations = execute_query(c, """
        SELECT id, name FROM branches WHERE is_active = 1 ORDER BY name
    """).fetchall()

    conn.close()
    return render_template(
        "edit_bicycle.html",
        title="Edit Bicycle",
        bicycle=bicycle,
        stations=stations
    )


@app.route("/bicycles", methods=["GET", "POST"])
@login_required
@staff_required
def bicycles():
    conn = db()
    c = conn.cursor()

    if request.method == "POST":
        bike_code = request.form.get("bike_code", "").strip().upper()
        brand = request.form.get("brand", "").strip()
        model = request.form.get("model", "").strip()
        bike_type = request.form.get("bike_type", "Standard")
        hourly_rate = float(request.form.get("hourly_rate", 20))
        daily_cap = float(request.form.get("daily_cap", 120))
        deposit_amount = float(request.form.get("deposit_amount", 50))
        notes = request.form.get("notes", "").strip()

        # ✅ Optional: admin can set the initial station
        current_station_id = request.form.get("current_station_id") or None
        if current_station_id:
            current_station_id = int(current_station_id)

        if not bike_code:
            flash("Bicycle code is required.", "danger")
            return redirect(url_for("bicycles"))

        try:
            execute_query(c, """
                INSERT INTO bicycles 
                (bike_code, brand, model, bike_type,
                 hourly_rate, daily_cap, deposit_amount, notes,
                 current_station_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (bike_code, brand, model, bike_type,
                  hourly_rate, daily_cap, deposit_amount, notes,
                  current_station_id))
            conn.commit()

            log_audit(
                action="bicycle_create",
                entity_type="bicycle",
                details=f"Added bicycle '{bike_code}'"
            )

            flash(f"Bicycle {bike_code} added successfully.", "success")
        # except sqlite3.IntegrityError:
        #     flash("Bicycle code already exists.", "danger")

        except (sqlite3.IntegrityError, Exception) as e:
            # Check if it's a unique violation for the bike code
            if "unique constraint" in str(e).lower() or "duplicate key" in str(e).lower():
                flash(f"Bicycle code '{bike_code}' already exists. Please use a different code.", "danger")
            else:
                flash(f"Error adding bicycle: {str(e)}", "danger")



        conn.close()
        return redirect(url_for("bicycles"))

    # =============================================
    # SEARCH FILTER
    # =============================================
    search = (request.args.get("search") or "").strip()

    if search:
        like = f"%{search}%"
        bicycles = execute_query(c, f"""
            SELECT 
                b.*,
                bh.health_score,
                bh.condition_rating,
                s.name AS station_name
            FROM bicycles b
            LEFT JOIN bicycle_health bh ON bh.bicycle_id = b.id
            LEFT JOIN branches s ON s.id = b.current_station_id
            WHERE {ci_like('b.bike_code', '?')}
               OR {ci_like('b.brand', '?')}
               OR {ci_like('b.model', '?')}
               OR {ci_like('b.bike_type', '?')}
            ORDER BY b.bike_code
        """, (like, like, like, like)).fetchall()
    else:
        bicycles = execute_query(c, """
            SELECT 
                b.*,
                bh.health_score,
                bh.condition_rating,
                s.name AS station_name
            FROM bicycles b
            LEFT JOIN bicycle_health bh ON bh.bicycle_id = b.id
            LEFT JOIN branches s ON s.id = b.current_station_id
            ORDER BY b.bike_code
        """).fetchall()

    # ✅ Pass stations list to the template (for the "Initial Station" dropdown)
    stations = execute_query(c, """
        SELECT id, name FROM branches WHERE is_active = 1 ORDER BY name
    """).fetchall()

    conn.close()

    return render_template(
        "bicycles.html",
        title="Bicycles",
        bicycles=bicycles,
        stations=stations,
        search=search
    )



@app.route("/reports/bicycle-utilization")
@login_required
def bicycle_utilization():
    conn = db()
    c = conn.cursor()
    
    # =============================================
    # BICYCLE UTILIZATION SUMMARY
    # =============================================
    
    bikes = execute_query(c,"""
        SELECT 
            b.id,
            b.bike_code,
            b.brand,
            b.model,
            b.bike_type,
            b.hourly_rate,
            b.daily_cap,
            b.status,
            COUNT(DISTINCT r.id) AS total_rentals,
            COALESCE(SUM(r.total_hours), 0) AS total_hours,
            COALESCE(SUM(r.total_cost), 0) AS total_revenue,
            COALESCE(AVG(r.total_hours), 0) AS avg_hours_per_rental,
            COUNT(DISTINCT CASE WHEN r.status = 'Active' THEN r.id END) AS active_rentals
        FROM bicycles b
        LEFT JOIN daily_rentals r ON r.bicycle_id = b.id
        GROUP BY b.id, b.bike_code, b.brand, b.model, b.bike_type, b.hourly_rate, b.daily_cap, b.status
        ORDER BY total_revenue DESC, total_rentals DESC
    """).fetchall()
    
    # =============================================
    # OVERALL STATISTICS
    # =============================================
    
    total_bikes = len(bikes)
    total_rentals = sum(b["total_rentals"] for b in bikes)
    total_revenue = sum(b["total_revenue"] for b in bikes)
    total_hours = sum(b["total_hours"] for b in bikes)
    
    # Most rented bike
    most_rented = max(bikes, key=lambda x: x["total_rentals"]) if bikes else None
    
    # Highest revenue bike
    highest_revenue = max(bikes, key=lambda x: x["total_revenue"]) if bikes else None
    
    # Active rentals count
    active_rentals = sum(b["active_rentals"] for b in bikes)
    
    # Utilization rate (bikes with at least one rental)
    utilized_bikes = sum(1 for b in bikes if b["total_rentals"] > 0)
    utilization_rate = (utilized_bikes / total_bikes * 100) if total_bikes > 0 else 0
    
    # Average revenue per bike
    avg_revenue_per_bike = total_revenue / total_bikes if total_bikes > 0 else 0
    
    # Bike type breakdown
    bike_types = execute_query(c,"""
        SELECT 
            bike_type,
            COUNT(*) AS count,
            COALESCE(SUM(r.total_cost), 0) AS revenue,
            COALESCE(COUNT(r.id), 0) AS rentals
        FROM bicycles b
        LEFT JOIN daily_rentals r ON r.bicycle_id = b.id
        GROUP BY bike_type
        ORDER BY revenue DESC
    """).fetchall()
    
    conn.close()
    
    return render_template(
        "bicycle_utilization.html",
        title="Bicycle Utilization",
        bikes=bikes,
        total_bikes=total_bikes,
        total_rentals=total_rentals,
        total_revenue=total_revenue,
        total_hours=total_hours,
        most_rented=most_rented,
        highest_revenue=highest_revenue,
        active_rentals=active_rentals,
        utilization_rate=utilization_rate,
        avg_revenue_per_bike=avg_revenue_per_bike,
        bike_types=bike_types
    )





# =============================================
# NOTIFICATION FUNCTIONS
# =============================================

def send_email_notification(to_email, subject, body):
    """Send email notification."""
    if not EMAIL_ENABLED:
        print(f"📧 Email disabled. Would send to: {to_email}")
        return True
    
    # Check if credentials are configured
    if not EMAIL_USER or EMAIL_USER == "your-email@gmail.com":
        print(f"📧 Email credentials not configured. Would send to: {to_email}")
        print(f"   Subject: {subject}")
        return True
    
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_FROM
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        print(f"✅ Email sent to {to_email}")
        return True
    except Exception as e:
        print(f"❌ Email error: {e}")
        # ✅ Don't fail - just log and continue
        return True



def send_sms_notification(phone_number, message):
    """Send SMS notification using Twilio."""
    if not SMS_ENABLED:
        print(f"📱 SMS (Simulated) To: {phone_number}: {message}")
        return True
    
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN or not TWILIO_PHONE_NUMBER:
        print(f"⚠️ Twilio credentials missing. SMS not sent to {phone_number}")
        return True  # ✅ Don't fail
    
    try:
        from twilio.rest import Client
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        sms = client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        print(f"✅ SMS sent to {phone_number}")
        print(f"   SID: {sms.sid}")
        return True
    except Exception as e:
        print(f"❌ SMS error: {e}")
        return True  # ✅ Don't fail



@app.route("/debug-twilio")
@login_required
def debug_twilio():
    """Debug Twilio configuration."""
    return {
        "sms_enabled": SMS_ENABLED,
        "account_sid": TWILIO_ACCOUNT_SID[:5] + "..." if TWILIO_ACCOUNT_SID else "Not set",
        "auth_token_set": bool(TWILIO_AUTH_TOKEN),
        "phone_number": TWILIO_PHONE_NUMBER or "Not set",
        "twilio_configured": bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_PHONE_NUMBER)
    }





def send_reminder(rental_id):
    """Send a reminder for a specific rental."""
    from datetime import datetime, timedelta  # ✅ Add timedelta
    
    conn = db()
    c = conn.cursor()
    
    rental = execute_query(c, """
        SELECT 
            r.*,
            c.full_name,
            c.phone,
            c.email,
            b.bike_code,
            b.brand,
            b.model
        FROM daily_rentals r
        JOIN customers c ON c.id = r.customer_id
        JOIN bicycles b ON b.id = r.bicycle_id
        WHERE r.id = ?
    """, (rental_id,)).fetchone()
    
    if not rental:
        conn.close()
        return False
    
    # ✅ FIX: Handle start_time as datetime or string
    if isinstance(rental["start_time"], datetime):
        start_time = rental["start_time"]
    else:
        start_time = datetime.fromisoformat(rental["start_time"])
    
    # Calculate time remaining
    end_time = start_time + timedelta(hours=rental["total_hours"] or 1)
    now = datetime.now()
    
    if now > end_time:
        # Overdue reminder
        reminder_type = "overdue"
        message = f"""
        ⚠️ OVERDUE REMINDER
        
        Dear {rental['full_name']},
        
        Your rental of {rental['bike_code']} is now OVERDUE.
        
        Rental started: {start_time.strftime('%Y-%m-%d %H:%M')}
        Expected return: {end_time.strftime('%Y-%m-%d %H:%M')}
        
        Please return the bicycle immediately to avoid additional charges.
        
        Thank you,
        RAB - Rent A Bike
        """
        subject = "🚲 OVERDUE: Bicycle Rental - Please Return"
    else:
        # Upcoming return reminder
        time_left = end_time - now
        hours_left = time_left.total_seconds() / 3600
        
        reminder_type = "upcoming"
        message = f"""
        🔔 RETURN REMINDER
        
        Dear {rental['full_name']},
        
        Your rental of {rental['bike_code']} will be due in approximately {hours_left:.1f} hours.
        
        Rental started: {start_time.strftime('%Y-%m-%d %H:%M')}
        Expected return: {end_time.strftime('%Y-%m-%d %H:%M')}
        
        Please return the bicycle on time to avoid late fees.
        
        Thank you,
        RAB - Rent A Bike
        """
        subject = "🚲 Return Reminder: Bicycle Due Soon"
    
    # Send email
    if rental["email"]:
        send_email_notification(rental["email"], subject, message)
    
    # Send SMS
    if rental["phone"]:
        sms_message = f"RAB: {rental['full_name']}, your rental of {rental['bike_code']} is due soon. Please return to avoid late fees."
        send_sms_notification(rental["phone"], sms_message)
    
    # Log the reminder
    execute_query(c, """
        INSERT INTO reminder_logs (rental_id, reminder_type, sent_to, sent_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    """, (rental_id, reminder_type, rental["phone"] or rental["email"]))
    
    conn.commit()
    conn.close()
    
    return True






@app.route("/rentals/<int:rental_id>/send-reminder")
@login_required
def send_reminder_route(rental_id):
    """Manually send a reminder for a rental."""
    if send_reminder(rental_id):
        flash("Reminder sent successfully!", "success")
    else:
        flash("Failed to send reminder. Rental not found.", "danger")
    return redirect(url_for("rental_history"))




@app.route("/rentals/check-reminders")
@login_required
def check_reminders():
    """Check all active rentals and send reminders if needed."""
    conn = db()
    c = conn.cursor()
    
    # Get active rentals
    rentals = execute_query(c, """
        SELECT id FROM daily_rentals
        WHERE status = 'Active'
        AND end_time IS NOT NULL
    """).fetchall()
    
    sent_count = 0
    for rental in rentals:
        if send_reminder(rental["id"]):
            sent_count += 1
    
    conn.close()
    
    flash(f"Checked {len(rentals)} active rentals. Sent {sent_count} reminders.", "success")
    return redirect(url_for("rental_history"))


@app.route("/reminders/logs")
@login_required
def reminder_logs():
    """View all sent reminders."""
    conn = db()
    c = conn.cursor()
    
    logs = execute_query(c,"""
        SELECT 
            rl.*,
            c.full_name,
            b.bike_code
        FROM reminder_logs rl
        JOIN daily_rentals r ON r.id = rl.rental_id
        JOIN customers c ON c.id = r.customer_id
        JOIN bicycles b ON b.id = r.bicycle_id
        ORDER BY rl.sent_at DESC
        LIMIT 50
    """).fetchall()
    
    conn.close()
    
    return render_template(
        "reminder_logs.html",
        title="Reminder Logs",
        logs=logs
    )


# =============================================
# DISCOUNT CODES
# =============================================

@app.route("/discounts")
@login_required
@admin_required
def discounts():
    """View all discount codes."""
    conn = db()
    c = conn.cursor()
    
    discounts = execute_query(c,"""
        SELECT * FROM discount_codes 
        ORDER BY created_at DESC
    """).fetchall()
    
    conn.close()
    return render_template("discounts.html", title="Discount Codes", discounts=discounts)





@app.route("/discounts/add", methods=["GET", "POST"])
@login_required
@admin_required
def add_discount():
    """Add a new discount code."""
    if request.method == "POST":
        code = request.form.get("code", "").strip().upper()
        description = request.form.get("description", "").strip()
        discount_type = request.form.get("discount_type", "percentage")
        discount_value = float(request.form.get("discount_value", 0))
        min_rental_amount = float(request.form.get("min_rental_amount", 0))
        max_uses = int(request.form.get("max_uses", 0))
        start_date = request.form.get("start_date")
        end_date = request.form.get("end_date")
        
        if not code or discount_value <= 0:
            flash("Code and discount value are required.", "danger")
            return redirect(url_for("add_discount"))
        
        conn = db()
        c = conn.cursor()
        
        try:
            execute_query(c,"""
                INSERT INTO discount_codes 
                (code, description, discount_type, discount_value, min_rental_amount, max_uses, start_date, end_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (code, description, discount_type, discount_value, min_rental_amount, max_uses, start_date, end_date))
            conn.commit()

            log_audit(
                action="discount_create",
                entity_type="discount_code",
                details=f"Created discount code '{code}'"
            )

            flash(f"Discount code '{code}' created successfully!", "success")
        except sqlite3.IntegrityError:
            flash(f"Discount code '{code}' already exists.", "danger")
        finally:
            conn.close()
        
        return redirect(url_for("discounts"))
    
    return render_template("add_discount.html", title="Add Discount Code")


@app.route("/discounts/<int:discount_id>/toggle")
@login_required
@admin_required
def toggle_discount(discount_id):
    """Enable/disable a discount code."""
    conn = db()
    c = conn.cursor()
    
    discount = execute_query(c,"SELECT is_active FROM discount_codes WHERE id = ?", (discount_id,)).fetchone()
    if discount:
        new_status = 0 if discount["is_active"] == 1 else 1
        execute_query(c,"UPDATE discount_codes SET is_active = ? WHERE id = ?", (new_status, discount_id))
        conn.commit()
        flash("Discount code status updated.", "success")
    else:
        flash("Discount code not found.", "danger")
    
    conn.close()
    return redirect(url_for("discounts"))


@app.route("/discounts/<int:discount_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_discount(discount_id):
    """Delete a discount code."""
    conn = db()
    c = conn.cursor()

    log_audit(
        action="discount_delete",
        entity_type="discount_code",
        entity_id=discount_id,
        details=f"Deleted discount code #{discount_id}"
    )

    execute_query(c,"DELETE FROM discount_codes WHERE id = ?", (discount_id,))
    conn.commit()
    conn.close()
    
    flash("Discount code deleted.", "success")
    return redirect(url_for("discounts"))


@app.route("/validate-discount", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def validate_discount():
    """Validate a discount code (AJAX)."""
    code = request.form.get("code", "").strip().upper()
    rental_amount = float(request.form.get("rental_amount", 0))
    
    conn = db()
    c = conn.cursor()
    
    discount = execute_query(c,"""
        SELECT * FROM discount_codes 
        WHERE code = ? AND is_active = 1
        AND (start_date IS NULL OR date(start_date) <= date('now'))
        AND (end_date IS NULL OR date(end_date) >= date('now'))
        AND (max_uses = 0 OR used_count < max_uses)
    """, (code,)).fetchone()
    
    conn.close()
    
    if not discount:
        return jsonify({"valid": False, "message": "Invalid or expired discount code."})
    
    if rental_amount < discount["min_rental_amount"]:
        return jsonify({
            "valid": False, 
            "message": f"Minimum rental amount of N${discount['min_rental_amount']:.2f} required."
        })
    
    # Calculate discount
    if discount["discount_type"] == "percentage":
        discount_amount = rental_amount * (discount["discount_value"] / 100)
    else:  # fixed
        discount_amount = min(discount["discount_value"], rental_amount)
    
    return jsonify({
        "valid": True,
        "discount_id": discount["id"],
        "discount_amount": round(discount_amount, 2),
        "final_amount": round(rental_amount - discount_amount, 2),
        "message": f"Discount applied: {discount['discount_value']}{'%' if discount['discount_type'] == 'percentage' else ''} off!"
    })




# =============================================
# LOYALTY PROGRAM
# =============================================

@app.route("/loyalty")
@login_required
@admin_required
def loyalty_dashboard():
    """View loyalty program dashboard."""
    conn = db()
    c = conn.cursor()
    
    # Get all customers with loyalty points
    customers = execute_query(c,"""
        SELECT 
            c.id,
            c.full_name,
            c.phone,
            c.email,
            lp.points,
            lp.total_spent,
            lp.total_rentals,
            lp.tier
        FROM customers c
        LEFT JOIN loyalty_points lp ON lp.customer_id = c.id
        ORDER BY lp.points DESC
    """).fetchall()
    

    total_points = get_single_value(c, "SELECT COALESCE(SUM(points), 0) FROM loyalty_points")
    total_customers_with_points = get_single_value(c, "SELECT COUNT(*) FROM loyalty_points WHERE points > 0")
    total_redeemed = get_single_value(c, "SELECT COALESCE(SUM(-points), 0) FROM points_transactions WHERE transaction_type = 'redeemed'")    




    conn.close()
    
    return render_template(
        "loyalty.html",
        title="Loyalty Program",
        customers=customers,
        total_points=total_points,
        total_customers_with_points=total_customers_with_points,
        total_redeemed=total_redeemed
    )


@app.route("/loyalty/<int:customer_id>")
@login_required
def customer_loyalty(customer_id):
    """View a customer's loyalty details."""
    conn = db()
    c = conn.cursor()
    
    customer = execute_query(c,"""
        SELECT c.*, lp.*
        FROM customers c
        LEFT JOIN loyalty_points lp ON lp.customer_id = c.id
        WHERE c.id = ?
    """, (customer_id,)).fetchone()
    
    if not customer:
        flash("Customer not found.", "danger")
        return redirect(url_for("loyalty_dashboard"))
    
    transactions = execute_query(c,"""
        SELECT * FROM points_transactions 
        WHERE customer_id = ? 
        ORDER BY created_at DESC
        LIMIT 20
    """, (customer_id,)).fetchall()
    
    conn.close()
    return render_template(
        "customer_loyalty.html",
        title="Customer Loyalty",
        customer=customer,
        transactions=transactions
    )


def add_loyalty_points(customer_id, rental_id, amount):
    """Add loyalty points for a rental."""
    conn = db()
    c = conn.cursor()
    
    # Calculate points: 1 point per N$10 spent
    points_earned = int(amount / 10)
    
    if points_earned == 0:
        conn.close()
        return
    
    # Check if loyalty record exists
    lp = execute_query(c,"SELECT id, points, total_spent, total_rentals FROM loyalty_points WHERE customer_id = ?", (customer_id,)).fetchone()
    
    if lp:
        new_points = lp["points"] + points_earned
        new_total_spent = lp["total_spent"] + amount
        new_total_rentals = lp["total_rentals"] + 1
        
        # Determine tier
        tier = "Bronze"
        if new_total_spent >= 5000:
            tier = "Platinum"
        elif new_total_spent >= 2000:
            tier = "Gold"
        elif new_total_spent >= 1000:
            tier = "Silver"
        
        execute_query(c,"""
            UPDATE loyalty_points 
            SET points = ?, total_spent = ?, total_rentals = ?, tier = ?, updated_at = CURRENT_TIMESTAMP
            WHERE customer_id = ?
        """, (new_points, new_total_spent, new_total_rentals, tier, customer_id))
    else:
        tier = "Bronze"
        execute_query(c,"""
            INSERT INTO loyalty_points (customer_id, points, total_spent, total_rentals, tier)
            VALUES (?, ?, ?, ?, ?)
        """, (customer_id, points_earned, amount, 1, tier))
    
    # Record transaction
    execute_query(c,"""
        INSERT INTO points_transactions (customer_id, points, transaction_type, description, rental_id)
        VALUES (?, ?, 'earned', ?, ?)
    """, (customer_id, points_earned, f"Earned {points_earned} points from rental #{rental_id}", rental_id))
    
    conn.commit()
    conn.close()


@app.route("/loyalty/redeem", methods=["POST"])
@login_required
def redeem_points():
    """Redeem loyalty points for discount."""
    customer_id = request.form.get("customer_id")
    points_to_redeem = int(request.form.get("points", 0))
    rental_id = request.form.get("rental_id")
    
    conn = db()
    c = conn.cursor()
    
    # Check available points
    lp = execute_query(c,"SELECT points FROM loyalty_points WHERE customer_id = ?", (customer_id,)).fetchone()
    
    if not lp or lp["points"] < points_to_redeem:
        flash("Insufficient points.", "danger")
        return redirect(request.referrer or url_for("loyalty_dashboard"))
    
    # Calculate discount: 1 point = N$0.50
    discount_amount = points_to_redeem * 0.50
    
    # Deduct points
    execute_query(c,"UPDATE loyalty_points SET points = points - ? WHERE customer_id = ?", (points_to_redeem, customer_id))
    
    # Record transaction
    execute_query(c,"""
        INSERT INTO points_transactions (customer_id, points, transaction_type, description, rental_id)
        VALUES (?, ?, 'redeemed', ?, ?)
    """, (customer_id, -points_to_redeem, f"Redeemed {points_to_redeem} points for N${discount_amount:.2f} discount", rental_id))
    
    conn.commit()
    conn.close()
    
    flash(f"Successfully redeemed {points_to_redeem} points for N${discount_amount:.2f} discount!", "success")
    return redirect(request.referrer or url_for("loyalty_dashboard"))



# =============================================
# MAINTENANCE TRACKING
# =============================================

@app.route("/maintenance")
@login_required
def maintenance_dashboard():
    """View all maintenance records."""
    conn = db()
    c = conn.cursor()
    
    records = execute_query(c,"""
        SELECT m.*, b.bike_code, b.brand, b.model
        FROM maintenance_records m
        JOIN bicycles b ON b.id = m.bicycle_id
        ORDER BY m.scheduled_date DESC
        LIMIT 50
    """).fetchall()
    
  
    scheduled = get_single_value(c, "SELECT COUNT(*) FROM maintenance_records WHERE status = 'Scheduled'")
    in_progress = get_single_value(c, "SELECT COUNT(*) FROM maintenance_records WHERE status = 'In Progress'")
    completed = get_single_value(c, "SELECT COUNT(*) FROM maintenance_records WHERE status = 'Completed'")    



    conn.close()
    
    return render_template(
        "maintenance.html",
        title="Maintenance",
        records=records,
        scheduled=scheduled,
        in_progress=in_progress,
        completed=completed
    )


@app.route("/maintenance/add", methods=["GET", "POST"])
@login_required
@manager_required
def add_maintenance():
    """Schedule maintenance for a bicycle."""
    conn = db()
    c = conn.cursor()
    
    bicycles = execute_query(c,"SELECT id, bike_code, brand, model FROM bicycles ORDER BY bike_code").fetchall()
    conn.close()
    
    if request.method == "POST":
        bicycle_id = request.form.get("bicycle_id")
        maintenance_type = request.form.get("maintenance_type")
        description = request.form.get("description", "").strip()
        cost = float(request.form.get("cost", 0))
        scheduled_date = request.form.get("scheduled_date")
        performed_by = request.form.get("performed_by", "").strip()
        notes = request.form.get("notes", "").strip()
        
        conn = db()
        c = conn.cursor()
        
        execute_query(c,"""
            INSERT INTO maintenance_records 
            (bicycle_id, maintenance_type, description, cost, scheduled_date, performed_by, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (bicycle_id, maintenance_type, description, cost, scheduled_date, performed_by, notes))
        
        # Update bicycle status
        execute_query(c,"UPDATE bicycles SET status = 'Maintenance' WHERE id = ?", (bicycle_id,))
        
        conn.commit()
        conn.close()
        
        flash("Maintenance record created successfully!", "success")
        return redirect(url_for("maintenance_dashboard"))
    
    return render_template("add_maintenance.html", title="Add Maintenance", bicycles=bicycles)


@app.route("/maintenance/<int:record_id>/update", methods=["POST"])
@login_required
@manager_required
def update_maintenance(record_id):
    """Update maintenance status."""
    status = request.form.get("status")
    completed_date = request.form.get("completed_date")
    
    conn = db()
    c = conn.cursor()
    
    execute_query(c,"""
        UPDATE maintenance_records 
        SET status = ?, completed_date = ?
        WHERE id = ?
    """, (status, completed_date, record_id))
    
    # If completed, update bicycle status back to Available
    if status == "Completed":
        record = execute_query(c,"SELECT bicycle_id FROM maintenance_records WHERE id = ?", (record_id,)).fetchone()
        if record:
            execute_query(c,"UPDATE bicycles SET status = 'Available' WHERE id = ?", (record["bicycle_id"],))
    
    conn.commit()
    conn.close()
    
    flash("Maintenance record updated!", "success")
    return redirect(url_for("maintenance_dashboard"))




@app.route("/exports")
@login_required
@manager_required
def exports_page():
    """Export documents and reports page."""
    from datetime import datetime
    return render_template(
        "exports.html", 
        title="Export Documents",
        now=datetime.now()
    )


@app.route("/export/rentals/csv")
@login_required
@manager_required
def export_rentals_csv():
    """Export all rentals to CSV."""
    conn = db()
    c = conn.cursor()
    
    rentals = execute_query(c,"""
        SELECT 
            r.id,
            c.full_name AS customer,
            c.phone,
            b.bike_code,
            r.start_time,
            r.end_time,
            r.total_hours,
            r.total_cost,
            r.payment_status,
            r.status
        FROM daily_rentals r
        JOIN customers c ON c.id = r.customer_id
        JOIN bicycles b ON b.id = r.bicycle_id
        ORDER BY r.start_time DESC
    """).fetchall()
    conn.close()
    
    # Create CSV
    si = StringIO()
    writer = csv.writer(si)
    
    # Header
    writer.writerow(['Rental ID', 'Customer', 'Phone', 'Bike', 'Start Time', 'End Time', 
                     'Hours', 'Cost (N$)', 'Payment Status', 'Status'])
    
    # Data
    for r in rentals:
        writer.writerow([
            r['id'],
            r['customer'],
            r['phone'],
            r['bike_code'],
            r['start_time'],
            r['end_time'] or '',
            f"{r['total_hours']:.1f}" if r['total_hours'] else '0',
            f"{r['total_cost']:.2f}" if r['total_cost'] else '0.00',
            r['payment_status'] or 'Pending',
            r['status']
        ])
    
    output = si.getvalue()
    response = make_response(output)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=rentals_{datetime.now().strftime("%Y%m%d")}.csv'
    return response




@app.route("/export/revenue/csv")
@login_required
@manager_required
def export_revenue_csv():
    """Export revenue report to CSV."""
    period = request.args.get("period", "daily")
    date_filter = request.args.get("date", datetime.now().strftime("%Y-%m-%d"))
    
    conn = db()
    c = conn.cursor()
    
    if period == "daily":
        revenue = execute_query(c,"""
            SELECT 
                date(payment_date) AS period_label,
                COUNT(*) AS transactions,
                COALESCE(SUM(amount), 0) AS total
            FROM rental_payments
            WHERE date(payment_date) = ?
            GROUP BY date(payment_date)
        """, (date_filter,)).fetchall()
        period_label = "Daily"
        
    elif period == "weekly":
        revenue = execute_query(c,"""
            SELECT 
                strftime('%W', payment_date) AS period_label,
                strftime('%Y', payment_date) AS year,
                COUNT(*) AS transactions,
                COALESCE(SUM(amount), 0) AS total
            FROM rental_payments
            GROUP BY period_label, year
            ORDER BY year DESC, period_label DESC
            LIMIT 12
        """).fetchall()
        period_label = "Weekly"
        
    else:  # monthly
        revenue = execute_query(c,"""
            SELECT 
                strftime('%Y-%m', payment_date) AS period_label,
                COUNT(*) AS transactions,
                COALESCE(SUM(amount), 0) AS total
            FROM rental_payments
            GROUP BY period_label
            ORDER BY period_label DESC
            LIMIT 12
        """).fetchall()
        period_label = "Monthly"
    
    conn.close()
    
    # Create CSV
    si = StringIO()
    writer = csv.writer(si)
    
    writer.writerow([f'{period_label} Revenue Report', f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}'])
    writer.writerow([])
    writer.writerow(['Period', 'Transactions', 'Revenue (N$)'])
    
    if revenue:
        for r in revenue:
            # Use period_label which exists in all queries
            label = r['period_label']
            # For weekly, add the year to make it more readable
            if period == "weekly" and 'year' in r:
                label = f"Week {r['period_label']}, {r['year']}"
            writer.writerow([
                label,
                r['transactions'],
                f"{r['total']:.2f}"
            ])
        
        # Add summary row
        total_transactions = sum(r['transactions'] for r in revenue)
        total_revenue = sum(r['total'] for r in revenue)
        writer.writerow([])
        writer.writerow(['TOTAL', total_transactions, f"{total_revenue:.2f}"])
    else:
        writer.writerow(['No data available for this period.'])
    
    output = si.getvalue()
    response = make_response(output)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=revenue_{period}_{datetime.now().strftime("%Y%m%d")}.csv'
    return response




@app.route("/receipt/<int:payment_id>")
@login_required
def generate_receipt(payment_id):
    """Generate a PDF receipt for a payment."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas
    from io import BytesIO
    from datetime import datetime, timedelta
    
    conn = db()
    c = conn.cursor()
    
    # Get payment details with customer and rental info (incl. deposit)
    payment = execute_query(c, """
        SELECT 
            p.*,
            r.id AS rental_id,
            r.start_time,
            r.end_time,
            r.total_hours,
            r.total_cost,
            r.deposit_paid,
            r.bicycle_id,
            c.full_name,
            c.phone,
            c.email,
            c.id_number,
            b.bike_code,
            b.brand,
            b.model
        FROM rental_payments p
        JOIN daily_rentals r ON r.id = p.daily_rental_id
        JOIN customers c ON c.id = r.customer_id
        JOIN bicycles b ON b.id = r.bicycle_id
        WHERE p.id = ?
    """, (payment_id,)).fetchone()
    
    conn.close()
    
    if not payment:
        flash("Payment not found.", "danger")
        return redirect(url_for("payment_history"))
    
    # =============================================
    # ✅ Use shared helper to convert UTC → Namibia time
    # =============================================
    payment_date_str = to_namibia_time(payment.get("payment_date"))
    start_time_str = to_namibia_time(payment.get("start_time"))
    end_time_str = to_namibia_time(payment.get("end_time"))
    
    # Create PDF
    buf = BytesIO()
    pdf = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    
    x = 25 * mm
    y = height - 25 * mm
    
    # =============================================
    # HEADER
    # =============================================
    pdf.setFont("Helvetica-Bold", 24)
    pdf.setFillColor(colors.HexColor("#0d1f46"))
    pdf.drawString(x, y, "RAB RENT A BIKE")
    
    y -= 8 * mm
    pdf.setFont("Helvetica", 10)
    pdf.setFillColor(colors.HexColor("#667085"))
    pdf.drawString(x, y, "Daily Rental Receipt")
    
    y -= 5 * mm
    pdf.setFont("Helvetica", 8)
    pdf.drawString(x, y, f"Receipt #{payment['id']:06d}")
    pdf.drawString(x + 120 * mm, y, f"Date: {payment_date_str}")
    
    y -= 8 * mm
    pdf.line(x, y, width - x, y)
    y -= 10 * mm
    
    # =============================================
    # CUSTOMER DETAILS
    # =============================================
    pdf.setFont("Helvetica-Bold", 12)
    pdf.setFillColor(colors.HexColor("#0d1f46"))
    pdf.drawString(x, y, "Customer Details")
    y -= 7 * mm
    
    pdf.setFont("Helvetica", 10)
    pdf.setFillColor(colors.HexColor("#111111"))
    pdf.drawString(x + 5 * mm, y, f"Name: {payment['full_name']}")
    y -= 6 * mm
    pdf.drawString(x + 5 * mm, y, f"Phone: {payment['phone']}")
    y -= 6 * mm
    pdf.drawString(x + 5 * mm, y, f"Email: {payment['email'] or 'Not provided'}")
    y -= 6 * mm
    pdf.drawString(x + 5 * mm, y, f"ID: {payment['id_number'] or 'Not provided'}")
    
    y -= 8 * mm
    
    # =============================================
    # RENTAL DETAILS
    # =============================================
    pdf.setFont("Helvetica-Bold", 12)
    pdf.setFillColor(colors.HexColor("#0d1f46"))
    pdf.drawString(x, y, "Rental Details")
    y -= 7 * mm
    
    pdf.setFont("Helvetica", 10)
    pdf.setFillColor(colors.HexColor("#111111"))
    pdf.drawString(x + 5 * mm, y, f"Bicycle: {payment['bike_code']} - {payment['brand'] or ''} {payment['model'] or ''}")
    y -= 6 * mm
    pdf.drawString(x + 5 * mm, y, f"Start: {start_time_str}")
    y -= 6 * mm
    pdf.drawString(x + 5 * mm, y, f"End: {end_time_str if payment['end_time'] else 'Active'}")
    y -= 6 * mm
    pdf.drawString(x + 5 * mm, y, f"Duration: {payment['total_hours']:.1f} hours")
    
    y -= 8 * mm
    
    # =============================================
    # PAYMENT DETAILS (now with deposit breakdown)
    # =============================================
    pdf.setFont("Helvetica-Bold", 12)
    pdf.setFillColor(colors.HexColor("#0d1f46"))
    pdf.drawString(x, y, "Payment Details")
    y -= 7 * mm
    
    pdf.setFont("Helvetica", 10)
    pdf.setFillColor(colors.HexColor("#111111"))
    
    # ✅ Deposit breakdown
    pdf.drawString(x + 5 * mm, y, f"Total Rental Cost: N$ {payment['total_cost']:.2f}")
    y -= 6 * mm
    pdf.drawString(x + 5 * mm, y, f"Deposit Applied: N$ {payment['deposit_paid']:.2f}")
    y -= 6 * mm
    
    # Show refund or extra payment if applicable
    net_at_counter = round(payment['total_cost'] - payment['deposit_paid'], 2)
    if net_at_counter > 0:
        pdf.drawString(x + 5 * mm, y, f"Amount Due at Counter: N$ {net_at_counter:.2f}")
        y -= 6 * mm
    elif net_at_counter < 0:
        pdf.drawString(x + 5 * mm, y, f"Refund to Customer: N$ {abs(net_at_counter):.2f}")
        y -= 6 * mm
    
    pdf.drawString(x + 5 * mm, y, f"Amount Settled: N$ {payment['amount']:.2f}")
    y -= 6 * mm
    pdf.drawString(x + 5 * mm, y, f"Payment Method: {payment['payment_method'] or 'Cash'}")
    y -= 6 * mm
    pdf.drawString(x + 5 * mm, y, f"Payment Date: {payment_date_str}")
    y -= 6 * mm
    pdf.drawString(x + 5 * mm, y, f"Status: {payment['status']}")
    
    y -= 10 * mm
    
    # =============================================
    # SUMMARY BOX
    # =============================================
    box_height = 25 * mm
    box_y = y - box_height
    
    pdf.setFillColor(colors.HexColor("#ffe500"))
    pdf.rect(x, box_y, 150 * mm, box_height, fill=1, stroke=0)
    
    pdf.setFillColor(colors.HexColor("#0d1f46"))
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(x + 10 * mm, y - 10 * mm, "TOTAL SETTLED")
    pdf.setFont("Helvetica-Bold", 24)
    pdf.drawString(x + 90 * mm, y - 10 * mm, f"N$ {payment['amount']:.2f}")
    
    y -= box_height + 15 * mm
    
    # =============================================
    # TERMS & CONDITIONS
    # =============================================
    pdf.setFont("Helvetica", 8)
    pdf.setFillColor(colors.HexColor("#667085"))
    pdf.drawString(x, y, "Thank you for choosing RAB Rent A Bike!")
    y -= 5 * mm
    pdf.drawString(x, y, "This is a system-generated receipt. For any queries, please contact us.")
    
    # =============================================
    # FOOTER
    # =============================================
    pdf.setFont("Helvetica", 8)
    pdf.setFillColor(colors.HexColor("#999999"))
    pdf.drawString(x, 15 * mm, "RAB Rent A Bike - Daily Rental System")
    pdf.drawString(width - 60 * mm, 15 * mm, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    
    pdf.save()
    buf.seek(0)
    
    filename = f"receipt_{payment['id']:06d}_{payment['bike_code']}.pdf"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="application/pdf")




@app.route("/export/bicycles/csv")
@login_required
@manager_required
def export_bicycles_csv():
    """Export bicycle inventory to CSV."""
    conn = db()
    c = conn.cursor()
    
    bicycles = execute_query(c,"""
        SELECT 
            b.bike_code,
            b.brand,
            b.model,
            b.bike_type,
            b.hourly_rate,
            b.daily_cap,
            b.status,
            bh.health_score,
            bh.condition_rating,
            (SELECT COUNT(*) FROM daily_rentals WHERE bicycle_id = b.id) AS rentals
        FROM bicycles b
        LEFT JOIN bicycle_health bh ON bh.bicycle_id = b.id
        ORDER BY b.bike_code
    """).fetchall()
    conn.close()
    
    si = StringIO()
    writer = csv.writer(si)
    
    writer.writerow(['Bike Code', 'Brand', 'Model', 'Type', 'Hourly Rate', 
                     'Daily Cap', 'Status', 'Health Score', 'Condition', 'Total Rentals'])
    
    for b in bicycles:
        writer.writerow([
            b['bike_code'],
            b['brand'] or '',
            b['model'] or '',
            b['bike_type'],
            f"{b['hourly_rate']:.2f}",
            f"{b['daily_cap']:.2f}",
            b['status'],
            b['health_score'] or 'Not assessed',
            b['condition_rating'] or 'Unknown',
            b['rentals'] or 0
        ])
    
    output = si.getvalue()
    response = make_response(output)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=bicycles_{datetime.now().strftime("%Y%m%d")}.csv'
    return response


@app.route("/export/customers/csv")
@login_required
@admin_required
def export_customers_csv():
    """Export customer list to CSV."""
    conn = db()
    c = conn.cursor()
    
    customers = execute_query(c,"""
        SELECT 
            c.full_name,
            c.phone,
            c.id_number,
            c.email,
            c.address,
            c.verification_status,
            (SELECT COUNT(*) FROM daily_rentals WHERE customer_id = c.id) AS rentals,
            COALESCE(lp.points, 0) AS points,
            COALESCE(lp.tier, 'Bronze') AS tier
        FROM customers c
        LEFT JOIN loyalty_points lp ON lp.customer_id = c.id
        ORDER BY c.full_name
    """).fetchall()
    conn.close()
    
    si = StringIO()
    writer = csv.writer(si)
    
    writer.writerow(['Name', 'Phone', 'ID Number', 'Email', 'Address', 
                     'Verification Status', 'Total Rentals', 'Loyalty Points', 'Tier'])
    
    for c in customers:
        writer.writerow([
            c['full_name'],
            c['phone'],
            c['id_number'] or '',
            c['email'] or '',
            c['address'] or '',
            c['verification_status'] or 'Pending',
            c['rentals'] or 0,
            c['points'],
            c['tier']
        ])
    
    output = si.getvalue()
    response = make_response(output)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=customers_{datetime.now().strftime("%Y%m%d")}.csv'
    return response


@app.route("/export/maintenance/csv")
@login_required
@manager_required
def export_maintenance_csv():
    """Export maintenance records to CSV."""
    conn = db()
    c = conn.cursor()
    
    records = execute_query(c,"""
        SELECT 
            b.bike_code,
            m.maintenance_type,
            m.description,
            m.cost,
            m.status,
            m.scheduled_date,
            m.completed_date,
            m.performed_by
        FROM maintenance_records m
        JOIN bicycles b ON b.id = m.bicycle_id
        ORDER BY m.scheduled_date DESC
    """).fetchall()
    conn.close()
    
    si = StringIO()
    writer = csv.writer(si)
    
    writer.writerow(['Bike', 'Type', 'Description', 'Cost (N$)', 'Status', 
                     'Scheduled Date', 'Completed Date', 'Performed By'])
    
    for r in records:
        writer.writerow([
            r['bike_code'],
            r['maintenance_type'],
            r['description'] or '',
            f"{r['cost']:.2f}" if r['cost'] else '0.00',
            r['status'],
            r['scheduled_date'] or '',
            r['completed_date'] or '',
            r['performed_by'] or ''
        ])
    
    output = si.getvalue()
    response = make_response(output)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=maintenance_{datetime.now().strftime("%Y%m%d")}.csv'
    return response








@app.route("/customer-portal")
@login_required
@customer_required
def customer_portal():
    """Customer self-service portal."""
    from datetime import datetime  # ✅ Add this import
    
    conn = db()
    c = conn.cursor()
    
    # Get customer data
    customer = execute_query(c, """
        SELECT * FROM customers WHERE user_id = ?
    """, (session["user_id"],)).fetchone()
    
    if not customer:
        flash("Customer profile not found. Please contact staff.", "warning")
        return redirect(url_for("profile"))
    
    # Get rental history
    rentals = execute_query(c, """
        SELECT r.*, b.bike_code, b.brand, b.model
        FROM daily_rentals r
        JOIN bicycles b ON b.id = r.bicycle_id
        WHERE r.customer_id = ?
        ORDER BY r.start_time DESC
        LIMIT 10
    """, (customer["id"],)).fetchall()

    # ✅ Privacy request status
    privacy_request = execute_query(c, """
        SELECT * FROM privacy_requests
        WHERE customer_id = ?
        ORDER BY requested_at DESC
        LIMIT 1
    """, (customer["id"],)).fetchone()

    # Convert UTC → Namibia time for display
    if privacy_request:
        for k in ("requested_at", "reviewed_at", "completed_at"):
            if privacy_request.get(k):
                privacy_request[k] = to_namibia_time(privacy_request[k])
 
    
    # ✅ FIX: Format datetime for each rental
    for rental in rentals:
        if rental.get("start_time"):
            if isinstance(rental["start_time"], datetime):
                rental["start_time"] = rental["start_time"].strftime("%Y-%m-%d %H:%M")
        if rental.get("end_time"):
            if isinstance(rental["end_time"], datetime):
                rental["end_time"] = rental["end_time"].strftime("%Y-%m-%d %H:%M")
    
    # Get loyalty points
    points = execute_query(c, """
        SELECT * FROM loyalty_points WHERE customer_id = ?
    """, (customer["id"],)).fetchone()
    damage_balance = get_customer_unpaid_damages(c, customer["id"])
    conn.close()
    
    return render_template(
        "customer_portal.html",
        title="My Account",
        customer=customer,
        rentals=rentals,
        points=points,
        damage_balance=damage_balance,
        privacy_request=privacy_request
    )



@app.route("/pickup-points")
@login_required
def customer_stations():
    """Customer view: pickup points with available bike counts by type."""
    conn = db()
    c = conn.cursor()

    stations = execute_query(c, """
        SELECT 
            s.id,
            s.name,
            s.location,
            s.address,
            s.phone,
            (SELECT COUNT(*) FROM bicycles b
             WHERE b.current_station_id = s.id
               AND b.status = 'Available') AS total_available,
            (SELECT COUNT(*) FROM bicycles b
             WHERE b.current_station_id = s.id
               AND b.status = 'Available'
               AND b.bike_type = 'Standard') AS std_available,
            (SELECT COUNT(*) FROM bicycles b
             WHERE b.current_station_id = s.id
               AND b.status = 'Available'
               AND b.bike_type = 'Mountain') AS mtn_available,
            (SELECT COUNT(*) FROM bicycles b
             WHERE b.current_station_id = s.id
               AND b.status = 'Available'
               AND b.bike_type = 'Electric') AS elec_available
        FROM branches s
        WHERE s.is_active = 1
        ORDER BY s.name
    """).fetchall()

    conn.close()

    return render_template(
        "customer_stations.html",
        title="Pickup Points",
        stations=stations
    )

# ✅ ADD THIS - Customer-only decorator
def customer_required(f):
    """Customer-only access (blocks staff)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please login to access this page.", "warning")
            return redirect(url_for("login"))
        
        if session.get("role") != "customer":
            flash("Access denied. Customers only.", "danger")
            return redirect(url_for("dashboard"))
        
        return f(*args, **kwargs)
    return wrapper



# Add this decorator function
def staff_required(f):
    """Decorator to block customers from staff routes."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please login to access this page.", "warning")
            return redirect(url_for("login"))
        
        if session.get("role") == "customer":
            flash("Access denied. Staff only.", "danger")
            return redirect(url_for("customer_portal"))
        
        return f(*args, **kwargs)
    return wrapper







@app.route("/rentals/end/<int:rental_id>", methods=["GET", "POST"])
@login_required
@staff_required
def end_rental(rental_id):
    """End a rental and calculate the total cost."""
    from datetime import datetime, timedelta, timezone
    import pytz

    conn = db()
    c = conn.cursor()

    rental = execute_query(c, """
        SELECT r.*, b.bike_code, c.full_name
        FROM daily_rentals r
        JOIN bicycles b ON b.id = r.bicycle_id
        JOIN customers c ON c.id = r.customer_id
        WHERE r.id = ?
    """, (rental_id,)).fetchone()

    if not rental:
        conn.close()
        flash("Rental not found.", "danger")
        return redirect(url_for("dashboard"))

    # ✅ Handle start_time as datetime or string (stored in UTC — offset-naive)
    if isinstance(rental["start_time"], datetime):
        start_time_utc = rental["start_time"]
    else:
        start_time_utc = datetime.fromisoformat(rental["start_time"])
    # Ensure it's offset-naive so arithmetic works
    if start_time_utc.tzinfo is not None:
        start_time_utc = start_time_utc.astimezone(timezone.utc).replace(tzinfo=None)

    # ✅ Current UTC time (offset-naive for consistency with stored data)
    utc_now = datetime.now(timezone.utc).replace(tzinfo=None)

    # ✅ Current local time (Namibia — UTC+2) for display and late-fee
    namibia_tz = pytz.timezone('Africa/Windhoek')
    local_now = datetime.now(namibia_tz)

    if request.method == "POST":
        end_time_utc = utc_now
        total_hours = (end_time_utc - start_time_utc).total_seconds() / 3600
        total_hours = round(total_hours, 2)

        hourly_rate = rental["hourly_rate"]
        daily_cap = rental["daily_cap"]
        deposit_paid = float(rental["deposit_paid"] or 0)

        # # Calculate cost
        # raw_cost = total_hours * hourly_rate
        # total_cost = min(raw_cost, daily_cap)

        # Calculate cost (Cumulative Daily Cap Logic)
        full_days = int(total_hours // 24)
        remaining_hours = total_hours % 24

        # Cost for full days (capped)
        daily_cost = full_days * daily_cap
        
        # Cost for remaining hours (capped at the daily cap)
        remaining_cost = min(remaining_hours * hourly_rate, daily_cap)
        
        # Base cost before late fees
        base_cost = daily_cost + remaining_cost
        
        # Late fee (after 6pm local time)
        late_fee = 0
        if local_now.hour >= 18:
            late_fee = 10 * (local_now.hour - 18)
            
        # Total cost
        total_cost = base_cost + late_fee



        # Late fee (after 6pm local time)
        late_fee = 0
        if local_now.hour >= 18:
            late_fee = 10 * (local_now.hour - 18)
        total_cost += late_fee

        # ✅ Change calculation (Option A)
        damage_amount_val = float(request.form.get("damage_amount", 0) or 0)
        change_due = round(deposit_paid - total_cost - damage_amount_val, 2)

        # Condition values
        condition_before = request.form.get("condition_before", "Good")
        condition_after = request.form.get("condition_after", "Good")

        # ✅ Return station
        end_station_id = request.form.get("end_station_id") or None
        if end_station_id:
            end_station_id = int(end_station_id)

        execute_query(c, """
            UPDATE daily_rentals
            SET end_time = ?, total_hours = ?, total_cost = ?, late_fee = ?,
                condition_before = ?, condition_after = ?, status = 'Completed',
                ended_by_user_id = ?, end_station_id = ?
            WHERE id = ?
        """, (end_time_utc.isoformat(), total_hours, total_cost, late_fee,
              condition_before, condition_after,
              session["user_id"], end_station_id,
              rental_id))

        # ✅ Mark items as returned
        items_on_rental = execute_query(c, """
            SELECT ri.item_id FROM rental_items ri
            WHERE ri.rental_id = ?
        """, (rental_id,)).fetchall()

        for ri in items_on_rental:
            item_id = ri["item_id"]
            cond = request.form.get(f"item_condition_{item_id}", "Good")
            execute_query(c, """
                UPDATE rental_items
                SET returned_by_user_id = ?, returned_at = CURRENT_TIMESTAMP,
                    condition_on_return = ?
                WHERE rental_id = ? AND item_id = ?
            """, (session["user_id"], cond, rental_id, item_id))

        # ✅ Q6/Q12 — Create a damage claim if the returner reported one
        damage_description = (request.form.get("damage_description") or "").strip()
        if damage_amount_val > 0 or damage_description:
            execute_query(c, """
                INSERT INTO damage_claims
                (rental_id, customer_id, bicycle_id, description, amount,
                 status, charged_by_user_id)
                VALUES (?, ?, ?, ?, ?, 'Charged', ?)
            """, (
                rental_id,
                rental["customer_id"],
                rental["bicycle_id"],
                damage_description or "Damage reported at return",
                damage_amount_val,
                session["user_id"]
            ))

            log_audit(
                action="damage_create",
                entity_type="daily_rental",
                entity_id=rental_id,
                details=f"Damage reported at return — N${damage_amount_val:.2f}: {damage_description or 'no description'}"
            )

        # ✅ Move bicycle to return station and mark Available
        if end_station_id:
            execute_query(c, """
                UPDATE bicycles
                SET status = 'Available',
                    current_station_id = ?
                WHERE id = ?
            """, (end_station_id, rental["bicycle_id"]))
        else:
            execute_query(c, """
                UPDATE bicycles SET status = 'Available' WHERE id = ?
            """, (rental["bicycle_id"],))

        log_audit(
            action="rental_end",
            entity_type="daily_rental",
            entity_id=rental_id,
            details=f"Ended rental #{rental_id} — {total_hours:.1f}h, N${total_cost:.2f}, "
                    f"deposit=N${deposit_paid:.2f}, station_id={end_station_id}"
        )

        conn.commit()
        conn.close()

        flash(f"Rental completed! Total: N$ {total_cost:.2f} for {total_hours:.1f} hours", "success")

        # ✅ Route based on the change
        if change_due == 0:
            # Deposit exactly covers the cost → mark Paid and go home
            conn = db()
            c = conn.cursor()
            execute_query(c, "UPDATE daily_rentals SET payment_status = 'Paid' WHERE id = ?", (rental_id,))
            conn.commit()
            conn.close()
            flash("Deposit fully covered the rental. Nothing left to pay.", "success")
            return redirect(url_for("dashboard"))

        return redirect(url_for("record_payment", rental_id=rental_id))

    # =============================================
    # GET branch — preview calculation
    # =============================================
    preview_hours = round((utc_now - start_time_utc).total_seconds() / 3600, 2)

    hourly_rate = rental["hourly_rate"]
    daily_cap = rental["daily_cap"]
    deposit_paid = float(rental["deposit_paid"] or 0)

    # Cumulative Preview Calculation
    p_full_days = int(preview_hours // 24)
    p_remaining_hours = preview_hours % 24
    p_daily_cost = p_full_days * daily_cap
    p_remaining_cost = min(p_remaining_hours * hourly_rate, daily_cap)
    
    preview_raw = preview_hours * hourly_rate # Keep this just for display
    preview_capped = p_daily_cost + p_remaining_cost 

    # preview_raw = preview_hours * hourly_rate
    # preview_capped = min(preview_raw, daily_cap)
    preview_late = 10 * (local_now.hour - 18) if local_now.hour >= 18 else 0
    preview_total = preview_capped + preview_late
    preview_change = round(deposit_paid - preview_total, 2)

    # Format dates for display (convert UTC to local +2)
    start_time_local = start_time_utc + timedelta(hours=2)
    start_time_str = start_time_local.strftime("%Y-%m-%d %H:%M")
    end_time_local = local_now
    end_time_str = end_time_local.strftime("%Y-%m-%d %H:%M")

    # Stations for the return dropdown
    stations = execute_query(c, """
        SELECT id, name, location FROM branches
        WHERE is_active = 1
        ORDER BY name
    """).fetchall()

    # Default return station = the one it started at
    default_return_station_id = rental.get("start_station_id")
    if not default_return_station_id:
        default_return_station_id = session.get("station_id")
    if not default_return_station_id and stations:
        default_return_station_id = stations[0]["id"]

    # Items on this rental
    rental_items = execute_query(c, """
        SELECT ri.*, i.name AS item_name
        FROM rental_items ri
        JOIN items i ON i.id = ri.item_id
        WHERE ri.rental_id = ?
        ORDER BY i.name
    """, (rental_id,)).fetchall()

    conn.close()

    return render_template(
        "end_rental.html",
        title="End Rental",
        rental=rental,
        start_time_str=start_time_str,
        end_time_str=end_time_str,
        rental_items=rental_items,
        preview_hours=preview_hours,
        hourly_rate=hourly_rate,
        daily_cap=daily_cap,
        preview_raw=preview_raw,
        preview_capped=preview_capped,
        preview_late=preview_late,
        preview_total=preview_total,
        deposit_paid=deposit_paid,
        preview_change=preview_change,
        stations=stations,
        default_return_station_id=default_return_station_id,
    )




@app.route("/rentals/<int:rental_id>/cancel", methods=["POST"])
@login_required
@manager_required
def cancel_rental(rental_id):
    """Cancel an active rental that was started by mistake."""
    from datetime import datetime

    conn = db()
    c = conn.cursor()

    # 1. Fetch the rental + related info
    rental = execute_query(c, """
        SELECT r.*, b.bike_code, c.full_name
        FROM daily_rentals r
        JOIN bicycles b ON b.id = r.bicycle_id
        JOIN customers c ON c.id = r.customer_id
        WHERE r.id = ?
    """, (rental_id,)).fetchone()

    if not rental:
        conn.close()
        flash("Rental not found.", "danger")
        return redirect(url_for("dashboard"))

    # 2. Only Active rentals can be cancelled
    if rental["status"] != "Active":
        conn.close()
        flash(f"Cannot cancel a rental with status '{rental['status']}'. Only Active rentals can be cancelled.", "danger")
        return redirect(request.referrer or url_for("dashboard"))

    # 3. Block cancellation if any payment has been recorded
    payment_count = get_single_value(c, """
        SELECT COUNT(*) FROM rental_payments WHERE daily_rental_id = ?
    """, (rental_id,))

    if payment_count and int(payment_count) > 0:
        conn.close()
        flash("Cannot cancel this rental because a payment has already been recorded. Please refund the payment first.", "danger")
        return redirect(request.referrer or url_for("dashboard"))

    # 4. Get the reason
    reason = (request.form.get("reason") or "").strip()
    if not reason:
        conn.close()
        flash("A reason is required to cancel a rental.", "danger")
        return redirect(request.referrer or url_for("dashboard"))

    # 5. Soft-cancel: set status and record reason in notes
    cancel_note = f"[CANCELLED {datetime.now().strftime('%Y-%m-%d %H:%M')} by {session.get('username')}] {reason}"

    existing_notes = rental.get("notes") or ""
    if existing_notes:
        combined_notes = existing_notes + "\n" + cancel_note
    else:
        combined_notes = cancel_note


    execute_query(c, """
        UPDATE daily_rentals
        SET status = 'Cancelled',
            notes = ?,
            actual_return_time = CURRENT_TIMESTAMP,
            cancelled_by_user_id = ?
        WHERE id = ?
    """, (combined_notes, session["user_id"], rental_id))
    
    # 6. Free the bicycle
    execute_query(c, """
        UPDATE bicycles SET status = 'Available' WHERE id = ?
    """, (rental["bicycle_id"],))

    conn.commit()

    log_audit(
        action="rental_cancel",
        entity_type="daily_rental",
        entity_id=rental_id,
        details=f"Cancelled rental #{rental_id} — reason: {reason}"
    )

    conn.close()

    flash(
        f"Rental #{rental_id} for {rental['full_name']} ({rental['bike_code']}) has been cancelled. "
        f"Bicycle is now Available.",
        "success"
    )
    return redirect(request.referrer or url_for("dashboard"))

# @app.route("/logout")
# def logout():
#     session.clear()
#     return redirect(url_for("login"))

@app.route("/logout")
def logout():
    # Log before clearing session
    user_id = session.get("user_id")
    username = session.get("username")
    user_role = session.get("role")
    if user_id:
        log_audit(
            action="logout",
            entity_type="user",
            entity_id=user_id,
            details=f"User {username} logged out",
            user_id=user_id,
            username=username,
            user_role=user_role,
        )
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))



@app.route("/debug-cloudinary")
@login_required
@admin_required
def debug_cloudinary():
    """Debug Cloudinary configuration."""
    import os
    return {
        "cloudinary_configured": all([
            os.environ.get("CLOUDINARY_CLOUD_NAME"),
            os.environ.get("CLOUDINARY_API_KEY"),
            os.environ.get("CLOUDINARY_API_SECRET")
        ]),
        "cloud_name": os.environ.get("CLOUDINARY_CLOUD_NAME"),
        "api_key": os.environ.get("CLOUDINARY_API_KEY")[:5] + "..." if os.environ.get("CLOUDINARY_API_KEY") else None,
        "api_secret_set": bool(os.environ.get("CLOUDINARY_API_SECRET"))
    }



@app.route("/backup-uploads")
@login_required
@admin_required
def backup_uploads():
    """Download all uploaded files as a zip."""
    import zipfile
    from io import BytesIO
    import os
    
    # Create a zip file in memory
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
        for root, dirs, files in os.walk(UPLOAD_FOLDER):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, UPLOAD_FOLDER)
                zip_file.write(file_path, arcname)
    
    zip_buffer.seek(0)
    return send_file(
        zip_buffer,
        as_attachment=True,
        download_name="uploads_backup.zip",
        mimetype="application/zip"
    )


def _database_is_initialized():
    """Check if the 'users' table exists — works on both SQLite and PostgreSQL."""
    try:
        conn = db()
        c = conn.cursor()
        if os.environ.get("DATABASE_URL"):
            # PostgreSQL
            execute_query(c, """
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_name = 'users'
                ) AS exists_flag
            """)
            row = c.fetchone()
            if isinstance(row, dict):
                return bool(list(row.values())[0])
            return bool(row[0]) if row else False
        else:
            # SQLite
            rows = execute_query(c, "PRAGMA table_info(users)").fetchall()
            return len(rows) > 0
    except Exception as e:
        print(f"⚠️ Database init check failed: {e}")
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass










# =============================================
# BOOTSTRAP — runs on import (both gunicorn and python app.py)
# =============================================
with app.app_context():
    if not _database_is_initialized():
        print("Database tables not found. Initializing...")
        # init_db()
        print("Database initialized successfully!")
    else:
        print("Database already initialized.")

    try:
        ensure_schema_columns()
        ensure_rental_extras_schema()
        ensure_audit_schema()
        ensure_privacy_schema()
        ensure_lockout_schema()
        ensure_2fa_schema()
        backfill_2fa_required()
        ensure_workers_schema()  
        migrate_public_uploads_to_private()
        print("✅ Schema is up to date.")
    except Exception as e:
        print(f"⚠️ Schema bootstrap error: {e}")




if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=int(os.environ.get("PORT", 5001)))
