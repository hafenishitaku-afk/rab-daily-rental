import os
import csv
import sqlite3
import smtplib
from io import StringIO, BytesIO
from pathlib import Path
from functools import wraps
from datetime import datetime, date, timedelta

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, make_response
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

# =============================================
# LOAD ENVIRONMENT VARIABLES
# =============================================
load_dotenv()

# =============================================
# BASE PATH
# =============================================
BASE = Path(__file__).resolve().parent
DB = BASE / "rab.db"

# =============================================
# CREATE APP
# =============================================
app = Flask(__name__)

# Secret key - use environment variable in production
app.secret_key = os.environ.get("SECRET_KEY", "daily-rental-secret-key")

# =============================================
# UPLOAD FOLDER
# =============================================
UPLOAD_FOLDER = os.path.join(BASE, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)



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
        conn.row_factory = sqlite3.Row
        return conn




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


# def format_date(date_value, format_str="%Y-%m-%d"):
#     """Format a date value for display (handles both string and datetime)."""
#     if date_value is None:
#         return ""
#     if isinstance(date_value, datetime):
#         return date_value.strftime(format_str)
#     if isinstance(date_value, str):
#         return date_value[:10]
#     return str(date_value)

def format_date(date_value, format_str="%Y-%m-%d"):
    """Format a date value for display (handles both string and datetime)."""
    from datetime import datetime
    
    if date_value is None:
        return ""
    if isinstance(date_value, datetime):
        return date_value.strftime(format_str)
    if isinstance(date_value, str):
        # ✅ Return as is, or truncate safely
        try:
            # Try to parse as datetime
            dt = datetime.fromisoformat(date_value.replace('Z', '+00:00'))
            return dt.strftime(format_str)
        except:
            # If parsing fails, return the string as is
            return date_value
    return str(date_value)




def get_duration_sql():
    """Return the correct duration SQL for the database."""
    if os.environ.get("DATABASE_URL"):
        return "TO_CHAR(CURRENT_TIMESTAMP, 'HH24:MI') AS duration"
    else:
        return "strftime('%H:%M', 'now', 'localtime') AS duration"


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
EMAIL_ENABLED = True
EMAIL_HOST = os.environ.get("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", 587))
EMAIL_USER = os.environ.get("EMAIL_USER", "your-email@gmail.com")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "your-app-password")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "noreply@rab.com")

# SMS settings
SMS_ENABLED = False  # Set to True when Twilio is configured





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
    
    if count == 0:
        if is_postgres:
            execute_query(c, "INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) VALUES ('Standard', 20, 120, 50)")
            execute_query(c, "INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) VALUES ('Electric', 30, 180, 75)")
            execute_query(c, "INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) VALUES ('Mountain', 25, 150, 60)")
        else:
            c.executescript("""
                INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) 
                VALUES ('Standard', 20, 120, 50);
                INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) 
                VALUES ('Electric', 30, 180, 75);
                INSERT INTO daily_rates (bike_type, hourly_rate, daily_cap, deposit) 
                VALUES ('Mountain', 25, 150, 60);
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



@app.route("/")
def home():
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))



@app.route("/login", methods=["GET", "POST"])
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
        
        
        if user and check_password_hash(user["password_hash"], password):
            # ✅ Check if user is customer - redirect to customer portal
            if user["role"] == "customer":
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                session["full_name"] = user["full_name"]
                
                # Get customer ID
                conn = db()
                c = conn.cursor()
                customer = execute_query(c,
                    "SELECT id FROM customers WHERE user_id = ?", 
                    (user["id"],)
                ).fetchone()
                conn.close()
                
                if customer:
                    session["customer_id"] = customer["id"]
                
                flash(f"Welcome back, {user['full_name'] or user['username']}!", "success")
                return redirect(url_for("customer_portal"))
            
            # Staff user
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["full_name"] = user["full_name"]
            
            flash(f"Welcome back, {user['full_name'] or user['username']}!", "success")
            return redirect(url_for("dashboard"))
        
        flash("Invalid username or password.", "danger")
    
    return render_template("login.html", title="Login - Daily Rentals")




@app.route("/customer-login", methods=["GET", "POST"])
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
        conn.close()
        
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["full_name"] = user["full_name"]
            
            # Get customer ID
            conn = db()
            c = conn.cursor()
            customer = execute_query(c,
                "SELECT id FROM customers WHERE user_id = ?", 
                (user["id"],)
            ).fetchone()
            conn.close()
            
            if customer:
                session["customer_id"] = customer["id"]
            
            flash(f"Welcome back, {user['full_name']}!", "success")
            return redirect(url_for("customer_portal"))
        
        flash("Invalid username or password.", "danger")
    
    return render_template("customer_login.html", title="Customer Login")



#KAMWE OKOHAKA NATANGO NGII MAALA INAKAPWA KAA. TYEKA SHITIIKA DESING NAWA NAWA





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

# def staff_required(f):
#     """Decorator for all logged-in users."""
#     return login_required(f)


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





# =============================================
# USER MANAGEMENT ROUTES
# =============================================


@app.route("/users")
@login_required
@admin_required
def users():
    """View all users (Admin only)."""
    conn = db()
    c = conn.cursor()
    
    users_list = execute_query(c, """
        SELECT id, username, role, full_name, email, created_at
        FROM users
        ORDER BY role, username
    """).fetchall()
    
    conn.close()
    
    # ✅ Format datetime for each user
    # for user in users_list:
    #     if user.get("created_at"):
    #         if isinstance(user["created_at"], datetime):
    #             user["created_at"] = user["created_at"].strftime("%Y-%m-%d")
    #         elif isinstance(user["created_at"], str):
    #             user["created_at"] = user["created_at"][:10]


# ✅ Format datetime for each user
    for user in users_list:
        if user.get("created_at"):
            if isinstance(user["created_at"], datetime):
                user["created_at"] = user["created_at"].strftime("%Y-%m-%d")
            elif isinstance(user["created_at"], str):
                user["created_at"] = user["created_at"]  # ✅ Return as is    
    
    return render_template("users.html", title="User Management", users=users_list)



@app.route("/users/add", methods=["GET", "POST"])
@login_required
@admin_required
def add_user():
    """Add a new user (Admin only)."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "staff")
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        
        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("add_user"))
        
        conn = db()
        c = conn.cursor()
        
        try:
            execute_query(c,"""
                INSERT INTO users (username, password_hash, role, full_name, email)
                VALUES (?, ?, ?, ?, ?)
            """, (username, generate_password_hash(password), role, full_name, email))
            conn.commit()
            flash(f"User '{username}' created successfully!", "success")
        except sqlite3.IntegrityError:
            flash(f"Username '{username}' already exists.", "danger")
        finally:
            conn.close()
        
        return redirect(url_for("users"))
    
    return render_template("add_user.html", title="Add User")


@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def edit_user(user_id):
    """Edit a user (Admin only)."""
    conn = db()
    c = conn.cursor()
    
    user = execute_query(c,"SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("users"))
    
    if request.method == "POST":
        role = request.form.get("role", "staff")
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        new_password = request.form.get("new_password", "").strip()
        
        if new_password:
            execute_query(c,"""
                UPDATE users 
                SET role = ?, full_name = ?, email = ?, password_hash = ?
                WHERE id = ?
            """, (role, full_name, email, generate_password_hash(new_password), user_id))
        else:
            execute_query(c,"""
                UPDATE users 
                SET role = ?, full_name = ?, email = ?
                WHERE id = ?
            """, (role, full_name, email, user_id))
        
        conn.commit()
        conn.close()
        
        flash(f"User '{user['username']}' updated successfully!", "success")
        return redirect(url_for("users"))
    
    conn.close()
    return render_template("edit_user.html", title="Edit User", user=user)




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
        new_password = request.form.get("new_password", "").strip()
        
        if not new_password or len(new_password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return redirect(url_for("reset_customer_password", customer_id=customer_id))
        
        # Update password
        execute_query(c,"""
            UPDATE users 
            SET password_hash = ? 
            WHERE id = ?
        """, (generate_password_hash(new_password), customer["user_id"]))
        
        conn.commit()
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
        conn.close()
        
        flash("Profile updated successfully!", "success")
        return redirect(url_for("profile"))
    
    conn.close()
    return render_template("profile.html", title="My Profile", user=user)









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
    """Customer view - browse available bikes (cannot start rental)."""
    conn = db()
    c = conn.cursor()
    
    # Get available bikes only
    bikes = execute_query(c,"""
        SELECT * FROM bicycles 
        WHERE status = 'Available'
        ORDER BY bike_code
    """).fetchall()
    
    conn.close()
    
    return render_template(
        "customer_rent.html",
        title="Available Bicycles",
        bikes=bikes
    )





@app.route("/dashboard")
@login_required
@staff_required
def dashboard():
    """Staff dashboard - NOT for customers."""
    conn = db()
    c = conn.cursor()
    
    # Stats - using get_single_value helper
    total_bikes = get_single_value(c, "SELECT COUNT(*) FROM bicycles WHERE status = 'Available'")
    active_rentals = get_single_value(c, "SELECT COUNT(*) FROM daily_rentals WHERE status = 'Active'")
    total_customers = get_single_value(c, "SELECT COUNT(*) FROM customers")
    pending_verification = get_single_value(c, "SELECT COUNT(*) FROM customers WHERE verification_status = 'Pending'")
    today_revenue = get_single_value(c, "SELECT COALESCE(SUM(total_cost), 0) FROM daily_rentals WHERE date(created_at) = date('now') AND status = 'Completed' AND payment_status = 'Paid'")
    

        
    duration_sql = get_duration_sql()
    rentals = execute_query(c, f"""
        SELECT 
            r.id,
            c.full_name,
            b.bike_code,
            r.start_time,
            {duration_sql}
        FROM daily_rentals r
        JOIN customers c ON c.id = r.customer_id
        JOIN bicycles b ON b.id = r.bicycle_id
        WHERE r.status = 'Active'
        ORDER BY r.start_time DESC
    """).fetchall()


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
    
    conn.close()
    
    return render_template(
        "dashboard.html",
        title="Dashboard - Daily Rentals",
        total_bikes=total_bikes,
        active_rentals=active_rentals,
        total_customers=total_customers,
        pending_verification=pending_verification,
        today_revenue=today_revenue,
        rentals=rentals,
        unpaid_rentals=unpaid_rentals
    )




@app.route("/rentals/start", methods=["GET", "POST"])
@login_required
@staff_required
def start_rental():
    conn = db()
    c = conn.cursor()
    
    if request.method == "POST":
        customer_id = request.form.get("customer_id")
        bicycle_id = request.form.get("bicycle_id")
        start_time = request.form.get("start_time")
        
        # Verify customer is verified
        customer = execute_query(c,
            "SELECT verification_status FROM customers WHERE id = ?",
            (customer_id,)
        ).fetchone()
        
        if not customer or customer["verification_status"] != "Verified":
            flash("Customer must be verified before renting.", "danger")
            return redirect(url_for("start_rental"))
        
        bike = execute_query(c,
            "SELECT hourly_rate, daily_cap, deposit_amount FROM bicycles WHERE id = ?",
            (bicycle_id,)
        ).fetchone()
        
        if not bike:
            flash("Bicycle not found.", "danger")
            return redirect(url_for("start_rental"))
        
        execute_query(c,"""
            INSERT INTO daily_rentals (
                customer_id, bicycle_id, start_time, 
                hourly_rate, daily_cap, deposit_paid, status,
                agreement_signed
            ) VALUES (?, ?, ?, ?, ?, ?, 'Active', 1)
        """, (
            customer_id, bicycle_id, start_time,
            bike["hourly_rate"], bike["daily_cap"], bike["deposit_amount"]
        ))
        
        rental_id = c.lastrowid
        
        execute_query(c,"UPDATE bicycles SET status = 'Rented' WHERE id = ?", (bicycle_id,))
        
        conn.commit()
        conn.close()
        
        flash(f"Rental started successfully! Rental ID: {rental_id}", "success")
        return redirect(url_for("dashboard"))
    
    customers = execute_query(c,
        "SELECT id, full_name, phone FROM customers WHERE verification_status = 'Verified' ORDER BY full_name"
    ).fetchall()
    
    bicycles = execute_query(c,
        "SELECT id, bike_code, brand, model, hourly_rate, daily_cap FROM bicycles WHERE status = 'Available'"
    ).fetchall()
    
    conn.close()
    
    return render_template(
        "start_rental.html",
        title="Start Rental",
        customers=customers,
        bicycles=bicycles,
        now=datetime.now().strftime("%Y-%m-%dT%H:%M")
    )




@app.route("/customers", methods=["GET", "POST"])
@login_required
@staff_required
def customers():
    import os  # ✅ Add this import
    conn = db()
    c = conn.cursor()
    
    is_postgres = os.environ.get("DATABASE_URL") is not None
    
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        phone = request.form.get("phone", "").strip()
        id_number = request.form.get("id_number", "").strip()
        email = request.form.get("email", "").strip()
        address = request.form.get("address", "").strip()
        id_photo = request.files.get("id_photo") if request.files else None
        customer_photo = request.files.get("customer_photo") if request.files else None
        
        # ✅ FIX: Convert checkbox to integer (1 or 0) for PostgreSQL
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
        
        # Check if username already exists
        existing_user = execute_query(c, "SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing_user:
            if email:
                username = email
            else:
                username = f"cust_{phone}"
        
        # Generate a random password
        import secrets
        import string
        temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
        password_hash = generate_password_hash(temp_password)
        
        # Insert user with role 'customer'
        try:
            execute_query(c, """
                INSERT INTO users (username, password_hash, role, full_name, email)
                VALUES (?, ?, 'customer', ?, ?)
            """, (username, password_hash, full_name, email))
            
            # Get the user ID after insert
            user_result = execute_query(c, "SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if user_result:
                user_id = user_result['id'] if isinstance(user_result, dict) else user_result[0]
            else:
                flash("Error: User created but ID not found.", "danger")
                return redirect(url_for("customers"))
                
        except sqlite3.IntegrityError:
            flash(f"Username '{username}' already exists. Please use a different phone or email.", "danger")
            return redirect(url_for("customers"))
        
        # Insert customer with user_id
        execute_query(c, """
            INSERT INTO customers (
                full_name, id_number, phone, email, address, user_id,
                terms_accepted, terms_accepted_date, signature_data, verification_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, 'Pending')
        """, (full_name, id_number, phone, email, address, user_id, 
              terms_accepted, signature_data))
        
        customer_id = c.lastrowid
        
        # If PostgreSQL, get the customer ID differently
        if is_postgres:
            customer_result = execute_query(c, "SELECT id FROM customers WHERE user_id = ?", (user_id,)).fetchone()
            if customer_result:
                customer_id = customer_result['id'] if isinstance(customer_result, dict) else customer_result[0]
        
        session["customer_id"] = customer_id
        
        # Save uploaded files
        from werkzeug.utils import secure_filename
        
        UPLOAD_FOLDER = os.path.join(BASE, 'static', 'uploads')
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        
        if id_photo and id_photo.filename:
            filename = f"id_{customer_id}_{secure_filename(id_photo.filename)}"
            id_photo.save(os.path.join(UPLOAD_FOLDER, filename))
            execute_query(c, """
                INSERT INTO customer_documents (customer_id, document_type, file_path)
                VALUES (?, 'id_copy', ?)
            """, (customer_id, f"uploads/{filename}"))
        
        if customer_photo and customer_photo.filename:
            filename = f"photo_{customer_id}_{secure_filename(customer_photo.filename)}"
            customer_photo.save(os.path.join(UPLOAD_FOLDER, filename))
            execute_query(c, """
                INSERT INTO customer_documents (customer_id, document_type, file_path)
                VALUES (?, 'customer_photo', ?)
            """, (customer_id, f"uploads/{filename}"))
        
        conn.commit()
        conn.close()
        
        flash(f"Customer '{full_name}' registered successfully!", "success")
        flash(f"🔑 Login Credentials - Username: {username}, Password: {temp_password}", "success")
        flash("📌 Please give these credentials to the customer.", "info")
        
        return redirect(url_for("customers"))
    
    # GET request - show customers list
    customers = execute_query(c, "SELECT * FROM customers ORDER BY full_name").fetchall()
    conn.close()
    
    return render_template("customers.html", title="Customers", customers=customers)


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
    conn = db()
    c = conn.cursor()
    
    doc = execute_query(c,"""
        SELECT * FROM customer_documents 
        WHERE id = ? AND customer_id = ?
    """, (doc_id, customer_id)).fetchone()
    conn.close()
    
    if not doc:
        flash("Document not found.", "danger")
        return redirect(url_for("customers"))
    
    return render_template(
        "view_document.html",
        title="View Document",
        doc=doc,
        customer_id=customer_id
    )



@app.route("/rentals/<int:rental_id>/payment", methods=["GET", "POST"])
@login_required
def record_payment(rental_id):
    from datetime import datetime  # ✅ Add this import
    
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
        flash("Rental not found.", "danger")
        return redirect(url_for("dashboard"))
    
    # ✅ FIX: Format datetime for display
    if rental.get("start_time"):
        if isinstance(rental["start_time"], datetime):
            rental["start_time"] = rental["start_time"].strftime("%Y-%m-%d %H:%M")
    
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
            SET payment_status = 'Paid' 
            WHERE id = ?
        """, (rental_id,))
        
        conn.commit()
        conn.close()
        
        flash(f"Payment of N$ {amount:.2f} recorded successfully!", "success")
        return redirect(url_for("payment_history"))
    
    # Get total payments for this rental
    total_paid = get_single_value(c, """
        SELECT COALESCE(SUM(amount), 0) 
        FROM rental_payments 
        WHERE daily_rental_id = ?
    """, (rental_id,))
    
    remaining_balance = rental["total_cost"] - total_paid if rental["total_cost"] else 0
    
    conn.close()
    
    return render_template(
        "record_payment.html",
        title="Record Payment",
        rental=rental,
        total_paid=total_paid,
        remaining_balance=remaining_balance
    )

# @app.route("/rentals/<int:rental_id>/payment", methods=["GET", "POST"])
# @login_required
# def record_payment(rental_id):
#     conn = db()
#     c = conn.cursor()
    
#     rental = execute_query(c, """
#         SELECT r.*, c.full_name, b.bike_code
#         FROM daily_rentals r
#         JOIN customers c ON c.id = r.customer_id
#         JOIN bicycles b ON b.id = r.bicycle_id
#         WHERE r.id = ?
#     """, (rental_id,)).fetchone()
    
#     if not rental:
#         flash("Rental not found.", "danger")
#         return redirect(url_for("dashboard"))
    
#     if request.method == "POST":
#         amount = float(request.form.get("amount", 0))
#         payment_method = request.form.get("payment_method", "Cash")
        
#         if amount <= 0:
#             flash("Payment amount must be greater than zero.", "danger")
#             return redirect(url_for("record_payment", rental_id=rental_id))
        
#         # Record the payment
#         execute_query(c, """
#             INSERT INTO rental_payments (daily_rental_id, amount, payment_method, status)
#             VALUES (?, ?, ?, 'Completed')
#         """, (rental_id, amount, payment_method))
        
#         # Update rental payment status
#         execute_query(c, """
#             UPDATE daily_rentals 
#             SET payment_status = 'Paid' 
#             WHERE id = ?
#         """, (rental_id,))
        
#         conn.commit()
#         conn.close()
        
#         flash(f"Payment of N$ {amount:.2f} recorded successfully!", "success")
#         return redirect(url_for("payment_history"))
    
#     # ✅ FIX: Use rental_id, not user_id
#     # Get total payments for this rental (if needed)
#     total_paid = get_single_value(c, """
#         SELECT COALESCE(SUM(amount), 0) 
#         FROM rental_payments 
#         WHERE daily_rental_id = ?
#     """, (rental_id,))
    
#     # If rental has a total_cost, calculate remaining balance
#     remaining_balance = rental["total_cost"] - total_paid if rental["total_cost"] else 0
    
#     conn.close()
    
#     return render_template(
#         "record_payment.html",
#         title="Record Payment",
#         rental=rental,
#         total_paid=total_paid,
#         remaining_balance=remaining_balance
#     )





# @app.route("/payments")
# @login_required
# def payment_history():
#     """Payment history - shows all payments."""
#     conn = db()
#     c = conn.cursor()
    
#     payments = execute_query(c, """
#         SELECT 
#             p.*,
#             r.id AS rental_id,
#             b.bike_code,
#             c.full_name
#         FROM rental_payments p
#         JOIN daily_rentals r ON r.id = p.daily_rental_id
#         JOIN bicycles b ON b.id = r.bicycle_id
#         JOIN customers c ON c.id = r.customer_id
#         ORDER BY p.payment_date DESC
#         LIMIT 50
#     """).fetchall()
    
#     # Get total revenue
#     total_revenue = get_single_value(c, "SELECT COALESCE(SUM(amount), 0) FROM rental_payments")
    
#     conn.close()
    
#     return render_template(
#         "payment_history.html",
#         title="Payment History",
#         payments=payments,
#         total_revenue=total_revenue
#     )

@app.route("/payments")
@login_required
@staff_required
def payment_history():
    """Payment history - shows all payments."""
    from datetime import datetime  # ✅ Add this import
    
    conn = db()
    c = conn.cursor()
    
    payments = execute_query(c, """
        SELECT 
            p.*,
            r.id AS rental_id,
            b.bike_code,
            c.full_name
        FROM rental_payments p
        JOIN daily_rentals r ON r.id = p.daily_rental_id
        JOIN bicycles b ON b.id = r.bicycle_id
        JOIN customers c ON c.id = r.customer_id
        ORDER BY p.payment_date DESC
        LIMIT 50
    """).fetchall()
    
    # # ✅ FIX: Format datetime for each payment
    for payment in payments: 
        # ✅ Format datetime properly
        if payment.get("payment_date"):
            if isinstance(payment["payment_date"], datetime):
                payment["payment_date"] = payment["payment_date"].strftime("%Y-%m-%d %H:%M")
            elif isinstance(payment["payment_date"], str):
                payment["payment_date"] = payment["payment_date"]  # Return as is


    # Get total revenue
    total_revenue = get_single_value(c, "SELECT COALESCE(SUM(amount), 0) FROM rental_payments")
    
    conn.close()
    
    return render_template(
        "payment_history.html",
        title="Payment History",
        payments=payments,
        total_revenue=total_revenue
    )



@app.route("/reports/revenue")
@login_required
@manager_required
def revenue_report():
    """Revenue report with daily/weekly/monthly views."""
    conn = db()
    c = conn.cursor()
    
    is_postgres = os.environ.get("DATABASE_URL") is not None
    
    # Get date range from query parameters
    period = request.args.get("period", "daily")
    date_filter = request.args.get("date", datetime.now().strftime("%Y-%m-%d"))
    
    if period == "daily":
        if is_postgres:
            # PostgreSQL syntax
            daily_revenue = execute_query(c, """
                SELECT 
                    DATE(r.payment_date) AS date,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(r.amount), 0) AS total,
                    STRING_AGG(DISTINCT b.bike_code, ', ') AS bikes_rented
                FROM rental_payments r
                JOIN daily_rentals dr ON dr.id = r.daily_rental_id
                JOIN bicycles b ON b.id = dr.bicycle_id
                WHERE DATE(r.payment_date) = %s
                GROUP BY DATE(r.payment_date)
                ORDER BY DATE(r.payment_date) DESC
            """, (date_filter,)).fetchall()
            
            daily_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(amount), 0) AS total,
                    COUNT(*) AS transactions,
                    COUNT(DISTINCT dr.customer_id) AS unique_customers
                FROM rental_payments r
                JOIN daily_rentals dr ON dr.id = r.daily_rental_id
                WHERE DATE(r.payment_date) = %s
            """, (date_filter,)).fetchone()
            
            available_dates = execute_query(c, """
                SELECT DISTINCT DATE(payment_date) AS date
                FROM rental_payments
                ORDER BY date DESC
            """).fetchall()
            
            weekly_trend = execute_query(c, """
                SELECT 
                    DATE(r.payment_date) AS date,
                    COALESCE(SUM(r.amount), 0) AS total
                FROM rental_payments r
                WHERE DATE(r.payment_date) >= CURRENT_DATE - INTERVAL '7 days'
                GROUP BY DATE(r.payment_date)
                ORDER BY DATE(r.payment_date) ASC
            """).fetchall()
        else:
            # SQLite syntax
            daily_revenue = execute_query(c, """
                SELECT 
                    date(r.payment_date) AS date,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(r.amount), 0) AS total,
                    GROUP_CONCAT(DISTINCT b.bike_code) AS bikes_rented
                FROM rental_payments r
                JOIN daily_rentals dr ON dr.id = r.daily_rental_id
                JOIN bicycles b ON b.id = dr.bicycle_id
                WHERE date(r.payment_date) = ?
                GROUP BY date(r.payment_date)
                ORDER BY date(r.payment_date) DESC
            """, (date_filter,)).fetchall()
            
            daily_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(amount), 0) AS total,
                    COUNT(*) AS transactions,
                    COUNT(DISTINCT dr.customer_id) AS unique_customers
                FROM rental_payments r
                JOIN daily_rentals dr ON dr.id = r.daily_rental_id
                WHERE date(r.payment_date) = ?
            """, (date_filter,)).fetchone()
            
            available_dates = execute_query(c, """
                SELECT DISTINCT date(payment_date) AS date
                FROM rental_payments
                ORDER BY date DESC
            """).fetchall()
            
            weekly_trend = execute_query(c, """
                SELECT 
                    date(r.payment_date) AS date,
                    COALESCE(SUM(r.amount), 0) AS total
                FROM rental_payments r
                WHERE date(r.payment_date) >= date('now', '-7 days')
                GROUP BY date(r.payment_date)
                ORDER BY date(r.payment_date) ASC
            """).fetchall()
        
        report_title = f"Revenue Report - {date_filter}"
        
    elif period == "weekly":
        year = request.args.get("year", datetime.now().strftime("%Y"))
        week = request.args.get("week", datetime.now().strftime("%W"))
        
        if is_postgres:
            # PostgreSQL syntax
            weekly_revenue = execute_query(c, """
                SELECT 
                    EXTRACT(WEEK FROM r.payment_date) AS week,
                    EXTRACT(YEAR FROM r.payment_date) AS year,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(r.amount), 0) AS total
                FROM rental_payments r
                WHERE EXTRACT(WEEK FROM r.payment_date) = %s
                AND EXTRACT(YEAR FROM r.payment_date) = %s
                GROUP BY EXTRACT(WEEK FROM r.payment_date), EXTRACT(YEAR FROM r.payment_date)
                ORDER BY year DESC, week DESC
            """, (week, year)).fetchall()
            
            weekly_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(amount), 0) AS total,
                    COUNT(*) AS transactions,
                    COUNT(DISTINCT dr.customer_id) AS unique_customers
                FROM rental_payments r
                JOIN daily_rentals dr ON dr.id = r.daily_rental_id
                WHERE EXTRACT(WEEK FROM r.payment_date) = %s
                AND EXTRACT(YEAR FROM r.payment_date) = %s
            """, (week, year)).fetchone()
            
            available_weeks = execute_query(c, """
                SELECT DISTINCT 
                    EXTRACT(WEEK FROM payment_date) AS week,
                    EXTRACT(YEAR FROM payment_date) AS year
                FROM rental_payments
                ORDER BY year DESC, week DESC
                LIMIT 20
            """).fetchall()
        else:
            # SQLite syntax
            weekly_revenue = execute_query(c, """
                SELECT 
                    strftime('%W', r.payment_date) AS week,
                    strftime('%Y', r.payment_date) AS year,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(r.amount), 0) AS total
                FROM rental_payments r
                WHERE strftime('%W', r.payment_date) = ?
                AND strftime('%Y', r.payment_date) = ?
                GROUP BY strftime('%W', r.payment_date), strftime('%Y', r.payment_date)
                ORDER BY year DESC, week DESC
            """, (week, year)).fetchall()
            
            weekly_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(amount), 0) AS total,
                    COUNT(*) AS transactions,
                    COUNT(DISTINCT dr.customer_id) AS unique_customers
                FROM rental_payments r
                JOIN daily_rentals dr ON dr.id = r.daily_rental_id
                WHERE strftime('%W', r.payment_date) = ?
                AND strftime('%Y', r.payment_date) = ?
            """, (week, year)).fetchone()
            
            available_weeks = execute_query(c, """
                SELECT DISTINCT 
                    strftime('%W', payment_date) AS week,
                    strftime('%Y', payment_date) AS year
                FROM rental_payments
                ORDER BY year DESC, week DESC
                LIMIT 20
            """).fetchall()
        
        daily_revenue = weekly_revenue
        available_dates = available_weeks
        report_title = f"Weekly Revenue Report - Week {week}, {year}"
        
    else:  # monthly
        month_filter = request.args.get("month", datetime.now().strftime("%Y-%m"))
        
        if is_postgres:
            # PostgreSQL syntax
            monthly_revenue = execute_query(c, """
                SELECT 
                    TO_CHAR(r.payment_date, 'YYYY-MM') AS month,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(r.amount), 0) AS total,
                    COUNT(DISTINCT dr.customer_id) AS unique_customers
                FROM rental_payments r
                JOIN daily_rentals dr ON dr.id = r.daily_rental_id
                WHERE TO_CHAR(r.payment_date, 'YYYY-MM') = %s
                GROUP BY TO_CHAR(r.payment_date, 'YYYY-MM')
                ORDER BY month DESC
            """, (month_filter,)).fetchall()
            
            monthly_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(amount), 0) AS total,
                    COUNT(*) AS transactions,
                    COUNT(DISTINCT dr.customer_id) AS unique_customers
                FROM rental_payments r
                JOIN daily_rentals dr ON dr.id = r.daily_rental_id
                WHERE TO_CHAR(r.payment_date, 'YYYY-MM') = %s
            """, (month_filter,)).fetchone()
            
            available_months = execute_query(c, """
                SELECT DISTINCT TO_CHAR(payment_date, 'YYYY-MM') AS month
                FROM rental_payments
                ORDER BY month DESC
            """).fetchall()
        else:
            # SQLite syntax
            monthly_revenue = execute_query(c, """
                SELECT 
                    strftime('%Y-%m', r.payment_date) AS month,
                    COUNT(*) AS transactions,
                    COALESCE(SUM(r.amount), 0) AS total,
                    COUNT(DISTINCT dr.customer_id) AS unique_customers
                FROM rental_payments r
                JOIN daily_rentals dr ON dr.id = r.daily_rental_id
                WHERE strftime('%Y-%m', r.payment_date) = ?
                GROUP BY strftime('%Y-%m', r.payment_date)
                ORDER BY month DESC
            """, (month_filter,)).fetchall()
            
            monthly_summary = execute_query(c, """
                SELECT 
                    COALESCE(SUM(amount), 0) AS total,
                    COUNT(*) AS transactions,
                    COUNT(DISTINCT dr.customer_id) AS unique_customers
                FROM rental_payments r
                JOIN daily_rentals dr ON dr.id = r.daily_rental_id
                WHERE strftime('%Y-%m', r.payment_date) = ?
            """, (month_filter,)).fetchone()
            
            available_months = execute_query(c, """
                SELECT DISTINCT strftime('%Y-%m', payment_date) AS month
                FROM rental_payments
                ORDER BY month DESC
            """).fetchall()
        
        daily_revenue = monthly_revenue
        available_dates = available_months
        report_title = f"Monthly Revenue Report - {month_filter}"
    
    conn.close()
    
    return render_template(
        "revenue_report.html",
        title="Revenue Report",
        report_title=report_title,
        period=period,
        date_filter=date_filter,
        daily_revenue=daily_revenue,
        daily_summary=daily_summary if 'daily_summary' in locals() else None,
        weekly_summary=weekly_summary if 'weekly_summary' in locals() else None,
        monthly_summary=monthly_summary if 'monthly_summary' in locals() else None,
        available_dates=available_dates,
        weekly_trend=weekly_trend if 'weekly_trend' in locals() else [],
        report_type=period
    )




@app.route("/rentals/history")
@login_required
@staff_required
def rental_history():
    from datetime import datetime  # ✅ Add this import
    
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
        query += """ AND (
            c.full_name LIKE ? OR 
            b.bike_code LIKE ? OR 
            c.phone LIKE ?
        )"""
        search_term = f"%{search}%"
        params.extend([search_term, search_term, search_term])
    
    query += " ORDER BY r.start_time DESC LIMIT 100"
    
    rentals = execute_query(c, query, params).fetchall()
    
    # ✅ FIX: Format datetime for each rental
    for rental in rentals:
        if rental.get("start_time"):
            if isinstance(rental["start_time"], datetime):
                rental["start_time"] = rental["start_time"].strftime("%Y-%m-%d %H:%M")
            elif isinstance(rental["start_time"], str):
                rental["start_time"] = rental["start_time"]
        
        if rental.get("end_time"):
            if isinstance(rental["end_time"], datetime):
                rental["end_time"] = rental["end_time"].strftime("%Y-%m-%d %H:%M")
            elif isinstance(rental["end_time"], str):
                rental["end_time"] = rental["end_time"]
    
    # Get summary stats
    total_rentals = len(rentals)
    total_revenue = sum(float(r["total_cost"] or 0) for r in rentals)
    paid_count = sum(1 for r in rentals if r["payment_status"] == "Paid")
    unpaid_count = sum(1 for r in rentals if r["payment_status"] != "Paid")
    active_count = sum(1 for r in rentals if r["rental_status"] == "Active")
    completed_count = sum(1 for r in rentals if r["rental_status"] == "Completed")
    
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
        search=search
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
    pdf.drawString(x + 5*mm, y, f"Start Time: {rental['start_time']}")
    y -= 6*mm
    if rental['end_time']:
        pdf.drawString(x + 5*mm, y, f"End Time: {rental['end_time']}")
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




# @app.route("/customers/<int:customer_id>/edit", methods=["GET", "POST"])
# @login_required
# def edit_customer(customer_id):
#     """Edit customer details."""
#     # ✅ Check if user has permission (admin or manager)
#     if session.get("role") not in ['admin', 'manager']:
#         flash("You don't have permission to access this page.", "danger")
#         return redirect(url_for("customers"))
    
#     conn = db()
#     c = conn.cursor()
    
#     # Get customer data
#     customer = execute_query(c,"SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
#     if not customer:
#         flash("Customer not found.", "danger")
#         return redirect(url_for("customers"))
    
#     if request.method == "POST":
#         full_name = request.form.get("full_name", "").strip()
#         id_number = request.form.get("id_number", "").strip()
#         phone = request.form.get("phone", "").strip()
#         email = request.form.get("email", "").strip()
#         address = request.form.get("address", "").strip()
#         verification_status = request.form.get("verification_status", "Pending")
        
#         if not full_name or not phone:
#             flash("Name and phone are required.", "danger")
#             return redirect(url_for("edit_customer", customer_id=customer_id))
        
#         # Handle file uploads
#         id_photo = request.files.get("id_photo") if request.files else None
#         customer_photo = request.files.get("customer_photo") if request.files else None
        
#         execute_query(c,"""
#             UPDATE customers 
#             SET full_name = ?, id_number = ?, phone = ?, email = ?, address = ?,
#                 verification_status = ?
#             WHERE id = ?
#         """, (full_name, id_number, phone, email, address, verification_status, customer_id))
        
#         # Handle document uploads
#         UPLOAD_FOLDER = os.path.join(BASE, 'static', 'uploads')
#         os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        
#         if id_photo and id_photo.filename:
#             filename = f"id_{customer_id}_{secure_filename(id_photo.filename)}"
#             id_photo.save(os.path.join(UPLOAD_FOLDER, filename))
#             execute_query(c,"""
#                 INSERT INTO customer_documents (customer_id, document_type, file_path)
#                 VALUES (?, 'id_copy', ?)
#             """, (customer_id, f"uploads/{filename}"))
        
#         if customer_photo and customer_photo.filename:
#             filename = f"photo_{customer_id}_{secure_filename(customer_photo.filename)}"
#             customer_photo.save(os.path.join(UPLOAD_FOLDER, filename))
#             execute_query(c,"""
#                 INSERT INTO customer_documents (customer_id, document_type, file_path)
#                 VALUES (?, 'customer_photo', ?)
#             """, (customer_id, f"uploads/{filename}"))
        
#         conn.commit()
#         conn.close()
        
#         flash(f"Customer '{full_name}' updated successfully!", "success")
#         return redirect(url_for("customers"))
    
#     # Get customer documents
#     documents = execute_query(c,"""
#         SELECT * FROM customer_documents 
#         WHERE customer_id = ? 
#         ORDER BY uploaded_at DESC
#     """, (customer_id,)).fetchall()
    
#     conn.close()
    
#     return render_template(
#         "edit_customer.html",
#         title="Edit Customer",
#         customer=customer,
#         documents=documents
#     )


@app.route("/customers/<int:customer_id>/edit", methods=["GET", "POST"])
@login_required
@manager_required
def edit_customer(customer_id):
    """Edit customer details."""
    from datetime import datetime  # ✅ Add this import
    
    conn = db()
    c = conn.cursor()
    
    # Get customer data
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
        
        # Handle file uploads
        id_photo = request.files.get("id_photo") if request.files else None
        customer_photo = request.files.get("customer_photo") if request.files else None
        
        execute_query(c, """
            UPDATE customers 
            SET full_name = ?, id_number = ?, phone = ?, email = ?, address = ?,
                verification_status = ?
            WHERE id = ?
        """, (full_name, id_number, phone, email, address, verification_status, customer_id))
        
        # Handle document uploads
        import os
        from werkzeug.utils import secure_filename
        
        UPLOAD_FOLDER = os.path.join(BASE, 'static', 'uploads')
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        
        if id_photo and id_photo.filename:
            filename = f"id_{customer_id}_{secure_filename(id_photo.filename)}"
            id_photo.save(os.path.join(UPLOAD_FOLDER, filename))
            execute_query(c, """
                INSERT INTO customer_documents (customer_id, document_type, file_path)
                VALUES (?, 'id_copy', ?)
            """, (customer_id, f"uploads/{filename}"))
        
        if customer_photo and customer_photo.filename:
            filename = f"photo_{customer_id}_{secure_filename(customer_photo.filename)}"
            customer_photo.save(os.path.join(UPLOAD_FOLDER, filename))
            execute_query(c, """
                INSERT INTO customer_documents (customer_id, document_type, file_path)
                VALUES (?, 'customer_photo', ?)
            """, (customer_id, f"uploads/{filename}"))
        
        conn.commit()
        conn.close()
        
        flash(f"Customer '{full_name}' updated successfully!", "success")
        return redirect(url_for("customers"))
    
    # Get customer documents
    documents = execute_query(c, """
        SELECT * FROM customer_documents 
        WHERE customer_id = ? 
        ORDER BY uploaded_at DESC
    """, (customer_id,)).fetchall()
    
    # ✅ FIX: Format uploaded_at datetime
    for doc in documents:
        if doc.get("uploaded_at"):
            if isinstance(doc["uploaded_at"], datetime):
                doc["uploaded_at"] = doc["uploaded_at"].strftime("%Y-%m-%d %H:%M")
            elif isinstance(doc["uploaded_at"], str):
                doc["uploaded_at"] = doc["uploaded_at"]
    
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
    conn = db()
    c = conn.cursor()
    
    # Get bicycle data
    bicycle = execute_query(c,"SELECT * FROM bicycles WHERE id = ?", (bicycle_id,)).fetchone()
    if not bicycle:
        flash("Bicycle not found.", "danger")
        return redirect(url_for("bicycle_health_dashboard"))
    
    # Get maintenance data
    maintenance = execute_query(c,"""
        SELECT 
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed,
            COALESCE(SUM(cost), 0) AS total_cost,
            COUNT(CASE WHEN status = 'Completed' AND date(completed_date) >= date('now', '-30 days') THEN 1 END) AS recent_maintenance
        FROM maintenance_records
        WHERE bicycle_id = ?
    """, (bicycle_id,)).fetchone()
    
    # Get rental data
    rentals = execute_query(c,"""
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
    health = execute_query(c,"SELECT * FROM bicycle_health WHERE bicycle_id = ?", (bicycle_id,)).fetchone()
    
    try:
        if health:
            execute_query(c,"""
                UPDATE bicycle_health 
                SET health_score = ?, condition_rating = ?, updated_at = CURRENT_TIMESTAMP,
                    total_maintenance_count = ?, total_repair_cost = ?
                WHERE bicycle_id = ?
            """, (health_score, condition_rating, completed_maintenance, maintenance["total_cost"] or 0, bicycle_id))
        else:
            execute_query(c,"""
                INSERT INTO bicycle_health (bicycle_id, health_score, condition_rating, 
                    total_maintenance_count, total_repair_cost)
                VALUES (?, ?, ?, ?, ?)
            """, (bicycle_id, health_score, condition_rating, completed_maintenance, maintenance["total_cost"] or 0))
        
        # Record health history
        execute_query(c,"""
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
    conn = db()
    c = conn.cursor()
    
    bicycles = execute_query(c,"SELECT id FROM bicycles").fetchall()
    
    count = 0
    
    for bicycle in bicycles:
        bike_id = bicycle["id"]
        
        # Maintenance data
        maintenance = execute_query(c,"""
            SELECT 
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed,
                COALESCE(SUM(cost), 0) AS total_cost,
                COUNT(CASE WHEN status = 'Completed' AND date(completed_date) >= date('now', '-30 days') THEN 1 END) AS recent_maintenance
            FROM maintenance_records
            WHERE bicycle_id = ?
        """, (bike_id,)).fetchone()
        
        # Rental data
        rentals = execute_query(c,"""
            SELECT 
                COUNT(*) AS total,
                COALESCE(SUM(total_hours), 0) AS total_hours,
                COUNT(CASE WHEN date(start_time) >= date('now', '-30 days') THEN 1 END) AS recent_rentals
            FROM daily_rentals
            WHERE bicycle_id = ? AND status = 'Completed'
        """, (bike_id,)).fetchone()
        
        # =============================================
        # ✅ FIX: Handle None values HERE - BEFORE calculations
        # =============================================
        total_hours = rentals["total_hours"] if rentals["total_hours"] is not None else 0
        completed_maintenance = maintenance["completed"] if maintenance["completed"] is not None else 0
        recent_rentals = rentals["recent_rentals"] if rentals["recent_rentals"] is not None else 0
        recent_maintenance = maintenance["recent_maintenance"] if maintenance["recent_maintenance"] is not None else 0
        total_cost = maintenance["total_cost"] if maintenance["total_cost"] is not None else 0
        
        # =============================================
        # Now use the cleaned variables in calculations
        # =============================================
        health_score = 100
        
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
        
        # Update or insert
        health = execute_query(c,"SELECT * FROM bicycle_health WHERE bicycle_id = ?", (bike_id,)).fetchone()
        if health:
            execute_query(c,"""
                UPDATE bicycle_health 
                SET health_score = ?, condition_rating = ?, updated_at = CURRENT_TIMESTAMP,
                    total_maintenance_count = ?, total_repair_cost = ?
                WHERE bicycle_id = ?
            """, (health_score, condition_rating, completed_maintenance, total_cost, bike_id))
        else:
            execute_query(c,"""
                INSERT INTO bicycle_health (bicycle_id, health_score, condition_rating, 
                    total_maintenance_count, total_repair_cost)
                VALUES (?, ?, ?, ?, ?)
            """, (bike_id, health_score, condition_rating, completed_maintenance, total_cost))
        
        # Record history
        execute_query(c,"""
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
    
    total_revenue = get_single_value(c, "SELECT COALESCE(SUM(amount), 0) FROM rental_payments")
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
        total_revenue=total_revenue,
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
    
    bicycle = execute_query(c,"SELECT * FROM bicycles WHERE id = ?", (bicycle_id,)).fetchone()
    if not bicycle:
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
        
        if not bike_code:
            flash("Bicycle code is required.", "danger")
            return redirect(url_for("edit_bicycle", bicycle_id=bicycle_id))
        
        try:
            execute_query(c,"""
                UPDATE bicycles 
                SET bike_code = ?, brand = ?, model = ?, bike_type = ?,
                    hourly_rate = ?, daily_cap = ?, deposit_amount = ?, notes = ?
                WHERE id = ?
            """, (bike_code, brand, model, bike_type, hourly_rate, daily_cap, deposit_amount, notes, bicycle_id))
            conn.commit()
            flash(f"Bicycle '{bike_code}' updated successfully!", "success")
        except sqlite3.IntegrityError:
            flash("Bicycle code already exists.", "danger")
        finally:
            conn.close()
        
        return redirect(url_for("bicycles"))
    
    conn.close()
    return render_template("edit_bicycle.html", title="Edit Bicycle", bicycle=bicycle)


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
        
        if not bike_code:
            flash("Bicycle code is required.", "danger")
            return redirect(url_for("bicycles"))
        
        try:
            execute_query(c,"""
                INSERT INTO bicycles 
                (bike_code, brand, model, bike_type, hourly_rate, daily_cap, deposit_amount, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (bike_code, brand, model, bike_type, hourly_rate, daily_cap, deposit_amount, notes))
            conn.commit()
            flash(f"Bicycle {bike_code} added successfully.", "success")
        except sqlite3.IntegrityError:
            flash("Bicycle code already exists.", "danger")
        
        return redirect(url_for("bicycles"))
    
    #bicycles = execute_query(c,"SELECT * FROM bicycles ORDER BY bike_code").fetchall()

    # Get bicycles with health data
    bicycles = execute_query(c,"""
        SELECT 
            b.*,
            bh.health_score,
            bh.condition_rating
        FROM bicycles b
        LEFT JOIN bicycle_health bh ON bh.bicycle_id = b.id
        ORDER BY b.bike_code
    """).fetchall()

    conn.close()
    
    return render_template("bicycles.html", title="Bicycles", bicycles=bicycles)


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
@login_required
def send_email_notification(to_email, subject, body):
    """Send email notification (development mode - prints to console)."""
    if not EMAIL_ENABLED:
        return False
    
    print("\n" + "=" * 60)
    print("📧 EMAIL NOTIFICATION")
    print("=" * 60)
    print(f"To: {to_email}")
    print(f"Subject: {subject}")
    print("-" * 60)
    print(body)
    print("=" * 60 + "\n")
    
    # For production, uncomment this:
    """
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
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False
    """
    return True

@login_required
def send_sms_notification(phone_number, message):
    """Send SMS notification (development mode - prints to console)."""
    if not SMS_ENABLED:
        print("\n" + "=" * 60)
        print("📱 SMS NOTIFICATION (Simulated)")
        print("=" * 60)
        print(f"To: {phone_number}")
        print("-" * 60)
        print(message)
        print("=" * 60 + "\n")
        return True
    
    # For production, uncomment this:
    """
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        return True
    except Exception as e:
        print(f"SMS error: {e}")
        return False
    """
    return True

@login_required
def send_reminder(rental_id):
    """Send a reminder for a specific rental."""
    conn = db()
    c = conn.cursor()
    
    rental = execute_query(c,"""
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
    
    # Calculate time remaining
    from datetime import datetime, timedelta
    start_time = datetime.fromisoformat(rental["start_time"])
    end_time = start_time + timedelta(hours=rental["total_hours"] or 1)
    now = datetime.now()
    
    if now > end_time:
        # Overdue reminder
        reminder_type = "overdue"
        message = f"""
        ⚠️ OVERDUE REMINDER
        
        Dear {rental['full_name']},
        
        Your rental of {rental['bike_code']} is now OVERDUE.
        
        Rental started: {rental['start_time']}
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
        
        Rental started: {rental['start_time']}
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
        # Shorten message for SMS
        sms_message = f"RAB: {rental['full_name']}, your rental of {rental['bike_code']} is due soon. Please return to avoid late fees."
        send_sms_notification(rental["phone"], sms_message)
    
    # Log the reminder
    execute_query(c,"""
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
    rentals = execute_query(c,"""
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
    execute_query(c,"DELETE FROM discount_codes WHERE id = ?", (discount_id,))
    conn.commit()
    conn.close()
    
    flash("Discount code deleted.", "success")
    return redirect(url_for("discounts"))


@app.route("/validate-discount", methods=["POST"])
@login_required
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
    from datetime import datetime
    
    conn = db()
    c = conn.cursor()
    
    # Get payment details with customer and rental info
    payment = execute_query(c, """
        SELECT 
            p.*,
            r.id AS rental_id,
            r.start_time,
            r.end_time,
            r.total_hours,
            r.total_cost,
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
    # ✅ FIX: Format all datetime values
    # =============================================
    def fmt_datetime(value):
        """Format datetime for display in PDF."""
        if value is None:
            return "N/A"
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d %H:%M")
        if isinstance(value, str):
            try:
                dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                return dt.strftime("%Y-%m-%d %H:%M")
            except:
                return value[:16] if len(value) >= 16 else value
        return str(value)
    
    # Format payment date
    payment_date_str = fmt_datetime(payment.get("payment_date"))
    start_time_str = fmt_datetime(payment.get("start_time"))
    end_time_str = fmt_datetime(payment.get("end_time"))
    
    # Create PDF
    buf = BytesIO()
    pdf = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    
    # Settings
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
    # ✅ FIXED: Use formatted payment_date_str
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
    # ✅ FIXED: Use formatted start_time_str
    pdf.drawString(x + 5 * mm, y, f"Start: {start_time_str}")
    y -= 6 * mm
    # ✅ FIXED: Use formatted end_time_str
    pdf.drawString(x + 5 * mm, y, f"End: {end_time_str if payment['end_time'] else 'Active'}")
    y -= 6 * mm
    pdf.drawString(x + 5 * mm, y, f"Duration: {payment['total_hours']:.1f} hours")
    
    y -= 8 * mm
    
    # =============================================
    # PAYMENT DETAILS
    # =============================================
    pdf.setFont("Helvetica-Bold", 12)
    pdf.setFillColor(colors.HexColor("#0d1f46"))
    pdf.drawString(x, y, "Payment Details")
    y -= 7 * mm
    
    pdf.setFont("Helvetica", 10)
    pdf.setFillColor(colors.HexColor("#111111"))
    pdf.drawString(x + 5 * mm, y, f"Amount Paid: N$ {payment['amount']:.2f}")
    y -= 6 * mm
    pdf.drawString(x + 5 * mm, y, f"Payment Method: {payment['payment_method'] or 'Cash'}")
    y -= 6 * mm
    # ✅ FIXED: Use formatted payment_date_str
    pdf.drawString(x + 5 * mm, y, f"Payment Date: {payment_date_str}")
    y -= 6 * mm
    pdf.drawString(x + 5 * mm, y, f"Status: {payment['status']}")
    
    y -= 10 * mm
    
    # =============================================
    # SUMMARY BOX
    # =============================================
    # Draw a box for the total
    box_height = 25 * mm
    box_y = y - box_height
    
    pdf.setFillColor(colors.HexColor("#ffe500"))
    pdf.rect(x, box_y, 150 * mm, box_height, fill=1, stroke=0)
    
    pdf.setFillColor(colors.HexColor("#0d1f46"))
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(x + 10 * mm, y - 10 * mm, "TOTAL PAID")
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
    
    conn.close()
    
    return render_template(
        "customer_portal.html",
        title="My Account",
        customer=customer,
        rentals=rentals,
        points=points
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
    from datetime import datetime
    
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
        flash("Rental not found.", "danger")
        return redirect(url_for("dashboard"))
    
    # ✅ FIX: Handle start_time as datetime or string
    if isinstance(rental["start_time"], datetime):
        start_time = rental["start_time"]
    else:
        start_time = datetime.fromisoformat(rental["start_time"])
    
    if request.method == "POST":
        end_time = datetime.now()
        total_hours = (end_time - start_time).total_seconds() / 3600
        total_hours = round(total_hours, 2)
        
        hourly_rate = rental["hourly_rate"]
        daily_cap = rental["daily_cap"]
        
        # Calculate cost
        raw_cost = total_hours * hourly_rate
        total_cost = min(raw_cost, daily_cap)
        
        # Late fee (after 6pm)
        late_fee = 0
        if end_time.hour >= 18:
            late_fee = 10 * (end_time.hour - 18)
        total_cost += late_fee
        
        # Get condition values
        condition_before = request.form.get("condition_before", "Good")
        condition_after = request.form.get("condition_after", "Good")
        
        execute_query(c, """
            UPDATE daily_rentals 
            SET end_time = ?, total_hours = ?, total_cost = ?, late_fee = ?,
                condition_before = ?, condition_after = ?, status = 'Completed'
            WHERE id = ?
        """, (end_time.isoformat(), total_hours, total_cost, late_fee,
              condition_before, condition_after, rental_id))
        
        execute_query(c, "UPDATE bicycles SET status = 'Available' WHERE id = ?", (rental["bicycle_id"],))
        
        conn.commit()
        conn.close()
        
        flash(f"Rental completed! Total: N$ {total_cost:.2f} for {total_hours:.1f} hours", "success")
        return redirect(url_for("record_payment", rental_id=rental_id))
    
    # Calculate preview for display
    now = datetime.now()
    preview_hours = round((now - start_time).total_seconds() / 3600, 2)
    
    hourly_rate = rental["hourly_rate"]
    daily_cap = rental["daily_cap"]
    preview_raw = preview_hours * hourly_rate
    preview_capped = min(preview_raw, daily_cap)
    preview_late = 10 * (now.hour - 18) if now.hour >= 18 else 0
    preview_total = preview_capped + preview_late
    
    # ✅ FIX: Format dates for display
    start_time_str = start_time.strftime("%Y-%m-%d %H:%M") if isinstance(start_time, datetime) else start_time
    
    conn.close()
    
    return render_template(
        "end_rental.html",
        title="End Rental",
        rental=rental,
        start_time_str=start_time_str,
        preview_hours=preview_hours,
        hourly_rate=hourly_rate,
        daily_cap=daily_cap,
        preview_raw=preview_raw,
        preview_capped=preview_capped,
        preview_late=preview_late,
        preview_total=preview_total
    )




@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))





with app.app_context():
    try:
        conn = db()
        c = conn.cursor()
        # This works for both SQLite and PostgreSQL
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        table_exists = c.fetchone()
        conn.close()
        
        if not table_exists:
            print("Database tables not found. Initializing...")
            init_db()
            print("Database initialized successfully!")
        else:
            print("Database already initialized.")
    except Exception as e:
        print(f"Error checking database: {e}")
        print("Attempting to initialize database...")
        try:
            init_db()
            print("Database initialized successfully!")
        except Exception as e2:
            print(f"Failed to initialize database: {e2}")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)