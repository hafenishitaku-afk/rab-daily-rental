import psycopg2
import os
from dotenv import load_dotenv

# Load local .env file (if you have it)
load_dotenv()

# 👇 PASTE YOUR EXTERNAL DATABASE URL HERE (the one ending in /rental_db)
DATABASE_URL = "postgresql://rabmaindb_ha8c_user:H4nm92XGJicAo787aplg5fhH9lUsQz87@dpg-dbne3m0u01pc73cgn5rg-a.virginia-postgres.render.com/rental_db"

def fix_db():
    print("Connecting to Render Database...")
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor()

    # The list of ALL columns we added that might be missing
    columns_to_add = [
        ("daily_rentals", "expected_end_station_id", "INTEGER"),
        ("customers", "banned_until", "TEXT"),
        ("customers", "gender", "TEXT"),
        ("warnings", "customer_id", "INTEGER"),
        ("warnings", "level", "TEXT"),
        ("pending_registrations", "rejection_reason", "TEXT"),
        ("pending_registrations", "reviewed_by", "INTEGER"),
        ("pending_registrations", "reviewed_at", "TEXT"),
        ("pending_registrations", "generated_username", "TEXT"),
        ("pending_registrations", "generated_password", "TEXT"),
    ]

    for table, column, col_type in columns_to_add:
        try:
            # We use IF NOT EXISTS so it won't crash if the column is already there
            sql = f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {col_type};"
            cursor.execute(sql)
            print(f"✅ Added {column} to {table}")
        except Exception as e:
            print(f"❌ Failed to add {column} to {table}: {e}")
            conn.rollback()

    # Also make sure the tables exist
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pending_registrations (
                id SERIAL PRIMARY KEY,
                full_name TEXT NOT NULL,
                id_number TEXT,
                phone TEXT NOT NULL,
                email TEXT,
                address TEXT,
                gender TEXT,
                id_photo_path TEXT,
                customer_photo_path TEXT,
                signature_data TEXT,
                terms_accepted INTEGER DEFAULT 0,
                status TEXT DEFAULT 'Pending',
                rejection_reason TEXT,
                reviewed_by INTEGER,
                reviewed_at TIMESTAMP,
                generated_username TEXT,
                generated_password TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        print("✅ Checked pending_registrations table")
    except Exception as e:
        print(f"❌ Failed to create pending_registrations: {e}")
        conn.rollback()

    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS warnings (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                customer_id INTEGER,
                issued_by_id INTEGER NOT NULL,
                level TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT DEFAULT 'Unsigned',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                signed_at TIMESTAMP
            );
        """)
        print("✅ Checked warnings table")
    except Exception as e:
        print(f"❌ Failed to create warnings: {e}")
        conn.rollback()

    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS awards (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                customer_id INTEGER,
                award_title TEXT NOT NULL,
                reason TEXT NOT NULL,
                issued_by_id INTEGER NOT NULL,
                issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        print("✅ Checked awards table")
    except Exception as e:
        print(f"❌ Failed to create awards: {e}")
        conn.rollback()



    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS suggestions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                user_name TEXT NOT NULL,
                user_role TEXT NOT NULL,
                content_type TEXT NOT NULL,
                content TEXT,
                file_path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        print("✅ Checked suggestions table")
    except Exception as e:
        print(f"❌ Failed to create suggestions: {e}")
        conn.rollback()

    conn.commit()
    cursor.close()
    conn.close()
    print("🎉 Database fixed successfully!")

if __name__ == "__main__":
    fix_db()