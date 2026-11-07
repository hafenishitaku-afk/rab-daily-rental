import psycopg2
from werkzeug.security import generate_password_hash

# 👇 PASTE YOUR EXTERNAL DATABASE URL HERE, ENDING WITH /rental_db
DATABASE_URL = "postgresql://rab_main_db_user:hNYrV6OfYmxNDw5ZvQdNZe4d3d1sGbqy@dpg-dbne3m0u01pc73cgn5rg-a.virginia-postgres.render.com/rental_db"

def create_admin():
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor()
    
    # Check if admin exists
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if cursor.fetchone():
        print("ℹ️ Admin user already exists.")
    else:
        print("Creating admin user...")
        hashed_pw = generate_password_hash("admin123")
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, full_name) VALUES (%s, %s, %s, %s)",
            ("admin", hashed_pw, "admin", "System Administrator")
        )
        conn.commit()
        print("✅ Admin user created successfully!")
        
    cursor.close()
    conn.close()

if __name__ == "__main__":
    create_admin()