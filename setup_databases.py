import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# 👇 PASTE YOUR EXTERNAL DATABASE URL HERE (Keep the quotes)
DATABASE_URL = "postgresql://rab_main_db_user:hNYrV6OfYmxNDw5ZvQdNZe4d3d1sGbqy@dpg-dbne3m0u01pc73cgn5rg-a.virginia-postgres.render.com/rab_main_db"

def create_databases():
    print("Connecting to Postgres...")
    # We connect to the default database to create new ones
    conn = psycopg2.connect(DATABASE_URL)
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cursor = conn.cursor()

    # Create rental_db
    try:
        cursor.execute("CREATE DATABASE rental_db;")
        print("✅ Successfully created 'rental_db'")
    except psycopg2.errors.DuplicateDatabase:
        print("ℹ️ 'rental_db' already exists.")
    except Exception as e:
        print(f"❌ Error creating rental_db: {e}")

    # Create race_db
    try:
        cursor.execute("CREATE DATABASE race_db;")
        print("✅ Successfully created 'race_db'")
    except psycopg2.errors.DuplicateDatabase:
        print("ℹ️ 'race_db' already exists.")
    except Exception as e:
        print(f"❌ Error creating race_db: {e}")

    cursor.close()
    conn.close()

if __name__ == "__main__":
    create_databases()