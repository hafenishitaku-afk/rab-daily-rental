import sqlite3

# Connect to your local database
conn = sqlite3.connect('rab.db')
c = conn.cursor()

# Drop the table
c.execute("DROP TABLE IF EXISTS warnings;")

conn.commit()
conn.close()
print("✅ The 'warnings' table has been dropped successfully!")