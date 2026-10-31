import sqlite3

conn = sqlite3.connect('rab.db')
c = conn.cursor()

# Update Standard bikes
c.execute("UPDATE bicycles SET hourly_rate = 60, daily_cap = 480 WHERE bike_type = 'Standard'")

# Update Mountain bikes
c.execute("UPDATE bicycles SET hourly_rate = 75, daily_cap = 600 WHERE bike_type = 'Mountain'")

# Update Electric bikes
c.execute("UPDATE bicycles SET hourly_rate = 90, daily_cap = 720 WHERE bike_type = 'Electric'")

conn.commit()
print("Successfully updated all existing bike prices!")

# Verify the changes
c.execute("SELECT bike_code, bike_type, hourly_rate, daily_cap FROM bicycles")
for row in c.fetchall():
    print(row)

conn.close()