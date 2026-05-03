# check_db.py
import sqlite3

conn = sqlite3.connect("logs/incidents.db")
rows = conn.execute(
    "SELECT id, ip, prediction, severity, abuse_score, is_blocked FROM incidents"
).fetchall()

print(f"{'ID':<6} {'IP':<20} {'Attack':<10} {'Severity':<10} {'Score':<7} {'Blocked'}")
print("-" * 65)
for r in rows:
    print(f"{r[0]:<6} {r[1]:<20} {r[2]:<10} {str(r[3] or 'N/A'):<10} {r[4] or 0:<7} {bool(r[5])}")

print(f"\nTotal incidents: {len(rows)}")
conn.close()