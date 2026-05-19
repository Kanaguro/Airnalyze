import sqlite3, json
p = r'c:\Users\rosal\Downloads\wifi_monitor\wifi_monitor.db'
conn = sqlite3.connect(p)
conn.row_factory = sqlite3.Row
rows = conn.execute('SELECT user_id, username, account_type FROM users').fetchall()
print(json.dumps([dict(r) for r in rows], indent=2))
conn.close()
