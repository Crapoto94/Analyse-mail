import sqlite3

conn = sqlite3.connect('compromis.db')
conn.row_factory = sqlite3.Row

# Vérifier les messages avec/sans IP
total = conn.execute('SELECT COUNT(*) as cnt FROM messages').fetchone()['cnt']
with_ip = conn.execute('SELECT COUNT(*) as cnt FROM messages WHERE from_ip!=""').fetchone()['cnt']
without_ip = conn.execute('SELECT COUNT(*) as cnt FROM messages WHERE from_ip="" OR from_ip IS NULL').fetchone()['cnt']

print(f"Total messages: {total}")
print(f"Messages avec IP: {with_ip}")
print(f"Messages sans IP: {without_ip}")

# Afficher quelques IPs
print("\nExemples d'IPs sources:")
ips = conn.execute('SELECT DISTINCT from_ip, COUNT(*) as cnt FROM messages WHERE from_ip!="" GROUP BY from_ip LIMIT 10').fetchall()
for row in ips:
    print(f"  {row['from_ip']}: {row['cnt']} messages")

conn.close()
