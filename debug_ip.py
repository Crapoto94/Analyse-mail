import sqlite3
import json
import urllib.request
import socket

conn = sqlite3.connect('compromis.db')
conn.row_factory = sqlite3.Row

# Vérifier les IPs dans messages
ips = conn.execute("SELECT DISTINCT from_ip FROM messages WHERE from_ip!=''").fetchall()
print(f"IPs dans messages: {len(ips)}")
for ip_row in ips:
    ip = ip_row['from_ip']
    print(f"\nTraitement de l'IP: {ip}")
    
    # Tester ipapi.co
    try:
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={'User-Agent': 'Analyse-Compromis'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get('error'):
                print(f"  Erreur API: {data.get('reason')}")
            else:
                print(f"  Ville: {data.get('city')}, Pays: {data.get('country_name')}")
                print(f"  ISP: {data.get('org')}")
                
                # Insérer dans ip_info
                hostname = ''
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    pass
                
                conn.execute('''INSERT OR REPLACE INTO ip_info 
                    (ip, country, country_code, region, region_name, city, zip, lat, lon, isp, org, as_name, is_vpn, timezone, continent, continent_code, currency, hostname)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (ip, data.get('country_name', ''), data.get('country_code', ''), data.get('region_code', ''),
                     data.get('region', ''), data.get('city', ''), data.get('postal', ''),
                     data.get('latitude'), data.get('longitude'), data.get('org', ''),
                     data.get('org', ''), data.get('asn', ''), False,
                     data.get('timezone', ''), data.get('continent_code', ''), data.get('continent_code', ''),
                     data.get('currency', ''), hostname))
                conn.commit()
                print(f"  => Inséré dans ip_info")
    except Exception as e:
        print(f"  Erreur: {e}")

conn.close()
print("\nTerminé!")
