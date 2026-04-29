import sqlite3
import json
import urllib.request
import socket
import time

conn = sqlite3.connect('compromis.db')
conn.row_factory = sqlite3.Row

# Vérifier les IPs dans messages
ips = conn.execute("SELECT DISTINCT from_ip FROM messages WHERE from_ip!=''").fetchall()
print(f"IPs dans messages: {len(ips)}")

for idx, ip_row in enumerate(ips):
    ip = ip_row['from_ip']
    print(f"\n{idx+1}/{len(ips)} - Traitement de l'IP: {ip}")
    
    # Vérifier si déjà en base
    existing = conn.execute("SELECT * FROM ip_info WHERE ip=?", (ip,)).fetchone()
    if existing:
        print(f"  => Déjà en base, skip")
        continue
    
    # Tester ipwho.is
    try:
        url = f"https://ipwho.is/{ip}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Analyse-Compromis/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            if not data.get('success'):
                print(f"  Erreur API: {data.get('message')}")
                continue
            
            print(f"  Ville: {data.get('city')}, Pays: {data.get('country')}")
            print(f"  ISP: {data.get('connection', {}).get('isp')}")
            
            # Récupérer hostname
            hostname = ''
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass
            
            isp = (data.get('connection', {}).get('isp', '') or '').lower()
            org = (data.get('connection', {}).get('org', '') or '').lower()
            asn = data.get('connection', {}).get('asn', '')
            
            is_vpn = any(kw in (isp + ' ' + org) for kw in ['vpn', 'proxy', 'tor', 'nord', 'express', 'surfshark'])
            
            conn.execute('''INSERT OR REPLACE INTO ip_info 
                (ip, country, country_code, region, region_name, city, zip, lat, lon, isp, org, as_name, is_vpn, timezone, continent, continent_code, currency, hostname)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (ip, data.get('country', ''), data.get('country_code', ''), data.get('region_code', ''),
                 data.get('region', ''), data.get('city', ''), data.get('postal', ''),
                 data.get('latitude'), data.get('longitude'), data.get('connection', {}).get('isp', ''),
                 data.get('connection', {}).get('org', ''), asn, is_vpn,
                 data.get('timezone', {}).get('id', ''), data.get('continent_code', ''), data.get('continent_code', ''),
                 data.get('currency', {}).get('code', ''), hostname))
            conn.commit()
            print(f"  => Inséré dans ip_info")
    except Exception as e:
        print(f"  Erreur: {e}")
    
    # Délai pour éviter rate limiting
    if idx < len(ips) - 1:
        print(f"  Attente 1.5s...")
        time.sleep(1.5)

conn.close()
print("\nTerminé!")
