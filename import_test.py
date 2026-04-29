import sqlite3, csv

def import_test():
    conn = sqlite3.connect('compromis.db')
    c = conn.cursor()
    c.execute("SELECT id FROM boites_compromises WHERE user_email = ?", ('test@ivry94.fr',))
    row = c.fetchone()
    if row:
        bid = row[0]
        print(f"Boite existante ID: {bid}")
        c.execute("DELETE FROM messages WHERE boite_id = ?", (bid,))
    else:
        c.execute("INSERT INTO boites_compromises (user_email, date_compromission) VALUES (?, ?)", 
                 ('test@ivry94.fr', '2026-04-27'))
        bid = c.lastrowid
        print(f"Nouvelle boite ID: {bid}")
    
    filepath = 'Compromission_test.csv'
    count = 0
    
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f, delimiter=';')
        print(f"Champs detectes: {reader.fieldnames}")
        
        for i, row in enumerate(reader, start=2):
            try:
                message_id = (row.get('MessageId') or '').strip().strip('"')
                received = (row.get('Received') or '').strip().strip('"')
                sender = (row.get('SenderAddress') or '').strip().strip('"')
                recipient = (row.get('RecipientAddress') or '').strip().strip('"')
                subject = (row.get('Subject') or '').strip().strip('"')
                status = (row.get('Status') or '').strip().strip('"')
                to_ip = (row.get('ToIP') or '').strip().strip('"')
                
                from_field = (row.get('FromIP') or '').strip().strip('"')
                parts = from_field.split(';')
                from_ip = parts[0].strip()
                size_raw = parts[1].strip() if len(parts) > 1 else ''
                
                if not size_raw.isdigit():
                    size_raw = (row.get('Size') or '0').strip().strip('"')
                size = int(size_raw) if size_raw.isdigit() else 0
                
                trace_id = (row.get('MessageTraceId') or '').strip().strip('"')
                
                c.execute('''INSERT INTO messages 
                    (boite_id, message_id, received, sender_address, recipient_address,
                     subject, status, to_ip, from_ip, size, message_trace_id, csv_source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (bid, message_id, received, sender, recipient,
                     subject, status, to_ip, from_ip, size, trace_id, filepath))
                count += 1
            except Exception as e:
                print(f"Erreur ligne {i}: {e}")
                continue
    
    conn.commit()
    conn.close()
    print(f"{count} messages importes pour test@ivry94.fr")

import_test()
