import os
import csv
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
import json

app = Flask(__name__)
app.secret_key = 'analyse-compromis-secret-key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('templates', exist_ok=True)

DB_PATH = 'compromis.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS boites_compromises (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT NOT NULL,
        date_compromission TEXT,
        heure_compromission TEXT,
        date_decouverte TEXT,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        boite_id INTEGER,
        message_id TEXT,
        received TEXT,
        sender_address TEXT,
        recipient_address TEXT,
        subject TEXT,
        status TEXT,
        to_ip TEXT,
        from_ip TEXT,
        size INTEGER,
        message_trace_id TEXT,
        csv_source TEXT,
        FOREIGN KEY (boite_id) REFERENCES boites_compromises(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value TEXT
    )''')
    conn.commit()
    conn.close()

def get_config(key, default=''):
    conn = get_db()
    row = conn.execute('SELECT value FROM config WHERE key=?', (key,)).fetchone()
    conn.close()
    return row['value'] if row else default

def set_config(key, value):
    conn = get_db()
    conn.execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', (key, value))
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    conn = get_db()
    boites = conn.execute('SELECT * FROM boites_compromises ORDER BY created_at DESC').fetchall()
    stats = {}
    for b in boites:
        bid = b['id']
        stats[bid] = {
            'nb_messages': conn.execute('SELECT COUNT(*) as c FROM messages WHERE boite_id=?', (bid,)).fetchone()['c'],
            'nb_recipients': conn.execute('SELECT COUNT(DISTINCT recipient_address) as c FROM messages WHERE boite_id=?', (bid,)).fetchone()['c'],
            'statuts': dict(conn.execute('SELECT status, COUNT(*) as c FROM messages WHERE boite_id=? GROUP BY status', (bid,)).fetchall())
        }
    conn.close()
    return render_template('index.html', boites=boites, stats=stats)

@app.route('/boite/add', methods=['GET', 'POST'])
def add_boite():
    if request.method == 'POST':
        conn = get_db()
        conn.execute('''INSERT INTO boites_compromises 
            (user_email, date_compromission, heure_compromission, date_decouverte, notes)
            VALUES (?, ?, ?, ?, ?)''',
            (request.form['user_email'], request.form['date_compromission'],
             request.form['heure_compromission'], request.form['date_decouverte'],
             request.form['notes']))
        conn.commit()
        bid = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()
        flash('Boîte compromise ajoutée avec succès')
        return redirect(url_for('view_boite', bid=bid))
    return render_template('add_boite.html')

@app.route('/boite/<int:bid>')
def view_boite(bid):
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    if not boite:
        flash('Boîte non trouvée')
        return redirect(url_for('index'))
    messages = conn.execute('SELECT * FROM messages WHERE boite_id=? ORDER BY received DESC', (bid,)).fetchall()
    ips = conn.execute('SELECT DISTINCT from_ip, COUNT(*) as cnt FROM messages WHERE boite_id=? AND from_ip!="" GROUP BY from_ip', (bid,)).fetchall()
    recipients = conn.execute('SELECT DISTINCT recipient_address, COUNT(*) as cnt FROM messages WHERE boite_id=? GROUP BY recipient_address ORDER BY cnt DESC LIMIT 50', (bid,)).fetchall()
    statuts = conn.execute('SELECT status, COUNT(*) as cnt FROM messages WHERE boite_id=? GROUP BY status', (bid,)).fetchall()
    
    # Extraire les domaines (top 50)
    domain_rows = conn.execute('SELECT recipient_address FROM messages WHERE boite_id=?', (bid,)).fetchall()
    domains = {}
    for row in domain_rows:
        email = row['recipient_address']
        if '@' in email:
            domain = email.split('@')[1].lower()
            domains[domain] = domains.get(domain, 0) + 1
    top_domains = sorted(domains.items(), key=lambda x: x[1], reverse=True)[:50]
    
    conn.close()
    return render_template('view_boite.html', boite=boite, messages=messages, ips=ips, recipients=recipients, statuts=statuts, top_domains=top_domains)

@app.route('/boite/<int:bid>/upload', methods=['GET', 'POST'])
def upload_csv(bid):
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    conn.close()
    if not boite:
        flash('Boîte non trouvée')
        return redirect(url_for('index'))
    if request.method == 'POST':
        if 'csv_file' not in request.files:
            flash('Aucun fichier sélectionné')
            return redirect(request.url)
        file = request.files['csv_file']
        if file.filename == '':
            flash('Aucun fichier sélectionné')
            return redirect(request.url)
        if file and file.filename.endswith('.csv'):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            count = import_csv(bid, filepath, filename)
            flash(f'{count} messages importés avec succès')
            return redirect(url_for('view_boite', bid=bid))
        else:
            flash('Format de fichier non supporté (CSV uniquement)')
    return render_template('upload.html', boite=boite)

def detect_delimiter(filepath):
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        first_line = f.readline()
        if ';' in first_line and ',' not in first_line:
            return ';'
    return ','

def import_csv(boite_id, filepath, source):
    conn = get_db()
    count = 0
    delimiter = detect_delimiter(filepath)
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        for row in reader:
            try:
                from_ip = row.get('FromIP', '').strip().split(';')[0].strip('"')
                size_raw = row.get('Size', '0')
                if not size_raw.isdigit():
                    size_raw = row.get('FromIP', '').split(';')[-1].strip('"') if ';' in row.get('FromIP', '') else '0'
                size = int(size_raw) if str(size_raw).isdigit() else 0
                conn.execute('''INSERT INTO messages 
                    (boite_id, message_id, received, sender_address, recipient_address,
                     subject, status, to_ip, from_ip, size, message_trace_id, csv_source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (boite_id, row.get('MessageId','').strip('"'), row.get('Received','').strip('"'),
                     row.get('SenderAddress','').strip('"'), row.get('RecipientAddress','').strip('"'),
                     row.get('Subject','').strip('"'), row.get('Status','').strip('"'),
                     row.get('ToIP','').strip('"'), from_ip,
                     size,
                     row.get('MessageTraceId','').strip('"'), source))
                count += 1
            except Exception as e:
                print(f"Erreur ligne: {e}")
                continue
    conn.commit()
    conn.close()
    return count

@app.route('/boite/<int:bid>/delete', methods=['POST'])
def delete_boite(bid):
    conn = get_db()
    conn.execute('DELETE FROM messages WHERE boite_id=?', (bid,))
    conn.execute('DELETE FROM boites_compromises WHERE id=?', (bid,))
    conn.commit()
    conn.close()
    flash('Boîte supprimée')
    return redirect(url_for('index'))

@app.route('/compare')
def compare_boites():
    conn = get_db()
    boites = conn.execute('SELECT id, user_email FROM boites_compromises ORDER BY id').fetchall()
    
    comparisons = []
    for i in range(len(boites)):
        for j in range(i+1, len(boites)):
            b1 = boites[i]
            b2 = boites[j]
            recipients1 = set(r['recipient_address'] for r in conn.execute('SELECT DISTINCT recipient_address FROM messages WHERE boite_id=?', (b1['id'],)).fetchall())
            recipients2 = set(r['recipient_address'] for r in conn.execute('SELECT DISTINCT recipient_address FROM messages WHERE boite_id=?', (b2['id'],)).fetchall())
            common = recipients1 & recipients2
            comparisons.append({
                'boite1': b1['user_email'],
                'boite2': b2['user_email'],
                'common_count': len(common),
                'common': sorted(list(common))[:100]
            })
    conn.close()
    return render_template('compare.html', comparisons=comparisons)

@app.route('/config', methods=['GET', 'POST'])
def config():
    if request.method == 'POST':
        if 'custom_message' in request.form:
            set_config('custom_message_emetteur_nom', request.form.get('custom_message_emetteur_nom', ''))
            set_config('custom_message_emetteur_email', request.form.get('custom_message_emetteur_email', ''))
            set_config('custom_message_titre', request.form.get('custom_message_titre', ''))
            set_config('custom_message_header1', request.form.get('custom_message_header1', ''))
            set_config('custom_message_header2', request.form.get('custom_message_header2', ''))
            set_config('custom_message_header3', request.form.get('custom_message_header3', ''))
            set_config('custom_message_cc', request.form.get('custom_message_cc', ''))
            set_config('custom_message', request.form.get('custom_message', ''))
            flash('Message enregistré avec succès')
        elif 'api_ville_token' in request.form or 'api_ville_doc_url' in request.form or 'api_ville_url' in request.form:
            set_config('api_ville_url', request.form.get('api_ville_url', ''))
            set_config('api_ville_doc_url', request.form.get('api_ville_doc_url', ''))
            set_config('api_ville_token', request.form.get('api_ville_token', ''))
            flash('Configuration API enregistrée avec succès')
        return redirect(url_for('config'))
    
    return render_template('config.html',
        custom_message_emetteur_nom=get_config('custom_message_emetteur_nom', ''),
        custom_message_emetteur_email=get_config('custom_message_emetteur_email', ''),
        custom_message_titre=get_config('custom_message_titre', ''),
        custom_message_header1=get_config('custom_message_header1', ''),
        custom_message_header2=get_config('custom_message_header2', ''),
        custom_message_header3=get_config('custom_message_header3', ''),
        custom_message_cc=get_config('custom_message_cc', ''),
        custom_message=get_config('custom_message', ''),
        api_ville_url=get_config('api_ville_url', 'https://api-ville.toulouse.fr/api'),
        api_ville_doc_url=get_config('api_ville_doc_url', 'https://api-ville.toulouse.fr/docs'),
        api_ville_token=get_config('api_ville_token', ''))

@app.route('/api/test-ville')
def test_api_ville():
    import urllib.request
    token = get_config('api_ville_token', '')
    api_url = get_config('api_ville_url', '')
    
    if not token:
        return jsonify({'success': False, 'message': 'Token non configuré'})
    
    if not api_url:
        return jsonify({'success': False, 'message': 'URL de l\'API non configurée'})
    
    try:
        req = urllib.request.Request(
            api_url.rstrip('/') + '/ping',
            headers={'X-API-KEY': token, 'Accept': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            return jsonify({'success': True, 'message': f'API accessible (HTTP {response.status})'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erreur: {str(e)}'})

@app.route('/api/test-send')
def test_send_email():
    import urllib.request
    token = get_config('api_ville_token', '')
    api_url = get_config('api_ville_url', '')
    
    if not token or not api_url:
        return jsonify({'error': 'Configuration manquante'})
    
    try:
        test_data = {
            'to': 'test@example.com',
            'subject': 'Test',
            'content': 'Test message',
            'from_name': 'Test',
            'from_email': 'test@example.com'
        }
        
        data = json.dumps(test_data).encode('utf-8')
        url = api_url.rstrip('/') + '/api/v1/mail/send'
        
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                'X-API-KEY': token,
                'Content-Type': 'application/json'
            },
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            return jsonify({
                'success': True,
                'status': response.status,
                'response': response.read().decode('utf-8'),
                'url': url,
                'data': test_data
            })
    except urllib.error.HTTPError as e:
        return jsonify({
            'success': False,
            'status': e.code,
            'error': e.read().decode('utf-8'),
            'url': api_url.rstrip('/') + '/api/v1/mail/send'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'url': api_url.rstrip('/') + '/api/v1/mail/send'})

@app.route('/boite/<int:bid>/recipients-count')
def get_recipients_count(bid):
    conn = get_db()
    count = conn.execute('SELECT COUNT(DISTINCT recipient_address) as cnt FROM messages WHERE boite_id=?', (bid,)).fetchone()['cnt']
    conn.close()
    return jsonify({'count': count})

@app.route('/boite/<int:bid>/send-emails', methods=['POST'])
def send_emails_to_recipients(bid):
    import urllib.request
    import traceback
    
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    if not boite:
        conn.close()
        return jsonify({'success': False, 'message': 'Boîte non trouvée'})
    
    recipients = conn.execute('SELECT DISTINCT recipient_address FROM messages WHERE boite_id=?', (bid,)).fetchall()
    conn.close()
    
    if not recipients:
        return jsonify({'success': False, 'message': 'Aucun destinataire trouvé'})
    
    api_url = get_config('api_ville_url', '')
    token = get_config('api_ville_token', '')
    
    if not api_url or not token:
        return jsonify({'success': False, 'message': 'Configuration API Ville incomplète'})
    
    emetteur_nom = get_config('custom_message_emetteur_nom', '')
    emetteur_email = get_config('custom_message_emetteur_email', '')
    titre = get_config('custom_message_titre', '')
    header1 = get_config('custom_message_header1', '')
    header2 = get_config('custom_message_header2', '')
    header3 = get_config('custom_message_header3', '')
    cc_raw = get_config('custom_message_cc', '')
    cc_list = [addr.strip() for addr in cc_raw.split(',') if addr.strip()] if cc_raw else []
    message_body = get_config('custom_message', '')
    
    results = {'success': 0, 'failed': 0, 'errors': [], 'debug': []}
    
    for r in recipients:
        recipient = r['recipient_address']
        try:
            email_data = {
                'to': recipient,
                'cc': cc_list,
                'from_name': emetteur_nom,
                'from_email': emetteur_email,
                'subject': titre,
                'content': message_body,
                'is_raw': False,
                'footer1': header1,
                'footer2': header2,
                'footer3': header3
            }
            
            data = json.dumps(email_data).encode('utf-8')
            full_url = api_url.rstrip('/') + '/api/v1/mail/send'
            results['debug'].append(f'Tentative envoi vers {full_url} pour {recipient}')
            
            req = urllib.request.Request(
                full_url,
                data=data,
                headers={
                    'X-API-KEY': token,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                response_text = response.read().decode('utf-8')
                results['debug'].append(f'Success: {response.status} - {response_text}')
                results['success'] += 1
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8') if e.fp else str(e)
            results['failed'] += 1
            results['errors'].append(f'{recipient}: HTTP {e.code} - {error_body}')
            results['debug'].append(f'HTTP Error: {e.code} - {error_body}')
        except Exception as e:
            results['failed'] += 1
            results['errors'].append(f'{recipient}: {str(e)}')
            results['debug'].append(f'Error: {traceback.format_exc()}')
    
    error_details = ' | '.join(results['errors'][:3]) if results['errors'] else ''
    return jsonify({
        'success': results['failed'] == 0,
        'message': f'{results["success"]} emails envoyés, {results["failed"]} échecs. Détails: {error_details}',
        'details': results
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
