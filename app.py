import os
import csv
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
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
        attachments TEXT,
        urls TEXT,
        FOREIGN KEY (boite_id) REFERENCES boites_compromises(id)
    )''')
    
    # Migrations pour ajouter les nouvelles colonnes si elles n'existent pas
    try:
        c.execute('ALTER TABLE messages ADD COLUMN attachments TEXT')
    except:
        pass
    try:
        c.execute('ALTER TABLE messages ADD COLUMN urls TEXT')
    except:
        pass
    c.execute('''CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS ip_info (
        ip TEXT PRIMARY KEY,
        country TEXT,
        country_code TEXT,
        region TEXT,
        region_name TEXT,
        city TEXT,
        zip TEXT,
        lat REAL,
        lon REAL,
        isp TEXT,
        org TEXT,
        as_name TEXT,
        is_vpn BOOLEAN DEFAULT 0,
        timezone TEXT,
        continent TEXT,
        continent_code TEXT,
        currency TEXT,
        hostname TEXT,
        query_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        level TEXT NOT NULL,
        category TEXT NOT NULL,
        message TEXT NOT NULL,
        details TEXT,
        boite_id INTEGER,
        recipient TEXT,
        FOREIGN KEY (boite_id) REFERENCES boites_compromises(id)
    )''')
    
    # Migration: ajouter colonne hostname si elle n'existe pas
    try:
        c.execute('ALTER TABLE ip_info ADD COLUMN hostname TEXT')
    except:
        pass  # La colonne existe déjà
    conn.commit()
    conn.close()

def get_ip_info(ip):
    import urllib.request
    import socket
    import time
    
    conn = get_db()
    row = conn.execute('SELECT * FROM ip_info WHERE ip=?', (ip,)).fetchone()
    if row:
        conn.close()
        return dict(row)
    
    try:
        # Utiliser ipwho.is (pas de rate limit strict)
        url = "https://ipwho.is/" + ip
        req = urllib.request.Request(url, headers={'User-Agent': 'Analyse-Compromis/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            if not data.get('success'):
                raise Exception(data.get('message', 'Unknown error'))
            
            # Récupérer le hostname via reverse DNS
            hostname = ''
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = ''
            
            isp = (data.get('connection', {}).get('isp', '') or '').lower()
            org = (data.get('connection', {}).get('org', '') or '').lower()
            asn = data.get('connection', {}).get('asn', '')
            
            is_vpn = any(kw in (isp + ' ' + org) for kw in ['vpn', 'proxy', 'tor', 'nord', 'express', 'surfshark', 'cyberghost'])
            
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
            row = conn.execute('SELECT * FROM ip_info WHERE ip=?', (ip,)).fetchone()
            conn.close()
            return dict(row) if row else None
    except Exception as e:
        print("Erreur IP info pour " + ip + ": " + str(e))
    
    conn.close()
    return None

def check_spf_dkim_dmarc(domain):
    import dns.resolver
    result = {'spf': 'Non vérifié', 'dkim': 'Non vérifié', 'dmarc': 'Non vérifié'}
    
    try:
        # Vérifier SPF
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                for s in rdata.strings:
                    if isinstance(s, bytes):
                        txt = s.decode('utf-8')
                    else:
                        txt = str(s)
                    if 'v=spf1' in txt.lower():
                        result['spf'] = txt
                        break
                if result['spf'] != 'Non vérifié':
                    break
        except dns.resolver.NXDOMAIN:
            result['spf'] = 'Domaine inexistant'
        except dns.resolver.NoAnswer:
            result['spf'] = 'Aucun enregistrement TXT'
        except Exception as e:
            result['spf'] = f'Erreur: {str(e)}'
        
        # Vérifier DMARC
        try:
            dmarc_domain = '_dmarc.' + domain
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                for s in rdata.strings:
                    if isinstance(s, bytes):
                        txt = s.decode('utf-8')
                    else:
                        txt = str(s)
                    if 'v=dmarc1' in txt.lower():
                        result['dmarc'] = txt
                        break
                if result['dmarc'] != 'Non vérifié':
                    break
        except dns.resolver.NXDOMAIN:
            result['dmarc'] = 'Aucun enregistrement DMARC'
        except dns.resolver.NoAnswer:
            result['dmarc'] = 'Aucun enregistrement DMARC'
        except Exception as e:
            result['dmarc'] = f'Erreur: {str(e)}'
        
        # DKIM (vérifie quelques sélecteurs courants)
        dkim_selectors = ['default', 'selector1', 'selector2', 'k1', 'google', 's1', 's2']
        for selector in dkim_selectors:
            try:
                dkim_domain = selector + '._domainkey.' + domain
                answers = dns.resolver.resolve(dkim_domain, 'TXT')
                for rdata in answers:
                    for s in rdata.strings:
                        if isinstance(s, bytes):
                            txt = s.decode('utf-8')
                        else:
                            txt = str(s)
                        if 'v=dkim1' in txt.lower():
                            result['dkim'] = 'Présent (sélecteur: ' + selector + ')'
                            break
                    if 'Présent' in result['dkim']:
                        break
            except:
                continue
        if 'Présent' not in result['dkim']:
            result['dkim'] = 'Aucun enregistrement DKIM détecté'
    except Exception as e:
        print("Erreur DNS pour " + domain + ": " + str(e))
    return result

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

def add_log(level, category, message, details=None, boite_id=None, recipient=None):
    try:
        conn = get_db()
        conn.execute('INSERT INTO logs (level, category, message, details, boite_id, recipient) VALUES (?, ?, ?, ?, ?, ?)',
                     (level, category, message, details, boite_id, recipient))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Erreur logging: {e}")

from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.authorization
        if not auth or not (auth.username == 'admin' and auth.password == 'Admin94200!!!2025'):
            return 'Unauthorized', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    conn = get_db()
    boites = conn.execute('SELECT * FROM boites_compromises ORDER BY created_at DESC').fetchall()
    stats = {}
    for b in boites:
        bid = b['id']
        messages = conn.execute('SELECT recipient_address FROM messages WHERE boite_id=?', (bid,)).fetchall()
        nb_ivry = sum(1 for m in messages if '@ivry94.fr' in m['recipient_address'].lower())
        nb_external = len(messages) - nb_ivry
        stats[bid] = {
            'nb_messages': len(messages),
            'nb_recipients': conn.execute('SELECT COUNT(DISTINCT recipient_address) as c FROM messages WHERE boite_id=?', (bid,)).fetchone()['c'],
            'nb_ips': conn.execute('SELECT COUNT(DISTINCT from_ip) as c FROM messages WHERE boite_id=? AND from_ip!=""', (bid,)).fetchone()['c'],
            'statuts': dict(conn.execute('SELECT status, COUNT(*) as c FROM messages WHERE boite_id=? GROUP BY status', (bid,)).fetchall()),
            'nb_ivry': nb_ivry,
            'nb_external': nb_external
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
    try:
        boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
        if not boite:
            flash('Boîte non trouvée')
            return redirect(url_for('index'))
        
        messages = conn.execute('SELECT * FROM messages WHERE boite_id=? ORDER BY received DESC', (bid,)).fetchall()
        ips = conn.execute('SELECT DISTINCT from_ip, COUNT(*) as cnt FROM messages WHERE boite_id=? AND from_ip!="" GROUP BY from_ip', (bid,)).fetchall()
        recipients = conn.execute('SELECT DISTINCT recipient_address, COUNT(*) as cnt FROM messages WHERE boite_id=? GROUP BY recipient_address ORDER BY cnt DESC LIMIT 50', (bid,)).fetchall()
        all_recipients = conn.execute('SELECT DISTINCT recipient_address, COUNT(*) as cnt FROM messages WHERE boite_id=? GROUP BY recipient_address ORDER BY cnt DESC', (bid,)).fetchall()
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
        all_domains = sorted(domains.items(), key=lambda x: x[1], reverse=True)
        
        # Géolocalisation des IPs
        ip_info_list = []
        print(f"DEBUG: {len(ips)} IPs trouvées")
        for ip_row in ips:
            ip = ip_row['from_ip']
            print(f"DEBUG: Géolocalisation de {ip}")
            info = get_ip_info(ip)
            if info:
                print(f"DEBUG: Info reçue pour {ip}: {info.get('city')}, {info.get('country')}")
                if isinstance(info, dict):
                    ip_info_list.append(info)
                else:
                    ip_info_list.append(dict(info))
            else:
                print(f"DEBUG: Pas d'info pour {ip}")
        
        # Vérification SPF/DKIM/DMARC pour le domaine expéditeur
        sender_domain = ''
        spf_dkim_dmarc = None
        if messages:
            sender_email = messages[0]['sender_address'] if messages else ''
            if '@' in sender_email:
                sender_domain = sender_email.split('@')[1].lower()
                spf_dkim_dmarc = check_spf_dkim_dmarc(sender_domain)
        
        # Analyse temporelle (par tranches de 15 min)
        timeline_rows = conn.execute('''SELECT 
            CASE 
                WHEN strftime('%M', received) < '15' THEN strftime('%Y-%m-%d %H:00', received)
                WHEN strftime('%M', received) < '30' THEN strftime('%Y-%m-%d %H:15', received)
                WHEN strftime('%M', received) < '45' THEN strftime('%Y-%m-%d %H:30', received)
                ELSE strftime('%Y-%m-%d %H:45', received)
            END as time_slot,
            COUNT(*) as cnt 
            FROM messages WHERE boite_id=? 
            GROUP BY time_slot
            ORDER BY time_slot''', (bid,)).fetchall()
        timeline = [{'hour': row['time_slot'], 'cnt': row['cnt']} for row in timeline_rows]
        
        # Analyse par domaine de destinataire
        domain_analysis = {}
        for row in domain_rows:
            email = row['recipient_address']
            if '@' in email:
                domain = email.split('@')[1].lower()
                if domain not in domain_analysis:
                    domain_analysis[domain] = {'count': 0, 'recipients': set()}
                domain_analysis[domain]['count'] += 1
                domain_analysis[domain]['recipients'].add(email)
        
        domain_stats = [{'domain': k, 'count': v['count'], 'recipients': len(v['recipients'])} 
                       for k, v in domain_analysis.items()]
        domain_stats.sort(key=lambda x: x['count'], reverse=True)
        
        # Calculer la fenetre d'attaque
        first_msg = conn.execute('SELECT MIN(received) as first FROM messages WHERE boite_id=?', (bid,)).fetchone()['first']
        last_msg = conn.execute('SELECT MAX(received) as last FROM messages WHERE boite_id=?', (bid,)).fetchone()['last']
        
    finally:
        conn.close()
    
    return render_template('view_boite.html', 
                         boite=boite, messages=messages, ips=ips, 
                         recipients=recipients, statuts=statuts, 
                         top_domains=top_domains, ip_info_list=ip_info_list,
                         timeline=timeline, domain_stats=domain_stats,
                         first_msg=first_msg, last_msg=last_msg,
                         sender_domain=sender_domain, spf_dkim_dmarc=spf_dkim_dmarc)

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
                
                # Gestion des nouveaux champs (peuvent ne pas exister dans l'ancien CSV)
                attachments = row.get('Attachments', '').strip('"') or None
                urls = row.get('Urls', '').strip('"') or None
                
                conn.execute('''INSERT INTO messages 
                    (boite_id, message_id, received, sender_address, recipient_address,
                     subject, status, to_ip, from_ip, size, message_trace_id, csv_source,
                     attachments, urls)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (boite_id, row.get('MessageId','').strip('"'), row.get('Received','').strip('"'),
                     row.get('SenderAddress','').strip('"'), row.get('RecipientAddress','').strip('"'),
                     row.get('Subject','').strip('"'), row.get('Status','').strip('"'),
                     row.get('ToIP','').strip('"'), from_ip,
                     size,
                     row.get('MessageTraceId','').strip('"'), source,
                     attachments, urls))
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

@app.route('/logs')
@login_required
def view_logs():
    conn = get_db()
    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page

    level_filter = request.args.get('level', '')
    category_filter = request.args.get('category', '')
    search = request.args.get('search', '')

    query = 'SELECT * FROM logs WHERE 1=1'
    params = []

    if level_filter:
        query += ' AND level=?'
        params.append(level_filter)
    if category_filter:
        query += ' AND category=?'
        params.append(category_filter)
    if search:
        query += ' AND (message LIKE ? OR details LIKE ? OR recipient LIKE ?)'
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

    query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
    params.extend([per_page, offset])

    logs = conn.execute(query, params).fetchall()

    count_query = 'SELECT COUNT(*) as cnt FROM logs WHERE 1=1'
    count_params = []
    if level_filter:
        count_query += ' AND level=?'
        count_params.append(level_filter)
    if category_filter:
        count_query += ' AND category=?'
        count_params.append(category_filter)
    if search:
        count_query += ' AND (message LIKE ? OR details LIKE ? OR recipient LIKE ?)'
        count_params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

    total = conn.execute(count_query, count_params).fetchone()['cnt']
    total_pages = (total + per_page - 1) // per_page

    levels = conn.execute('SELECT DISTINCT level FROM logs ORDER BY level').fetchall()
    categories = conn.execute('SELECT DISTINCT category FROM logs ORDER BY category').fetchall()

    conn.close()
    return render_template('logs.html', logs=logs, page=page, total_pages=total_pages,
                           levels=levels, categories=categories,
                           level_filter=level_filter, category_filter=category_filter, search=search)

@app.route('/logs/clear', methods=['POST'])
@login_required
def clear_logs():
    conn = get_db()
    conn.execute('DELETE FROM logs')
    conn.commit()
    conn.close()
    flash('Logs supprimés')
    return redirect(url_for('view_logs'))

@app.route('/log/<int:log_id>')
@login_required
def view_log_detail(log_id):
    conn = get_db()
    log = conn.execute('SELECT * FROM logs WHERE id=?', (log_id,)).fetchone()
    conn.close()
    if not log:
        flash('Log non trouvé')
        return redirect(url_for('view_logs'))
    return render_template('log_detail.html', log=log)

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
            set_config('api_verify_ssl', request.form.get('api_verify_ssl', 'True'))
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
            response_body = response.read().decode('utf-8')
            return jsonify({
                'success': True, 
                'message': f'API accessible (HTTP {response.status})',
                'response': response_body,
                'url': api_url.rstrip('/') + '/ping'
            })
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        return jsonify({
            'success': False, 
            'message': f'Erreur HTTP {e.code}',
            'response': error_body,
            'url': api_url.rstrip('/') + '/ping'
        })
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

@app.route('/api/test-send-custom', methods=['POST'])
def test_send_custom():
    import urllib.request
    
    token = get_config('api_ville_token', '')
    api_url = get_config('api_ville_url', '')
    
    if not token or not api_url:
        return jsonify({'success': False, 'message': 'Configuration API manquante'})
    
    data = request.get_json() or {}
    emetteur_nom = data.get('emetteur_nom', '')
    emetteur_email = data.get('emetteur_email', '')
    titre = data.get('titre', '')
    header1 = data.get('header1', '')
    header2 = data.get('header2', '')
    header3 = data.get('header3', '')
    cc_raw = data.get('cc', '')
    cc_list = [addr.strip() for addr in cc_raw.split(',') if addr.strip()] if cc_raw else []
    message_body = data.get('message', '')
    
    try:
        test_recipient = cc_list[0] if cc_list else 'test@example.com'
        email_data = {
            'to': test_recipient,
            'cc': [],
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
                'message': f'Test réussi (HTTP {response.status})',
                'response': response.read().decode('utf-8')
            })
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        return jsonify({
            'success': False,
            'message': f'Erreur HTTP {e.code}: {error_body}'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erreur: {str(e)}'})

@app.route('/boite/<int:bid>/recipients-count')
def get_recipients_count(bid):
    conn = get_db()
    count = conn.execute('SELECT COUNT(DISTINCT recipient_address) as cnt FROM messages WHERE boite_id=?', (bid,)).fetchone()['cnt']
    conn.close()
    return jsonify({'count': count})

@app.route('/boite/<int:bid>/send-emails', methods=['POST'])
def send_emails_to_recipients(bid):
    import urllib.request
    import urllib.error
    import traceback
    import ssl

    def make_ssl_context():
        """Crée un contexte SSL qui ignore la vérification si api_verify_ssl=False"""
        verify_ssl = get_config('api_verify_ssl', 'True') == 'True'
        if verify_ssl:
            return ssl.create_default_context()
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx

    def make_opener():
        """Crée un opener avec le contexte SSL approprié"""
        ctx = make_ssl_context()
        https_handler = urllib.request.HTTPSHandler(context=ctx)
        return urllib.request.build_opener(https_handler)

    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    if not boite:
        conn.close()
        add_log('ERROR', 'EMAIL', f'Boîte {bid} non trouvée lors de l\'envoi d\'emails')
        return jsonify({'success': False, 'message': 'Boîte non trouvée'})

    recipients = conn.execute('SELECT DISTINCT recipient_address FROM messages WHERE boite_id=?', (bid,)).fetchall()
    conn.close()

    if not recipients:
        add_log('WARNING', 'EMAIL', f'Aucun destinataire trouvé pour la boîte {bid}')
        return jsonify({'success': False, 'message': 'Aucun destinataire trouvé'})

    api_url = get_config('api_ville_url', '')
    token = get_config('api_ville_token', '')

    if not api_url or not token:
        add_log('ERROR', 'EMAIL', f'Configuration API Ville incomplète pour la boîte {bid} ({boite["user_email"]})', f'api_url: {api_url}, token présent: {bool(token)}', bid)
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

    add_log('INFO', 'EMAIL', f'Début envoi emails pour boîte {bid}', f'{len(recipients)} destinataires, sujet: {titre}', bid)

    results = {'success': 0, 'failed': 0, 'errors': [], 'debug': []}

    for r in recipients:
        recipient = r['recipient_address']
        full_url = api_url.rstrip('/') + '/api/v1/mail/send'
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
            
            # Contexte SSL selon config
            ctx = ssl.create_default_context()
            if not verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            
            https_handler = urllib.request.HTTPSHandler(context=ctx)
            opener = urllib.request.build_opener(https_handler)
            
            with opener.open(req, timeout=30) as response:
                response_text = response.read().decode('utf-8')
                results['debug'].append(f'Success: {response.status} - {response_text}')
                results['success'] += 1
                add_log('INFO', 'EMAIL', f'Email envoyé avec succès vers {recipient}', f'Boîte: {boite["user_email"]}, Sujet: {titre}, HTTP {response.status}, Réponse: {response_text}', bid, recipient)
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8') if e.fp else str(e)
            results['failed'] += 1
            results['errors'].append(f'{recipient}: HTTP {e.code} - {error_body}')
            results['debug'].append(f'HTTP Error: {e.code} - {error_body}')
            add_log('ERROR', 'EMAIL', f'Échec envoi email vers {recipient}', f'Boîte: {boite["user_email"]}, Sujet: {titre}, API: {full_url}, HTTP {e.code}: {error_body}', bid, recipient)
        except Exception as e:
            results['failed'] += 1
            results['errors'].append(f'{recipient}: {str(e)}')
            results['debug'].append(f'Error: {traceback.format_exc()}')
            add_log('ERROR', 'EMAIL', f'Échec envoi email vers {recipient}', f'Boîte: {boite["user_email"]}, Sujet: {titre}, API: {full_url}, Erreur: {str(e)}\n{traceback.format_exc()}', bid, recipient)

    error_details = ' | '.join(results['errors'][:3]) if results['errors'] else ''
    add_log('INFO', 'EMAIL', f'Fin envoi emails pour boîte {bid}', f'{results["success"]} succès, {results["failed"]} échecs', bid)
    return jsonify({
        'success': results['failed'] == 0,
        'message': f'{results["success"]} emails envoyés, {results["failed"]} échecs. Détails: {error_details}',
        'details': results
    })

@app.route('/boite/<int:bid>/export-pdf')
def export_boite_pdf(bid):
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    if not boite:
        conn.close()
        flash('Boîte non trouvée')
        return redirect(url_for('index'))
    
    messages = conn.execute('SELECT * FROM messages WHERE boite_id=? ORDER BY received DESC', (bid,)).fetchall()
    ips = conn.execute('SELECT DISTINCT from_ip, COUNT(*) as cnt FROM messages WHERE boite_id=? AND from_ip!="" GROUP BY from_ip', (bid,)).fetchall()
    recipients = conn.execute('SELECT DISTINCT recipient_address, COUNT(*) as cnt FROM messages WHERE boite_id=? GROUP BY recipient_address ORDER BY cnt DESC', (bid,)).fetchall()
    
    # Extraire les domaines
    domain_rows = conn.execute('SELECT recipient_address FROM messages WHERE boite_id=?', (bid,)).fetchall()
    domains = {}
    for row in domain_rows:
        email = row['recipient_address']
        if '@' in email:
            domain = email.split('@')[1].lower()
            domains[domain] = domains.get(domain, 0) + 1
    top_domains = sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Géolocalisation des IPs
    ip_info_list = []
    for ip_row in ips:
        ip = ip_row['from_ip']
        info = get_ip_info(ip)
        if info:
            ip_info_list.append(info)
    
    # Vérification SPF/DKIM/DMARC
    sender_domain = ''
    spf_dkim_dmarc = None
    if messages:
        sender_email = messages[0]['sender_address'] if messages else ''
        if '@' in sender_email:
            sender_domain = sender_email.split('@')[1].lower()
            spf_dkim_dmarc = check_spf_dkim_dmarc(sender_domain)
    
    # Analyse temporelle
    timeline_rows = conn.execute('''SELECT 
        CASE 
            WHEN strftime('%M', received) < '15' THEN strftime('%Y-%m-%d %H:00', received)
            WHEN strftime('%M', received) < '30' THEN strftime('%Y-%m-%d %H:15', received)
            WHEN strftime('%M', received) < '45' THEN strftime('%Y-%m-%d %H:30', received)
            ELSE strftime('%Y-%m-%d %H:45', received)
        END as time_slot,
        COUNT(*) as cnt 
        FROM messages WHERE boite_id=? 
        GROUP BY time_slot
        ORDER BY time_slot''', (bid,)).fetchall()
    timeline = [{'hour': row['time_slot'], 'cnt': row['cnt']} for row in timeline_rows]
    
    first_msg = conn.execute('SELECT MIN(received) as first FROM messages WHERE boite_id=?', (bid,)).fetchone()['first']
    last_msg = conn.execute('SELECT MAX(received) as last FROM messages WHERE boite_id=?', (bid,)).fetchone()['last']
    
    conn.close()
    
    # Rendre le template HTML pour impression/PDF
    html_content = render_template('boite_print.html',
                                  boite=boite, messages=messages, ips=ips,
                                  recipients=recipients, top_domains=top_domains,
                                  ip_info_list=ip_info_list,
                                  spf_dkim_dmarc=spf_dkim_dmarc,
                                  timeline=timeline, first_msg=first_msg, last_msg=last_msg)
    
    response = make_response(html_content)
    response.headers['Content-Type'] = 'text/html'
    return response


@app.route('/boite/<int:bid>/export')
def export_messages(bid):
    import io
    conn = get_db()
    boite = conn.execute('SELECT user_email FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    if not boite:
        conn.close()
        flash('Boîte non trouvée')
        return redirect(url_for('index'))
    
    messages = conn.execute('SELECT * FROM messages WHERE boite_id=? ORDER BY received DESC', (bid,)).fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(['Date/Heure', 'Destinataire', 'Sujet', 'Statut', 'IP Source', 'Taille (KB)', 'Pièces jointes', 'URLs'])
    
    for msg in messages:
        writer.writerow([
            msg['received'],
            msg['recipient_address'],
            msg['subject'],
            msg['status'],
            msg['from_ip'],
            round(msg['size'] / 1024, 1) if msg['size'] else 0,
            msg['attachments'] or '',
            msg['urls'] or ''
        ])
    
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    response.headers['Content-Disposition'] = f'attachment; filename=messages_{boite["user_email"].replace("@", "_")}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    return response

def load_config_from_env():
    import os
    api_url = os.environ.get('API_VILLE_URL', '')
    api_token = os.environ.get('API_VILLE_TOKEN', '')
    if api_url:
        set_config('api_ville_url', api_url)
    if api_token:
        set_config('api_ville_token', api_token)

load_config_from_env()

if __name__ == '__main__':
    import sys
    load_config_from_env()
    if len(sys.argv) > 1 and sys.argv[1] == '--dev':
        app.run(host='0.0.0.0', debug=True, port=5050)
    else:
        from waitress import serve
        print("Démarrage avec Waitress (stable)...")
        serve(app, host='0.0.0.0', port=5050, threads=4)
