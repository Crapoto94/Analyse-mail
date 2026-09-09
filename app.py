import os
import csv
import sqlite3
import re
import unicodedata
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

    c.execute('''CREATE TABLE IF NOT EXISTS signin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        boite_id INTEGER,
        date_utc TEXT,
        request_id TEXT,
        correlation_id TEXT,
        user_display_name TEXT,
        user_upn TEXT,
        ip_address TEXT,
        location TEXT,
        country TEXT,
        status TEXT,
        error_code TEXT,
        failure_reason TEXT,
        application TEXT,
        client_app TEXT,
        device_id TEXT,
        browser TEXT,
        os TEXT,
        is_compliant TEXT,
        is_managed TEXT,
        conditional_access TEXT,
        mfa_result TEXT,
        mfa_method TEXT,
        asn TEXT,
        flagged TEXT,
        user_agent TEXT,
        csv_source TEXT,
        raw_json TEXT,
        FOREIGN KEY (boite_id) REFERENCES boites_compromises(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        boite_id INTEGER,
        date_utc TEXT,
        correlation_id TEXT,
        service TEXT,
        categorie TEXT,
        activite TEXT,
        resultat TEXT,
        result_reason TEXT,
        actor_type TEXT,
        actor_display_name TEXT,
        actor_upn TEXT,
        ip_address TEXT,
        target_type TEXT,
        target_display_name TEXT,
        target_upn TEXT,
        modifications_summary TEXT,
        csv_source TEXT,
        raw_json TEXT,
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
            'nb_external': nb_external,
            'nb_signins': conn.execute('SELECT COUNT(*) as c FROM signin_logs WHERE boite_id=?', (bid,)).fetchone()['c'],
            'nb_audit': conn.execute('SELECT COUNT(*) as c FROM audit_logs WHERE boite_id=?', (bid,)).fetchone()['c'],
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
        nb_signins = conn.execute('SELECT COUNT(*) as c FROM signin_logs WHERE boite_id=?', (bid,)).fetchone()['c']
        nb_audit = conn.execute('SELECT COUNT(*) as c FROM audit_logs WHERE boite_id=?', (bid,)).fetchone()['c']
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
                         sender_domain=sender_domain, spf_dkim_dmarc=spf_dkim_dmarc,
                         nb_signins=nb_signins, nb_audit=nb_audit)

def _timeline_query(conn, table, bid):
    rows = conn.execute(f'''SELECT
        CASE
            WHEN strftime('%M', date_utc) < '15' THEN strftime('%Y-%m-%d %H:00', date_utc)
            WHEN strftime('%M', date_utc) < '30' THEN strftime('%Y-%m-%d %H:15', date_utc)
            WHEN strftime('%M', date_utc) < '45' THEN strftime('%Y-%m-%d %H:30', date_utc)
            ELSE strftime('%Y-%m-%d %H:45', date_utc)
        END as time_slot,
        COUNT(*) as cnt
        FROM {table} WHERE boite_id=? AND date_utc IS NOT NULL AND date_utc != ''
        GROUP BY time_slot
        ORDER BY time_slot''', (bid,)).fetchall()
    return [{'hour': row['time_slot'], 'cnt': row['cnt']} for row in rows]


def _is_success_status(status):
    s = (status or '').lower()
    return 'réussi' in s or 'success' in s or 'reussi' in s


def _is_truthy(value):
    return (value or '').strip().lower() in ('true', 'vrai', 'yes', 'oui', '1')


@app.route('/boite/<int:bid>/signins')
def view_signins(bid):
    conn = get_db()
    try:
        boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
        if not boite:
            flash('Boîte non trouvée')
            return redirect(url_for('index'))

        signins = conn.execute('SELECT * FROM signin_logs WHERE boite_id=? ORDER BY date_utc DESC', (bid,)).fetchall()
        total = len(signins)
        nb_success = sum(1 for s in signins if _is_success_status(s['status']))
        nb_failed = total - nb_success

        distinct_users = sorted(set(s['user_upn'] for s in signins if s['user_upn']))
        distinct_ips = sorted(set(s['ip_address'] for s in signins if s['ip_address']))

        country_counts = {}
        for s in signins:
            c = s['country'] or 'Inconnu'
            country_counts[c] = country_counts.get(c, 0) + 1
        country_stats = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
        baseline_country = country_stats[0][0] if country_stats else ''

        app_counts = {}
        for s in signins:
            a = s['application'] or 'Inconnu'
            app_counts[a] = app_counts.get(a, 0) + 1
        app_stats = sorted(app_counts.items(), key=lambda x: x[1], reverse=True)[:20]

        mfa_counts = {}
        for s in signins:
            m = s['mfa_result'] or 'N/A'
            mfa_counts[m] = mfa_counts.get(m, 0) + 1
        mfa_stats = sorted(mfa_counts.items(), key=lambda x: x[1], reverse=True)

        ip_info_list = []
        for ip in distinct_ips:
            info = get_ip_info(ip)
            if info:
                ip_info_list.append(dict(info))

        flagged_rows = [s for s in signins if _is_truthy(s['flagged'])]
        foreign_success = [s for s in signins if _is_success_status(s['status']) and baseline_country
                            and s['country'] and s['country'] != baseline_country]
        failed_rows = [s for s in signins if not _is_success_status(s['status'])]

        timeline = _timeline_query(conn, 'signin_logs', bid)
        first_signin = conn.execute('SELECT MIN(date_utc) as first FROM signin_logs WHERE boite_id=?', (bid,)).fetchone()['first']
        last_signin = conn.execute('SELECT MAX(date_utc) as last FROM signin_logs WHERE boite_id=?', (bid,)).fetchone()['last']
    finally:
        conn.close()

    return render_template('signins.html', boite=boite, signins=signins, total=total,
                         nb_success=nb_success, nb_failed=nb_failed,
                         distinct_users=distinct_users, distinct_ips=distinct_ips,
                         country_stats=country_stats, baseline_country=baseline_country,
                         app_stats=app_stats, mfa_stats=mfa_stats, ip_info_list=ip_info_list,
                         flagged_rows=flagged_rows, foreign_success=foreign_success, failed_rows=failed_rows,
                         timeline=timeline, first_signin=first_signin, last_signin=last_signin)


@app.route('/signin/<int:signin_id>')
def view_signin_detail(signin_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM signin_logs WHERE id=?', (signin_id,)).fetchone()
    conn.close()
    if not row:
        flash('Connexion non trouvée')
        return redirect(url_for('index'))
    try:
        raw = json.loads(row['raw_json']) if row['raw_json'] else {}
    except Exception:
        raw = {}
    return render_template('raw_detail.html', row=row, raw=raw,
                         title=f"Connexion #{row['id']} - {row['user_upn'] or row['user_display_name']}",
                         subtitle=row['date_utc'],
                         back_url=url_for('view_signins', bid=row['boite_id']),
                         back_label='Retour aux connexions')


@app.route('/boite/<int:bid>/audit')
def view_audit(bid):
    conn = get_db()
    try:
        boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
        if not boite:
            flash('Boîte non trouvée')
            return redirect(url_for('index'))

        events = conn.execute('SELECT * FROM audit_logs WHERE boite_id=? ORDER BY date_utc DESC', (bid,)).fetchall()
        total = len(events)

        activity_counts = {}
        for e in events:
            a = e['activite'] or 'Inconnu'
            activity_counts[a] = activity_counts.get(a, 0) + 1
        activity_stats = sorted(activity_counts.items(), key=lambda x: x[1], reverse=True)

        result_counts = {}
        for e in events:
            r = e['resultat'] or 'Inconnu'
            result_counts[r] = result_counts.get(r, 0) + 1
        result_stats = sorted(result_counts.items(), key=lambda x: x[1], reverse=True)

        actor_counts = {}
        for e in events:
            a = e['actor_display_name'] or e['actor_upn'] or 'Inconnu'
            actor_counts[a] = actor_counts.get(a, 0) + 1
        actor_stats = sorted(actor_counts.items(), key=lambda x: x[1], reverse=True)[:20]

        def is_suspicious(activite):
            norm = _normalize_header(activite or '')
            return any(kw in norm for kw in SUSPICIOUS_AUDIT_KEYWORDS)

        suspicious_events = [e for e in events if is_suspicious(e['activite'])]

        timeline = _timeline_query(conn, 'audit_logs', bid)
        first_event = conn.execute('SELECT MIN(date_utc) as first FROM audit_logs WHERE boite_id=?', (bid,)).fetchone()['first']
        last_event = conn.execute('SELECT MAX(date_utc) as last FROM audit_logs WHERE boite_id=?', (bid,)).fetchone()['last']
    finally:
        conn.close()

    return render_template('audit.html', boite=boite, events=events, total=total,
                         activity_stats=activity_stats, result_stats=result_stats,
                         actor_stats=actor_stats, suspicious_events=suspicious_events,
                         timeline=timeline, first_event=first_event, last_event=last_event)


@app.route('/auditevent/<int:event_id>')
def view_audit_detail(event_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM audit_logs WHERE id=?', (event_id,)).fetchone()
    conn.close()
    if not row:
        flash('Événement non trouvé')
        return redirect(url_for('index'))
    try:
        raw = json.loads(row['raw_json']) if row['raw_json'] else {}
    except Exception:
        raw = {}
    return render_template('raw_detail.html', row=row, raw=raw,
                         title=f"Événement d'audit #{row['id']} - {row['activite']}",
                         subtitle=row['date_utc'],
                         back_url=url_for('view_audit', bid=row['boite_id']),
                         back_label="Retour au journal d'audit")


@app.route('/boite/<int:bid>/upload', methods=['GET', 'POST'])
def upload_csv(bid):
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    conn.close()
    if not boite:
        flash('Boîte non trouvée')
        return redirect(url_for('index'))
    if request.method == 'POST':
        uploads = [
            ('csv_file', import_csv, 'message(s)'),
            ('audit_file', import_audit_logs, "événement(s) d'audit"),
            ('signin_file', import_signin_logs, 'connexion(s) interactive(s)'),
        ]
        summary = []
        any_file = False
        for field_name, importer, label in uploads:
            file = request.files.get(field_name)
            if not file or file.filename == '':
                continue
            any_file = True
            if not file.filename.endswith('.csv'):
                flash(f'Format non supporté pour {file.filename} (CSV uniquement)')
                continue
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            try:
                count, duplicates = importer(bid, filepath, filename)
                line = f'{count} {label}'
                if duplicates:
                    line += f' ({duplicates} doublon(s) ignoré(s))'
                summary.append(line)
            except Exception as e:
                flash(f"Erreur lors de l'import de {file.filename}: {e}")

        if not any_file:
            flash('Aucun fichier sélectionné')
            return redirect(request.url)
        if summary:
            flash('Import réussi : ' + ', '.join(summary))
        return redirect(url_for('view_boite', bid=bid))
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
    duplicates = 0
    delimiter = detect_delimiter(filepath)
    existing = set(
        (r['message_id'], r['recipient_address'], r['received'])
        for r in conn.execute('SELECT message_id, recipient_address, received FROM messages WHERE boite_id=?', (boite_id,)).fetchall()
    )
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        for row in reader:
            try:
                message_id = row.get('MessageId', '').strip('"')
                received = row.get('Received', '').strip('"')
                recipient_address = row.get('RecipientAddress', '').strip('"')
                key = (message_id, recipient_address, received)
                if key in existing:
                    duplicates += 1
                    continue

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
                    (boite_id, message_id, received,
                     row.get('SenderAddress','').strip('"'), recipient_address,
                     row.get('Subject','').strip('"'), row.get('Status','').strip('"'),
                     row.get('ToIP','').strip('"'), from_ip,
                     size,
                     row.get('MessageTraceId','').strip('"'), source,
                     attachments, urls))
                existing.add(key)
                count += 1
            except Exception as e:
                print(f"Erreur ligne: {e}")
                continue
    conn.commit()
    conn.close()
    return count, duplicates

def _normalize_header(h):
    """Normalise un nom de colonne CSV pour le rendre tolérant aux variations
    d'export (accents, apostrophes typographiques, espaces insécables, casse)."""
    if not h:
        return ''
    h = h.replace('’', "'").replace('–', '-').replace('\xa0', ' ')
    h = unicodedata.normalize('NFKD', h)
    h = ''.join(ch for ch in h if not unicodedata.combining(ch))
    h = h.lower()
    return re.sub(r'[^a-z0-9]+', '', h)


# Colonnes attendues pour l'export "Interactive sign-ins" de Microsoft Entra ID (Azure AD),
# avec variantes possibles selon la version/langue de l'export.
SIGNIN_FIELD_CANDIDATES = {
    'date': ['Date (UTC)'],
    'request_id': ['ID de requête'],
    'user_agent': ['Agent utilisateur'],
    'correlation_id': ['ID de corrélation'],
    'user_id': ['Identifiant utilisateur'],
    'user_display_name': ['Utilisateur'],
    'user_upn': ["Nom d'utilisateur"],
    'application': ['Application'],
    'ip_address': ['Adresse IP'],
    'location': ['Emplacement'],
    'status': ['Statut'],
    'error_code': ["Code d'erreur de connexion"],
    'failure_reason': ["Raison de l'échec"],
    'client_app': ['Application cliente'],
    'device_id': ["ID de l'appareil"],
    'browser': ['Navigateur'],
    'os': ["Système d'exploitation"],
    'is_compliant': ['Conforme'],
    'is_managed': ['Géré'],
    'conditional_access': ['Accès conditionnel'],
    'mfa_result': ["Résultat de l'authentification multifacteur", 'Résultat de l’authentification multifacteur'],
    'mfa_method': ["Méthode d'authentification multifacteur", 'Méthode d’authentification multifacteur'],
    'asn': ['Numéro de système autonome'],
    'flagged': ['Signalé pour révision'],
}

# Colonnes attendues pour l'export "Audit logs" de Microsoft Entra ID (Azure AD).
AUDIT_FIELD_CANDIDATES = {
    'date': ['Date (UTC)'],
    'correlation_id': ['CorrelationId'],
    'service': ['Service'],
    'categorie': ['Catégorie'],
    'activite': ['Activité'],
    'resultat': ['Résultat'],
    'result_reason': ['ResultReason'],
    'actor_type': ['ActorType'],
    'actor_display_name': ['ActorDisplayName'],
    'actor_upn': ['ActorUserPrincipalName'],
    'ip_address': ['IPAddress'],
    'target_type': ['Target1Type'],
    'target_display_name': ['Target1DisplayName'],
    'target_upn': ['Cible1UserPrincipalName'],
}

# Mots-clés (normalisés) d'activités d'audit sensibles à surveiller en priorité
# lors d'une investigation de compromission de compte.
SUSPICIOUS_AUDIT_KEYWORDS = [
    'inboxrule', 'transportrule', 'forward', 'redirect', 'delegate', 'consent',
    'serviceprincipal', 'approleassignment', 'addowner', 'federation', 'password',
    'credential', 'authenticationmethod', 'strongauthentication', 'mfa', 'phonenumber',
    'permission', 'roleassignment', 'admin', 'stsrefreshtokenvalidfrom',
]


def _build_header_lookup(fieldnames):
    return {_normalize_header(h): h for h in (fieldnames or [])}


def _get_field(row, norm_to_orig, field_map, key):
    for candidate in field_map.get(key, []):
        orig = norm_to_orig.get(_normalize_header(candidate))
        if orig is not None:
            value = row.get(orig, '')
            if value is not None:
                return value.strip().strip('"')
    return ''


def _parse_country(location):
    """Extrait le code pays depuis un champ 'Emplacement' du type 'Paris, Paris, FR'."""
    if not location:
        return ''
    parts = [p.strip() for p in location.split(',') if p.strip()]
    return parts[-1] if parts else ''


def import_signin_logs(boite_id, filepath, source):
    conn = get_db()
    count = 0
    duplicates = 0
    delimiter = detect_delimiter(filepath)
    existing = set(
        (r['request_id'], r['date_utc'], r['user_upn'], r['ip_address'])
        for r in conn.execute('SELECT request_id, date_utc, user_upn, ip_address FROM signin_logs WHERE boite_id=?', (boite_id,)).fetchall()
    )
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        norm_to_orig = _build_header_lookup(reader.fieldnames)
        for row in reader:
            try:
                def g(key):
                    return _get_field(row, norm_to_orig, SIGNIN_FIELD_CANDIDATES, key)
                request_id = g('request_id')
                date_utc = g('date')
                user_upn = g('user_upn')
                ip_address = g('ip_address')
                key = (request_id, date_utc, user_upn, ip_address)
                if key in existing:
                    duplicates += 1
                    continue

                location = g('location')
                conn.execute('''INSERT INTO signin_logs
                    (boite_id, date_utc, request_id, correlation_id, user_display_name, user_upn,
                     ip_address, location, country, status, error_code, failure_reason, application,
                     client_app, device_id, browser, os, is_compliant, is_managed, conditional_access,
                     mfa_result, mfa_method, asn, flagged, user_agent, csv_source, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (boite_id, date_utc, request_id, g('correlation_id'), g('user_display_name'),
                     user_upn, ip_address, location, _parse_country(location), g('status'),
                     g('error_code'), g('failure_reason'), g('application'), g('client_app'),
                     g('device_id'), g('browser'), g('os'), g('is_compliant'), g('is_managed'),
                     g('conditional_access'), g('mfa_result'), g('mfa_method'), g('asn'), g('flagged'),
                     g('user_agent'), source, json.dumps(row, ensure_ascii=False)))
                existing.add(key)
                count += 1
            except Exception as e:
                print(f"Erreur ligne sign-in: {e}")
                continue
    conn.commit()
    conn.close()
    return count, duplicates


def _summarize_modifications(row, norm_to_orig):
    """Reconstruit un résumé lisible des propriétés modifiées (Target1..3, Property1..5)
    présentes dans un export Audit Logs Entra ID."""
    parts = []
    for target_idx in (1, 2, 3):
        for prop_idx in (1, 2, 3, 4, 5):
            name_key = f'Target{target_idx}ModifiedProperty{prop_idx}Name'
            old_key = f'Target{target_idx}ModifiedProperty{prop_idx}OldValue'
            new_key = f'Target{target_idx}ModifiedProperty{prop_idx}NewValue'
            orig_name = norm_to_orig.get(_normalize_header(name_key))
            if not orig_name:
                continue
            prop_name = (row.get(orig_name) or '').strip().strip('"')
            if not prop_name:
                continue
            orig_old = norm_to_orig.get(_normalize_header(old_key))
            orig_new = norm_to_orig.get(_normalize_header(new_key))
            old_val = (row.get(orig_old) or '').strip().strip('"') if orig_old else ''
            new_val = (row.get(orig_new) or '').strip().strip('"') if orig_new else ''
            parts.append(f'{prop_name}: {old_val} -> {new_val}')
    return ' | '.join(parts)


def import_audit_logs(boite_id, filepath, source):
    conn = get_db()
    count = 0
    duplicates = 0
    delimiter = detect_delimiter(filepath)
    existing = set(
        (r['date_utc'], r['correlation_id'], r['activite'], r['target_upn'])
        for r in conn.execute('SELECT date_utc, correlation_id, activite, target_upn FROM audit_logs WHERE boite_id=?', (boite_id,)).fetchall()
    )
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        norm_to_orig = _build_header_lookup(reader.fieldnames)
        for row in reader:
            try:
                def g(key):
                    return _get_field(row, norm_to_orig, AUDIT_FIELD_CANDIDATES, key)
                date_utc = g('date')
                correlation_id = g('correlation_id')
                activite = g('activite')
                target_upn = g('target_upn')
                key = (date_utc, correlation_id, activite, target_upn)
                if key in existing:
                    duplicates += 1
                    continue

                conn.execute('''INSERT INTO audit_logs
                    (boite_id, date_utc, correlation_id, service, categorie, activite, resultat,
                     result_reason, actor_type, actor_display_name, actor_upn, ip_address,
                     target_type, target_display_name, target_upn, modifications_summary,
                     csv_source, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (boite_id, date_utc, correlation_id, g('service'), g('categorie'),
                     activite, g('resultat'), g('result_reason'), g('actor_type'),
                     g('actor_display_name'), g('actor_upn'), g('ip_address'), g('target_type'),
                     g('target_display_name'), target_upn, _summarize_modifications(row, norm_to_orig),
                     source, json.dumps(row, ensure_ascii=False)))
                existing.add(key)
                count += 1
            except Exception as e:
                print(f"Erreur ligne audit: {e}")
                continue
    conn.commit()
    conn.close()
    return count, duplicates


@app.route('/boite/<int:bid>/delete', methods=['POST'])
def delete_boite(bid):
    conn = get_db()
    conn.execute('DELETE FROM messages WHERE boite_id=?', (bid,))
    conn.execute('DELETE FROM signin_logs WHERE boite_id=?', (bid,))
    conn.execute('DELETE FROM audit_logs WHERE boite_id=?', (bid,))
    conn.execute('DELETE FROM boites_compromises WHERE id=?', (bid,))
    conn.commit()
    conn.close()
    flash('Boîte supprimée')
    return redirect(url_for('index'))


@app.route('/boite/<int:bid>/messages/clear', methods=['POST'])
def clear_messages(bid):
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    if not boite:
        conn.close()
        flash('Boîte non trouvée')
        return redirect(url_for('index'))
    cnt = conn.execute('SELECT COUNT(*) as c FROM messages WHERE boite_id=?', (bid,)).fetchone()['c']
    conn.execute('DELETE FROM messages WHERE boite_id=?', (bid,))
    conn.commit()
    conn.close()
    add_log('INFO', 'IMPORT', f'Messages importés effacés pour la boîte {bid} ({boite["user_email"]})', f'{cnt} message(s) supprimé(s)', bid)
    flash(f'{cnt} message(s) importé(s) effacé(s)')
    return redirect(url_for('view_boite', bid=bid))


@app.route('/boite/<int:bid>/signins/clear', methods=['POST'])
def clear_signins(bid):
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    if not boite:
        conn.close()
        flash('Boîte non trouvée')
        return redirect(url_for('index'))
    cnt = conn.execute('SELECT COUNT(*) as c FROM signin_logs WHERE boite_id=?', (bid,)).fetchone()['c']
    conn.execute('DELETE FROM signin_logs WHERE boite_id=?', (bid,))
    conn.commit()
    conn.close()
    add_log('INFO', 'IMPORT', f'Connexions importées effacées pour la boîte {bid} ({boite["user_email"]})', f'{cnt} connexion(s) supprimée(s)', bid)
    flash(f'{cnt} connexion(s) importée(s) effacée(s)')
    return redirect(url_for('view_boite', bid=bid))


@app.route('/boite/<int:bid>/audit/clear', methods=['POST'])
def clear_audit(bid):
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    if not boite:
        conn.close()
        flash('Boîte non trouvée')
        return redirect(url_for('index'))
    cnt = conn.execute('SELECT COUNT(*) as c FROM audit_logs WHERE boite_id=?', (bid,)).fetchone()['c']
    conn.execute('DELETE FROM audit_logs WHERE boite_id=?', (bid,))
    conn.commit()
    conn.close()
    add_log('INFO', 'IMPORT', f'Événements d\'audit importés effacés pour la boîte {bid} ({boite["user_email"]})', f'{cnt} événement(s) supprimé(s)', bid)
    flash(f'{cnt} événement(s) d\'audit importé(s) effacé(s)')
    return redirect(url_for('view_boite', bid=bid))

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
    
    # Contexte SSL qui ignore totalement la vérification
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    opener = urllib.request.build_opener(https_handler)
    
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
