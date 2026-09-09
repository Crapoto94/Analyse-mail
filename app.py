import os
import csv
import sqlite3
import re
import unicodedata
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import json

app = Flask(__name__)
app.secret_key = 'analyse-compromis-secret-key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


def format_paris_datetime(value, fmt='%d/%m/%Y %H:%M:%S'):
    """Convertit une date ISO8601 (UTC, telle que fournie par les CSV Microsoft 365 /
    l'API Graph) en date/heure française (fuseau Europe/Paris, heure d'été gérée
    automatiquement). Retourne la valeur d'origine si elle est vide ou non reconnue."""
    if not value:
        return ''
    from datetime import datetime
    try:
        from zoneinfo import ZoneInfo
    except ImportError:
        return value

    s = str(value).strip()
    try:
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        if '.' in s:
            head, _, rest = s.partition('.')
            tz = ''
            for sep in ('+', '-'):
                if sep in rest:
                    frac, _, tz_part = rest.partition(sep)
                    tz = sep + tz_part
                    rest = frac
                    break
            rest = (rest[:6] or '0').ljust(6, '0')
            s = f'{head}.{rest}{tz}'
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo('UTC'))
        return dt.astimezone(ZoneInfo('Europe/Paris')).strftime(fmt)
    except Exception:
        return value


app.jinja_env.filters['paris'] = format_paris_datetime

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

    c.execute('''CREATE TABLE IF NOT EXISTS mailbox_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        boite_id INTEGER,
        rule_id TEXT,
        display_name TEXT,
        is_enabled TEXT,
        sequence INTEGER,
        conditions_summary TEXT,
        actions_summary TEXT,
        forwards_to TEXT,
        is_suspicious TEXT,
        source TEXT,
        raw_json TEXT,
        FOREIGN KEY (boite_id) REFERENCES boites_compromises(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS monitored_mailboxes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT UNIQUE NOT NULL,
        interval_minutes INTEGER NOT NULL DEFAULT 60,
        is_active INTEGER NOT NULL DEFAULT 1,
        last_scan_at TEXT,
        last_scan_score INTEGER,
        last_scan_verdict TEXT,
        last_scan_findings_count INTEGER,
        last_error TEXT,
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Migration : creer un compte admin par defaut si la table users est vide, en reprenant
    # l'ancien mot de passe HTTP Basic pour ne pas verrouiller l'acces existant.
    if c.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
        c.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                   ('admin', generate_password_hash('Admin94200!!!2025'), 'admin'))

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

# ============================================================================
# Microsoft Graph API : recuperation directe des connexions, du journal
# d'audit et des regles de messagerie d'une boite via l'API, en alternative
# a l'import manuel de CSV. Authentification "app-only" (flux client
# credentials) : necessite un App Registration Entra ID avec les permissions
# d'application suivantes, consentement admin donne :
#   - AuditLog.Read.All      -> connexions (signIns) et journal d'audit (directoryAudits)
#   - MailboxSettings.Read   -> regles de messagerie (transfert, suppression...)
#   - Mail.Read              -> messages envoyes (optionnel, dossier Elements envoyes)
#   - Directory.Read.All     -> resolution des informations utilisateur (optionnel)
# Voir la page /config pour la configuration (tenant ID, client ID, client secret).
# ============================================================================

_graph_token_cache = {'token': None, 'expires_at': 0}


def get_graph_token(force_refresh=False):
    """Recupere (et met en cache) un jeton d'acces app-only pour Microsoft Graph
    via le flux OAuth2 client_credentials."""
    import time
    import urllib.request
    import urllib.parse
    import urllib.error

    tenant_id = get_config('graph_tenant_id', '').strip()
    client_id = get_config('graph_client_id', '').strip()
    client_secret = get_config('graph_client_secret', '').strip()
    if not (tenant_id and client_id and client_secret):
        raise RuntimeError("Configuration Microsoft Graph incomplète (tenant ID / client ID / client secret manquant) — voir /config")

    now = time.time()
    if not force_refresh and _graph_token_cache['token'] and _graph_token_cache['expires_at'] > now + 60:
        return _graph_token_cache['token']

    url = f'https://login.microsoftonline.com/{urllib.parse.quote(tenant_id)}/oauth2/v2.0/token'
    data = urllib.parse.urlencode({
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://graph.microsoft.com/.default',
        'grant_type': 'client_credentials',
    }).encode('utf-8')
    req = urllib.request.Request(url, data=data, method='POST',
                                  headers={'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8') if e.fp else str(e)
        raise RuntimeError(f"Authentification Microsoft Graph refusée (HTTP {e.code}) : {error_body}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Impossible de joindre Microsoft Graph : {e}")

    token = payload.get('access_token')
    if not token:
        raise RuntimeError(f"Réponse d'authentification Microsoft Graph inattendue : {payload}")
    _graph_token_cache['token'] = token
    _graph_token_cache['expires_at'] = now + int(payload.get('expires_in', 3600))
    return token


def graph_get_all(path, params=None):
    """Effectue un GET sur Microsoft Graph avec pagination automatique (@odata.nextLink).
    `path` est soit un chemin relatif ('/organization'), soit une URL absolue."""
    import urllib.request
    import urllib.parse
    import urllib.error

    token = get_graph_token()
    url = path if path.startswith('http') else 'https://graph.microsoft.com/v1.0' + path
    if params:
        sep = '&' if '?' in url else '?'
        url += sep + urllib.parse.urlencode(params)

    results = []
    while url:
        req = urllib.request.Request(url, headers={
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json',
            'ConsistencyLevel': 'eventual',
        })
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8') if e.fp else str(e)
            raise RuntimeError(f"Erreur Microsoft Graph (HTTP {e.code}) sur {url} : {error_body}")
        if isinstance(payload, dict) and 'value' in payload:
            results.extend(payload['value'])
            url = payload.get('@odata.nextLink')
        else:
            results.append(payload)
            url = None
    return results


def _graph_status_text(status_obj):
    error_code = (status_obj or {}).get('errorCode')
    return 'Success' if error_code in (0, None) else 'Failure'


def _map_graph_signin(item):
    """Convertit un objet Graph auditLogs/signIns en dict aligne sur les colonnes de
    signin_logs. Fonction pure (aucun acces DB) : reutilisee pour l'import persistant
    et pour le scan rapide ephemere."""
    status = item.get('status') or {}
    device = item.get('deviceDetail') or {}
    location = item.get('location') or {}
    mfa = item.get('mfaDetail') or {}
    country = location.get('countryOrRegion', '') or ''
    location_str = ', '.join(p for p in [location.get('city', ''), location.get('state', ''), country] if p)
    risky = item.get('riskLevelAggregated') in ('medium', 'high') or item.get('riskState') == 'atRisk'
    return {
        'date_utc': item.get('createdDateTime', ''),
        'request_id': item.get('id', ''),
        'correlation_id': item.get('correlationId', ''),
        'user_display_name': item.get('userDisplayName', ''),
        'user_upn': item.get('userPrincipalName', ''),
        'ip_address': item.get('ipAddress', ''),
        'location': location_str,
        'country': country,
        'status': _graph_status_text(status),
        'error_code': str(status.get('errorCode', '') if status.get('errorCode') is not None else ''),
        'failure_reason': status.get('failureReason', ''),
        'application': item.get('appDisplayName', ''),
        'client_app': item.get('clientAppUsed', ''),
        'device_id': device.get('deviceId', ''),
        'browser': device.get('browser', ''),
        'os': device.get('operatingSystem', ''),
        'is_compliant': str(device.get('isCompliant', '')).lower(),
        'is_managed': str(device.get('isManaged', '')).lower(),
        'conditional_access': item.get('conditionalAccessStatus', ''),
        'mfa_result': item.get('authenticationRequirement', ''),
        'mfa_method': mfa.get('authMethod', ''),
        'asn': str(item.get('autonomousSystemNumber', '') or ''),
        'flagged': 'true' if risky else 'false',
        'user_agent': '',
        'raw': item,
    }


def _map_graph_audit(item):
    """Convertit un objet Graph auditLogs/directoryAudits en dict aligne sur les
    colonnes de audit_logs. Fonction pure, reutilisee import persistant + scan rapide."""
    targets = item.get('targetResources') or []
    target = targets[0] if targets else {}
    initiated_by = item.get('initiatedBy') or {}
    actor_user = initiated_by.get('user') or {}
    actor_app = initiated_by.get('app') or {}
    mods = target.get('modifiedProperties') or []
    mods_summary = ' | '.join(
        f"{m.get('displayName','')}: {m.get('oldValue','')} -> {m.get('newValue','')}"
        for m in mods if m.get('displayName')
    )
    return {
        'date_utc': item.get('activityDateTime', ''),
        'correlation_id': item.get('correlationId', ''),
        'service': item.get('loggedByService', ''),
        'categorie': item.get('category', ''),
        'activite': item.get('activityDisplayName', ''),
        'resultat': 'Success' if item.get('result') == 'success' else 'Failure',
        'result_reason': item.get('resultReason', ''),
        'actor_type': 'User' if actor_user else ('Application' if actor_app else ''),
        'actor_display_name': actor_user.get('displayName') or actor_app.get('displayName', ''),
        'actor_upn': actor_user.get('userPrincipalName', ''),
        'ip_address': actor_user.get('ipAddress', ''),
        'target_type': target.get('type', ''),
        'target_display_name': target.get('displayName', ''),
        'target_upn': target.get('userPrincipalName', ''),
        'modifications_summary': mods_summary,
        'raw': item,
    }


def _map_graph_rule(item):
    """Convertit un objet Graph messageRule en dict aligne sur les colonnes de
    mailbox_rules. Fonction pure, reutilisee import persistant + scan rapide."""
    actions = item.get('actions') or {}
    conditions = item.get('conditions') or {}
    forward_targets = []
    for field in ('forwardTo', 'redirectTo', 'forwardAsAttachmentTo'):
        for rec in (actions.get(field) or []):
            addr = (rec.get('emailAddress') or {}).get('address')
            if addr:
                forward_targets.append(addr)
    actions_parts = [f'{k}: {v}' for k, v in actions.items() if v]
    conditions_parts = [f'{k}: {v}' for k, v in conditions.items() if v]
    # Une suppression simple n'est consideree suspecte que si elle cible du courrier lie a la
    # securite (voir SECURITY_RULE_KEYWORDS) : une regle "delete" banale (notifications de
    # supervision, mailer-daemon...) est tres frequente et generalement benigne.
    text_for_keywords = f"{item.get('displayName', '')} {' '.join(conditions_parts)}".lower()
    looks_security_related = any(kw in text_for_keywords for kw in SECURITY_RULE_KEYWORDS)
    suspicious = bool(forward_targets) or bool(actions.get('permanentDelete')) or \
        (bool(actions.get('delete')) and looks_security_related)
    return {
        'rule_id': item.get('id', ''),
        'display_name': item.get('displayName', ''),
        'is_enabled': str(item.get('isEnabled', '')).lower(),
        'sequence': item.get('sequence', 0),
        'conditions_summary': ' | '.join(conditions_parts),
        'actions_summary': ' | '.join(actions_parts),
        'forwards_to': ', '.join(forward_targets),
        'is_suspicious': 'true' if suspicious else 'false',
        'raw': item,
    }


def fetch_signins_from_graph(boite_id, user_upn, days=30):
    """Recupere les connexions interactives (auditLogs/signIns) d'un utilisateur
    sur les N derniers jours et les insere dans signin_logs (avec deduplication)."""
    from datetime import datetime, timedelta, timezone

    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')
    upn_escaped = (user_upn or '').replace("'", "''")
    filter_q = f"userPrincipalName eq '{upn_escaped}' and createdDateTime ge {since}"
    items = graph_get_all('/auditLogs/signIns', params={'$filter': filter_q, '$top': '999'})

    conn = get_db()
    existing = set(
        (r['request_id'], r['date_utc'], r['user_upn'], r['ip_address'])
        for r in conn.execute('SELECT request_id, date_utc, user_upn, ip_address FROM signin_logs WHERE boite_id=?', (boite_id,)).fetchall()
    )
    count = 0
    duplicates = 0
    for item in items:
        d = _map_graph_signin(item)
        key = (d['request_id'], d['date_utc'], d['user_upn'], d['ip_address'])
        if key in existing:
            duplicates += 1
            continue

        conn.execute('''INSERT INTO signin_logs
            (boite_id, date_utc, request_id, correlation_id, user_display_name, user_upn,
             ip_address, location, country, status, error_code, failure_reason, application,
             client_app, device_id, browser, os, is_compliant, is_managed, conditional_access,
             mfa_result, mfa_method, asn, flagged, user_agent, csv_source, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (boite_id, d['date_utc'], d['request_id'], d['correlation_id'], d['user_display_name'],
             d['user_upn'], d['ip_address'], d['location'], d['country'], d['status'],
             d['error_code'], d['failure_reason'], d['application'], d['client_app'], d['device_id'],
             d['browser'], d['os'], d['is_compliant'], d['is_managed'], d['conditional_access'],
             d['mfa_result'], d['mfa_method'], d['asn'], d['flagged'], d['user_agent'],
             'Microsoft Graph API', json.dumps(item, ensure_ascii=False)))
        existing.add(key)
        count += 1
    conn.commit()
    conn.close()
    return count, duplicates


def fetch_audit_from_graph(boite_id, user_upn, days=30):
    """Recupere les evenements du journal d'audit (auditLogs/directoryAudits) concernant
    un utilisateur (cible ou initiateur) sur les N derniers jours, et les insere dans
    audit_logs (avec deduplication). Le filtre serveur ne portant que sur la date, le
    tri par utilisateur est fait cote client sur les cibles/initiateurs de chaque evenement."""
    from datetime import datetime, timedelta, timezone

    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')
    items = graph_get_all('/auditLogs/directoryAudits', params={'$filter': f'activityDateTime ge {since}', '$top': '999'})

    upn_lower = (user_upn or '').lower()
    relevant = []
    for item in items:
        targets = item.get('targetResources') or []
        initiator = (item.get('initiatedBy') or {}).get('user') or {}
        if any((t.get('userPrincipalName') or '').lower() == upn_lower for t in targets) or \
           (initiator.get('userPrincipalName') or '').lower() == upn_lower:
            relevant.append(item)

    conn = get_db()
    existing = set(
        (r['date_utc'], r['correlation_id'], r['activite'], r['target_upn'])
        for r in conn.execute('SELECT date_utc, correlation_id, activite, target_upn FROM audit_logs WHERE boite_id=?', (boite_id,)).fetchall()
    )
    count = 0
    duplicates = 0
    for item in relevant:
        d = _map_graph_audit(item)
        key = (d['date_utc'], d['correlation_id'], d['activite'], d['target_upn'])
        if key in existing:
            duplicates += 1
            continue

        conn.execute('''INSERT INTO audit_logs
            (boite_id, date_utc, correlation_id, service, categorie, activite, resultat,
             result_reason, actor_type, actor_display_name, actor_upn, ip_address,
             target_type, target_display_name, target_upn, modifications_summary,
             csv_source, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (boite_id, d['date_utc'], d['correlation_id'], d['service'], d['categorie'],
             d['activite'], d['resultat'], d['result_reason'], d['actor_type'], d['actor_display_name'],
             d['actor_upn'], d['ip_address'], d['target_type'], d['target_display_name'],
             d['target_upn'], d['modifications_summary'],
             'Microsoft Graph API', json.dumps(item, ensure_ascii=False)))
        existing.add(key)
        count += 1
    conn.commit()
    conn.close()
    return count, duplicates


def fetch_inbox_rules_from_graph(boite_id, user_upn):
    """Recupere les regles de la boite de reception (transfert, suppression...) via
    Microsoft Graph. Contrairement aux connexions/audit (journal d'evenements), les
    regles representent un etat courant : le precedent instantane issu de Graph est
    remplace a chaque appel (les regles importees depuis un CSV, s'il y en a, sont conservees)."""
    import urllib.parse

    encoded_upn = urllib.parse.quote(user_upn or '')
    items = graph_get_all(f'/users/{encoded_upn}/mailFolders/inbox/messageRules')

    conn = get_db()
    conn.execute("DELETE FROM mailbox_rules WHERE boite_id=? AND source=?", (boite_id, 'Microsoft Graph API'))
    count = 0
    for item in items:
        d = _map_graph_rule(item)
        conn.execute('''INSERT INTO mailbox_rules
            (boite_id, rule_id, display_name, is_enabled, sequence, conditions_summary,
             actions_summary, forwards_to, is_suspicious, source, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (boite_id, d['rule_id'], d['display_name'], d['is_enabled'], d['sequence'],
             d['conditions_summary'], d['actions_summary'], d['forwards_to'], d['is_suspicious'],
             'Microsoft Graph API', json.dumps(item, ensure_ascii=False)))
        count += 1
    conn.commit()
    conn.close()
    return count


def _extract_ip_from_headers(headers):
    """Tente d'extraire une IP source depuis les en-tetes internet d'un message
    (X-Originating-IP / X-Sender-IP en priorite, sinon le premier en-tete Received).
    Note : a la difference d'un export "Message trace" M365, cette IP n'est pas
    toujours presente (dependant du chemin de routage et des serveurs traversés)."""
    import re
    if not headers:
        return ''
    by_name = {}
    for h in headers:
        name = (h.get('name') or '').lower()
        if name not in by_name:
            by_name[name] = h.get('value', '')
    for candidate in ('x-originating-ip', 'x-sender-ip', 'x-source-ip'):
        val = by_name.get(candidate)
        if val:
            m = re.search(r'[0-9a-fA-F:.]{7,45}', val)
            if m:
                return m.group(0).strip('[]')
    received = by_name.get('received', '')
    m = re.search(r'\[?(\d{1,3}(?:\.\d{1,3}){3})\]?', received)
    return m.group(1) if m else ''


def _extract_urls_from_text(text, limit=5):
    import re
    if not text:
        return ''
    urls = re.findall(r'https?://[^\s"\'<>]+', text)
    return ', '.join(urls[:limit])


def fetch_sent_messages_from_graph(boite_id, user_upn, days=30):
    """Recupere les messages envoyes (dossier "Elements envoyes") d'une boite via
    Microsoft Graph sur les N derniers jours, et les insere dans la table messages
    (une ligne par destinataire To/Cc/Cci, comme pour un import CSV de message trace),
    avec deduplication. Contrairement au message trace M365, l'IP source du client
    n'est pas garantie par Graph : elle est recherchee au mieux dans les en-tetes
    internet du message (X-Originating-IP ou a defaut le premier Received)."""
    from datetime import datetime, timedelta, timezone
    import urllib.parse

    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')
    encoded_upn = urllib.parse.quote(user_upn or '')
    select = ('id,subject,sender,from,toRecipients,ccRecipients,bccRecipients,sentDateTime,'
              'hasAttachments,internetMessageId,internetMessageHeaders,bodyPreview')
    items = graph_get_all(
        f'/users/{encoded_upn}/mailFolders/SentItems/messages',
        params={'$filter': f'sentDateTime ge {since}', '$select': select, '$top': '999'}
    )

    conn = get_db()
    existing = set(
        (r['message_id'], r['recipient_address'], r['received'])
        for r in conn.execute('SELECT message_id, recipient_address, received FROM messages WHERE boite_id=?', (boite_id,)).fetchall()
    )
    count = 0
    duplicates = 0
    for item in items:
        message_id = item.get('internetMessageId') or item.get('id', '')
        received = item.get('sentDateTime', '')
        sender = (item.get('sender') or {}).get('emailAddress') or (item.get('from') or {}).get('emailAddress') or {}
        sender_address = sender.get('address', '')
        subject = item.get('subject', '') or ''
        from_ip = _extract_ip_from_headers(item.get('internetMessageHeaders'))
        urls = _extract_urls_from_text(item.get('bodyPreview', ''))
        attachments = 'Oui' if item.get('hasAttachments') else None

        recipients = []
        for field in ('toRecipients', 'ccRecipients', 'bccRecipients'):
            for rec in (item.get(field) or []):
                addr = (rec.get('emailAddress') or {}).get('address')
                if addr:
                    recipients.append(addr)
        if not recipients:
            recipients = ['']

        for recipient_address in recipients:
            key = (message_id, recipient_address, received)
            if key in existing:
                duplicates += 1
                continue
            conn.execute('''INSERT INTO messages
                (boite_id, message_id, received, sender_address, recipient_address,
                 subject, status, to_ip, from_ip, size, message_trace_id, csv_source,
                 attachments, urls)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (boite_id, message_id, received, sender_address, recipient_address,
                 subject, 'Envoyé', '', from_ip, 0, item.get('id', ''), 'Microsoft Graph API',
                 attachments, urls or None))
            existing.add(key)
            count += 1
    conn.commit()
    conn.close()
    return count, duplicates


from functools import wraps

# Routes accessibles sans etre connecte (endpoints Flask, pas les URLs).
PUBLIC_ENDPOINTS = {'login', 'static'}


@app.before_request
def require_login():
    """Impose une connexion pour toute l'application, sauf la page de connexion elle-meme
    et les fichiers statiques. Remplace l'ancienne authentification HTTP Basic globale."""
    if request.endpoint is None or request.endpoint in PUBLIC_ENDPOINTS:
        return
    if not session.get('user_id'):
        return redirect(url_for('login', next=request.path))


def login_required(f):
    """Conserve pour compatibilite/explicite sur certaines routes ; la verification globale
    est de toute facon assuree par before_request ci-dessus."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login', next=request.path))
        if session.get('role') != 'admin':
            flash("Accès réservé aux administrateurs")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username=? AND is_active=1', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            next_url = request.form.get('next') or url_for('index')
            return redirect(next_url)
        flash('Identifiants incorrects')
    return render_template('login.html', next=request.args.get('next', ''))


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/users')
@admin_required
def list_users():
    conn = get_db()
    users = conn.execute('SELECT * FROM users ORDER BY username').fetchall()
    conn.close()
    return render_template('users.html', users=users)


@app.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'user')
    if role not in ('admin', 'user'):
        role = 'user'
    if not username or not password:
        flash("Nom d'utilisateur et mot de passe requis")
        return redirect(url_for('list_users'))
    if len(password) < 8:
        flash('Le mot de passe doit contenir au moins 8 caractères')
        return redirect(url_for('list_users'))

    conn = get_db()
    try:
        conn.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                     (username, generate_password_hash(password), role))
        conn.commit()
        flash(f"Utilisateur {username} créé avec succès")
    except sqlite3.IntegrityError:
        flash(f"Le nom d'utilisateur {username} existe déjà")
    finally:
        conn.close()
    return redirect(url_for('list_users'))


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('Vous ne pouvez pas supprimer votre propre compte')
        return redirect(url_for('list_users'))

    conn = get_db()
    target = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not target:
        conn.close()
        flash('Utilisateur non trouvé')
        return redirect(url_for('list_users'))
    if target['role'] == 'admin':
        nb_admins = conn.execute("SELECT COUNT(*) as c FROM users WHERE role='admin' AND is_active=1").fetchone()['c']
        if nb_admins <= 1:
            conn.close()
            flash('Impossible de supprimer le dernier administrateur')
            return redirect(url_for('list_users'))

    conn.execute('DELETE FROM users WHERE id=?', (user_id,))
    conn.commit()
    conn.close()
    flash(f"Utilisateur {target['username']} supprimé")
    return redirect(url_for('list_users'))


@app.route('/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def toggle_user(user_id):
    if user_id == session.get('user_id'):
        flash('Vous ne pouvez pas désactiver votre propre compte')
        return redirect(url_for('list_users'))

    conn = get_db()
    target = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not target:
        conn.close()
        flash('Utilisateur non trouvé')
        return redirect(url_for('list_users'))
    new_active = 0 if target['is_active'] else 1
    if target['role'] == 'admin' and not new_active:
        nb_admins = conn.execute("SELECT COUNT(*) as c FROM users WHERE role='admin' AND is_active=1").fetchone()['c']
        if nb_admins <= 1:
            conn.close()
            flash('Impossible de désactiver le dernier administrateur')
            return redirect(url_for('list_users'))
    conn.execute('UPDATE users SET is_active=? WHERE id=?', (new_active, user_id))
    conn.commit()
    conn.close()
    return redirect(url_for('list_users'))


@app.route('/')
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
    graph_configured = bool(get_config('graph_tenant_id', '') and get_config('graph_client_id', '') and get_config('graph_client_secret', ''))
    return render_template('index.html', boites=boites, stats=stats, graph_configured=graph_configured)

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
        nb_rules = conn.execute('SELECT COUNT(*) as c FROM mailbox_rules WHERE boite_id=?', (bid,)).fetchone()['c']
        nb_suspicious_rules = conn.execute("SELECT COUNT(*) as c FROM mailbox_rules WHERE boite_id=? AND is_suspicious='true'", (bid,)).fetchone()['c']
        graph_configured = bool(get_config('graph_tenant_id', '') and get_config('graph_client_id', '') and get_config('graph_client_secret', ''))
        risk_analysis = analyze_compromise(bid)
        risk_score = risk_analysis['score']
        risk_verdict = risk_analysis['verdict']
        risk_findings_count = len(risk_analysis['findings'])
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
                         nb_signins=nb_signins, nb_audit=nb_audit,
                         nb_rules=nb_rules, nb_suspicious_rules=nb_suspicious_rules,
                         graph_configured=graph_configured,
                         risk_score=risk_score, risk_verdict=risk_verdict, risk_findings_count=risk_findings_count)

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


def _parse_iso(value):
    """Parse une date ISO8601 (avec 'Z', fractions de secondes variables, ou offset) en
    datetime naïf UTC comparable. Retourne None si la valeur est absente/invalide."""
    from datetime import datetime, timezone
    if not value:
        return None
    s = str(value).strip()
    try:
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        if '.' in s:
            head, _, rest = s.partition('.')
            tz = ''
            for sep in ('+', '-'):
                if sep in rest:
                    frac, _, tz_part = rest.partition(sep)
                    tz = sep + tz_part
                    rest = frac
                    break
            rest = (rest[:6] or '0').ljust(6, '0')
            s = f'{head}.{rest}{tz}'
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        return None


def _build_signin_event(s, ref_id=None):
    """Construit un evenement de timeline a partir d'une ligne signin_logs (sqlite3.Row
    ou dict). Fonction pure : reutilisee pour les boites en base et le scan rapide."""
    success = _is_success_status(s['status'])
    title = ('Connexion réussie' if success else 'Connexion échouée')
    if s['application']:
        title += f" — {s['application']}"
    detail_parts = [s['user_upn'] or s['user_display_name'] or '']
    if s['ip_address']:
        detail_parts.append(f"depuis {s['ip_address']}")
    if s['location']:
        detail_parts.append(f"({s['location']})")
    if not success and s['failure_reason']:
        detail_parts.append(f"— {s['failure_reason']}")
    return {
        'timestamp': s['date_utc'],
        'dt': _parse_iso(s['date_utc']),
        'type': 'signin',
        'success': success,
        'title': title,
        'detail': ' '.join(p for p in detail_parts if p),
        'ip': s['ip_address'],
        'country': s['country'],
        'user': s['user_upn'] or s['user_display_name'] or '',
        'ref_id': ref_id if ref_id is not None else s['id'] if 'id' in s.keys() else None,
    }


def _build_audit_event(a, ref_id=None):
    """Construit un evenement de timeline a partir d'une ligne audit_logs (sqlite3.Row
    ou dict). Fonction pure : reutilisee pour les boites en base et le scan rapide."""
    title = a['activite'] or 'Événement d\'audit'
    detail_parts = []
    actor = a['actor_display_name'] or a['actor_upn']
    target = a['target_upn'] or a['target_display_name']
    if actor:
        detail_parts.append(f"par {actor}")
    if target:
        detail_parts.append(f"sur {target}")
    if a['modifications_summary']:
        detail_parts.append(f"— {a['modifications_summary']}")
    return {
        'timestamp': a['date_utc'],
        'dt': _parse_iso(a['date_utc']),
        'type': 'audit',
        'success': (a['resultat'] == 'Success' or _is_success_status(a['resultat'])),
        'title': title,
        'detail': ' '.join(p for p in detail_parts if p),
        'ip': a['ip_address'],
        'country': '',
        'user': target or actor or '',
        'ref_id': ref_id if ref_id is not None else a['id'] if 'id' in a.keys() else None,
    }


def build_timeline_events(signins, audits):
    """Fusionne des lignes signin_logs/audit_logs (ou dicts equivalents issus d'un scan
    rapide) en une seule liste d'evenements tries chronologiquement. Fonction pure,
    aucun acces DB."""
    events = [_build_signin_event(s) for s in signins] + [_build_audit_event(a) for a in audits]
    events.sort(key=lambda e: e['timestamp'] or '')
    return events


def build_unified_timeline(boite_id):
    """Fusionne les connexions (signin_logs) et le journal d'audit (audit_logs) d'une
    boite (persistee en base) en une seule liste d'evenements tries chronologiquement."""
    conn = get_db()
    signins = conn.execute('SELECT * FROM signin_logs WHERE boite_id=? ORDER BY date_utc', (boite_id,)).fetchall()
    audits = conn.execute('SELECT * FROM audit_logs WHERE boite_id=? ORDER BY date_utc', (boite_id,)).fetchall()
    conn.close()
    return build_timeline_events(signins, audits)


def compute_risk_score(findings):
    """Convertit la liste de findings (issus de analyze_compromise_events) en un score
    de risque de compromission sur 10, a partir de la severite de chaque signal."""
    weights = {'critical': 4, 'high': 2, 'medium': 1, 'low': 0.5}
    score = sum(weights.get(f['severity'], 0) for f in findings)
    return min(10, round(score))


def analyze_compromise_events(events, suspicious_rules=None, owner_domain=''):
    """Analyse heuristique d'une liste d'evenements (connexions + audit) deja fusionnee
    pour identifier ce qui ressemble a une compromission : deplacement impossible,
    connexion reussie depuis un pays inhabituel, rafale d'echecs suivie d'un succes,
    activite sensible (changement de mot de passe/MFA, regle de boite mail...), et
    enchainement temporel entre une connexion suspecte et une action sensible juste
    apres. Fonction pure (aucun acces DB) : reutilisee pour les boites en base
    (analyze_compromise) et pour le scan rapide ephemere (quick_scan_mailbox)."""
    suspicious_rules = suspicious_rules or []
    findings = []

    signin_events = [e for e in events if e['type'] == 'signin']
    successful_signins = [e for e in signin_events if e['success']]

    # Pays de reference = pays le plus frequent parmi les connexions reussies
    country_counts = {}
    for e in successful_signins:
        if e['country']:
            country_counts[e['country']] = country_counts.get(e['country'], 0) + 1
    baseline_country = max(country_counts, key=country_counts.get) if country_counts else None

    # 1) Deplacement impossible : deux connexions reussies consecutives, pays different,
    #    ecart de temps trop court pour un vrai deplacement (< 2h)
    prev = None
    for e in successful_signins:
        if prev and e['dt'] and prev['dt'] and e['country'] and prev['country'] and e['country'] != prev['country']:
            delta = abs((e['dt'] - prev['dt']).total_seconds())
            if delta < 2 * 3600:
                findings.append({
                    'severity': 'critical',
                    'title': 'Déplacement impossible (impossible travel)',
                    'description': (f"Connexion réussie depuis {prev['country']} ({prev['ip']}) à {prev['timestamp']}, "
                                     f"puis depuis {e['country']} ({e['ip']}) à {e['timestamp']} — seulement "
                                     f"{int(delta // 60)} min d'écart : physiquement impossible pour un seul utilisateur."),
                    'events': [prev, e],
                })
        prev = e

    # 2) Connexion reussie depuis un pays inhabituel par rapport a la reference
    for e in successful_signins:
        if baseline_country and e['country'] and e['country'] != baseline_country:
            findings.append({
                'severity': 'high',
                'title': 'Connexion réussie depuis un pays inhabituel',
                'description': f"{e['user']} s'est connecté avec succès depuis {e['country']} ({e['ip']}) le {e['timestamp']}, alors que le pays habituel est {baseline_country}.",
                'events': [e],
            })

    # 3) Rafale d'echecs suivie d'un succes (>=3 echecs en 15 min puis succes dans les 15 min suivantes)
    failures_window = []
    for e in signin_events:
        if not e['dt']:
            continue
        if not e['success']:
            failures_window = [f for f in failures_window if (e['dt'] - f['dt']).total_seconds() <= 900] + [e]
        else:
            recent_failures = [f for f in failures_window if 0 <= (e['dt'] - f['dt']).total_seconds() <= 900]
            if len(recent_failures) >= 3:
                findings.append({
                    'severity': 'high',
                    'title': "Rafale d'échecs de connexion suivie d'un succès",
                    'description': (f"{len(recent_failures)} échecs de connexion en moins de 15 min pour {e['user']}, "
                                     f"suivis d'une connexion réussie à {e['timestamp']} depuis {e['ip']} — signature typique "
                                     f"d'une attaque par force brute/password spray ayant abouti."),
                    'events': recent_failures + [e],
                })
            failures_window = []

    # 4) Activites d'audit sensibles (mot de passe, MFA, regles de messagerie, consentement...)
    for e in events:
        if e['type'] != 'audit':
            continue
        norm = _normalize_header(e['title'] or '')
        if any(kw in norm for kw in SUSPICIOUS_AUDIT_KEYWORDS):
            findings.append({
                'severity': 'medium',
                'title': f"Activité sensible : {e['title']}",
                'description': e['detail'] or e['title'],
                'events': [e],
            })

    # 5) Enchainement : activite sensible survenant peu apres (< 2h) une connexion suspecte
    #    (deplacement impossible ou pays inhabituel) -> tres probable compromission
    suspicious_signin_times = [
        f['events'][-1]['dt'] for f in findings
        if f['title'] in ('Déplacement impossible (impossible travel)', 'Connexion réussie depuis un pays inhabituel')
        and f['events'][-1]['dt']
    ]
    for e in events:
        if e['type'] != 'audit' or not e['dt']:
            continue
        norm = _normalize_header(e['title'] or '')
        if not any(kw in norm for kw in SUSPICIOUS_AUDIT_KEYWORDS):
            continue
        for sdt in suspicious_signin_times:
            delta = (e['dt'] - sdt).total_seconds()
            if 0 <= delta <= 2 * 3600:
                findings.append({
                    'severity': 'critical',
                    'title': 'Action sensible juste après une connexion suspecte',
                    'description': (f"« {e['title']} » effectuée à {e['timestamp']} — seulement {int(delta // 60)} min après "
                                     f"une connexion suspecte. Enchaînement typique d'une prise de contrôle du compte "
                                     f"(l'attaquant se connecte puis modifie le compte pour garder l'accès)."),
                    'events': [e],
                })
                break

    # 6) Regles de messagerie suspectes (transfert/suppression), passees en parametre.
    #    - Un transfert vers une adresse du meme domaine (ex: collegue en delegation/absence)
    #      est nettement moins alarmant qu'un transfert vers un domaine externe/inconnu.
    #    - Une suppression automatique simple (delete) est tres majoritairement une regle de
    #      confort banale (notifications de supervision, mailer-daemon, newsletters...) : elle
    #      n'est remontee que si elle cible specifiquement des messages lies a la securite
    #      (alertes de connexion, mots de passe...), ou si elle est definitive (permanentDelete),
    #      seuls cas ou elle peut servir a masquer des traces d'une compromission.
    owner_domain = (owner_domain or '').lower()
    for r in suspicious_rules:
        targets = [t.strip() for t in (r['forwards_to'] or '').split(',') if t.strip()]
        external_targets = [t for t in targets if '@' in t and t.split('@')[-1].lower() != owner_domain]
        internal_targets = [t for t in targets if t not in external_targets]
        actions_summary = (r['actions_summary'] or '')
        is_permanent_delete = 'permanentdelete: true' in actions_summary.lower()
        text_for_keywords = f"{r['display_name'] or ''} {r['conditions_summary'] or ''}".lower()
        looks_security_related = any(kw in text_for_keywords for kw in SECURITY_RULE_KEYWORDS)

        if external_targets:
            severity = 'critical'
            note = f"vers une adresse EXTERNE : {', '.join(external_targets)}"
        elif internal_targets:
            severity = 'medium'
            note = f"vers une adresse interne (même domaine) : {', '.join(internal_targets)} — probablement légitime (délégation, absence...), à confirmer auprès de l'utilisateur"
        elif is_permanent_delete:
            severity = 'high' if looks_security_related else 'medium'
            note = 'suppression DÉFINITIVE automatique (sans passer par les éléments supprimés)' + (
                ' — cible des messages liés à la sécurité : à vérifier en priorité' if looks_security_related else '')
        elif looks_security_related:
            severity = 'high'
            note = 'suppression automatique de messages liés à la sécurité (alertes, connexions...) — peut servir à masquer des alertes'
        else:
            # Suppression simple sans lien avec la securite : tres frequent et generalement
            # benin (filtrage de notifications automatiques...) -> pas remonte comme signal.
            continue

        findings.append({
            'severity': severity,
            'title': f"Règle de messagerie suspecte : {r['display_name']}",
            'description': f"Actions : {r['actions_summary']} — {note}",
            'events': [],
        })

    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    findings.sort(key=lambda f: severity_order.get(f['severity'], 9))

    if any(f['severity'] == 'critical' for f in findings):
        verdict = 'compromise_likely'
    elif any(f['severity'] in ('high', 'medium') for f in findings):
        verdict = 'signals_to_check'
    else:
        verdict = 'no_strong_signal'

    return {
        'events': events,
        'findings': findings,
        'baseline_country': baseline_country,
        'verdict': verdict,
        'score': compute_risk_score(findings),
    }


def analyze_compromise(boite_id):
    """Analyse heuristique des connexions + journal d'audit d'une boite deja presente
    en base (voir analyze_compromise_events pour le detail des regles de detection)."""
    events = build_unified_timeline(boite_id)
    conn = get_db()
    boite_row = conn.execute('SELECT user_email FROM boites_compromises WHERE id=?', (boite_id,)).fetchone()
    suspicious_rules = conn.execute("SELECT * FROM mailbox_rules WHERE boite_id=? AND is_suspicious='true'", (boite_id,)).fetchall()
    conn.close()
    owner_domain = (boite_row['user_email'].split('@')[-1] if boite_row and '@' in (boite_row['user_email'] or '') else '')
    return analyze_compromise_events(events, suspicious_rules=suspicious_rules, owner_domain=owner_domain)


def quick_scan_mailbox(user_upn, days=7):
    """Scan rapide et EPHEMERE d'une boite via Microsoft Graph (rien n'est ecrit en base) :
    recupere connexions + journal d'audit + regles de messagerie sur les N derniers jours,
    et applique la meme analyse heuristique que pour une boite deja suivie."""
    from datetime import datetime, timedelta, timezone
    import urllib.parse

    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')
    upn_escaped = (user_upn or '').replace("'", "''")

    signin_items = graph_get_all('/auditLogs/signIns', params={
        '$filter': f"userPrincipalName eq '{upn_escaped}' and createdDateTime ge {since}", '$top': '999'})
    signin_dicts = [_map_graph_signin(it) for it in signin_items]

    audit_items = graph_get_all('/auditLogs/directoryAudits', params={'$filter': f'activityDateTime ge {since}', '$top': '999'})
    upn_lower = (user_upn or '').lower()
    audit_dicts = []
    for it in audit_items:
        targets = it.get('targetResources') or []
        initiator = (it.get('initiatedBy') or {}).get('user') or {}
        if any((t.get('userPrincipalName') or '').lower() == upn_lower for t in targets) or \
           (initiator.get('userPrincipalName') or '').lower() == upn_lower:
            audit_dicts.append(_map_graph_audit(it))

    encoded_upn = urllib.parse.quote(user_upn or '')
    rule_items = graph_get_all(f'/users/{encoded_upn}/mailFolders/inbox/messageRules')
    rule_dicts = [_map_graph_rule(it) for it in rule_items]
    suspicious_rules = [r for r in rule_dicts if r['is_suspicious'] == 'true']

    owner_domain = user_upn.split('@')[-1] if user_upn and '@' in user_upn else ''
    events = build_timeline_events(signin_dicts, audit_dicts)
    analysis = analyze_compromise_events(events, suspicious_rules=suspicious_rules, owner_domain=owner_domain)
    analysis['nb_signins'] = len(signin_dicts)
    analysis['nb_audit'] = len(audit_dicts)
    analysis['nb_rules'] = len(rule_dicts)
    analysis['user_upn'] = user_upn
    analysis['days'] = days
    return analysis


@app.route('/boite/<int:bid>/timeline')
def view_timeline(bid):
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    conn.close()
    if not boite:
        flash('Boîte non trouvée')
        return redirect(url_for('index'))

    analysis = analyze_compromise(bid)
    return render_template('timeline.html', boite=boite, **analysis)


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


@app.route('/quick-scan', methods=['POST'])
def quick_scan():
    email = request.form.get('email', '').strip()
    if not email or '@' not in email:
        flash('Adresse email invalide pour le scan rapide')
        return redirect(url_for('index'))

    try:
        days = max(1, min(int(request.form.get('days', '7')), 90))
    except ValueError:
        days = 7

    try:
        result = quick_scan_mailbox(email, days)
    except Exception as e:
        add_log('ERROR', 'GRAPH', f'Échec du scan rapide pour {email}', str(e))
        flash(f"Erreur lors du scan rapide via Microsoft Graph : {e}")
        return redirect(url_for('index'))

    add_log('INFO', 'GRAPH', f'Scan rapide effectué pour {email}',
            f"score {result['score']}/10, verdict {result['verdict']}, {len(result['findings'])} signal(aux)")

    existing = None
    conn = get_db()
    row = conn.execute('SELECT id FROM boites_compromises WHERE user_email=? ORDER BY id DESC LIMIT 1', (email,)).fetchone()
    conn.close()
    if row:
        existing = row['id']

    return render_template('quick_scan_result.html', email=email, existing_boite_id=existing, **result)


@app.route('/quick-scan/create', methods=['POST'])
def quick_scan_create():
    email = request.form.get('email', '').strip()
    if not email or '@' not in email:
        flash('Adresse email invalide')
        return redirect(url_for('index'))
    try:
        days = max(1, min(int(request.form.get('days', '7')), 90))
    except ValueError:
        days = 7

    conn = get_db()
    row = conn.execute('SELECT id FROM boites_compromises WHERE user_email=? ORDER BY id DESC LIMIT 1', (email,)).fetchone()
    if row:
        bid = row['id']
        conn.close()
        flash(f"Une boîte existait déjà pour {email} — réutilisation de l'investigation existante.")
    else:
        from datetime import date
        conn.execute('''INSERT INTO boites_compromises (user_email, date_compromission, notes)
            VALUES (?, ?, ?)''',
            (email, date.today().isoformat(), "Créée automatiquement depuis l'analyse rapide (page d'accueil)."))
        conn.commit()
        bid = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()

    summary = []
    errors = []
    try:
        c, d = fetch_signins_from_graph(bid, email, days)
        summary.append(f'{c} connexion(s) ({d} doublon(s) ignoré(s))')
    except Exception as e:
        errors.append(f'Connexions : {e}')
    try:
        c, d = fetch_audit_from_graph(bid, email, days)
        summary.append(f"{c} événement(s) d'audit ({d} doublon(s) ignoré(s))")
    except Exception as e:
        errors.append(f'Journal d\'audit : {e}')
    try:
        c = fetch_inbox_rules_from_graph(bid, email)
        summary.append(f'{c} règle(s) de messagerie')
    except Exception as e:
        errors.append(f'Règles de messagerie : {e}')

    if summary:
        add_log('INFO', 'GRAPH', f'Boîte créée/mise à jour depuis analyse rapide pour {email}', ', '.join(summary), bid)
        flash("Boîte compromise créée, données importées : " + ', '.join(summary))
    for err in errors:
        add_log('ERROR', 'GRAPH', f'Erreur import Microsoft Graph pour {email}', err, bid)
        flash(f'Erreur Microsoft Graph — {err}')

    return redirect(url_for('view_timeline', bid=bid))


# ============================================================================
# Surveillance planifiee : scan rapide automatique (via Microsoft Graph) d'une
# liste de boites a intervalle regulier, sans creer de dossier d'investigation
# tant que rien d'anormal n'est detecte. Reserve aux administrateurs.
# ============================================================================

import threading
import time as _time

_monitoring_thread_started = False
_monitoring_lock = threading.Lock()


def run_monitoring_scan(mailbox_row):
    """Execute un scan rapide pour une boite surveillee et enregistre le resultat
    (score, verdict, nombre de signaux) sur la ligne monitored_mailboxes, plus une
    entree dans le journal applicatif (categorie MONITORING)."""
    email = mailbox_row['user_email']
    now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    conn = get_db()
    try:
        # Marquer immediatement last_scan_at pour eviter qu'un autre passage du
        # planificateur ne relance le meme scan en parallele (verrouillage optimiste).
        conn.execute('UPDATE monitored_mailboxes SET last_scan_at=? WHERE id=?', (now_iso, mailbox_row['id']))
        conn.commit()

        result = quick_scan_mailbox(email, days=1)

        conn.execute('''UPDATE monitored_mailboxes SET
            last_scan_at=?, last_scan_score=?, last_scan_verdict=?, last_scan_findings_count=?, last_error=NULL
            WHERE id=?''',
            (now_iso, result['score'], result['verdict'], len(result['findings']), mailbox_row['id']))
        conn.commit()

        level = 'WARNING' if result['score'] >= 6 else 'INFO'
        add_log(level, 'MONITORING',
                f"Scan de surveillance pour {email} : score {result['score']}/10 ({result['verdict']})",
                f"{len(result['findings'])} signal(aux) détecté(s) sur les dernières 24h")
    except Exception as e:
        conn.execute('UPDATE monitored_mailboxes SET last_scan_at=?, last_error=? WHERE id=?',
                     (now_iso, str(e), mailbox_row['id']))
        conn.commit()
        add_log('ERROR', 'MONITORING', f'Échec du scan de surveillance pour {email}', str(e))
    finally:
        conn.close()


def _monitoring_scan_due(row, now):
    if not row['last_scan_at']:
        return True
    last = _parse_iso(row['last_scan_at'])
    if not last:
        return True
    elapsed_minutes = (now - last).total_seconds() / 60
    return elapsed_minutes >= (row['interval_minutes'] or 60)


def monitoring_scheduler_tick():
    """Un passage du planificateur : scanne toutes les boites actives dont l'intervalle
    est ecoule. Ne fait rien si la configuration Microsoft Graph est incomplete."""
    if not (get_config('graph_tenant_id', '') and get_config('graph_client_id', '') and get_config('graph_client_secret', '')):
        return
    conn = get_db()
    rows = conn.execute('SELECT * FROM monitored_mailboxes WHERE is_active=1').fetchall()
    conn.close()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for row in rows:
        if _monitoring_scan_due(row, now):
            run_monitoring_scan(row)


def monitoring_scheduler_loop(tick_seconds=60):
    while True:
        try:
            with _monitoring_lock:
                monitoring_scheduler_tick()
        except Exception as e:
            print(f"Erreur boucle de surveillance: {e}")
        _time.sleep(tick_seconds)


def start_monitoring_scheduler():
    global _monitoring_thread_started
    if _monitoring_thread_started:
        return
    _monitoring_thread_started = True
    t = threading.Thread(target=monitoring_scheduler_loop, daemon=True, name='monitoring-scheduler')
    t.start()


@app.route('/monitoring')
@admin_required
def view_monitoring():
    conn = get_db()
    mailboxes = conn.execute('SELECT * FROM monitored_mailboxes ORDER BY user_email').fetchall()
    conn.close()
    graph_configured = bool(get_config('graph_tenant_id', '') and get_config('graph_client_id', '') and get_config('graph_client_secret', ''))
    return render_template('monitoring.html', mailboxes=mailboxes, graph_configured=graph_configured)


@app.route('/monitoring/add', methods=['POST'])
@admin_required
def add_monitored_mailbox():
    email = request.form.get('email', '').strip()
    try:
        interval = max(5, min(int(request.form.get('interval_minutes', '60')), 10080))
    except ValueError:
        interval = 60
    if not email or '@' not in email:
        flash('Adresse email invalide')
        return redirect(url_for('view_monitoring'))

    conn = get_db()
    try:
        conn.execute('''INSERT INTO monitored_mailboxes (user_email, interval_minutes, created_by)
            VALUES (?, ?, ?)''', (email, interval, session.get('username', '')))
        conn.commit()
        flash(f'{email} ajoutée à la surveillance (toutes les {interval} min)')
    except sqlite3.IntegrityError:
        flash(f'{email} est déjà surveillée')
    finally:
        conn.close()
    return redirect(url_for('view_monitoring'))


@app.route('/monitoring/<int:mailbox_id>/update', methods=['POST'])
@admin_required
def update_monitored_mailbox(mailbox_id):
    try:
        interval = max(5, min(int(request.form.get('interval_minutes', '60')), 10080))
    except ValueError:
        interval = 60
    conn = get_db()
    conn.execute('UPDATE monitored_mailboxes SET interval_minutes=? WHERE id=?', (interval, mailbox_id))
    conn.commit()
    conn.close()
    flash('Intervalle mis à jour')
    return redirect(url_for('view_monitoring'))


@app.route('/monitoring/<int:mailbox_id>/toggle', methods=['POST'])
@admin_required
def toggle_monitored_mailbox(mailbox_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM monitored_mailboxes WHERE id=?', (mailbox_id,)).fetchone()
    if row:
        conn.execute('UPDATE monitored_mailboxes SET is_active=? WHERE id=?', (0 if row['is_active'] else 1, mailbox_id))
        conn.commit()
    conn.close()
    return redirect(url_for('view_monitoring'))


@app.route('/monitoring/<int:mailbox_id>/delete', methods=['POST'])
@admin_required
def delete_monitored_mailbox(mailbox_id):
    conn = get_db()
    conn.execute('DELETE FROM monitored_mailboxes WHERE id=?', (mailbox_id,))
    conn.commit()
    conn.close()
    flash('Boîte retirée de la surveillance')
    return redirect(url_for('view_monitoring'))


@app.route('/monitoring/<int:mailbox_id>/scan-now', methods=['POST'])
@admin_required
def scan_now_monitored_mailbox(mailbox_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM monitored_mailboxes WHERE id=?', (mailbox_id,)).fetchone()
    conn.close()
    if not row:
        flash('Boîte non trouvée')
        return redirect(url_for('view_monitoring'))
    run_monitoring_scan(row)
    flash(f"Scan effectué pour {row['user_email']}")
    return redirect(url_for('view_monitoring'))


@app.route('/boite/<int:bid>/graph/fetch', methods=['POST'])
def graph_fetch(bid):
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    conn.close()
    if not boite:
        flash('Boîte non trouvée')
        return redirect(url_for('index'))

    try:
        days = max(1, min(int(request.form.get('days', '30')), 90))
    except ValueError:
        days = 30

    include_messages = request.form.get('include_messages') == 'on'
    summary = []
    errors = []

    if include_messages:
        try:
            c, d = fetch_sent_messages_from_graph(bid, boite['user_email'], days)
            summary.append(f'{c} message(s) envoyé(s) ({d} doublon(s) ignoré(s))')
        except Exception as e:
            errors.append(f'Messages envoyés : {e}')

    try:
        c, d = fetch_signins_from_graph(bid, boite['user_email'], days)
        summary.append(f'{c} connexion(s) ({d} doublon(s) ignoré(s))')
    except Exception as e:
        errors.append(f'Connexions : {e}')

    try:
        c, d = fetch_audit_from_graph(bid, boite['user_email'], days)
        summary.append(f"{c} événement(s) d'audit ({d} doublon(s) ignoré(s))")
    except Exception as e:
        errors.append(f'Journal d\'audit : {e}')

    try:
        c = fetch_inbox_rules_from_graph(bid, boite['user_email'])
        summary.append(f'{c} règle(s) de messagerie')
    except Exception as e:
        errors.append(f'Règles de messagerie : {e}')

    if summary:
        add_log('INFO', 'GRAPH', f"Import Microsoft Graph pour {boite['user_email']}", ', '.join(summary), bid)
        flash('Import Microsoft Graph (' + str(days) + ' jours) : ' + ', '.join(summary))
    for err in errors:
        add_log('ERROR', 'GRAPH', f"Erreur import Microsoft Graph pour {boite['user_email']}", err, bid)
        flash(f'Erreur Microsoft Graph — {err}')

    return redirect(url_for('view_boite', bid=bid))


@app.route('/boite/<int:bid>/rules')
def view_rules(bid):
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    if not boite:
        conn.close()
        flash('Boîte non trouvée')
        return redirect(url_for('index'))
    rules = conn.execute('SELECT * FROM mailbox_rules WHERE boite_id=? ORDER BY is_suspicious DESC, sequence ASC', (bid,)).fetchall()
    conn.close()
    return render_template('rules.html', boite=boite, rules=rules)


@app.route('/boite/<int:bid>/rules/clear', methods=['POST'])
def clear_rules(bid):
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    if not boite:
        conn.close()
        flash('Boîte non trouvée')
        return redirect(url_for('index'))
    cnt = conn.execute('SELECT COUNT(*) as c FROM mailbox_rules WHERE boite_id=?', (bid,)).fetchone()['c']
    conn.execute('DELETE FROM mailbox_rules WHERE boite_id=?', (bid,))
    conn.commit()
    conn.close()
    add_log('INFO', 'IMPORT', f"Règles de messagerie effacées pour la boîte {bid} ({boite['user_email']})", f'{cnt} règle(s) supprimée(s)', bid)
    flash(f'{cnt} règle(s) de messagerie effacée(s)')
    return redirect(url_for('view_rules', bid=bid))


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

# Mots-clés (substring, non normalises) indiquant qu'une regle de suppression automatique de
# messages cible specifiquement du courrier lie a la securite (alertes de connexion, mots de
# passe...). Une suppression qui ne matche aucun de ces mots-clés est tres majoritairement une
# regle de confort banale (notifications de supervision, mailer-daemon, newsletters...) et
# n'est donc pas consideree comme suspecte.
SECURITY_RULE_KEYWORDS = [
    'security', 'securite', 'sécurité', 'alert', 'alerte', 'unusual', 'inhabituel',
    'sign-in', 'signin', 'connexion', 'password', 'mot de passe', 'mfa',
    'suspicious', 'suspect', 'risk', 'risque', 'compromise', 'compromis', 'protection',
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
        elif 'graph_tenant_id' in request.form or 'graph_client_id' in request.form or 'graph_client_secret' in request.form:
            set_config('graph_tenant_id', request.form.get('graph_tenant_id', '').strip())
            set_config('graph_client_id', request.form.get('graph_client_id', '').strip())
            # Ne pas ecraser le secret existant si le champ est laisse vide (evite d'effacer
            # accidentellement un secret deja enregistre lors d'une simple mise a jour du tenant/client ID)
            new_secret = request.form.get('graph_client_secret', '')
            if new_secret:
                set_config('graph_client_secret', new_secret.strip())
            _graph_token_cache['token'] = None
            flash('Configuration Microsoft Graph enregistrée avec succès')
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
        api_ville_token=get_config('api_ville_token', ''),
        graph_tenant_id=get_config('graph_tenant_id', ''),
        graph_client_id=get_config('graph_client_id', ''),
        graph_client_secret_set=bool(get_config('graph_client_secret', '')))

@app.route('/api/test-graph')
def test_api_graph():
    try:
        get_graph_token(force_refresh=True)
        orgs = graph_get_all('/organization')
        org_name = orgs[0].get('displayName') if orgs else 'N/A'
        return jsonify({'success': True, 'message': f"Connexion Microsoft Graph réussie (tenant : {org_name})"})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

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
        # Sous le reloader Werkzeug, le script tourne dans 2 processus (superviseur +
        # enfant) : ne demarrer le planificateur que dans le processus qui sert reellement
        # les requetes, sous peine de le lancer en double.
        if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
            start_monitoring_scheduler()
        app.run(host='0.0.0.0', debug=True, port=5050)
    else:
        from waitress import serve
        start_monitoring_scheduler()
        print("Démarrage avec Waitress (stable)...")
        serve(app, host='0.0.0.0', port=5050, threads=4)
