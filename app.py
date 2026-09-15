import os
import csv
import sqlite3
import re
import secrets
import hashlib
import unicodedata
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response, session, g
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import Markup, escape
import json

app = Flask(__name__)
app.secret_key = 'analyse-compromis-secret-key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Derriere un reverse proxy qui termine le HTTPS (nginx, IIS...), waitress ne voit que du
# HTTP en interne : sans ProxyFix, url_for(_external=True) (utilise pour l'URI de
# redirection Microsoft) generait du "http://" au lieu du "https://" attendu par Azure,
# provoquant une erreur AADSTS50011 (URI de redirection non reconnue). ProxyFix fait
# confiance aux en-tetes X-Forwarded-* envoyes par le proxy pour retrouver le schema, l'hote
# et le chemin d'origine reels — le proxy DOIT positionner ces en-tetes (voir /config).
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)


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


def format_action_datetime(value, fmt='%d/%m/%Y %H:%M'):
    """Affiche la date/heure (saisie manuellement par un utilisateur via un champ HTML
    'datetime-local', donc deja en heure locale, sans fuseau) d'une action DSI. A la
    difference de format_paris_datetime, aucune conversion de fuseau n'est faite : la
    valeur est prise telle quelle, au format 'YYYY-MM-DDTHH:MM' (eventuellement avec
    secondes)."""
    if not value:
        return ''
    s = str(value).strip()
    for candidate_fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M'):
        try:
            return datetime.strptime(s, candidate_fmt).strftime(fmt)
        except ValueError:
            continue
    return value


app.jinja_env.filters['action_dt'] = format_action_datetime


def _now_local_datetime_input():
    """Date/heure actuelle au format attendu par un champ HTML <input type="datetime-local">
    (heure de Paris, sans fuseau), utilisee comme valeur par defaut quand l'utilisateur ne
    precise pas explicitement la date/heure d'une action DSI."""
    try:
        from zoneinfo import ZoneInfo
        now = datetime.now(ZoneInfo('Europe/Paris'))
    except Exception:
        now = datetime.now()
    return now.strftime('%Y-%m-%dT%H:%M')


# Codes d'erreur Entra ID connus pour indiquer un echec lie a l'authentification forte
# (MFA), utilises pour deduire un statut MFA lisible quand le champ dedie de Graph
# (authenticationRequirement) est vide — ce qui est frequent en pratique.
MFA_FAILURE_ERROR_CODES = {'50074', '50076', '500121', '50158', '530032'}
MFA_FAILURE_KEYWORDS = ['strong authentication', 'multi-factor', 'multifactor', 'mfa']
MFA_REQUIREMENT_LABELS = {
    'multifactorauthentication': 'MFA requise',
    'singlefactorauthentication': 'Facteur unique',
}


def format_mfa_status(row):
    """Deduit un libelle lisible pour le statut MFA d'une connexion (table signin_logs).
    Le champ Graph dedie (authenticationRequirement) est souvent absent en pratique ; a
    defaut, on infere un echec MFA a partir du code/motif d'erreur de la connexion."""
    def _get(key):
        try:
            return (row[key] or '').strip()
        except Exception:
            return ''

    mfa_result = _get('mfa_result')
    if mfa_result:
        return MFA_REQUIREMENT_LABELS.get(mfa_result.lower(), mfa_result)

    if _is_mfa_failure_row(row):
        return 'MFA requise (non complétée)'

    return '-'


def _is_mfa_failure_row(row):
    """True si une ligne signin_logs correspond a un echec specifiquement du au MFA
    (code d'erreur ou motif connu), independamment du champ mfa_result (souvent absent)."""
    def _get(key):
        try:
            return (row[key] or '').strip()
        except Exception:
            return ''
    error_code = _get('error_code')
    failure_reason = _get('failure_reason').lower()
    return error_code in MFA_FAILURE_ERROR_CODES or any(kw in failure_reason for kw in MFA_FAILURE_KEYWORDS)


def _row_get(row, key, default=''):
    try:
        val = row[key]
        return val if val is not None else default
    except Exception:
        return default


def _compute_mfa_linkage(signins, window_seconds=15):
    """Determine, pour chaque connexion reussie, si un echec specifiquement MFA doit lui
    etre associe. Microsoft Graph journalise parfois l'etape d'authentification primaire
    et l'etape MFA d'une meme tentative de connexion comme deux lignes signIns distinctes,
    et n'attribue PAS toujours le meme correlation_id aux deux (en particulier quand le
    MFA est declenche apres coup par une exigence d'acces conditionnel). Deux signaux sont
    donc combines :
      1) meme correlation_id (le lien le plus fiable, quand disponible) ;
      2) a defaut, meme utilisateur + meme IP, et VOISIN IMMEDIAT dans la chronologie de
         ce couple (pas seulement "dans une fenetre de N secondes") a moins de
         `window_seconds` d'ecart. Se limiter au voisin le plus proche evite qu'une seule
         erreur MFA, au milieu d'une rafale de connexions reussies rapprochees (plusieurs
         jetons applicatifs demandes en quelques secondes, tres courant), ne se retrouve
         liee a des dizaines de succes qui n'ont rien a voir avec elle.
    Retourne { request_id ou identite de repli: {'linked': bool, 'reason': str} } pour les
    connexions REUSSIES uniquement."""
    parsed = []
    for s in signins:
        dt = _parse_iso(_row_get(s, 'date_utc'))
        success = _is_success_status(_row_get(s, 'status'))
        parsed.append({
            'row': s,
            'dt': dt,
            'success': success,
            'mfa_failure': (not success) and _is_mfa_failure_row(s),
            'cid': _row_get(s, 'correlation_id').strip(),
            'ip': _row_get(s, 'ip_address').strip(),
            'user': _row_get(s, 'user_upn').strip(),
            'request_id': _row_get(s, 'request_id', None),
            'failure_reason': _row_get(s, 'failure_reason'),
        })

    # 1) Regroupement par correlation_id
    cid_groups = {}
    for p in parsed:
        if not p['cid']:
            continue
        g = cid_groups.setdefault(p['cid'], {'mfa_failure': False, 'reason': ''})
        if p['mfa_failure']:
            g['mfa_failure'] = True
            g['reason'] = p['failure_reason'] or 'MFA non complétée'

    def row_key(p):
        return p['request_id'] or id(p['row'])

    linkage = {}
    for p in parsed:
        if not p['success']:
            continue
        linked, reason = False, ''
        if p['cid'] and cid_groups.get(p['cid'], {}).get('mfa_failure'):
            linked, reason = True, cid_groups[p['cid']]['reason']
        linkage[row_key(p)] = {'linked': linked, 'reason': reason}

    # 2) Complement : meme utilisateur + meme IP, uniquement le voisin immediat dans la
    #    chronologie de ce couple (pas tout ce qui tombe dans une fenetre large).
    groups_by_user_ip = {}
    for p in parsed:
        if p['dt'] and p['user'] and p['ip']:
            groups_by_user_ip.setdefault((p['user'], p['ip']), []).append(p)
    for group in groups_by_user_ip.values():
        group.sort(key=lambda p: p['dt'])
        for i, p in enumerate(group):
            if not p['success']:
                continue
            key = row_key(p)
            if linkage.get(key, {}).get('linked'):
                continue
            for j in (i - 1, i + 1):
                if 0 <= j < len(group):
                    neighbor = group[j]
                    if neighbor['mfa_failure'] and abs((p['dt'] - neighbor['dt']).total_seconds()) <= window_seconds:
                        linkage[key] = {'linked': True, 'reason': neighbor['failure_reason'] or 'MFA non complétée'}
                        break

    return linkage


app.jinja_env.filters['mfa_status'] = format_mfa_status


def friendly_graph_error(message):
    """Resume une erreur technique Microsoft Graph (souvent une longue URL + un corps
    JSON) en une phrase courte et comprehensible, pour affichage direct dans l'UI (le
    message brut integral reste disponible en infobulle). Un message peut regrouper
    plusieurs sources d'echec separees par ' / ' (voir run_monitoring_scan) : chaque
    segment est traite independamment, et les segments correspondant a un etat normal
    (ex: boite sans licence Exchange) sont retires plutot que juste reformules — on ne
    veut pas les afficher DU TOUT, meme sous une forme adoucie. Si tous les segments
    sont ainsi retires (y compris pour une donnee deja enregistree avant ce filtrage),
    la fonction retourne une chaine vide et l'appelant doit alors n'afficher aucune
    alerte : c'est reevalue a chaque affichage, pas seulement a l'ecriture."""
    if not message:
        return ''

    outer_prefix = ''
    body = message
    if message.startswith('Scan partiel : '):
        outer_prefix, body = 'Scan partiel : ', message[len('Scan partiel : '):]

    summaries = []
    for seg in (s.strip() for s in body.split(' / ')):
        if not seg:
            continue
        prefix, rest = '', seg
        if ': ' in seg:
            candidate_prefix, candidate_rest = seg.split(': ', 1)
            if len(candidate_prefix) <= 40 and 'http' not in candidate_prefix.lower():
                prefix, rest = candidate_prefix + ' : ', candidate_rest

        text = rest.lower()
        if 'mailboxnotenabledforrestapi' in text or ('404' in text and 'mailfolders' in text):
            continue  # etat normal (compte sans boite Exchange) : ne pas afficher du tout
        elif 'read operation timed out' in text or "n'a pas répondu à temps" in text or 'timed out' in text:
            summary = "Microsoft Graph n'a pas répondu à temps (temporaire, devrait se résoudre au prochain scan)"
        elif 'http 403' in text or 'authorization_requestdenied' in text:
            summary = "permission Microsoft Graph manquante ou consentement admin non accordé (voir Configuration)"
        elif 'http 401' in text or 'invalidauthenticationtoken' in text:
            summary = 'authentification Microsoft Graph refusée (secret expiré ou configuration incorrecte)'
        elif 'configuration microsoft graph incomplète' in text:
            summary = 'configuration Microsoft Graph incomplète (voir Configuration)'
        else:
            summary = rest if len(rest) <= 140 else rest[:140] + '…'
        summaries.append(prefix + summary)

    if not summaries:
        return ''
    return outer_prefix + ' / '.join(summaries)


app.jinja_env.filters['friendly_graph_error'] = friendly_graph_error


def _is_no_mailbox_error(e):
    """True si une erreur Graph correspond a un compte sans boite Exchange (courant et
    normal pour un compte d'administration dedie 'adm-*') : ce n'est pas un vrai echec
    de scan, juste l'absence de regles de messagerie a examiner pour ce compte."""
    return 'mailboxnotenabledforrestapi' in str(e).lower()

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
    # Migration : resultat de la derniere analyse IA (Groq) sur la boite, mis en cache
    # pour ne pas avoir a rappeler l'API a chaque affichage de la fiche.
    try:
        c.execute('ALTER TABLE boites_compromises ADD COLUMN ai_analysis TEXT')
    except:
        pass
    try:
        c.execute('ALTER TABLE boites_compromises ADD COLUMN ai_analysis_at TEXT')
    except:
        pass
    try:
        c.execute('ALTER TABLE boites_compromises ADD COLUMN ai_analysis_model TEXT')
    except:
        pass
    try:
        c.execute('ALTER TABLE boites_compromises ADD COLUMN ai_analysis_provider TEXT')
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

    # IPs de confiance declarees par un administrateur (ex: IPs de la ville elle-meme) :
    # toujours affichees en vert avec un badge dedie (label personnalisable, "Ville" par
    # defaut), sans jamais interroger AbuseIPDB pour elles (inutile de depenser du quota
    # sur une IP deja connue et de confiance).
    c.execute('''CREATE TABLE IF NOT EXISTS trusted_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        label TEXT NOT NULL DEFAULT 'Ville',
        note TEXT,
        city TEXT,
        lat REAL,
        lon REAL,
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Migration : localisation precise declarable manuellement pour une IP de confiance
    # (bases existantes) — la geolocalisation automatique (ipwho.is, ou celle deja fournie
    # par Microsoft Graph dans les journaux de connexion) retombe souvent sur la grande
    # ville la plus proche du bloc IP plutot que la commune exacte (ex: Paris au lieu
    # d'Ivry-sur-Seine pour une IP de la ville) ; un administrateur peut ici corriger.
    for _col in ('city TEXT', 'lat REAL', 'lon REAL'):
        try:
            c.execute(f'ALTER TABLE trusted_ips ADD COLUMN {_col}')
        except Exception:
            pass

    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        level TEXT NOT NULL,
        category TEXT NOT NULL,
        message TEXT NOT NULL,
        details TEXT,
        boite_id INTEGER,
        recipient TEXT,
        username TEXT,
        FOREIGN KEY (boite_id) REFERENCES boites_compromises(id)
    )''')

    # Migration : compte a l'origine de l'action journalisee (bases existantes ne l'ont pas
    # encore) — renseigne explicitement par les actions "Premiers secours" (voir add_log),
    # laisse vide pour les entrees automatiques du planificateur (pas d'acteur humain).
    try:
        c.execute('ALTER TABLE logs ADD COLUMN username TEXT')
    except Exception:
        pass

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

    # Connexions de TOUT le tenant (pas limitees aux boites deja suivies) : alimentee par
    # refresh_tenant_signins(), rafraichie automatiquement toutes les N minutes (reglable,
    # voir get_tenant_signins_refresh_minutes) par le planificateur de surveillance — voir /connexions.
    c.execute('''CREATE TABLE IF NOT EXISTS tenant_signins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id TEXT UNIQUE,
        date_utc TEXT,
        user_upn TEXT,
        user_display_name TEXT,
        ip_address TEXT,
        location TEXT,
        city TEXT,
        country TEXT,
        lat REAL,
        lon REAL,
        status TEXT,
        error_code TEXT,
        failure_reason TEXT,
        application TEXT,
        client_app TEXT,
        mfa_result TEXT,
        flagged TEXT,
        fetched_at TEXT
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_tenant_signins_date ON tenant_signins(date_utc)')

    # Acquittement des lieux suspects de la carte des connexions (voir /#cartes et la
    # fonction compute_dashboard_kpis) : un administrateur peut "acquitter" un lieu
    # sensible deja examine (ex: connexion VPN de l'equipe en deplacement) ; le point
    # passe alors en rouge fixe reduit (plus d'animation) et le popup affiche "vérifié
    # par X". La cle est (ville, code pays), identique au bucketing de la carte.
    c.execute('''CREATE TABLE IF NOT EXISTS signin_acks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        city TEXT DEFAULT '',
        country_code TEXT DEFAULT '',
        acknowledged_by TEXT NOT NULL,
        acknowledged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(city, country_code)
    )''')

    # Migration : ville + coordonnees fournies directement par Microsoft Graph pour chaque
    # connexion (bases existantes) — voir _map_graph_signin, nettement plus precises qu'une
    # geolocalisation par bloc IP pour le placement sur les cartes du tableau de bord.
    for _col in ('city TEXT', 'lat REAL', 'lon REAL'):
        try:
            c.execute(f'ALTER TABLE tenant_signins ADD COLUMN {_col}')
        except Exception:
            pass

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

    # Scan periodique (ou a la demande) des regles de messagerie de TOUTES les boites du
    # tenant (pas seulement les boites deja suivies/investiguees) — contrairement a
    # mailbox_rules (une boite precise, liee a une fiche d'incident ou a la surveillance),
    # ce scan interroge l'annuaire complet via Microsoft Graph. tenant_rule_scans garde un
    # historique limite des passages (voir TENANT_RULES_SCAN_RETENTION), tenant_mailbox_rules
    # les regles trouvees a chaque passage — voir scan_tenant_mailbox_rules et /monitoring/rules.
    c.execute('''CREATE TABLE IF NOT EXISTS tenant_rule_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL DEFAULT 'running',
        triggered_by TEXT,
        total_accounts INTEGER,
        scanned_accounts INTEGER DEFAULT 0,
        accounts_with_rules INTEGER DEFAULT 0,
        suspicious_count INTEGER DEFAULT 0,
        error_count INTEGER DEFAULT 0,
        last_error TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS tenant_mailbox_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        user_upn TEXT,
        user_display_name TEXT,
        rule_id TEXT,
        display_name TEXT,
        is_enabled TEXT,
        sequence INTEGER,
        conditions_summary TEXT,
        actions_summary TEXT,
        forwards_to TEXT,
        is_suspicious TEXT,
        raw_json TEXT,
        FOREIGN KEY (scan_id) REFERENCES tenant_rule_scans(id)
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_tenant_mailbox_rules_scan ON tenant_mailbox_rules(scan_id)')

    # Historique des regles traitees (marquees comme examinaees par un administrateur) :
    # persiste meme si la regle disparait lors du scan suivant (utilisateur supprime,
    # regle modifiee/supprimee). Cle unique (user_upn, rule_id) — si une meme regle
    # reapparait, le traitement est conserve.
    c.execute('''CREATE TABLE IF NOT EXISTS tenant_rule_processed (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_upn TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        rule_display_name TEXT,
        comment TEXT,
        processed_by TEXT NOT NULL,
        processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_upn, rule_id)
    )''')

    # Actions de remediation deja realisees par la DSI sur une boite (ex: mot de passe
    # reinitialise, MFA renforce...) : saisies manuellement, elles sont a la fois
    # affichees sur la fiche de la boite ET injectees dans le prompt d'analyse IA pour
    # que le modele ne re-recommande pas des actions deja effectuees.
    c.execute('''CREATE TABLE IF NOT EXISTS dsi_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        boite_id INTEGER NOT NULL,
        action_text TEXT NOT NULL,
        action_at TEXT,
        created_by TEXT,
        created_at TEXT,
        updated_by TEXT,
        updated_at TEXT,
        FOREIGN KEY (boite_id) REFERENCES boites_compromises(id)
    )''')

    # Migration : ajouter les colonnes date/heure de l'action et tracabilite des
    # modifications (bases existantes ne les ont pas encore).
    for _col in ('action_at TEXT', 'updated_by TEXT', 'updated_at TEXT'):
        try:
            c.execute(f'ALTER TABLE dsi_actions ADD COLUMN {_col}')
        except Exception:
            pass

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        is_active INTEGER NOT NULL DEFAULT 1,
        auth_source TEXT NOT NULL DEFAULT 'local',
        must_change_password INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Migration: ajouter la colonne auth_source si elle n'existe pas (bases existantes)
    try:
        c.execute("ALTER TABLE users ADD COLUMN auth_source TEXT NOT NULL DEFAULT 'local'")
    except Exception:
        pass

    # Migration : force le changement de mot de passe a la prochaine connexion — utilise
    # pour le compte admin par defaut (voir plus bas) et chaque fois qu'un administrateur
    # cree un compte ou reinitialise un mot de passe pour quelqu'un d'autre (voir add_user
    # et reset_user_password) : la personne choisit alors elle-meme son mot de passe des
    # sa premiere connexion, plutot que de garder indefiniment celui fixe par un tiers.
    try:
        c.execute('ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0')
    except Exception:
        pass

    # Migration : qualification manuelle "super-administrateur" (voir user_is_superadmin) —
    # en plus des comptes reconnus automatiquement par leur identifiant (motif
    # adm*@ivry94fr.onmicrosoft.com), un super-administrateur existant peut qualifier
    # explicitement un autre compte admin comme tel depuis /users.
    try:
        c.execute('ALTER TABLE users ADD COLUMN is_superadmin INTEGER NOT NULL DEFAULT 0')
    except Exception:
        pass

    # Migration : retrait effectif du statut super-administrateur. Un compte reconnu par
    # son identifiant (admin, adm*@ivry94fr.onmicrosoft.com) reste super-admin par defaut ;
    # superadmin_disabled=1 permet de lui RETIRER ce statut malgre l'auto-reconnaissance.
    try:
        c.execute('ALTER TABLE users ADD COLUMN superadmin_disabled INTEGER NOT NULL DEFAULT 0')
    except Exception:
        pass

    c.execute('''CREATE TABLE IF NOT EXISTS monitored_mailboxes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT UNIQUE NOT NULL,
        interval_minutes INTEGER NOT NULL DEFAULT 60,
        is_active INTEGER NOT NULL DEFAULT 1,
        last_scan_at TEXT,
        last_scan_score INTEGER,
        last_scan_verdict TEXT,
        last_scan_findings_count INTEGER,
        last_scan_findings_summary TEXT,
        last_error TEXT,
        created_by TEXT,
        source_pattern_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Migration: ajouter la colonne last_scan_findings_summary si elle n'existe pas
    try:
        c.execute('ALTER TABLE monitored_mailboxes ADD COLUMN last_scan_findings_summary TEXT')
    except Exception:
        pass

    c.execute('''CREATE TABLE IF NOT EXISTS monitoring_patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        prefix TEXT UNIQUE NOT NULL,
        interval_minutes INTEGER NOT NULL DEFAULT 60,
        is_active INTEGER NOT NULL DEFAULT 1,
        last_sync_at TEXT,
        last_sync_count INTEGER,
        last_error TEXT,
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Migration: ajouter la colonne source_pattern_id si elle n'existe pas (bases existantes)
    try:
        c.execute('ALTER TABLE monitored_mailboxes ADD COLUMN source_pattern_id INTEGER')
    except Exception:
        pass

    # Cles d'API delivrees aux applications externes qui consomment l'API /api/v1/* (voir
    # section "API externe" plus bas dans ce fichier). La cle en clair n'est jamais stockee :
    # seul son empreinte SHA-256 (key_hash) l'est, comme un mot de passe. key_prefix (les
    # premiers caracteres de la cle) sert uniquement a l'identifier dans la liste admin sans
    # avoir a la reafficher en entier.
    c.execute('''CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        key_prefix TEXT NOT NULL,
        key_hash TEXT NOT NULL UNIQUE,
        is_paused INTEGER NOT NULL DEFAULT 0,
        is_revoked INTEGER NOT NULL DEFAULT 0,
        expires_at TEXT,
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used_at TEXT
    )''')

    # Journal des appels effectues avec chaque cle (endpoint, methode, code retour) — permet
    # a l'admin de voir comment une application externe utilise l'API depuis la page de
    # gestion des cles. api_key_id est NULL quand l'appel a echoue avant meme d'identifier
    # une cle valide (en-tete absent ou cle inconnue) : conserve quand meme, pour l'audit
    # des tentatives d'acces invalides.
    c.execute('''CREATE TABLE IF NOT EXISTS api_key_usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_key_id INTEGER,
        endpoint TEXT,
        method TEXT,
        status_code INTEGER,
        ip_address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (api_key_id) REFERENCES api_keys(id)
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_api_key_usage_key_id ON api_key_usage(api_key_id)')

    # Migration : creer un compte admin par defaut si la table users est vide. Identifiants
    # volontairement simples (admin/admin) puisque must_change_password=1 force de toute
    # facon un changement de mot de passe des la premiere connexion — pas de mot de passe
    # "definitif" fixe dans le code source a retenir/proteger.
    if c.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
        c.execute('INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, ?, 1)',
                   ('admin', generate_password_hash('admin'), 'admin'))

    # Migration: ajouter colonne hostname si elle n'existe pas
    try:
        c.execute('ALTER TABLE ip_info ADD COLUMN hostname TEXT')
    except:
        pass  # La colonne existe déjà

    # Migration : reputation de l'IP (score d'abus, type d'usage — residentiel, hebergeur,
    # datacenter...) via AbuseIPDB (cle optionnelle, voir /config), avec repli heuristique
    # si aucune cle n'est configuree. Mise en cache comme le reste de ip_info, mais avec sa
    # propre date de rafraichissement (reputation_checked_at) car ces donnees evoluent dans
    # le temps, contrairement a la geolocalisation.
    for _col in ('abuse_score INTEGER', 'usage_type TEXT', 'ip_domain TEXT', 'total_reports INTEGER',
                 'is_whitelisted BOOLEAN', 'last_reported_at TEXT', 'reputation_source TEXT',
                 'reputation_checked_at TEXT'):
        try:
            c.execute(f'ALTER TABLE ip_info ADD COLUMN {_col}')
        except Exception:
            pass
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


# Duree de fraicheur du cache de reputation (en heures) : contrairement a la geolocalisation
# (get_ip_info, mise en cache indefiniment — une IP ne change pas de pays), la reputation
# d'une IP evolue dans le temps (nouveaux signalements d'abus...), d'ou un rafraichissement
# periodique plutot qu'un cache permanent. Fixe a 4h pour ne pas surcharger le quota gratuit
# d'AbuseIPDB (1000 requetes/jour) : chaque IP deja recherchee est servie depuis la base
# locale (table ip_info) pendant 4h avant qu'un nouvel appel a l'API ne soit refait.
IP_REPUTATION_CACHE_HOURS = 4


# Seuils appliques au score d'abus AbuseIPDB (0-100, confiance qu'une IP soit malveillante)
# pour la pastille verte/orange/rouge. Ce sont les seuils generalement recommandes par
# AbuseIPDB elle-meme et repris par la plupart des integrations (SIEM, pare-feu...) :
#   < 25  : vert   — pas de signalement significatif
#   25-74 : orange — signalee au moins une fois, a verifier
#   >= 75 : rouge  — forte confiance d'abus
# Volontairement pas 90+ (seuil parfois utilise pour du blocage automatique reseau, donc
# plus conservateur) : ici la pastille sert juste a attirer l'oeil pendant une
# investigation, mieux vaut sur-signaler (faux positif visuel, sans consequence) que
# rater une IP a 80% de confiance d'abus.
IP_REPUTATION_RED_THRESHOLD = 75
IP_REPUTATION_ORANGE_THRESHOLD = 25


def _compute_reputation_level(abuse_score, usage_type, is_vpn_heuristic):
    """Convertit un score d'abus AbuseIPDB (0=aucun signalement, 100=confiance d'abus
    maximale) en niveau vert/orange/rouge. Sans score disponible (pas de cle configuree),
    retombe sur l'heuristique VPN/proxy/Tor existante. Seul un VPN/proxy/Tor detecte
    remonte le niveau au moins a l'orange meme avec un score d'abus bas — le type
    d'usage (hebergeur/datacenter...) reste affiche dans le detail mais n'influence plus
    la couleur : beaucoup d'IP legitimes (dont celles de Microsoft 365 lui-meme) sont
    hebergees en datacenter, ce qui produisait trop de faux positifs oranges."""
    if abuse_score is None:
        # Pas de cle AbuseIPDB : estimation grossiere a partir du seul heuristique existant.
        return ('orange', 'estimation') if is_vpn_heuristic else ('green', 'estimation')

    if abuse_score >= IP_REPUTATION_RED_THRESHOLD:
        level = 'red'
    elif abuse_score >= IP_REPUTATION_ORANGE_THRESHOLD:
        level = 'orange'
    else:
        level = 'green'

    if is_vpn_heuristic and level == 'green':
        level = 'orange'
    return (level, 'abuseipdb')


def _fetch_abuseipdb(ip, api_key):
    """Interroge AbuseIPDB (https://api.abuseipdb.com) pour le score de confiance d'abus et
    le type d'usage (residentiel, hebergeur, mobile...) d'une IP. Retourne le dict 'data' de
    la reponse. Leve une exception en cas d'echec (cle invalide, quota depasse, timeout...)."""
    import urllib.request
    import urllib.parse
    import urllib.error

    url = 'https://api.abuseipdb.com/api/v2/check?' + urllib.parse.urlencode({
        'ipAddress': ip, 'maxAgeInDays': '90'})
    req = urllib.request.Request(url, headers={
        'Key': api_key, 'Accept': 'application/json', 'User-Agent': 'Analyse-Compromis/1.0'})
    with urllib.request.urlopen(req, timeout=8) as response:
        payload = json.loads(response.read().decode('utf-8'))
    if 'data' not in payload:
        raise RuntimeError(payload.get('errors', [{}])[0].get('detail', 'Réponse AbuseIPDB invalide'))
    return payload['data']


def get_trusted_ip(ip):
    """Renvoie la ligne trusted_ips correspondante (id, ip, label, note...) si l'IP a ete
    declaree de confiance par un administrateur (page /admin/trusted-ips), sinon None."""
    ip = (ip or '').strip()
    if not ip:
        return None
    conn = get_db()
    row = conn.execute('SELECT * FROM trusted_ips WHERE ip=?', (ip,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_ip_geo(ip):
    """Geolocalisation d'une IP pour affichage (carte, colonne 'Localisation'...), avec
    priorite a la localisation precise declaree manuellement pour une IP de confiance : la
    geolocalisation automatique par bloc IP (ipwho.is, ou celle deja fournie par Microsoft
    Graph dans les journaux de connexion) retombe souvent sur la grande ville la plus
    proche plutot que la commune exacte (ex: Paris au lieu d'Ivry-sur-Seine pour une IP de
    la ville) — corrige ici plutot que de faire confiance a un tiers pour une IP dont on
    connait deja l'emplacement reel. Retourne un dict {city, country, country_code, lat,
    lon} (valeurs possiblement None si indisponibles), jamais None lui-meme."""
    trusted = get_trusted_ip(ip)
    info = get_ip_info(ip) or {}
    result = {
        'city': info.get('city'), 'country': info.get('country'),
        'country_code': info.get('country_code'), 'lat': info.get('lat'), 'lon': info.get('lon'),
    }
    if trusted and trusted.get('lat') is not None and trusted.get('lon') is not None:
        result['lat'] = trusted['lat']
        result['lon'] = trusted['lon']
        if trusted.get('city'):
            result['city'] = trusted['city']
        result['country'] = result['country'] or 'France'
        result['country_code'] = result['country_code'] or 'FR'
    return result


def get_display_location(ip, raw_location=''):
    """Libelle de localisation a afficher pour une IP (ex: colonne 'Localisation' de
    /connexions) : la ville declaree pour une IP de confiance prime sur le texte brut
    fourni par Microsoft Graph (souvent imprecis — voir get_ip_geo). A defaut de
    surcharge, renvoie le texte d'origine tel quel."""
    trusted = get_trusted_ip(ip)
    if trusted and trusted.get('city'):
        return f"{trusted['city']}, France"
    return raw_location


def get_ip_reputation(ip):
    """Geolocalisation (get_ip_info, cache permanent) + reputation (score d'abus, type
    d'usage — servie depuis la base locale pendant IP_REPUTATION_CACHE_HOURS avant tout
    nouvel appel a l'API) d'une IP. Utilise AbuseIPDB si une cle est configuree (voir
    /config), sinon repli sur l'heuristique VPN/proxy/Tor deja existante (champ is_vpn).
    Une IP declaree de confiance (trusted_ips) court-circuite tout ceci : toujours verte,
    jamais interrogee sur AbuseIPDB (inutile de depenser du quota dessus).
    Retourne un dict pret a afficher (geo + reputation + niveau vert/orange/rouge), ou None
    si l'IP est vide/invalide."""
    ip = (ip or '').strip()
    if not ip:
        return None

    trusted = get_trusted_ip(ip)

    info = get_ip_info(ip)
    if info is None:
        # Geolocalisation indisponible (IP privee, service en panne...) : reputation seule,
        # sans le reste (pays, ville...).
        info = {'ip': ip}

    if trusted:
        info['reputation_level'] = 'green'
        info['reputation_basis'] = 'trusted'
        info['is_trusted'] = True
        info['trusted_label'] = trusted.get('label') or 'Ville'
        # Localisation precise declaree manuellement prevaut sur la geolocalisation
        # automatique par bloc IP (souvent imprecise — voir get_ip_geo pour le detail).
        if trusted.get('lat') is not None and trusted.get('lon') is not None:
            info['lat'] = trusted['lat']
            info['lon'] = trusted['lon']
            if trusted.get('city'):
                info['city'] = trusted['city']
        return info

    needs_refresh = True
    checked_at = info.get('reputation_checked_at')
    if checked_at:
        checked_dt = _parse_iso(checked_at)
        if checked_dt:
            age_hours = (datetime.now(timezone.utc).replace(tzinfo=None) - checked_dt).total_seconds() / 3600
            if age_hours < IP_REPUTATION_CACHE_HOURS:
                needs_refresh = False

    if needs_refresh:
        api_key = get_config('abuseipdb_api_key', '').strip()
        now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        update_fields = {'reputation_checked_at': now_iso}
        if api_key:
            try:
                data = _fetch_abuseipdb(ip, api_key)
                update_fields.update({
                    'abuse_score': data.get('abuseConfidenceScore'),
                    'usage_type': data.get('usageType') or '',
                    'ip_domain': data.get('domain') or '',
                    'total_reports': data.get('totalReports'),
                    'is_whitelisted': bool(data.get('isWhitelisted')),
                    'last_reported_at': data.get('lastReportedAt') or '',
                    'reputation_source': 'abuseipdb',
                })
                if data.get('isTor'):
                    update_fields['is_vpn'] = True
            except Exception as e:
                print(f"Erreur reputation AbuseIPDB pour {ip}: {e}")
                update_fields['reputation_source'] = 'abuseipdb_error'
        else:
            update_fields['reputation_source'] = 'heuristic'
            # Sans cle AbuseIPDB, meilleur effort pour distinguer un hebergeur/datacenter
            # d'une IP residentielle : les FAI grand public n'apparaissent pas dans cette
            # liste, les principaux hebergeurs/cloud oui — a defaut de vraie donnee, un
            # simple mot-cle sur l'ISP/l'organisation reste plus utile qu'une absence totale
            # d'indication de "residentiel ou pas".
            isp_org = ((info.get('isp') or '') + ' ' + (info.get('org') or '')).lower()
            hosting_keywords = ['amazon', 'aws', 'google', 'microsoft', 'azure', 'ovh', 'hetzner',
                                 'digitalocean', 'digital ocean', 'linode', 'akamai', 'vultr', 'oracle cloud',
                                 'alibaba', 'contabo', 'scaleway', 'cloudflare', 'hosting', 'datacenter',
                                 'data center', 'server', 'colo']
            if any(kw in isp_org for kw in hosting_keywords):
                update_fields['usage_type'] = 'Hébergeur/Datacenter (estimation heuristique)'

        conn = get_db()
        # S'assurer qu'une ligne existe (cas ou get_ip_info a echoue mais qu'on veut quand
        # meme conserver la reputation) avant de mettre a jour.
        conn.execute('INSERT OR IGNORE INTO ip_info (ip) VALUES (?)', (ip,))
        set_clause = ', '.join(f'{k}=?' for k in update_fields)
        conn.execute(f'UPDATE ip_info SET {set_clause} WHERE ip=?', (*update_fields.values(), ip))
        conn.commit()
        row = conn.execute('SELECT * FROM ip_info WHERE ip=?', (ip,)).fetchone()
        conn.close()
        info = dict(row) if row else {**info, **update_fields}

    level, basis = _compute_reputation_level(info.get('abuse_score'), info.get('usage_type'), bool(info.get('is_vpn')))
    info['reputation_level'] = level
    info['reputation_basis'] = basis
    return info


REPUTATION_LEVEL_COLOR = {'green': '#198754', 'orange': '#fd7e14', 'red': '#dc3545'}
REPUTATION_LEVEL_LABELS = {
    'green': 'Faible risque', 'orange': 'Risque modéré', 'red': 'Risque élevé',
}
REPUTATION_BASIS_LABELS = {
    'abuseipdb': 'AbuseIPDB',
    'abuseipdb_error': "AbuseIPDB (échec de la requête — dernière donnée connue)",
    'estimation': "Estimation heuristique (aucune clé AbuseIPDB configurée)",
    'trusted': "IP de confiance déclarée par un administrateur",
}


def ip_reputation_payload(ip):
    """Construit le dict JSON-serialisable decrivant la reputation d'une IP (utilise par le
    badge Jinja rendu cote serveur ET par les routes AJAX /api/ip-info et /api/ip-info-batch
    qui alimentent la detection d'IP dans du texte libre — analyse IA, timeline... — cote
    client). Retourne None si la reputation n'a pas pu etre determinee."""
    ip = (ip or '').strip()
    if not ip:
        return None
    try:
        info = get_ip_reputation(ip)
    except Exception as e:
        print(f"Erreur ip_reputation_payload pour {ip}: {e}")
        return None
    if not info:
        return None

    level = info.get('reputation_level') or 'orange'
    return {
        'ip': ip,
        'level': level,
        'level_label': REPUTATION_LEVEL_LABELS.get(level, level),
        'basis_label': REPUTATION_BASIS_LABELS.get(info.get('reputation_basis'), info.get('reputation_basis') or ''),
        'country': info.get('country') or '',
        'city': info.get('city') or '',
        'isp': info.get('isp') or '',
        'org': info.get('org') or '',
        'asn': info.get('as_name') or '',
        'hostname': info.get('hostname') or '',
        'usage_type': info.get('usage_type') or '',
        'domain': info.get('ip_domain') or '',
        'abuse_score': info.get('abuse_score'),
        'total_reports': info.get('total_reports'),
        'is_whitelisted': bool(info.get('is_whitelisted')),
        'last_reported_at': info.get('last_reported_at') or '',
        'is_vpn': bool(info.get('is_vpn')),
        'is_trusted': bool(info.get('is_trusted')),
        'trusted_label': info.get('trusted_label') or '',
        # Badge "DC" (hebergeur/datacenter) : jamais pour une IP de confiance deja
        # identifiee et validee par un administrateur, meme si AbuseIPDB la classe ainsi.
        'is_datacenter': (not info.get('is_trusted')) and any(
            kw in (info.get('usage_type') or '').lower() for kw in ('data center', 'datacenter')),
        # Badges "FAI Fixe" / "Mobile" : type d'usage AbuseIPDB "Fixed Line ISP" / "Mobile
        # ISP" — contexte rassurant (connexion grand public typique), affiche que l'IP soit
        # de confiance ou non, contrairement au badge DC qui est un signal d'attention.
        'is_fixed_line_isp': 'fixed line isp' in (info.get('usage_type') or '').lower(),
        'is_mobile_isp': 'mobile isp' in (info.get('usage_type') or '').lower(),
    }


def _ip_badge_html(payload):
    """Construit le HTML d'un badge IP (pastille couleur + badge de confiance/VPN eventuel)
    a partir du payload retourne par ip_reputation_payload — factorise entre render_ip_badge
    (rendu serveur) et la detection cote client (voir /api/ip-info-batch, meme structure de
    donnees, meme rendu construit en JS dans base.html)."""
    ip = payload['ip']
    color = REPUTATION_LEVEL_COLOR.get(payload['level'], '#6c757d')
    extra_badges = ''
    if payload.get('is_trusted'):
        extra_badges += f' <span class="badge bg-primary" style="font-size:0.65em;">{escape(payload.get("trusted_label") or "Ville")}</span>'
    if payload.get('is_vpn'):
        extra_badges += ' <span class="badge bg-warning text-dark" style="font-size:0.65em;">VPN/Proxy</span>'
    if payload.get('is_datacenter'):
        extra_badges += ' <span class="badge bg-secondary" style="font-size:0.65em;">DC</span>'
    if payload.get('is_fixed_line_isp'):
        extra_badges += ' <span class="badge bg-info text-dark" style="font-size:0.65em;">FAI Fixe</span>'
    if payload.get('is_mobile_isp'):
        extra_badges += ' <span class="badge text-white" style="font-size:0.65em;background-color:#6f42c1;">Mobile</span>'
    data_attr = escape(json.dumps(payload, ensure_ascii=False))
    return Markup(
        f'<span class="ip-badge text-nowrap"><code>{escape(ip)}</code> '
        f'<a href="#" class="ip-rep-badge" data-bs-toggle="modal" data-bs-target="#ipInfoModal" '
        f'data-ip-info="{data_attr}" title="{escape(payload["level_label"])} — cliquer pour le détail">'
        f'<span class="ip-rep-dot" style="background-color:{color};"></span></a>{extra_badges}</span>'
    )


def render_ip_badge(ip):
    """Fonction globale Jinja ({{ ip_badge(x) }}) : affiche une IP suivie d'une pastille de
    reputation verte/orange/rouge (+ badge VPN/Proxy si detecte) cliquable, qui ouvre la
    modale de detail partagee (voir le gestionnaire JS dans base.html) sans requete AJAX
    supplementaire — toutes les donnees sont deja embarquees dans l'attribut data-ip-info
    au moment du rendu de la page."""
    ip = (ip or '').strip()
    if not ip:
        return Markup('')
    payload = ip_reputation_payload(ip)
    if not payload:
        return Markup(f'<code>{escape(ip)}</code>')
    return _ip_badge_html(payload)


app.jinja_env.globals['ip_badge'] = render_ip_badge


@app.route('/api/ip-info/<ip>')
def api_ip_info(ip):
    """Reputation d'une seule IP en JSON — utilise en secours par le detecteur d'IP cote
    client (voir linkifyIPsIn/flushIpLinkifyQueue dans base.html) si l'appel groupe
    /api/ip-info-batch a echoue. Necessite une session connectee (avant_request global),
    pas de restriction admin : c'est une simple consultation, comme les pages elles-memes."""
    payload = ip_reputation_payload(ip)
    if not payload:
        return jsonify({'error': 'IP invalide ou reputation indisponible'}), 404
    return jsonify(payload)


@app.route('/api/ip-info-batch', methods=['POST'])
def api_ip_info_batch():
    """Reputation de plusieurs IPs en une seule requete — utilise par le detecteur d'IP
    cote client pour colorer en un seul aller-retour toutes les IPs reperees dans du texte
    libre (analyse IA, timeline, journal...) apres coup, sans les avoir fait passer par
    ip_badge() cote serveur au moment du rendu. Plafonne a 50 IPs par appel."""
    body = request.get_json(silent=True) or {}
    ips = body.get('ips') or []
    if not isinstance(ips, list):
        return jsonify({'error': 'ips doit être une liste'}), 400
    results = {}
    for ip in ips[:50]:
        payload = ip_reputation_payload(str(ip))
        if payload:
            results[str(ip)] = payload
    return jsonify(results)


def render_ip_reputation_label(ip):
    """Variante texte brut (pas de HTML/JS) de la reputation d'une IP, pour les contextes
    ou une modale/pastille n'a pas de sens (export/impression). Renvoie un libelle du style
    'Faible risque', ou une chaine vide si l'IP est vide."""
    ip = (ip or '').strip()
    if not ip:
        return ''
    try:
        info = get_ip_reputation(ip)
    except Exception:
        info = None
    level = (info or {}).get('reputation_level')
    return REPUTATION_LEVEL_LABELS.get(level, '')


app.jinja_env.globals['ip_reputation_label'] = render_ip_reputation_label


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

def add_log(level, category, message, details=None, boite_id=None, recipient=None, username=None):
    """`username` : compte a l'origine de l'action (ex: administrateur ayant declenche une
    action "Premiers secours"). Laisse a None pour les entrees automatiques (planificateur,
    imports periodiques...) qui n'ont pas d'acteur humain."""
    try:
        conn = get_db()
        conn.execute('''INSERT INTO logs (level, category, message, details, boite_id, recipient, username)
            VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (level, category, message, details, boite_id, recipient, username))
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
        with urllib.request.urlopen(req, timeout=20) as resp:
            payload = json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8') if e.fp else str(e)
        raise RuntimeError(f"Authentification Microsoft Graph refusée (HTTP {e.code}) : {error_body}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise RuntimeError(f"Impossible de joindre Microsoft Graph (authentification) : {e}")

    token = payload.get('access_token')
    if not token:
        raise RuntimeError(f"Réponse d'authentification Microsoft Graph inattendue : {payload}")
    _graph_token_cache['token'] = token
    _graph_token_cache['expires_at'] = now + int(payload.get('expires_in', 3600))
    return token


def graph_get_all(path, params=None, timeout=30, max_pages=25, retries=1):
    """Effectue un GET sur Microsoft Graph avec pagination automatique (@odata.nextLink).
    `path` est soit un chemin relatif ('/organization'), soit une URL absolue.

    - `timeout` (secondes) s'applique a CHAQUE page recuperee, pas au total : une requete
      non filtree sur un tenant tres actif peut necessiter plusieurs pages, chacune avec
      sa propre marge de tempo, plutot qu'un timeout global qui echouerait a coup sur.
    - `max_pages` protege contre une pagination incontrolee (ex: requete non filtree sur
      un tenant tres actif) : au-dela, on s'arrete et on retourne ce qui a deja ete recupere
      plutot que de risquer un blocage tres long ou une consommation memoire excessive.
    - `retries` : nombre de nouvelles tentatives PAR PAGE en cas de timeout/erreur reseau
      ou de reponse Graph transitoire (429 limitation de debit, 503/504 indisponibilite) —
      ces incidents sont frequemment ponctuels et une simple relance suffit generalement,
      evitant de faire echouer tout un import pour un seul alea reseau."""
    import urllib.request
    import urllib.parse
    import urllib.error
    import time as _time_mod

    token = get_graph_token()
    url = path if path.startswith('http') else 'https://graph.microsoft.com/v1.0' + path
    if params:
        sep = '&' if '?' in url else '?'
        url += sep + urllib.parse.urlencode(params)

    results = []
    pages = 0
    while url:
        req = urllib.request.Request(url, headers={
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json',
            'ConsistencyLevel': 'eventual',
        })
        attempt = 0
        while True:
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    payload = json.loads(resp.read().decode('utf-8'))
                break
            except urllib.error.HTTPError as e:
                if e.code in (429, 503, 504) and attempt < retries:
                    retry_after = e.headers.get('Retry-After') if e.headers else None
                    wait = float(retry_after) if retry_after and retry_after.strip().isdigit() else 2
                    _time_mod.sleep(min(wait, 10))
                    attempt += 1
                    continue
                error_body = e.read().decode('utf-8') if e.fp else str(e)
                raise RuntimeError(f"Erreur Microsoft Graph (HTTP {e.code}) sur {url} : {error_body}")
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                if attempt < retries:
                    attempt += 1
                    _time_mod.sleep(1)
                    continue
                raise RuntimeError(f"Microsoft Graph n'a pas répondu à temps sur {url} : {e}")
        if isinstance(payload, dict) and 'value' in payload:
            results.extend(payload['value'])
            url = payload.get('@odata.nextLink')
        else:
            results.append(payload)
            url = None
        pages += 1
        if pages >= max_pages and url:
            print(f"graph_get_all: arrêt après {pages} pages (max_pages atteint) pour {path}")
            break
    return results


def _graph_quote(value):
    import urllib.parse
    return urllib.parse.quote(value or '')


def graph_request(method, path, body=None, timeout=20):
    """Effectue UNE requete d'ecriture (PATCH/POST/DELETE, sans pagination) sur Microsoft
    Graph — a la difference de graph_get_all (lecture seule, paginee). Utilise pour les
    actions d'urgence du menu "Premiers secours" (desactivation de compte, revocation de
    sessions, reinitialisation de mot de passe...), qui necessitent la permission
    d'application User.ReadWrite.All (voir /config)."""
    import urllib.request
    import urllib.error

    token = get_graph_token()
    url = path if path.startswith('http') else 'https://graph.microsoft.com/v1.0' + path
    data = json.dumps(body).encode('utf-8') if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8') if e.fp else str(e)
        raise RuntimeError(f"Erreur Microsoft Graph (HTTP {e.code}) sur {method} {url} : {error_body}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise RuntimeError(f"Microsoft Graph n'a pas répondu à temps sur {method} {url} : {e}")


def rh_studio_check_presence(email=None, q=None, nom=None, prenom=None):
    """Interroge l'API RH Studio (GET /api/agents/presence) pour verifier si un agent
    est present, parti, ou pas encore arrive. Renvoie un dict avec les cles found,
    matchType, score, agent (dict ou None). En cas d'erreur lève une exception."""
    import urllib.request, urllib.parse, ssl
    api_url = get_config('rh_studio_url', '').rstrip('/')
    api_key = get_config('rh_studio_api_key', '')
    if not api_url:
        raise ValueError("URL de l'API RH Studio non configurée")
    if not api_key:
        raise ValueError("Clé API RH Studio non configurée")
    params = {}
    if email:
        params['email'] = email
    elif q:
        params['q'] = q
    elif nom:
        params['nom'] = nom
        if prenom:
            params['prenom'] = prenom
    elif prenom:
        params['prenom'] = prenom
    else:
        raise ValueError("Aucun paramètre de recherche fourni")
    qs = urllib.parse.urlencode(params)
    base = api_url
    if base.endswith('/api'):
        base = base[:-4]
    url = f"{base}/api/agents/presence?{qs}"
    req = urllib.request.Request(url, headers={
        'X-Api-Key': api_key,
        'Accept': 'application/json',
    })
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
        return json.loads(resp.read().decode('utf-8'))


def rh_studio_batch_check(upns):
    """Interroge RH Studio pour chaque UPN (email) et renvoie un dict
    {upn: {'status': 'present'|'parti'|'not_found'|'error', ...}}.
    Silencieux : en cas d'erreur API ou de config manquante, renvoie un dict vide."""
    if not upns:
        return {}
    api_url = get_config('rh_studio_url', '').rstrip('/')
    api_key = get_config('rh_studio_api_key', '')
    if not api_url or not api_key:
        return {}
    results = {}
    for upn in upns:
        if not upn:
            continue
        try:
            resp = rh_studio_check_presence(email=upn)
            agent = resp.get('agent')
            if not agent:
                results[upn] = {'status': 'not_found'}
            else:
                results[upn] = {'status': agent.get('status', 'unknown')}
        except Exception:
            results[upn] = {'status': 'error'}
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
    # Coordonnees fournies directement par Microsoft Graph (signInLocation.geoCoordinates),
    # quand disponibles : nettement plus precises qu'une geolocalisation par bloc IP
    # (ipwho.is) qui retombe souvent sur la grande ville la plus proche plutot que la
    # commune exacte — utilisees en priorite pour le placement sur les cartes.
    geo_coords = location.get('geoCoordinates') or {}
    return {
        'date_utc': item.get('createdDateTime', ''),
        'request_id': item.get('id', ''),
        'correlation_id': item.get('correlationId', ''),
        'user_display_name': item.get('userDisplayName', ''),
        'user_upn': item.get('userPrincipalName', ''),
        'ip_address': item.get('ipAddress', ''),
        'location': location_str,
        'city': location.get('city', ''),
        'country': country,
        'lat': geo_coords.get('latitude'),
        'lon': geo_coords.get('longitude'),
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
    has_conditions = bool(conditions_parts)
    # Une suppression simple n'est consideree suspecte que si elle cible du courrier lie a la
    # securite (voir SECURITY_RULE_KEYWORDS) : une regle "delete" banale (notifications de
    # supervision, mailer-daemon...) est tres frequente et generalement benigne.
    text_for_keywords = f"{item.get('displayName', '')} {' '.join(conditions_parts)}".lower()
    looks_security_related = any(kw in text_for_keywords for kw in SECURITY_RULE_KEYWORDS)
    # Un transfert limite par des conditions (expediteur, sujet...) est une redirection ciblee
    # courante et legitime (correspondant, partenaire, delegation ponctuelle...), meme vers une
    # adresse externe. Seul un transfert SANS AUCUNE CONDITION - qui s'applique donc a tous les
    # messages entrants - est le schema classique d'exfiltration utilise apres compromission.
    suspicious = (bool(forward_targets) and not has_conditions) or bool(actions.get('permanentDelete')) or \
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
    # $top plus modeste (chaque page se genere plus vite cote Graph) et timeout genereux :
    # cet import complet est declenche a la demande (pas dans la boucle de surveillance),
    # on peut se permettre d'attendre un peu plus pour eviter un echec sur un simple alea.
    items = graph_get_all('/auditLogs/signIns', params={'$filter': filter_q, '$top': '500'}, timeout=45)

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
    items = graph_get_all('/auditLogs/directoryAudits', params={'$filter': f'activityDateTime ge {since}', '$top': '500'}, timeout=45)

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


def graph_list_users_by_prefix(prefix):
    """Liste les utilisateurs du tenant dont l'UPN commence par `prefix` (utilise pour la
    decouverte automatique de boites a surveiller, ex: toutes les boites 'adm-*').
    Necessite la permission d'application User.Read.All (ou Directory.Read.All)."""
    prefix_escaped = (prefix or '').replace("'", "''")
    items = graph_get_all('/users', params={
        '$filter': f"startswith(userPrincipalName,'{prefix_escaped}')",
        '$select': 'id,userPrincipalName,displayName,accountEnabled',
        '$top': '999',
    })
    return [it for it in items if it.get('userPrincipalName') and it.get('accountEnabled', True)]


def graph_list_tenant_mailbox_users(max_pages=50):
    """Liste TOUS les comptes membres actifs du tenant (candidats a posseder une boite
    Exchange), utilise par le scan complet des regles de messagerie (voir
    scan_tenant_mailbox_rules) — contrairement a graph_list_users_by_prefix, aucun filtre
    sur l'UPN. Exclut les comptes invites (userType 'Guest') et desactives, qui n'ont
    generalement pas de boite active a auditer. Necessite User.Read.All."""
    items = graph_get_all('/users', params={
        '$filter': "userType eq 'Member' and accountEnabled eq true",
        '$select': 'id,userPrincipalName,displayName',
        '$top': '999',
    }, timeout=30, max_pages=max_pages)
    return [it for it in items if it.get('userPrincipalName')]


# ============================================================================
# Menu "Premiers secours" (/admin/compte) : consultation rapide des infos cles d'un
# compte et actions d'urgence en cas de compromission averee — desactivation du compte,
# revocation de toutes les sessions/jetons, reinitialisation du mot de passe, consultation
# des methodes MFA enregistrees. Necessite en plus la permission d'application
# User.ReadWrite.All (ecriture), et UserAuthenticationMethod.Read.All (ReadWrite.All pour
# l'action MFA) pour la partie methodes d'authentification — voir /config.
# ============================================================================

_sku_name_cache = {'map': None, 'expires_at': 0}


def graph_get_sku_names():
    """Traduit les identifiants de licence (skuId, un GUID) en nom lisible (skuPartNumber,
    ex: 'ENTERPRISEPREMIUM') via /subscribedSkus — mis en cache 1h (comme le jeton Graph)
    pour ne pas refaire cet appel a chaque consultation de compte."""
    import time
    now = time.time()
    if _sku_name_cache['map'] is not None and _sku_name_cache['expires_at'] > now:
        return _sku_name_cache['map']
    try:
        items = graph_get_all('/subscribedSkus', timeout=20, max_pages=3)
        mapping = {it['skuId']: it.get('skuPartNumber', it['skuId']) for it in items if it.get('skuId')}
    except Exception:
        mapping = {}
    _sku_name_cache['map'] = mapping
    _sku_name_cache['expires_at'] = now + 3600
    return mapping


_ACCOUNT_OVERVIEW_BASE_FIELDS = (
    'id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,jobTitle,'
    'department,officeLocation,onPremisesSyncEnabled,userType,assignedLicenses'
)


def graph_get_account_overview(upn):
    """Recupere les informations cles d'un compte pour la page /admin/compte/<upn> :
    identite, statut (actif/desactive), derniere connexion (signInActivity), licences
    affectees (traduites en noms lisibles). Retourne {} si le compte n'existe pas dans
    l'annuaire.

    signInActivity a un comportement particulier documente par Microsoft : si l'app n'a
    pas A LA FOIS AuditLog.Read.All ET User.Read.All (par ex. consentement admin pas encore
    accorde pour l'une des deux), Graph renvoie une erreur 400 Bad Request — pas le 403
    habituel pour une permission manquante — ce qui ferait echouer toute la fiche pour un
    seul champ. On retente donc sans ce champ dans ce cas precis, plutot que de priver
    l'administrateur du reste des informations du compte en pleine urgence."""
    try:
        items = graph_get_all(f'/users/{_graph_quote(upn)}', params={
            '$select': _ACCOUNT_OVERVIEW_BASE_FIELDS + ',signInActivity',
        }, timeout=20, max_pages=1)
    except RuntimeError as e:
        if 'HTTP 400' not in str(e):
            raise
        items = graph_get_all(f'/users/{_graph_quote(upn)}', params={
            '$select': _ACCOUNT_OVERVIEW_BASE_FIELDS,
        }, timeout=20, max_pages=1)
    data = dict(items[0]) if items else {}
    if data.get('id'):
        sku_names = graph_get_sku_names()
        data['license_names'] = [sku_names.get(l.get('skuId'), l.get('skuId')) for l in (data.get('assignedLicenses') or [])]
    return data


_AUTH_METHOD_LABELS = {
    '#microsoft.graph.passwordAuthenticationMethod': 'Mot de passe',
    '#microsoft.graph.phoneAuthenticationMethod': 'Téléphone',
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod': 'Microsoft Authenticator',
    '#microsoft.graph.fido2AuthenticationMethod': 'Clé de sécurité FIDO2',
    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod': 'Windows Hello Entreprise',
    '#microsoft.graph.softwareOathAuthenticationMethod': 'Application OTP logicielle',
    '#microsoft.graph.temporaryAccessPassAuthenticationMethod': "Pass d'accès temporaire",
    '#microsoft.graph.emailAuthenticationMethod': 'E-mail (récupération)',
}


# Methodes qui NE constituent PAS un veritable second facteur : le mot de passe (toujours
# present, c'est l'identifiant primaire) et l'e-mail de recuperation (secours pour la
# reinitialisation en libre-service, pas un facteur de connexion). Toute autre methode
# retournee par Graph (Authenticator, telephone, FIDO2, Windows Hello, OTP logiciel...)
# compte comme un vrai MFA — voir _has_real_mfa.
_NON_MFA_METHOD_TYPES = {
    '#microsoft.graph.passwordAuthenticationMethod',
    '#microsoft.graph.emailAuthenticationMethod',
}


def graph_get_auth_methods(upn):
    """Liste les methodes d'authentification (MFA) enregistrees pour un compte —
    permet de reperer une methode ajoutee par un attaquant apres compromission (nouveau
    telephone, nouvelle app Authenticator...). Necessite UserAuthenticationMethod.Read.All
    (permission distincte de celles deja utilisees par l'appli, voir /config)."""
    items = graph_get_all(f'/users/{_graph_quote(upn)}/authentication/methods', timeout=20, max_pages=3)
    out = []
    for it in items:
        t = it.get('@odata.type', '')
        out.append({
            'type': _AUTH_METHOD_LABELS.get(t, t.replace('#microsoft.graph.', '').replace('AuthenticationMethod', '')),
            'raw_type': t,
            'is_real_mfa': t not in _NON_MFA_METHOD_TYPES,
            'detail': it.get('displayName') or it.get('phoneNumber') or '',
            'created': it.get('createdDateTime'),
        })
    return out


def _has_real_mfa(auth_methods):
    """Vrai si au moins une methode d'authentification enregistree constitue un vrai
    second facteur (voir _NON_MFA_METHOD_TYPES) — mot de passe et e-mail de recuperation
    seuls ne comptent pas comme du MFA."""
    return any(m.get('raw_type') not in _NON_MFA_METHOD_TYPES for m in auth_methods)


def graph_set_account_enabled(upn, enabled):
    """Active/desactive un compte (bloque toute nouvelle connexion, immediat). Necessite
    User.ReadWrite.All."""
    graph_request('PATCH', f'/users/{_graph_quote(upn)}', {'accountEnabled': bool(enabled)})


def graph_revoke_sessions(upn):
    """Revoque TOUS les jetons d'acces/actualisation deja emis pour ce compte (deconnexion
    forcee partout, y compris sessions mobiles/Outlook deja ouvertes) — action classique de
    premiers secours en cas de compromission averee. Necessite User.ReadWrite.All."""
    return graph_request('POST', f'/users/{_graph_quote(upn)}/revokeSignInSessions')


def graph_reset_password(upn, password=None):
    """Reinitialise le mot de passe et force son changement a la prochaine connexion.
    Si `password` est fourni (saisi par l'administrateur), il est utilise tel quel — sinon
    un mot de passe temporaire aleatoire est genere. Retourne (mot_de_passe, was_generated) ;
    le mot de passe genere doit etre affiche UNE SEULE FOIS a l'administrateur (jamais
    stocke) — celui saisi manuellement, deja connu de l'administrateur, n'a pas besoin
    d'etre reaffiche. Necessite User.ReadWrite.All ; peut echouer avec 'Insufficient
    privileges' si le compte cible a un role d'administration plus eleve que le role
    assigne a cette application, ou avec un message de politique de mots de passe si le
    mot de passe saisi ne respecte pas les exigences de complexite du tenant."""
    was_generated = not password
    if was_generated:
        import secrets
        import string
        pool_upper, pool_lower, pool_digits, pool_symbols = string.ascii_uppercase, string.ascii_lowercase, string.digits, '!@#$%*?-_'
        chars = [secrets.choice(pool_upper), secrets.choice(pool_lower), secrets.choice(pool_digits), secrets.choice(pool_symbols)]
        all_pool = pool_upper + pool_lower + pool_digits + pool_symbols
        chars += [secrets.choice(all_pool) for _ in range(10)]
        secrets.SystemRandom().shuffle(chars)
        temp_password = ''.join(chars)
    else:
        temp_password = password
    graph_request('PATCH', f'/users/{_graph_quote(upn)}', {
        'passwordProfile': {'forceChangePasswordNextSignIn': True, 'password': temp_password}
    })
    return temp_password, was_generated


def graph_set_per_user_mfa_state(upn, state):
    """Positionne l'etat MFA "par utilisateur" (mecanisme historique, endpoint beta) —
    SANS EFFET si le tenant applique le MFA via l'Acces conditionnel ou les Defauts de
    securite (les deux mecanismes modernes, largement majoritaires aujourd'hui) plutot que
    le MFA par utilisateur : dans ce cas l'appel reussit mais ne change rien de concret.
    Necessite UserAuthenticationMethod.ReadWrite.All. `state` : 'enabled' | 'enforced' |
    'disabled'."""
    graph_request('PATCH', f'https://graph.microsoft.com/beta/users/{_graph_quote(upn)}/authentication/requirements',
                  {'perUserMfaState': state})


def graph_get_per_user_mfa_state(upn):
    """Etat MFA "par utilisateur" (mecanisme historique) pour ce compte precis — endpoint
    beta, meme permission que graph_set_per_user_mfa_state (UserAuthenticationMethod.Read.All
    suffit pour la lecture). Retourne 'disabled' | 'enabled' | 'enforced'."""
    data = graph_request('GET', f'https://graph.microsoft.com/beta/users/{_graph_quote(upn)}/authentication/requirements')
    return data.get('perUserMfaState', 'disabled')


def graph_get_security_defaults_enabled():
    """Vrai si les Defauts de securite (Security Defaults) sont actifs sur le tenant —
    parametre global qui, s'il est active, exige le MFA pour quasi tous les utilisateurs
    (independamment de l'Acces conditionnel ou du MFA par utilisateur). Necessite
    Policy.Read.All."""
    data = graph_request('GET', '/policies/identitySecurityDefaultsEnforcementPolicy')
    return bool(data.get('isEnabled'))


def graph_get_conditional_access_mfa_policies():
    """Liste les politiques d'Acces conditionnel ACTIVES qui exigent le MFA (controle
    integre 'mfa') — a titre informatif : determiner si une politique donnee s'applique
    reellement a UN compte precis demanderait d'evaluer ses inclusions/exclusions
    (utilisateurs, groupes, applications...), non fait ici. Necessite Policy.Read.All."""
    items = graph_get_all('/identity/conditionalAccess/policies', timeout=20, max_pages=5)
    out = []
    for p in items:
        if p.get('state') != 'enabled':
            continue
        controls = ((p.get('grantControls') or {}).get('builtInControls')) or []
        if 'mfa' in controls:
            out.append({'displayName': p.get('displayName', ''), 'id': p.get('id', '')})
    return out


def sync_monitoring_pattern(pattern_row):
    """Interroge Microsoft Graph pour la liste actuelle des boites correspondant au motif
    (prefixe d'UPN), et ajoute a la surveillance celles qui n'y sont pas deja. N'enleve
    jamais une boite deja surveillee (meme si elle ne correspond plus au motif) : a faire
    manuellement depuis /monitoring si besoin."""
    now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    conn = get_db()
    try:
        users = graph_list_users_by_prefix(pattern_row['prefix'])
        added = 0
        for u in users:
            upn = u['userPrincipalName']
            existing = conn.execute('SELECT id FROM monitored_mailboxes WHERE user_email=?', (upn,)).fetchone()
            if existing:
                continue
            conn.execute('''INSERT INTO monitored_mailboxes
                (user_email, interval_minutes, created_by, source_pattern_id)
                VALUES (?, ?, ?, ?)''',
                (upn, pattern_row['interval_minutes'], f"motif:{pattern_row['prefix']}", pattern_row['id']))
            added += 1
        conn.execute('''UPDATE monitoring_patterns SET last_sync_at=?, last_sync_count=?, last_error=NULL
            WHERE id=?''', (now_iso, len(users), pattern_row['id']))
        conn.commit()
        if added:
            add_log('INFO', 'MONITORING', f"Découverte automatique ({pattern_row['prefix']}*) : {added} nouvelle(s) boîte(s) ajoutée(s) à la surveillance")
        return added
    except Exception as e:
        conn.execute('UPDATE monitoring_patterns SET last_sync_at=?, last_error=? WHERE id=?',
                     (now_iso, str(e), pattern_row['id']))
        conn.commit()
        add_log('ERROR', 'MONITORING', f"Échec de la découverte automatique pour le motif {pattern_row['prefix']}*", str(e))
        raise
    finally:
        conn.close()


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
PUBLIC_ENDPOINTS = {'login', 'static', 'microsoft_login', 'microsoft_callback'}

# Endpoints encore accessibles a un compte dont le mot de passe doit etre change (en plus
# des routes publiques ci-dessus) : la page de changement elle-meme et la deconnexion,
# sans quoi un compte fraichement cree se retrouverait bloque sans issue.
PASSWORD_CHANGE_ALLOWED_ENDPOINTS = {'change_password', 'logout'}


@app.before_request
def require_login():
    """Impose une connexion pour toute l'application, sauf la page de connexion elle-meme,
    les fichiers statiques, et l'API externe /api/v1/* (qui a sa propre authentification par
    cle, voir require_api_key — sans cette exception, un appelant externe muni d'une cle
    valide mais d'aucune session navigateur se faisait rediriger vers /login au lieu
    d'obtenir la reponse JSON attendue : la cle n'etait alors jamais verifiee). Remplace
    l'ancienne authentification HTTP Basic globale. Impose egalement le changement de mot de
    passe (compte fraichement cree/reinitialise par un administrateur, ou compte admin par
    defaut jamais personnalise) avant tout acces au reste de l'application."""
    if request.endpoint is None or request.endpoint in PUBLIC_ENDPOINTS or request.path.startswith('/api/v1/'):
        return
    if not session.get('user_id'):
        return redirect(url_for('login', next=request.path))
    if session.get('must_change_password') and request.endpoint not in PASSWORD_CHANGE_ALLOWED_ENDPOINTS:
        return redirect(url_for('change_password'))


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


# Motif reconnaissant automatiquement les comptes "super-administrateur" par leur
# identifiant : le compte admin racine et les boites d'administration Microsoft dediees
# du tenant (ex: adm-marc@ivry94fr.onmicrosoft.com). Ne depend d'aucune configuration —
# a adapter ici si le domaine du tenant change.
SUPERADMIN_USERNAME_RE = re.compile(r'^(admin|adm[^@]*@ivry94fr\.onmicrosoft\.com)$', re.IGNORECASE)


def is_superadmin_username(username):
    return bool(username) and bool(SUPERADMIN_USERNAME_RE.match(username.strip()))


def user_is_superadmin(user_row):
    """Vrai si le compte est reconnu super-administrateur : soit par son identifiant
    (voir SUPERADMIN_USERNAME_RE), soit parce qu'il a ete explicitement qualifie comme tel
    par un super-administrateur existant (colonne is_superadmin, voir /users). Le flag
    superadmin_disabled (voir toggle_superadmin) permet de RETIRER effectivement ce statut,
    meme pour un identifiant normalement auto-reconnu. Les super-administrateurs sont seuls
    a pouvoir consulter /logs et gerer les comptes /users (donnees potentiellement
    sensibles : qui a consulte/agi sur quel compte, y compris via "Premiers secours")."""
    if not user_row:
        return False
    try:
        if bool(user_row['superadmin_disabled']):
            return False
    except (KeyError, IndexError):
        pass
    if is_superadmin_username(user_row['username']):
        return True
    try:
        return bool(user_row['is_superadmin'])
    except (KeyError, IndexError):
        return False


app.jinja_env.globals['user_is_superadmin'] = user_is_superadmin
app.jinja_env.globals['is_superadmin_username'] = is_superadmin_username


def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login', next=request.path))
        # Re-verification en base a chaque demande : un retrait de super-admin (fait sur
        # soi-meme ou par un autre) prend effet immediatement, sans attendre la prochaine
        # connexion, et le flag de session reste coherent.
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
        conn.close()
        if not user or not user_is_superadmin(user):
            session.pop('is_superadmin', None)
            flash("Accès réservé aux super-administrateurs")
            return redirect(url_for('index'))
        if not session.get('is_superadmin'):
            session['is_superadmin'] = True
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
            session['is_superadmin'] = user_is_superadmin(user)
            session['must_change_password'] = bool(user['must_change_password'])
            next_url = request.form.get('next') or url_for('index')
            return redirect(next_url)
        flash('Identifiants incorrects')
    graph_configured = bool(get_config('graph_tenant_id', '') and get_config('graph_client_id', '') and get_config('graph_client_secret', ''))
    return render_template('login.html', next=request.args.get('next', ''), graph_configured=graph_configured)


@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    """Changement de mot de passe force (compte fraichement cree/reinitialise par un
    administrateur, ou compte admin par defaut jamais personnalise — voir must_change_password
    et require_login). Accessible aussi volontairement par n'importe quel utilisateur connecte
    pour changer son propre mot de passe a tout moment (pas seulement quand c'est impose)."""
    if not session.get('user_id'):
        return redirect(url_for('login'))
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    if not user:
        conn.close()
        session.clear()
        return redirect(url_for('login'))
    if user['auth_source'] == 'microsoft':
        conn.close()
        flash("Ce compte s'authentifie via Microsoft — aucun mot de passe local à changer ici")
        return redirect(url_for('index'))

    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        if not check_password_hash(user['password_hash'], current_password):
            conn.close()
            flash('Mot de passe actuel incorrect')
            return render_template('change_password.html', forced=bool(session.get('must_change_password')))
        if len(new_password) < 8:
            conn.close()
            flash('Le nouveau mot de passe doit contenir au moins 8 caractères')
            return render_template('change_password.html', forced=bool(session.get('must_change_password')))
        if new_password != confirm_password:
            conn.close()
            flash('La confirmation ne correspond pas au nouveau mot de passe')
            return render_template('change_password.html', forced=bool(session.get('must_change_password')))
        conn.execute('UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?',
                     (generate_password_hash(new_password), user['id']))
        conn.commit()
        conn.close()
        session['must_change_password'] = False
        add_log('INFO', 'AUTH', f"Mot de passe changé par {user['username']}")
        flash('Mot de passe modifié avec succès')
        return redirect(url_for('index'))

    conn.close()
    return render_template('change_password.html', forced=bool(session.get('must_change_password')))


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


def _microsoft_redirect_uri():
    """Calcule l'URI de redirection OAuth Microsoft. Si un administrateur a renseigne
    une "URL publique de l'application" (config 'public_base_url'), elle est utilisee
    directement — independamment de ce que le reverse proxy transmet comme en-tetes
    X-Forwarded-*. Utile quand ProxyFix ne suffit pas (en-tetes non transmis par le
    proxy, chaine de proxies non standard...) : l'admin fixe la valeur une fois pour
    toutes plutot que de deboguer indefiniment la configuration reseau. A defaut,
    reprend le comportement base sur ProxyFix/url_for(_external=True)."""
    base = get_config('public_base_url', '').strip().rstrip('/')
    if base:
        return base + url_for('microsoft_callback')
    return url_for('microsoft_callback', _external=True)


@app.route('/auth/microsoft/login')
def microsoft_login():
    """Demarre la connexion via Microsoft Entra ID (flux OAuth2 authorization code),
    en utilisant l'App Registration deja configuree pour l'API Graph. Restreint au
    tenant configure (endpoint /{tenant_id}/... et non /common/) : seuls les comptes
    de cette organisation peuvent se connecter."""
    tenant_id = get_config('graph_tenant_id', '').strip()
    client_id = get_config('graph_client_id', '').strip()
    if not (tenant_id and client_id):
        flash("Connexion Microsoft indisponible : configuration Graph incomplète (voir Configuration)")
        return redirect(url_for('login'))

    import secrets
    import urllib.parse

    state = secrets.token_urlsafe(24)
    session['ms_oauth_state'] = state
    session['ms_oauth_next'] = request.args.get('next', '')

    redirect_uri = _microsoft_redirect_uri()
    params = {
        'client_id': client_id,
        'response_type': 'code',
        'redirect_uri': redirect_uri,
        'response_mode': 'query',
        'scope': 'openid profile email User.Read',
        'state': state,
        # Force systematiquement l'ecran de choix de compte : sans ca, Microsoft ne le
        # montre que s'il detecte plusieurs comptes actifs dans le navigateur — avec un
        # seul compte deja connecte (ex: personnel), il enchaine silencieusement dessus,
        # ce qui peut ne pas etre le compte professionnel attendu pour cette application.
        'prompt': 'select_account',
    }
    auth_url = (f'https://login.microsoftonline.com/{urllib.parse.quote(tenant_id)}/oauth2/v2.0/authorize?'
                + urllib.parse.urlencode(params))
    return redirect(auth_url)


@app.route('/auth/microsoft/callback')
def microsoft_callback():
    """Recoit le retour de Microsoft, echange le code contre un jeton, recupere
    l'identite via Graph /me, puis cree/connecte le compte local correspondant.
    Les nouveaux comptes sont provisionnes automatiquement : role 'admin' si l'UPN
    commence par 'adm-' (insensible a la casse), 'user' sinon. Un compte deja existant
    (cree localement ou lors d'une connexion Microsoft precedente) conserve son role
    actuel, meme s'il a ete change manuellement depuis /users."""
    error = request.args.get('error')
    if error:
        flash(f"Connexion Microsoft annulée ou refusée : {request.args.get('error_description', error)}")
        return redirect(url_for('login'))

    state = request.args.get('state', '')
    expected_state = session.pop('ms_oauth_state', None)
    next_url = session.pop('ms_oauth_next', '') or url_for('index')
    if not expected_state or state != expected_state:
        flash('Connexion Microsoft refusée (état de sécurité invalide) — réessayez')
        return redirect(url_for('login'))

    code = request.args.get('code')
    if not code:
        flash('Connexion Microsoft incomplète (code manquant)')
        return redirect(url_for('login'))

    tenant_id = get_config('graph_tenant_id', '').strip()
    client_id = get_config('graph_client_id', '').strip()
    client_secret = get_config('graph_client_secret', '').strip()
    if not (tenant_id and client_id and client_secret):
        flash("Connexion Microsoft indisponible : configuration Graph incomplète")
        return redirect(url_for('login'))

    import urllib.request
    import urllib.parse
    import urllib.error

    redirect_uri = _microsoft_redirect_uri()
    token_url = f'https://login.microsoftonline.com/{urllib.parse.quote(tenant_id)}/oauth2/v2.0/token'
    data = urllib.parse.urlencode({
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'scope': 'openid profile email User.Read',
    }).encode('utf-8')

    try:
        req = urllib.request.Request(token_url, data=data, method='POST',
                                      headers={'Content-Type': 'application/x-www-form-urlencoded'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            token_payload = json.loads(resp.read().decode('utf-8'))
        access_token = token_payload['access_token']

        req2 = urllib.request.Request('https://graph.microsoft.com/v1.0/me', headers={
            'Authorization': f'Bearer {access_token}', 'Accept': 'application/json'})
        with urllib.request.urlopen(req2, timeout=15) as resp2:
            me = json.loads(resp2.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8') if e.fp else str(e)
        add_log('ERROR', 'AUTH', 'Échec de la connexion Microsoft', f'HTTP {e.code}: {error_body}')
        flash(f"Échec de la connexion Microsoft (HTTP {e.code})")
        return redirect(url_for('login'))
    except Exception as e:
        add_log('ERROR', 'AUTH', 'Échec de la connexion Microsoft', str(e))
        flash(f"Échec de la connexion Microsoft : {e}")
        return redirect(url_for('login'))

    upn = (me.get('userPrincipalName') or me.get('mail') or '').strip()
    if not upn:
        flash("Connexion Microsoft impossible : identifiant utilisateur introuvable dans la réponse Graph")
        return redirect(url_for('login'))

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username=?', (upn,)).fetchone()
    if not user:
        role = 'admin' if upn.lower().startswith('adm-') else 'user'
        placeholder_hash = generate_password_hash(uuid.uuid4().hex)
        conn.execute('INSERT INTO users (username, password_hash, role, auth_source) VALUES (?, ?, ?, ?)',
                      (upn, placeholder_hash, role, 'microsoft'))
        conn.commit()
        user = conn.execute('SELECT * FROM users WHERE username=?', (upn,)).fetchone()
        conn.close()
        add_log('INFO', 'AUTH', f'Compte {upn} créé automatiquement via connexion Microsoft (rôle {role})')
    elif not user['is_active']:
        conn.close()
        flash('Ce compte est désactivé — contactez un administrateur')
        return redirect(url_for('login'))
    else:
        conn.close()

    session.clear()
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    session['is_superadmin'] = user_is_superadmin(user)
    add_log('INFO', 'AUTH', f'Connexion Microsoft réussie pour {upn}')
    return redirect(next_url)


@app.route('/users')
@superadmin_required
def list_users():
    conn = get_db()
    users = conn.execute('SELECT * FROM users ORDER BY username').fetchall()
    conn.close()
    return render_template('users.html', users=users)


@app.route('/users/add', methods=['POST'])
@superadmin_required
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
        # must_change_password=1 : c'est l'administrateur qui choisit ce mot de passe
        # initial, pas la personne elle-meme — elle devra le changer a sa premiere connexion.
        conn.execute('INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, ?, 1)',
                     (username, generate_password_hash(password), role))
        conn.commit()
        flash(f"Utilisateur {username} créé avec succès")
    except sqlite3.IntegrityError:
        flash(f"Le nom d'utilisateur {username} existe déjà")
    finally:
        conn.close()
    return redirect(url_for('list_users'))


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@superadmin_required
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
@superadmin_required
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


@app.route('/users/<int:user_id>/toggle-superadmin', methods=['POST'])
@superadmin_required
def toggle_superadmin(user_id):
    """Qualifie ou RETIRE le statut super-administrateur d'un compte admin (seul acces
    autorise a /logs et /users) — reserve aux super-administrateurs existants. Le retrait
    est effectif meme pour un identifiant normalement auto-reconnu (voir
    SUPERADMIN_USERNAME_RE) via le flag superadmin_disabled, re-evalue a chaque requete
    par superadmin_required : si l'on se retire soi-meme, l'acces tombe immediatement."""
    conn = get_db()
    target = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not target:
        conn.close()
        flash('Utilisateur non trouvé')
        return redirect(url_for('list_users'))
    if target['role'] != 'admin':
        conn.close()
        flash('Seul un compte administrateur peut être qualifié super-administrateur')
        return redirect(url_for('list_users'))
    currently = user_is_superadmin(target)
    if currently:
        conn.execute('UPDATE users SET is_superadmin=0, superadmin_disabled=1 WHERE id=?', (user_id,))
        label = 'retiré'
    else:
        conn.execute('UPDATE users SET is_superadmin=1, superadmin_disabled=0 WHERE id=?', (user_id,))
        label = 'qualifié'
    conn.commit()
    if user_id == session.get('user_id'):
        updated = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        session['is_superadmin'] = user_is_superadmin(updated)
    conn.close()
    add_log('WARNING', 'AUTH',
            f"{target['username']} {label} super-administrateur",
            username=session.get('username'))
    flash(f"{target['username']} {label} super-administrateur")
    return redirect(url_for('list_users'))


@app.route('/users/<int:user_id>/reset-password', methods=['POST'])
@superadmin_required
def reset_user_password(user_id):
    new_password = request.form.get('new_password', '')
    if len(new_password) < 8:
        flash('Le mot de passe doit contenir au moins 8 caractères')
        return redirect(url_for('list_users'))

    conn = get_db()
    target = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not target:
        conn.close()
        flash('Utilisateur non trouvé')
        return redirect(url_for('list_users'))

    conn.execute('UPDATE users SET password_hash=?, must_change_password=1 WHERE id=?',
                 (generate_password_hash(new_password), user_id))
    conn.commit()
    conn.close()
    add_log('INFO', 'AUTH', f"Mot de passe modifié pour {target['username']} par {session.get('username')}")
    flash(f"Mot de passe de {target['username']} modifié avec succès")
    return redirect(url_for('list_users'))


@app.route('/boites')
def list_boites():
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


@app.route('/search')
def global_search():
    """Recherche transverse (email, IP, sujet, application...) a travers TOUTES les boites
    d'incident, sans avoir a ouvrir chacune une par une — utile par exemple pour savoir si
    une IP ou un destinataire donne apparait ailleurs que sur la boite en cours
    d'investigation. Requetes LIKE simples (pas d'index plein texte) : largement suffisant
    au volume de donnees d'une investigation de securite, mais chaque categorie est
    plafonnee pour rester rapide meme sur une base volumineuse."""
    q = (request.args.get('q') or '').strip()
    results = {'boites': [], 'messages': [], 'signins': [], 'audit': [], 'monitored': []}
    if not q or len(q) < 2:
        return render_template('search_results.html', q=q, results=results, too_short=bool(q))

    like = f'%{q}%'
    conn = get_db()

    results['boites'] = conn.execute('''
        SELECT id, user_email, date_compromission, date_decouverte, created_at
        FROM boites_compromises
        WHERE user_email LIKE ? OR notes LIKE ?
        ORDER BY created_at DESC LIMIT 50''', (like, like)).fetchall()

    results['messages'] = conn.execute('''
        SELECT m.id, m.boite_id, b.user_email AS boite_email, m.received, m.sender_address,
               m.recipient_address, m.subject, m.from_ip
        FROM messages m JOIN boites_compromises b ON b.id = m.boite_id
        WHERE m.recipient_address LIKE ? OR m.sender_address LIKE ? OR m.subject LIKE ? OR m.from_ip LIKE ?
        ORDER BY m.received DESC LIMIT 50''', (like, like, like, like)).fetchall()

    results['signins'] = conn.execute('''
        SELECT s.id, s.boite_id, b.user_email AS boite_email, s.date_utc, s.user_upn,
               s.ip_address, s.application, s.status
        FROM signin_logs s JOIN boites_compromises b ON b.id = s.boite_id
        WHERE s.user_upn LIKE ? OR s.ip_address LIKE ? OR s.application LIKE ?
        ORDER BY s.date_utc DESC LIMIT 50''', (like, like, like)).fetchall()

    results['audit'] = conn.execute('''
        SELECT a.id, a.boite_id, b.user_email AS boite_email, a.date_utc, a.activite,
               a.actor_upn, a.target_upn, a.ip_address
        FROM audit_logs a JOIN boites_compromises b ON b.id = a.boite_id
        WHERE a.actor_upn LIKE ? OR a.target_upn LIKE ? OR a.ip_address LIKE ? OR a.activite LIKE ?
        ORDER BY a.date_utc DESC LIMIT 50''', (like, like, like, like)).fetchall()

    results['monitored'] = conn.execute('''
        SELECT id, user_email, is_active, last_scan_score, last_scan_verdict
        FROM monitored_mailboxes WHERE user_email LIKE ? ORDER BY user_email LIMIT 50''', (like,)).fetchall()

    conn.close()
    total = sum(len(v) for v in results.values())
    return render_template('search_results.html', q=q, results=results, total=total, too_short=False)


# Nombre maximum de boites sur lesquelles le tableau de bord recalcule le detail des
# signaux detectes (voir analyze_compromise) : plafonne pour rester rapide meme sur une
# base avec beaucoup d'incidents deja clotures — les plus recents sont les plus pertinents
# a afficher. NB : ce n'est PAS ce qui determine si une boite est "un incident" — chaque
# ligne de boites_compromises EST par definition un incident deja confirme (c'est pour ca
# qu'elle a ete creee) ; ce recalcul ne sert qu'a illustrer la force des preuves deja
# importees pour chacune, pas a re-decider si elle est compromise ou non.
DASHBOARD_MAX_SCORED_BOITES = 100

# Fenetre glissante sur laquelle sont calculees les statistiques de connexions du tableau
# de bord (echecs, score de confiance moyen, top utilisateurs en echec...).
DASHBOARD_SIGNINS_WINDOW_HOURS = 24


def compute_dashboard_kpis():
    """Calcule tous les KPI du tableau de bord : incidents (tendance, signaux detectes, IPs
    partagees), surveillance automatisee (monitored_mailboxes) et monitoring connexions
    (tenant_signins). Point d'entree UNIQUE pour cette logique — utilise a la fois par la
    page d'accueil (rendu HTML) et par l'API externe (/api/v1/kpis, voir api_v1_kpis), pour
    garantir que les deux affichent exactement les memes chiffres. Ne retourne que des
    types JSON-serialisables (dict/list/str/int/float/None), pas de sqlite3.Row."""
    conn = get_db()

    incidents_by_month = [dict(r) for r in conn.execute('''
        SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as c
        FROM boites_compromises GROUP BY month ORDER BY month''').fetchall()]

    boite_ids = [r['id'] for r in conn.execute(
        'SELECT id FROM boites_compromises ORDER BY created_at DESC LIMIT ?',
        (DASHBOARD_MAX_SCORED_BOITES,)).fetchall()]
    conn.close()

    # Repartition du niveau de signal detecte sur les incidents deja enregistres — PAS "sont-ils
    # compromis" (ils le sont tous, par definition, voir docstring) mais "les preuves deja
    # importees suffisent-elles a le confirmer heuristiquement". Un incident en "signaux à
    # vérifier" ou "RAS" ici manque simplement d'import Graph (connexions/audit), pas de
    # compromission reelle.
    verdict_counts = {'compromise_likely': 0, 'signals_to_check': 0, 'no_strong_signal': 0}
    for bid in boite_ids:
        try:
            analysis = analyze_compromise(bid)
            verdict_counts[analysis['verdict']] = verdict_counts.get(analysis['verdict'], 0) + 1
        except Exception:
            continue

    conn = get_db()
    # IPs qui reviennent sur plusieurs boites differentes (messages + connexions + audit
    # confondus) : signal fort de compromission croisee (meme attaquant, plusieurs comptes).
    shared_ips = [dict(r) for r in conn.execute('''
        SELECT ip, COUNT(DISTINCT boite_id) as nb_boites FROM (
            SELECT from_ip as ip, boite_id FROM messages WHERE from_ip != ''
            UNION ALL
            SELECT ip_address as ip, boite_id FROM signin_logs WHERE ip_address != ''
            UNION ALL
            SELECT ip_address as ip, boite_id FROM audit_logs WHERE ip_address != ''
        ) GROUP BY ip HAVING nb_boites >= 2 ORDER BY nb_boites DESC LIMIT 20''').fetchall()]

    nb_boites_total = conn.execute('SELECT COUNT(*) as c FROM boites_compromises').fetchone()['c']
    top_recipients = [dict(r) for r in conn.execute('''
        SELECT recipient_address, COUNT(*) as c FROM messages
        WHERE recipient_address != '' GROUP BY recipient_address ORDER BY c DESC LIMIT 10''').fetchall()]

    # --- KPI surveillance automatisee (monitored_mailboxes) -----------------------------
    # A partir des colonnes deja stockees (dernier resultat de scan), pas d'un recalcul —
    # coherent avec ce que la page Surveillance affiche elle-meme, contrairement au
    # verdict_counts ci-dessus qui, lui, recalcule a la volee sur les boites d'incident.
    nb_monitored_total = conn.execute('SELECT COUNT(*) as c FROM monitored_mailboxes').fetchone()['c']
    nb_monitored_active = conn.execute('SELECT COUNT(*) as c FROM monitored_mailboxes WHERE is_active=1').fetchone()['c']
    monitored_verdict_rows = conn.execute('''
        SELECT COALESCE(last_scan_verdict, 'not_scanned') as verdict, COUNT(*) as c
        FROM monitored_mailboxes WHERE is_active=1 GROUP BY verdict''').fetchall()
    monitored_verdict_counts = {'compromise_likely': 0, 'signals_to_check': 0, 'no_strong_signal': 0, 'not_scanned': 0}
    for row in monitored_verdict_rows:
        monitored_verdict_counts[row['verdict']] = row['c']
    nb_monitored_errors = conn.execute('''
        SELECT COUNT(*) as c FROM monitored_mailboxes
        WHERE is_active=1 AND last_error IS NOT NULL AND last_error != ''
    ''').fetchone()['c']

    # --- KPI monitoring connexions (tenant_signins), fenetre glissante ------------------
    # date_utc est stocke au format ISO 8601 avec 'T' et 'Z' final (voir refresh_tenant_signins),
    # alors que datetime('now', ...) de SQLite produit 'YYYY-MM-DD HH:MM:SS' (espace, sans 'Z').
    # Compares comme du texte, les deux formats divergent des le 11e caractere ('T' > ' '), donc
    # le filtre laissait passer TOUTE la journee du seuil : la fenetre etait de 24 a 48h au lieu
    # de 24h. On calcule donc le seuil dans le meme format que les donnees stockees.
    from datetime import timedelta
    window_cutoff = (datetime.now(timezone.utc).replace(tzinfo=None)
                     - timedelta(hours=DASHBOARD_SIGNINS_WINDOW_HOURS)).strftime('%Y-%m-%dT%H:%M:%SZ')
    nb_signins_window = conn.execute(
        'SELECT COUNT(*) as c FROM tenant_signins WHERE date_utc >= ?', (window_cutoff,)).fetchone()['c']
    nb_signins_failed_window = conn.execute(
        "SELECT COUNT(*) as c FROM tenant_signins WHERE date_utc >= ? AND status != 'Success'",
        (window_cutoff,)).fetchone()['c']
    signin_failure_rate = round(100 * nb_signins_failed_window / nb_signins_window) if nb_signins_window else 0
    top_failed_users = [dict(r) for r in conn.execute('''
        SELECT COALESCE(NULLIF(user_upn, ''), '(inconnu)') as user_upn, COUNT(*) as c
        FROM tenant_signins WHERE date_utc >= ? AND status != 'Success'
        GROUP BY user_upn ORDER BY c DESC LIMIT 5''', (window_cutoff,)).fetchall()]

    home_country = get_home_country_code()
    signin_window_rows = conn.execute(
        'SELECT ip_address, country, city, lat, lon, status FROM tenant_signins WHERE date_utc >= ?',
        (window_cutoff,)).fetchall()
    acks = {((r['city'] or '').lower(), (r['country_code'] or '').upper()): dict(r) for r in
            conn.execute('SELECT city, country_code, acknowledged_by, acknowledged_at FROM signin_acks').fetchall()}
    conn.close()

    nb_signins_foreign = 0
    trust_scores = []
    # Agregation par lieu (ville + pays) pour les cartes du tableau de bord : un cercle par
    # lieu, dont le rayon depend du nombre de connexions et la couleur/le clignotement du
    # niveau de suspicion (echecs et/ou score de confiance faible a cet endroit). Position
    # du cercle : priorite aux coordonnees fournies directement par Microsoft Graph pour
    # cette connexion precise (city/lat/lon, nettement plus fiables qu'une geolocalisation
    # par bloc IP qui regroupe a tort des lieux distincts sous la grande ville la plus
    # proche — ex: Anneville-en-Saire ecrasee sous Paris) ; repli sur get_ip_geo (IP de
    # confiance en priorite, puis ipwho.is en cache local) seulement si Graph n'a pas
    # fourni de coordonnees pour cet evenement.
    geo_buckets = {}
    # Cache par IP : get_ip_reputation interroge AbuseIPDB et get_ip_info peut faire un appel
    # reseau (ipwho.is, DNS inverse, timeouts de plusieurs secondes) ; sans cache ces appels
    # etaient refaits pour CHAQUE ligne de connexion (souvent plusieurs milliers) a chaque
    # affichage du tableau de bord, d'ou une page extremement lente. Idem pour get_trusted_ip
    # et get_ip_geo (une requete SQLite chacune).
    ip_reputation_cache = {}
    trusted_ip_cache = {}
    ip_geo_cache = {}
    for r in signin_window_rows:
        ip = r['ip_address']
        row_country = (r['country'] or '').strip().upper()
        if row_country != home_country:
            nb_signins_foreign += 1
        if ip not in ip_reputation_cache:
            try:
                ip_reputation_cache[ip] = ip_reputation_payload(ip)
            except Exception:
                ip_reputation_cache[ip] = None
        ip_payload = ip_reputation_cache[ip]
        row_trust = compute_connection_trust_score(ip_payload, r['country'], home_country)
        trust_scores.append(row_trust)

        city, country, country_code, lat, lon = r['city'], None, row_country, r['lat'], r['lon']
        # Une IP de confiance (localisation declaree manuellement) prime toujours, meme sur
        # les coordonnees Graph — c'est justement le cas ou l'admin sait mieux que quiconque.
        if ip not in trusted_ip_cache:
            trusted_ip_cache[ip] = get_trusted_ip(ip)
        trusted = trusted_ip_cache[ip]
        if trusted and trusted.get('lat') is not None and trusted.get('lon') is not None:
            lat, lon = trusted['lat'], trusted['lon']
            city = trusted.get('city') or city
        elif lat is None or lon is None:
            if ip not in ip_geo_cache:
                try:
                    ip_geo_cache[ip] = get_ip_geo(ip)
                except Exception:
                    ip_geo_cache[ip] = None
            geo = ip_geo_cache[ip]
            if geo and geo.get('lat') is not None and geo.get('lon') is not None:
                city, lat, lon = geo.get('city'), geo['lat'], geo['lon']
                country_code = (geo.get('country_code') or country_code or '').upper()
                country = geo.get('country')

        if lat is not None and lon is not None:
            key = (city or '', country_code or '')
            bucket = geo_buckets.setdefault(key, {
                'city': city or '', 'country': country or r['country'] or '',
                'country_code': country_code or '', 'count': 0, 'fail_count': 0,
                'lats': [], 'lons': [], 'trust_scores': [],
            })
            bucket['count'] += 1
            if (r['status'] or 'Success') != 'Success':
                bucket['fail_count'] += 1
            bucket['lats'].append(lat)
            bucket['lons'].append(lon)
            bucket['trust_scores'].append(row_trust)

    avg_trust_score = round(sum(trust_scores) / len(trust_scores)) if trust_scores else None
    nb_low_trust = sum(1 for s in trust_scores if s < 50)

    connections_geo_world = []
    connections_geo_home = []
    for bucket in geo_buckets.values():
        bucket_trust = round(sum(bucket['trust_scores']) / len(bucket['trust_scores']))
        fail_ratio = bucket['fail_count'] / bucket['count']
        # Suspect : beaucoup d'echecs a cet endroit, ou une confiance moyenne faible (loin
        # du pays de reference et/ou IP a mauvaise reputation) — cligote sur la carte pour
        # attirer l'oeil, plutot qu'un simple point statique parmi d'autres.
        is_suspicious = fail_ratio >= 0.5 or bucket_trust < 40
        ack = acks.get(((bucket['city'] or '').lower(), (bucket['country_code'] or '').upper()))
        point = {
            'city': bucket['city'], 'country': bucket['country'], 'country_code': bucket['country_code'],
            'count': bucket['count'], 'fail_count': bucket['fail_count'],
            'trust_score': bucket_trust, 'is_suspicious': is_suspicious,
            'lat': sum(bucket['lats']) / len(bucket['lats']),
            'lon': sum(bucket['lons']) / len(bucket['lons']),
            # Acquittement : lieu suspect deja examine/valide par un administrateur — la
            # carte le montre en rouge fixe reduit (plus de clignotement), le popup affiche
            # "vérifié par <user>". Demande non acquittee -> proposition d'acquittement.
            'is_acknowledged': bool(ack),
            'acknowledged_by': (ack or {}).get('acknowledged_by', ''),
            'acknowledged_at': (ack or {}).get('acknowledged_at', ''),
        }
        connections_geo_world.append(point)
        if bucket['country_code'].upper() == home_country:
            connections_geo_home.append(point)
    connections_geo_world.sort(key=lambda p: -p['count'])
    connections_geo_home.sort(key=lambda p: -p['count'])

    return {
        'incidents_by_month': incidents_by_month, 'verdict_counts': verdict_counts,
        'shared_ips': shared_ips, 'nb_boites_total': nb_boites_total,
        'top_recipients': top_recipients, 'scored_boites_count': len(boite_ids),
        'nb_monitored_total': nb_monitored_total, 'nb_monitored_active': nb_monitored_active,
        'monitored_verdict_counts': monitored_verdict_counts, 'nb_monitored_errors': nb_monitored_errors,
        'nb_signins_window': nb_signins_window, 'nb_signins_failed_window': nb_signins_failed_window,
        'signin_failure_rate': signin_failure_rate, 'top_failed_users': top_failed_users,
        'nb_signins_foreign': nb_signins_foreign, 'avg_trust_score': avg_trust_score,
        'nb_low_trust': nb_low_trust, 'signins_window_hours': DASHBOARD_SIGNINS_WINDOW_HOURS,
        'home_country_code': home_country,
        'connections_geo_world': connections_geo_world, 'connections_geo_home': connections_geo_home,
    }


@app.route('/')
def index():
    """Page d'accueil de l'application (pour tout le monde, pas seulement les admins) :
    tableau de bord agrege plutot que la liste des boites (voir /boites, accessible via le
    bouton "Voir les boîtes"). Tendance des incidents dans le temps, IPs qui reviennent sur
    plusieurs boites (signal de compromission croisee), et KPI sur la surveillance
    automatisee (boites suivies) et le monitoring des connexions (tout le tenant) — pour
    avoir une vue d'ensemble sans ouvrir boite par boite ni page par page. Memes chiffres
    que l'API externe /api/v1/kpis (voir compute_dashboard_kpis)."""
    return render_template('dashboard.html', **compute_dashboard_kpis())


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
            return redirect(url_for('list_boites'))
        
        messages = conn.execute('SELECT * FROM messages WHERE boite_id=? ORDER BY received DESC', (bid,)).fetchall()
        nb_signins = conn.execute('SELECT COUNT(*) as c FROM signin_logs WHERE boite_id=?', (bid,)).fetchone()['c']
        nb_audit = conn.execute('SELECT COUNT(*) as c FROM audit_logs WHERE boite_id=?', (bid,)).fetchone()['c']
        nb_rules = conn.execute('SELECT COUNT(*) as c FROM mailbox_rules WHERE boite_id=?', (bid,)).fetchone()['c']
        nb_suspicious_rules = conn.execute("SELECT COUNT(*) as c FROM mailbox_rules WHERE boite_id=? AND is_suspicious='true'", (bid,)).fetchone()['c']
        graph_configured = bool(get_config('graph_tenant_id', '') and get_config('graph_client_id', '') and get_config('graph_client_secret', ''))
        ai_models = [m for m in get_all_ai_models() if m['active']]
        ai_configured = bool(ai_models)
        rh_studio_configured = bool(get_config('rh_studio_url', '') and get_config('rh_studio_api_key', ''))
        dsi_actions = conn.execute('SELECT * FROM dsi_actions WHERE boite_id=? ORDER BY created_at ASC', (bid,)).fetchall()
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
                         graph_configured=graph_configured, ai_configured=ai_configured,
                         ai_models=ai_models,
                         dsi_actions=dsi_actions, now_local_dt=_now_local_datetime_input(),
                         risk_score=risk_score, risk_verdict=risk_verdict, risk_findings_count=risk_findings_count,
                         rh_studio_configured=rh_studio_configured)

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


def _build_signin_event(s, ref_id=None, mfa_linkage=None):
    """Construit un evenement de timeline a partir d'une ligne signin_logs (sqlite3.Row
    ou dict). Fonction pure : reutilisee pour les boites en base et le scan rapide.

    Si `mfa_linkage` (voir _compute_mfa_linkage) indique que cette connexion reussie est
    liee a un echec MFA (meme correlation_id, ou meme utilisateur/IP a quelques instants
    d'ecart), elle est marquee 'mfa_linked_failure' : elle a materiellement abouti, mais
    le MFA a echoue au meme moment — a ne pas compter comme un succes sans reserve."""
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

    mfa_linked_failure = False
    mfa_linked_reason = ''
    if success and mfa_linkage:
        key = _row_get(s, 'request_id', None) or id(s)
        entry = mfa_linkage.get(key)
        if entry and entry['linked']:
            mfa_linked_failure = True
            mfa_linked_reason = entry['reason']
            detail_parts.append(f"⚠ MFA échouée dans la même séquence d'authentification ({mfa_linked_reason})")

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
        'mfa_linked_failure': mfa_linked_failure,
        'mfa_linked_reason': mfa_linked_reason,
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
    aucun acces DB. Relie aussi les succes de connexion a un echec MFA associe (voir
    _compute_mfa_linkage / _build_signin_event)."""
    mfa_linkage = _compute_mfa_linkage(signins)
    events = [_build_signin_event(s, mfa_linkage=mfa_linkage) for s in signins] + [_build_audit_event(a) for a in audits]
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


def build_cross_timeline(boite_ids):
    """Fusionne les timelines de plusieurs boites en une seule, chaque evenement etant
    tague avec son origine (boite_id/boite_label), pour reperer une activite correlee
    entre comptes (meme IP, meme cible de transfert, enchainement rapide d'un compte
    a l'autre...). Retourne (events, boites) ou boites = {id: sqlite3.Row}."""
    if not boite_ids:
        return [], {}
    conn = get_db()
    placeholders = ','.join('?' * len(boite_ids))
    boites = {b['id']: b for b in conn.execute(
        f'SELECT * FROM boites_compromises WHERE id IN ({placeholders})', boite_ids).fetchall()}
    conn.close()

    all_events = []
    for bid in boite_ids:
        boite = boites.get(bid)
        label = boite['user_email'] if boite else f'Boîte #{bid}'
        for e in build_unified_timeline(bid):
            e['boite_id'] = bid
            e['boite_label'] = label
            all_events.append(e)
    all_events.sort(key=lambda e: e['timestamp'] or '')
    return all_events, boites


def analyze_cross_boite_signals(events, boites, boite_ids):
    """Detecte des correlations ENTRE plusieurs boites, en plus de l'analyse individuelle
    de chacune : adresse IP reussie partagee entre comptes, meme cible de transfert
    externe configuree sur plusieurs boites, connexions quasi simultanees depuis la
    meme IP sur des comptes differents (mouvement lateral potentiel)."""
    findings = []

    # 1) IP partagee entre plusieurs boites pour des connexions reussies
    ip_to_boites = {}
    for e in events:
        if e['type'] == 'signin' and e['success'] and e.get('ip'):
            ip_to_boites.setdefault(e['ip'], set()).add(e['boite_id'])
    for ip, bids in ip_to_boites.items():
        if len(bids) > 1:
            labels = sorted(boites[b]['user_email'] for b in bids if b in boites)
            findings.append({
                'severity': 'high',
                'title': 'Adresse IP partagée entre plusieurs boîtes',
                'description': (f"L'IP {ip} a servi à des connexions réussies sur {len(bids)} boîtes différentes : "
                                 f"{', '.join(labels)}. Signal fort d'une source d'attaque commune "
                                 f"(à défaut d'un poste ou VPN d'entreprise partagé légitime, à vérifier)."),
                'events': [],
            })

    # 2) Connexions quasi simultanees (< 30 min) depuis la meme IP sur des comptes differents
    #    = mouvement lateral potentiel (identifiants multiples compromis depuis la meme source)
    by_ip = {}
    for e in events:
        if e['type'] == 'signin' and e['success'] and e.get('ip') and e['dt']:
            by_ip.setdefault(e['ip'], []).append(e)
    seen_pairs = set()
    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e['dt'])
        for i in range(len(ip_events) - 1):
            a, b = ip_events[i], ip_events[i + 1]
            if a['boite_id'] == b['boite_id']:
                continue
            delta = (b['dt'] - a['dt']).total_seconds()
            if 0 <= delta <= 1800:
                pair_key = (ip, min(a['boite_id'], b['boite_id']), max(a['boite_id'], b['boite_id']))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)
                findings.append({
                    'severity': 'critical',
                    'title': 'Bascule rapide entre comptes depuis la même IP',
                    'description': (f"Connexion réussie sur {a['boite_label']} à {a['timestamp']}, puis sur "
                                     f"{b['boite_label']} à {b['timestamp']} ({int(delta // 60)} min d'écart) — toutes deux "
                                     f"depuis {ip}. Évoque un mouvement latéral avec plusieurs comptes compromis depuis la même source."),
                    'events': [],
                })

    # 3) Meme cible de transfert externe configuree sur plusieurs boites (regles suspectes)
    conn = get_db()
    placeholders = ','.join('?' * len(boite_ids))
    rules = conn.execute(
        f"SELECT * FROM mailbox_rules WHERE boite_id IN ({placeholders}) AND is_suspicious='true'", boite_ids).fetchall()
    conn.close()
    target_to_boites = {}
    for r in rules:
        for t in (r['forwards_to'] or '').split(','):
            t = t.strip()
            if t:
                target_to_boites.setdefault(t, set()).add(r['boite_id'])
    for target, bids in target_to_boites.items():
        if len(bids) > 1:
            labels = sorted(boites[b]['user_email'] for b in bids if b in boites)
            findings.append({
                'severity': 'critical',
                'title': 'Même adresse de transfert utilisée par plusieurs boîtes',
                'description': (f"Une règle de transfert vers {target} est configurée sur {len(bids)} boîtes : "
                                 f"{', '.join(labels)}. Schéma typique d'une exfiltration coordonnée par un même attaquant."),
                'events': [],
            })

    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    findings.sort(key=lambda f: severity_order.get(f['severity'], 9))
    return findings


def compute_risk_score(findings):
    """Convertit la liste de findings (issus de analyze_compromise_events) en un score
    de risque de compromission sur 10, a partir de la severite de chaque signal.

    Les poids 'medium'/'low' sont volontairement faibles : ces signaux isoles (ex:
    quelques changements de methode MFA, une friction de connexion depuis le pays
    habituel...) sont frequents et le plus souvent benins pris individuellement.
    Seule une accumulation consequente, ou un signal 'high'/'critical' — plus rares et
    bien plus specifiques d'une compromission reelle — doivent faire monter le score
    significativement. L'arrondi par troncature (int, pas round) evite de sur-noter
    une situation encore incertaine ("a verifier") au-dela de ce qu'elle justifie."""
    weights = {'critical': 4, 'high': 2, 'medium': 0.5, 'low': 0.25}
    score = sum(weights.get(f['severity'], 0) for f in findings)
    return min(10, int(score))


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

    # 2bis) Authentification aboutie malgre un echec MFA associe (meme correlation_id, ou
    #    meme utilisateur/IP a quelques secondes d'ecart) : la connexion n'est un succes
    #    "propre" que si l'etape primaire ET le MFA ont reussi. Regroupe TOUTES les
    #    occurrences en un seul finding : sur une session chargee, des dizaines de succes
    #    rapproches peuvent chacun avoir un echec MFA voisin (prompts relances) — c'est
    #    alors un pattern de friction a examiner globalement, pas N incidents distincts a
    #    additionner (ce qui gonflait artificiellement le score).
    mfa_linked = [e for e in successful_signins if e.get('mfa_linked_failure')]
    if len(mfa_linked) == 1:
        e = mfa_linked[0]
        findings.append({
            'severity': 'medium',
            'title': 'Authentification aboutie malgré un échec MFA associé',
            'description': (f"{e['user']} — la connexion à {e['timestamp']} depuis {e['ip']} a réussi, mais un échec MFA "
                             f"({e.get('mfa_linked_reason') or 'MFA non complétée'}) a été journalisé au même moment. "
                             f"À vérifier : l'accès a-t-il réellement validé le second facteur, ou s'agit-il d'un contournement/rejeu ?"),
            'events': [e],
        })
    elif len(mfa_linked) > 1:
        users = sorted(set(e['user'] for e in mfa_linked if e['user']))
        findings.append({
            'severity': 'medium',
            'title': f"{len(mfa_linked)} authentifications abouties malgré un échec MFA associé",
            'description': (f"Entre {mfa_linked[0]['timestamp']} et {mfa_linked[-1]['timestamp']}, {len(mfa_linked)} connexions "
                             f"réussies de {', '.join(users) or 'l’utilisateur'} ont chacune un échec MFA journalisé au même "
                             f"moment — évoque plutôt une session avec friction MFA répétée (prompts relancés) que des "
                             f"incidents distincts. À vérifier si le volume ou la période sort de l'ordinaire pour ce compte."),
            'events': mfa_linked,
        })

    # 3) Rafale d'echecs suivie d'un succes (>=3 echecs en 15 min puis succes dans les 15 min suivantes).
    #    Ce n'est un signal fort que si la connexion reussie provient d'un pays INHABITUEL :
    #    des echecs suivis d'un succes depuis le pays/l'IP habituel(le) sont tres majoritairement
    #    de la friction normale (mot de passe mal saisi, prompt MFA relance...), pas une attaque.
    failures_window = []
    for e in signin_events:
        if not e['dt']:
            continue
        if not e['success']:
            failures_window = [f for f in failures_window if (e['dt'] - f['dt']).total_seconds() <= 900] + [e]
        else:
            recent_failures = [f for f in failures_window if 0 <= (e['dt'] - f['dt']).total_seconds() <= 900]
            if len(recent_failures) >= 3:
                unusual_country = bool(baseline_country and e['country'] and e['country'] != baseline_country)
                if unusual_country:
                    findings.append({
                        'severity': 'high',
                        'title': "Rafale d'échecs de connexion suivie d'un succès",
                        'description': (f"{len(recent_failures)} échecs de connexion en moins de 15 min pour {e['user']}, "
                                         f"suivis d'une connexion réussie à {e['timestamp']} depuis {e['ip']} ({e['country']}, "
                                         f"pays inhabituel) — signature typique d'une attaque par force brute/password spray ayant abouti."),
                        'events': recent_failures + [e],
                    })
                else:
                    findings.append({
                        'severity': 'low',
                        'title': "Échecs de connexion suivis d'un succès (pays habituel)",
                        'description': (f"{len(recent_failures)} échec(s) de connexion en moins de 15 min pour {e['user']}, "
                                         f"suivis d'une connexion réussie à {e['timestamp']} depuis {e['ip']}"
                                         + (f" ({e['country']})" if e['country'] else '') +
                                         " — le pays correspond à l'usage habituel du compte : probablement une simple "
                                         "erreur de saisie ou une relance MFA, à confirmer si le doute persiste."),
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
    #    - Un transfert limite par des conditions (expediteur, sujet...) est une redirection
    #      ciblee courante et legitime (correspondant, partenaire externe, delegation
    #      ponctuelle...) : suspicious_rules ne contient donc, pour les transferts, que ceux
    #      SANS AUCUNE CONDITION (s'appliquant a tous les messages entrants) — le veritable
    #      schema d'exfiltration utilise apres compromission. Un transfert externe sans
    #      condition reste plus alarmant qu'un transfert interne sans condition.
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
            note = f"vers une adresse EXTERNE, SANS AUCUNE CONDITION (s'applique à tous les messages entrants) : {', '.join(external_targets)}"
        elif internal_targets:
            severity = 'medium'
            note = f"vers une adresse interne (même domaine), sans condition : {', '.join(internal_targets)} — probablement légitime (délégation, absence...), à confirmer auprès de l'utilisateur"
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


# ============================================================================
# Analyse IA : envoie un resume structure des journaux d'une boite (evenements + signaux
# deja detectes par l'analyse heuristique) a un modele de langage, et demande une
# explication du scenario le plus probable ainsi que des recommandations. Le prompt est
# entierement parametrable en configuration (admin). Deux fournisseurs compatibles
# OpenAI sont supportes : Groq (prioritaire) et NVIDIA (repli automatique si Groq
# echoue ou n'est pas configure — cle manquante, quota/limite de debit depasse, panne...).
# GROQ_DEFAULT_PROMPT_TEMPLATE n'est utilise que si l'admin n'a rien personnalise.
# ============================================================================

GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions'
GROQ_DEFAULT_MODEL = 'openai/gpt-oss-20b'
GROQ_AVAILABLE_MODELS = [
    'openai/gpt-oss-20b',
    'llama-3.3-70b-versatile',
    'llama-3.1-8b-instant',
    'meta-llama/llama-4-maverick-17b-128e-instruct',
    'meta-llama/llama-4-scout-17b-16e-instruct',
]

# NVIDIA NIM (build.nvidia.com) : API OpenAI-compatible donnant acces a un tres grand
# catalogue de modeles (100+, en evolution constante) — pas de liste figee ici, l'admin
# saisit librement l'identifiant du modele de son choix (ex: meta/llama-3.1-70b-instruct).
NVIDIA_API_URL = 'https://integrate.api.nvidia.com/v1/chat/completions'
NVIDIA_DEFAULT_MODEL = 'mixtral-8x7b-instruct'

# Léger parser pour les modèles multiples.
# Accepte deux formats (l'un ou l'autre, pas besoin des deux mélangés) :
#   Format A (pipe) : "nom1|model1|nom2|model2"   — peut être sur une ligne ou plusieurs
#   Format B (ligne) : un modèle par ligne, soit "modèle_technique"
#                    soit "nom_user|modèle_technique"
# La fonction détecte automatiquement quel format est utilisé.
def _parse_models(text):
    """Retourne [{'name': ..., 'model': ...}, ...]"""
    if not text or not text.strip():
        return []

    text = text.strip()
    lines = [l.strip() for l in text.splitlines() if l.strip()]

    # Format B : si au moins une ligne contient un '|', on traite chaque ligne
    # comme "nom|modèle" ou juste "modèle". On strippe pour enlever \r\n.
    any_pipe = any('|' in line for line in lines)

    if any_pipe:
        result = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if '|' in line:
                name, model = line.split('|', 1)
                result.append({'name': name.strip(), 'model': model.strip()})
            else:
                result.append({'name': line, 'model': line})
        return result

    # Format A : pas de '|' sur les lignes -> try pipe-separated on single line
    if len(lines) == 1:
        parts = text.split('|')
        parts = [p.strip() for p in parts if p.strip()]
        if len(parts) >= 2 and len(parts) % 2 == 0:
            return [{'name': parts[i], 'model': parts[i+1]} for i in range(0, len(parts)-1, 2)]
        return [{'name': text.strip(), 'model': text.strip()}]
    # Plusieurs lignes sans '|' -> chaque ligne est un modèle
    return [{'name': line, 'model': line} for line in lines]

OLLAMA_DEFAULT_URL = 'http://10.103.130.166:11434'
OLLAMA_DEFAULT_MODEL = 'gemma4:e4b'

PROVIDER_LABELS = {'groq': 'Groq', 'nvidia': 'NVIDIA', 'ollama': 'Ollama'}

# ----------------------------------------------------------------------------
# Gestion "plusieurs modèles par fournisseur" : chaque fournisseur (Groq, NVIDIA,
# Ollama) peut avoir 0, 1 ou plusieurs modèles enregistrés, chacun avec un nom
# choisi par l'admin (ex: "Rapide") et un identifiant technique (ex:
# "llama-3.1-8b-instant"). Stocké en JSON (clé de config "<provider>_models_json"),
# un modèle = {'id': ..., 'name': ..., 'model': ...}. L'ancien format texte
# ("nom1|model1|nom2|model2", clé "<provider>_models") est migré automatiquement
# la première fois qu'on le lit.
# ----------------------------------------------------------------------------

def _load_provider_models(provider):
    """Retourne [{'id', 'name', 'model'}, ...] pour ce fournisseur, en migrant si besoin
    l'ancien format texte vers le nouveau format JSON (une seule fois, résultat persisté)."""
    json_raw = get_config(f'{provider}_models_json', '')
    if json_raw:
        try:
            models = json.loads(json_raw)
        except (ValueError, TypeError):
            models = None
        if isinstance(models, list):
            changed = False
            for m in models:
                if not m.get('id'):
                    m['id'] = uuid.uuid4().hex[:8]
                    changed = True
            if changed:
                _save_provider_models(provider, models)
            return models

    # Migration depuis l'ancien format texte, si présent.
    legacy = _parse_models(get_config(f'{provider}_models', ''))
    if legacy:
        models = [{'id': uuid.uuid4().hex[:8], 'name': m['name'], 'model': m['model']} for m in legacy]
        _save_provider_models(provider, models)
        return models
    return []


def _save_provider_models(provider, models):
    set_config(f'{provider}_models_json', json.dumps(models, ensure_ascii=False))


def _provider_active(provider):
    if provider == 'groq':
        return bool(get_config('groq_api_key', ''))
    if provider == 'nvidia':
        return bool(get_config('nvidia_api_key', ''))
    if provider == 'ollama':
        return (get_config('ollama_enabled', '1') != '0') and bool(get_config('ollama_url', '') or OLLAMA_DEFAULT_URL)
    return False


def get_all_ai_models():
    """Retourne tous les modèles configurés, tous fournisseurs confondus :
    [{'key': 'groq:abcd1234', 'provider', 'provider_label', 'id', 'name', 'model',
      'active' (le fournisseur est configuré), 'is_default'}, ...].
    Si un fournisseur configuré n'a aucun modèle personnalisé, on retombe sur son
    modèle classique historique pour ne jamais le faire disparaître de la liste."""
    default_key = get_config('ai_default_model', '')

    all_models = []
    for provider in ('groq', 'nvidia', 'ollama'):
        active = _provider_active(provider)
        models = _load_provider_models(provider)
        if not models:
            fallback_model = {
                'groq': get_config('groq_model', '') or GROQ_DEFAULT_MODEL,
                'nvidia': get_config('nvidia_model', '') or NVIDIA_DEFAULT_MODEL,
                'ollama': get_config('ollama_model', '') or OLLAMA_DEFAULT_MODEL,
            }[provider]
            models = [{'id': 'default', 'name': PROVIDER_LABELS[provider], 'model': fallback_model}]
        for m in models:
            key = f"{provider}:{m['id']}"
            all_models.append({
                'key': key,
                'provider': provider,
                'provider_label': PROVIDER_LABELS[provider],
                'id': m['id'],
                'name': m['name'],
                'model': m['model'],
                'active': active,
                'is_default': (key == default_key),
            })

    # Pas de défaut choisi explicitement (ou il pointe vers un modèle supprimé) :
    # le premier modèle d'un fournisseur actif devient le défaut implicite.
    if not any(m['is_default'] for m in all_models):
        for m in all_models:
            if m['active']:
                m['is_default'] = True
                break

    return all_models


GROQ_DEFAULT_PROMPT_TEMPLATE = """Tu es un analyste en cybersécurité spécialisé dans la réponse à incident sur Microsoft 365 / Entra ID (Azure AD).

Voici les journaux collectés pour la boîte {{email}}, ainsi que le résultat d'une analyse heuristique automatique (score de risque {{score}}/10, verdict : {{verdict}}).

Signaux détectés automatiquement :
{{findings}}

Chronologie des événements (connexions et audit, du plus ancien au plus récent) :
{{events}}

Actions de remédiation déjà réalisées par la DSI sur cette boîte :
{{dsi_actions}}

En te basant uniquement sur ces éléments, et en tenant compte de ce que la DSI a déjà fait (ne redemande pas une action déjà réalisée ci-dessus — évalue plutôt si elle est suffisante au vu des signaux observés), réponds en français et de façon structurée :
1. Ce que tu observes concrètement dans ces journaux.
2. Le scénario le plus probable (la boîte est-elle réellement compromise ? Si oui, comment et depuis quand ? Sinon, pourquoi ces signaux sont probablement bénins ?).
3. Ton niveau de confiance dans ce scénario et les éléments qui manquent pour en être sûr.
4. Des recommandations concrètes et priorisées pour l'équipe sécurité, qui complètent (et ne répètent pas) les actions déjà réalisées par la DSI."""

# Nombre maximum d'evenements inclus dans le prompt (les plus recents), et longueur max
# du detail de chaque evenement / de la description de chaque signal : au-dela, le
# prompt devient trop volumineux et declenche des erreurs cote fournisseur IA (requete
# trop grosse, ou quota de tokens/minute depasse — frequent sur les offres gratuites),
# sans apporter d'information supplementaire utile a l'analyse.
AI_MAX_EVENTS_IN_PROMPT = 60
AI_MAX_EVENT_DETAIL_CHARS = 160
AI_MAX_FINDING_DESC_CHARS = 300


def _truncate(text, max_chars):
    text = text or ''
    return text if len(text) <= max_chars else text[:max_chars].rstrip() + '…'


def _render_ai_prompt(template, values):
    """Remplace les paires {{cle}} dans le gabarit par leur valeur. Volontairement pas
    de str.format() : le gabarit est du texte libre parametre par l'admin et peut tres
    bien contenir des accolades simples (extraits de logs, JSON...) qui feraient planter
    .format() avec une KeyError/IndexError."""
    out = template
    for key, val in values.items():
        out = out.replace('{{' + key + '}}', str(val))
    return out


def build_ai_analysis_prompt(bid):
    """Construit le prompt d'analyse IA pour une boite : reutilise l'analyse heuristique
    deja existante (evenements + signaux) plutot que d'exporter les journaux bruts, et
    tronque le tout (nombre d'evenements, longueur des textes) pour rester dans les
    limites de taille/debit des API gratuites tout en gardant un contexte utile."""
    conn = get_db()
    boite = conn.execute('SELECT user_email FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    dsi_action_rows = conn.execute(
        'SELECT action_text, action_at, created_by, created_at FROM dsi_actions WHERE boite_id=? ORDER BY created_at ASC', (bid,)
    ).fetchall()
    conn.close()
    if not boite:
        raise ValueError('Boîte non trouvée')

    analysis = analyze_compromise(bid)
    findings = analysis['findings']
    events = analysis['events']

    findings_text = '\n'.join(
        f"- [{f['severity'].upper()}] {f['title']} — {_truncate(f['description'], AI_MAX_FINDING_DESC_CHARS)}"
        for f in findings
    ) or "Aucun signal détecté par l'analyse automatique."

    shown_events = events[-AI_MAX_EVENTS_IN_PROMPT:]
    events_lines = []
    for e in shown_events:
        status = 'succès' if e['success'] else 'échec'
        events_lines.append(
            f"- {e['timestamp']} [{e['type']}] ({status}) {e['title']} — {_truncate(e['detail'], AI_MAX_EVENT_DETAIL_CHARS)} "
            f"(IP: {e['ip'] or 'N/A'}, pays: {e.get('country') or 'N/A'})")
    events_text = '\n'.join(events_lines) or 'Aucun événement.'
    if len(events) > AI_MAX_EVENTS_IN_PROMPT:
        events_text += f"\n(+{len(events) - AI_MAX_EVENTS_IN_PROMPT} événement(s) plus ancien(s) non affiché(s) pour limiter la taille de l'analyse)"

    # Actions deja realisees par la DSI (saisies manuellement sur la fiche de la boite) :
    # transmises a l'IA pour qu'elle ne re-recommande pas des actions deja effectuees et
    # qu'elle puisse evaluer si la remediation est suffisante au vu des signaux observes.
    dsi_actions_text = '\n'.join(
        f"- {_truncate(a['action_text'], 300)}" + (f" (par {a['created_by']}, {a['created_at']})" if a['created_by'] else '')
        for a in dsi_action_rows
    ) or "Aucune action de remédiation n'a encore été enregistrée par la DSI pour cette boîte."

    template = get_config('groq_prompt_template', '') or GROQ_DEFAULT_PROMPT_TEMPLATE
    return _render_ai_prompt(template, {
        'email': boite['user_email'],
        'score': analysis['score'],
        'verdict': analysis['verdict'],
        'findings': findings_text,
        'events': events_text,
        'dsi_actions': dsi_actions_text,
    }), analysis


def _call_openai_compatible_chat(api_url, api_key, model, prompt, timeout, provider_label):
    """Appelle une API de completion de chat compatible OpenAI (Groq, NVIDIA NIM...) et
    retourne le texte de la reponse. Utilise urllib (comme les autres appels API du
    projet) plutot qu'une dependance supplementaire."""
    import urllib.request
    import urllib.error

    payload = json.dumps({
        'model': model,
        'messages': [{'role': 'user', 'content': prompt}],
        'temperature': 0.3,
        # 2000 coupait parfois la reponse avant la fin (ex: section recommandations
        # manquante) sur une analyse structuree en 4 parties — marge portee a 4000.
        'max_tokens': 4000,
    }).encode('utf-8')

    req = urllib.request.Request(
        api_url, data=payload, method='POST',
        headers={
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            # Certains fournisseurs (dont Groq, derriere Cloudflare) bloquent le
            # User-Agent par defaut d'urllib ("Python-urllib/x.y"), detecte comme un bot
            # (HTTP 403 "error code: 1010"). Un User-Agent classique passe la verification.
            'User-Agent': 'Mozilla/5.0 (compatible; Analyse-Compromis/1.0)',
        })

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        try:
            msg = json.loads(body).get('error', {}).get('message', body)
        except Exception:
            msg = body
        raise RuntimeError(f'Erreur API {provider_label} (HTTP {e.code}) : {msg}')
    except urllib.error.URLError as e:
        raise RuntimeError(f"Erreur réseau vers l'API {provider_label} : {e.reason}")

    choices = data.get('choices') or []
    if not choices:
        raise RuntimeError(f'Réponse {provider_label} vide (aucun choix retourné)')
    choice = choices[0]
    content = choice['message']['content']
    if choice.get('finish_reason') == 'length':
        content += ("\n\n---\n⚠️ **Réponse tronquée** : la limite de longueur de réponse a été atteinte "
                     "avant la fin (une section, probablement les recommandations, peut manquer). "
                     "Relancez l'analyse si besoin.")
    return content


def call_groq_chat(prompt, api_key=None, model=None, timeout=60):
    api_key = api_key or get_config('groq_api_key', '')
    model = model or get_config('groq_model', '') or GROQ_DEFAULT_MODEL
    if not api_key:
        raise RuntimeError("Clé API Groq non configurée")
    return _call_openai_compatible_chat(GROQ_API_URL, api_key, model, prompt, timeout, 'Groq')


def call_nvidia_chat(prompt, api_key=None, model=None, timeout=60):
    api_key = api_key or get_config('nvidia_api_key', '')
    model = model or get_config('nvidia_model', '') or NVIDIA_DEFAULT_MODEL
    if not api_key:
        raise RuntimeError("Clé API NVIDIA non configurée")
    if not model:
        raise RuntimeError("Modèle NVIDIA non configuré")
    return _call_openai_compatible_chat(NVIDIA_API_URL, api_key, model, prompt, timeout, 'NVIDIA')


def call_ollama_chat(prompt, url=None, model=None, timeout=120):
    url = url or get_config('ollama_url', '') or OLLAMA_DEFAULT_URL
    model = model or get_config('ollama_model', '') or OLLAMA_DEFAULT_MODEL
    if not url:
        raise RuntimeError("URL de l'instance Ollama non configurée")
    ollama_api_url = url.rstrip('/') + '/v1/chat/completions'
    return _call_openai_compatible_chat(ollama_api_url, 'ollama', model, prompt, timeout, 'Ollama')


def run_ai_analysis(bid, preferred_model_key=None):
    """Construit le prompt pour la boite et interroge l'IA : essaie d'abord le modèle
    précis choisi par l'utilisateur (ex: 'nvidia:ab12cd34', voir get_all_ai_models), puis
    bascule automatiquement sur le modèle par défaut de chaque autre fournisseur configuré
    en cas d'échec (panne, quota dépassé, clé invalide...). Retourne (texte, fournisseur, modele)."""
    prompt, _analysis = build_ai_analysis_prompt(bid)

    all_models = get_all_ai_models()
    active_models = [m for m in all_models if m['active']]
    if not active_models:
        raise RuntimeError('Aucun fournisseur IA configuré (Groq, NVIDIA ou Ollama)')

    # Ordre d'essai : le modèle demandé en premier (s'il existe et que son fournisseur est
    # actif), puis le premier modèle configuré de chaque autre fournisseur actif, en repli.
    ordered = []
    seen_providers = set()
    if preferred_model_key:
        chosen = next((m for m in active_models if m['key'] == preferred_model_key), None)
        if chosen:
            ordered.append(chosen)
            seen_providers.add(chosen['provider'])
    for provider in ('groq', 'nvidia', 'ollama'):
        if provider in seen_providers:
            continue
        candidates = [m for m in active_models if m['provider'] == provider]
        if not candidates:
            continue
        ordered.append(candidates[0])
        seen_providers.add(provider)

    groq_key = get_config('groq_api_key', '')
    nvidia_key = get_config('nvidia_api_key', '')
    ollama_url = get_config('ollama_url', '') or OLLAMA_DEFAULT_URL

    errors = []
    for m in ordered:
        try:
            if m['provider'] == 'groq':
                return call_groq_chat(prompt, api_key=groq_key, model=m['model']), 'Groq', m['model']
            elif m['provider'] == 'nvidia':
                return call_nvidia_chat(prompt, api_key=nvidia_key, model=m['model']), 'NVIDIA', m['model']
            elif m['provider'] == 'ollama':
                return call_ollama_chat(prompt, url=ollama_url, model=m['model']), 'Ollama', m['model']
        except Exception as e:
            errors.append(f"{m['provider_label']} ({m['name']}) : {e}")

    raise RuntimeError(' / '.join(errors))


def quick_scan_mailbox(user_upn, days=7, on_step=None):
    """Scan rapide et EPHEMERE d'une boite via Microsoft Graph (rien n'est ecrit en base) :
    recupere connexions + journal d'audit + regles de messagerie sur les N derniers jours,
    et applique la meme analyse heuristique que pour une boite deja suivie.

    Chaque source est recuperee independamment : si l'une d'elles echoue (timeout reseau,
    permission manquante...), le scan continue avec les autres plutot que d'echouer
    entierement — le resultat indique alors quelles sources n'ont pas pu etre lues
    (cle 'errors'), et le score/verdict restent calcules sur les donnees disponibles.

    `on_step(step_name, state)` est appele (si fourni) avant/apres chaque source, avec
    state parmi 'running'/'done'/'error', pour permettre un affichage de progression."""
    from datetime import datetime, timedelta, timezone
    import urllib.parse

    def notify(step, state):
        if on_step:
            try:
                on_step(step, state)
            except Exception:
                pass

    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')
    upn_escaped = (user_upn or '').replace("'", "''")
    errors = []

    signin_dicts = []
    notify('signins', 'running')
    try:
        signin_items = graph_get_all('/auditLogs/signIns', params={
            '$filter': f"userPrincipalName eq '{upn_escaped}' and createdDateTime ge {since}", '$top': '500'})
        signin_dicts = [_map_graph_signin(it) for it in signin_items]
        notify('signins', 'done')
    except Exception as e:
        errors.append(f'Connexions : {e}')
        notify('signins', 'error')

    # Filtre serveur sur l'initiateur (rapide et fiable) : capte le scenario le plus frequent
    # d'une boite compromise, l'attaquant agissant via la session de l'utilisateur lui-meme.
    # Les actions effectuees SUR l'utilisateur par un tiers (ex: reinitialisation de mot de
    # passe par un admin) ne sont pas filtrables efficacement cote serveur et ne sont donc
    # pas incluses ici (elles restent visibles via "Récupérer via Microsoft Graph" sur la
    # fiche de la boite, une fois celle-ci creee, qui fait une recherche plus large).
    audit_dicts = []
    notify('audit', 'running')
    try:
        audit_items = graph_get_all('/auditLogs/directoryAudits', params={
            '$filter': f"activityDateTime ge {since} and initiatedBy/user/userPrincipalName eq '{upn_escaped}'",
            '$top': '500'})
        audit_dicts = [_map_graph_audit(it) for it in audit_items]
        notify('audit', 'done')
    except Exception as e:
        errors.append(f"Journal d'audit : {e}")
        notify('audit', 'error')

    rule_dicts = []
    suspicious_rules = []
    notify('rules', 'running')
    try:
        encoded_upn = urllib.parse.quote(user_upn or '')
        rule_items = graph_get_all(f'/users/{encoded_upn}/mailFolders/inbox/messageRules')
        rule_dicts = [_map_graph_rule(it) for it in rule_items]
        suspicious_rules = [r for r in rule_dicts if r['is_suspicious'] == 'true']
        notify('rules', 'done')
    except Exception as e:
        if not _is_no_mailbox_error(e):
            errors.append(f'Règles de messagerie : {e}')
        notify('rules', 'done')

    if len(errors) == 3:
        # Les 3 sources ont echoue : remonter une vraie erreur plutot qu'un scan "propre" trompeur
        # (une liste vide peut aussi, legitimement, signifier "aucun evenement sur la periode").
        raise RuntimeError(' / '.join(errors))

    owner_domain = user_upn.split('@')[-1] if user_upn and '@' in user_upn else ''
    events = build_timeline_events(signin_dicts, audit_dicts)
    analysis = analyze_compromise_events(events, suspicious_rules=suspicious_rules, owner_domain=owner_domain)
    analysis['nb_signins'] = len(signin_dicts)
    analysis['nb_audit'] = len(audit_dicts)
    analysis['nb_rules'] = len(rule_dicts)
    analysis['user_upn'] = user_upn
    analysis['days'] = days
    analysis['errors'] = errors
    return analysis


@app.route('/boite/<int:bid>/timeline')
def view_timeline(bid):
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    conn.close()
    if not boite:
        flash('Boîte non trouvée')
        return redirect(url_for('list_boites'))

    analysis = analyze_compromise(bid)
    return render_template('timeline.html', boite=boite, **analysis)


# Palette de couleurs stable pour distinguer les boites sur la timeline croisee
CROSS_TIMELINE_COLORS = ['#0d6efd', '#dc3545', '#198754', '#fd7e14', '#6f42c1', '#20c997', '#d63384', '#0dcaf0']


@app.route('/timeline/cross', methods=['GET', 'POST'])
def cross_timeline():
    conn = get_db()
    all_boites = conn.execute('SELECT id, user_email FROM boites_compromises ORDER BY user_email').fetchall()
    conn.close()

    if request.method == 'POST':
        selected_ids = sorted(set(int(i) for i in request.form.getlist('boite_ids') if i.isdigit()))
    else:
        ids_param = request.args.get('ids', '')
        selected_ids = sorted(set(int(i) for i in ids_param.split(',') if i.strip().isdigit()))

    events, findings, boites, colors = None, None, None, {}
    if len(selected_ids) >= 2:
        events, boites = build_cross_timeline(selected_ids)
        findings = analyze_cross_boite_signals(events, boites, selected_ids)
        colors = {bid: CROSS_TIMELINE_COLORS[i % len(CROSS_TIMELINE_COLORS)] for i, bid in enumerate(selected_ids)}
    elif request.method == 'POST':
        flash('Sélectionnez au moins 2 boîtes pour croiser leurs timelines')

    return render_template('cross_timeline.html', all_boites=all_boites, selected_ids=selected_ids,
                         events=events, findings=findings, boites=boites, colors=colors)


@app.route('/boite/<int:bid>/signins')
def view_signins(bid):
    conn = get_db()
    try:
        boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
        if not boite:
            flash('Boîte non trouvée')
            return redirect(url_for('list_boites'))

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

        # Une connexion "reussie" dont le MFA a echoue (meme correlation_id, ou meme
        # utilisateur/IP a quelques instants d'ecart) n'est pas un succes sans reserve.
        mfa_linkage = _compute_mfa_linkage(signins)
        mfa_linked_failure_ids = set()
        for s in signins:
            if _is_success_status(s['status']):
                key = s['request_id'] or id(s)
                if mfa_linkage.get(key, {}).get('linked'):
                    mfa_linked_failure_ids.add(s['id'])

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
                         timeline=timeline, first_signin=first_signin, last_signin=last_signin,
                         mfa_linked_failure_ids=mfa_linked_failure_ids)


@app.route('/signin/<int:signin_id>')
def view_signin_detail(signin_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM signin_logs WHERE id=?', (signin_id,)).fetchone()
    conn.close()
    if not row:
        flash('Connexion non trouvée')
        return redirect(url_for('list_boites'))
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
            return redirect(url_for('list_boites'))

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
        return redirect(url_for('list_boites'))
    try:
        raw = json.loads(row['raw_json']) if row['raw_json'] else {}
    except Exception:
        raw = {}
    return render_template('raw_detail.html', row=row, raw=raw,
                         title=f"Événement d'audit #{row['id']} - {row['activite']}",
                         subtitle=row['date_utc'],
                         back_url=url_for('view_audit', bid=row['boite_id']),
                         back_label="Retour au journal d'audit")


@app.route('/quick-scan/start', methods=['POST'])
def quick_scan_start():
    """Demarre un scan rapide en tache de fond et retourne immediatement un identifiant
    de job ; la progression (par source : connexions/audit/regles) est ensuite consultee
    via /jobs/<job_id>/poll pour afficher une vraie barre de progression cote client."""
    email = request.form.get('email', '').strip()
    if not email or '@' not in email:
        return jsonify({'error': 'Adresse email invalide pour le scan rapide'}), 400
    try:
        days = max(1, min(int(request.form.get('days', '7')), 90))
    except ValueError:
        days = 7

    job_id = _job_create(['signins', 'audit', 'rules'])

    def worker():
        try:
            result = quick_scan_mailbox(email, days, on_step=lambda s, st: _job_step(job_id, s, st))
            add_log('INFO', 'GRAPH', f'Scan rapide effectué pour {email}',
                    f"score {result['score']}/10, verdict {result['verdict']}, {len(result['findings'])} signal(aux)")
            conn = get_db()
            row = conn.execute('SELECT id FROM boites_compromises WHERE user_email=? ORDER BY id DESC LIMIT 1', (email,)).fetchone()
            conn.close()
            payload = {'email': email, 'existing_boite_id': row['id'] if row else None, **result}
            _job_finish(job_id, redirect=f'/quick-scan/result/{job_id}', result=payload)
        except Exception as e:
            add_log('ERROR', 'GRAPH', f'Échec du scan rapide pour {email}', str(e))
            _job_finish(job_id, error=f"Erreur lors du scan rapide via Microsoft Graph : {e}")

    threading.Thread(target=worker, daemon=True, name=f'quick-scan-{job_id[:8]}').start()
    return jsonify({'job_id': job_id})


@app.route('/quick-scan/result/<job_id>')
def quick_scan_result_page(job_id):
    job = _job_get(job_id)
    if not job or job['status'] != 'done' or not job.get('result'):
        flash('Résultat du scan introuvable ou expiré — relancez une analyse rapide')
        return redirect(url_for('list_boites'))
    return render_template('quick_scan_result.html', **job['result'])


@app.route('/jobs/<job_id>/poll')
def poll_job(job_id):
    """Etat courant d'un job en arriere-plan (scan rapide, import Microsoft Graph...),
    pour affichage d'une barre de progression cote client."""
    job = _job_get(job_id)
    if not job:
        return jsonify({'status': 'not_found'}), 404
    return jsonify({'status': job['status'], 'steps': job['steps'], 'order': job['order'],
                     'error': job['error'], 'redirect': job['redirect']})


@app.route('/quick-scan/create', methods=['POST'])
def quick_scan_create():
    email = request.form.get('email', '').strip()
    if not email or '@' not in email:
        flash('Adresse email invalide')
        return redirect(url_for('list_boites'))
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
        if not _is_no_mailbox_error(e):
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
import uuid

# ============================================================================
# Jobs en arriere-plan : execute une action longue (appels Microsoft Graph) dans un
# thread separe et expose sa progression etape par etape, pour que la page puisse
# afficher une vraie barre de progression (et pas un simple spinner "ca charge")
# pendant que la requete HTTP initiale revient immediatement avec un identifiant de job.
# Stockage en memoire (process unique, waitress/reloader) : suffisant pour un outil
# interne mono-instance ; les jobs termines sont purges au bout de quelques minutes.
# ============================================================================

_bg_jobs = {}
_bg_jobs_lock = threading.Lock()
_BG_JOB_TTL_SECONDS = 900


def _job_create(steps):
    """Cree un nouveau job avec la liste ordonnee des etapes (cles techniques, ex:
    ['signins', 'audit', 'rules']), toutes initialement 'pending'. Retourne son id."""
    job_id = uuid.uuid4().hex
    with _bg_jobs_lock:
        # Purge legere des jobs perimes a chaque creation
        now = _time.time()
        for jid in [j for j, v in _bg_jobs.items() if now - v['created_at'] > _BG_JOB_TTL_SECONDS]:
            del _bg_jobs[jid]
        _bg_jobs[job_id] = {
            'steps': {s: 'pending' for s in steps},
            'order': list(steps),
            'status': 'running',
            'error': None,
            'result': None,
            'redirect': None,
            'created_at': now,
        }
    return job_id


def _job_step(job_id, step, state):
    """Met a jour l'etat d'une etape : 'pending' | 'running' | 'done' | 'error'."""
    with _bg_jobs_lock:
        job = _bg_jobs.get(job_id)
        if job:
            job['steps'][step] = state


def _job_finish(job_id, redirect=None, error=None, result=None):
    with _bg_jobs_lock:
        job = _bg_jobs.get(job_id)
        if job:
            job['status'] = 'error' if error else 'done'
            job['error'] = error
            job['redirect'] = redirect
            job['result'] = result


def _job_get(job_id):
    with _bg_jobs_lock:
        return _bg_jobs.get(job_id)


_monitoring_thread_started = False
_monitoring_lock = threading.Lock()

# Fenetre d'analyse (en jours) utilisee par chaque scan periodique de surveillance.
# Doit correspondre a ce que l'analyse rapide utilise par defaut (7 jours) : une fenetre
# plus courte (ex: 1 jour) faisait manquer des signaux plus anciens que la derniere
# execution du planificateur, donnant un score incoherent avec un scan rapide manuel
# portant sur la meme boite.
MONITORING_SCAN_WINDOW_DAYS = 7

# Seuil de score (sur 10, voir compute_risk_score) au-dela duquel un scan de surveillance
# declenche une alerte Teams — 5 par defaut, mais reglable par un administrateur depuis
# Configuration (voir get_teams_alert_threshold ci-dessous et le POST /config).
TEAMS_ALERT_SCORE_THRESHOLD_DEFAULT = 5


def get_teams_alert_threshold():
    """Seuil configure par un administrateur (config 'teams_alert_score_threshold'), avec
    repli sur TEAMS_ALERT_SCORE_THRESHOLD_DEFAULT si absent ou invalide."""
    raw = get_config('teams_alert_score_threshold', '').strip()
    try:
        value = int(raw)
        if 0 <= value <= 10:
            return value
    except ValueError:
        pass
    return TEAMS_ALERT_SCORE_THRESHOLD_DEFAULT

VERDICT_LABELS = {
    'compromise_likely': 'Compromission probable',
    'signals_to_check': 'Signaux à vérifier',
    'no_strong_signal': 'RAS',
}


def send_teams_alert(email, score, verdict, findings_summary, mailbox_id=None, boite_id=None):
    """Poste une carte d'alerte dans le canal Microsoft Teams configure (webhook entrant,
    cle 'teams_webhook_url') quand une boite surveillee bascule en compromission probable
    (score > seuil configurable, voir get_teams_alert_threshold). Ne fait rien si aucune URL n'est configuree.
    Utilise le format "MessageCard" classique des webhooks entrants Teams (Office 365
    Connector) — pas de dependance externe (urllib.request, comme le reste de l'appli).
    Si `boite_id` est fourni (fiche d'incident deja creee/instruite par
    escalate_to_incident), le lien pointe directement dessus ; sinon, a defaut de fiche,
    vers la page de surveillance generale (`mailbox_id`, dans monitored_mailboxes, n'est
    alors utilise que pour le contexte, pas pour construire un lien)."""
    import urllib.request
    import urllib.error

    webhook_url = get_config('teams_webhook_url', '').strip()
    if not webhook_url:
        return False

    verdict_label = VERDICT_LABELS.get(verdict, verdict or 'Inconnu')
    lien = None
    base = get_config('public_base_url', '').strip().rstrip('/')
    try:
        path = url_for('view_boite', bid=boite_id) if boite_id is not None else url_for('view_monitoring')
        lien = (base + path) if base else path
    except Exception:
        lien = None

    text_lines = [
        f"**Boîte concernée : {email}**",
        f"Score de risque : **{score}/10** — {verdict_label}",
    ]
    if findings_summary:
        text_lines.append(f"Signaux détectés : {findings_summary}")
    if lien:
        text_lines.append(f"[{'Voir la fiche de la boîte' if boite_id is not None else 'Voir la page de surveillance'}]({lien})")

    payload = {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        'summary': f"Alerte compromission : {email}",
        'themeColor': 'D9534F' if verdict == 'compromise_likely' else 'F0AD4E',
        'title': f"🚨 Alerte compromission — {email}",
        'text': '\n\n'.join(text_lines),
    }

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            response.read()
        add_log('WARNING', 'TEAMS', f"Alerte Teams envoyée pour {email} (score {score}/10)", findings_summary)
        return True
    except Exception as e:
        add_log('ERROR', 'TEAMS', f"Échec de l'envoi de l'alerte Teams pour {email}", str(e))
        return False


def escalate_to_incident(email, score, verdict, findings_summary):
    """Quand une boite surveillee bascule en compromission probable (score >
    get_teams_alert_threshold()), transforme automatiquement l'alerte en debut
    d'investigation complete : cree (ou reutilise) la fiche d'incident correspondante,
    importe via Microsoft Graph tout ce qu'importe manuellement un analyste (connexions,
    journal d'audit, regles de messagerie ET messages envoyes), lance l'analyse IA si un
    fournisseur est configure, puis poste l'alerte Teams avec le lien direct vers cette
    fiche deja instruite plutot que vers la page de surveillance generale.

    Volontairement synchrone (pas de job en tache de fond) : cette fonction ne s'execute
    que depuis le planificateur de surveillance, deja lui-meme dans un thread dedie."""
    conn = get_db()
    existing = conn.execute(
        'SELECT id FROM boites_compromises WHERE user_email=? ORDER BY created_at DESC LIMIT 1', (email,)
    ).fetchone()
    if existing:
        bid = existing['id']
        conn.close()
    else:
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        notes = (f"Fiche créée automatiquement suite à une alerte de surveillance "
                 f"(score {score}/10, {VERDICT_LABELS.get(verdict, verdict)}).")
        conn.execute('''INSERT INTO boites_compromises
            (user_email, date_compromission, heure_compromission, date_decouverte, notes)
            VALUES (?, ?, ?, ?, ?)''', (email, '', '', today, notes))
        conn.commit()
        bid = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()
        add_log('WARNING', 'MONITORING', f"Fiche d'incident créée automatiquement pour {email}", notes, bid)

    # Import complet via Microsoft Graph (mêmes sources que "Récupérer via Microsoft
    # Graph" sur la fiche de la boîte, messages envoyés inclus).
    days = MONITORING_SCAN_WINDOW_DAYS
    summary, errors = [], []
    try:
        c, d = fetch_sent_messages_from_graph(bid, email, days)
        summary.append(f'{c} message(s) envoyé(s) ({d} doublon(s) ignoré(s))')
    except Exception as e:
        errors.append(f'Messages envoyés : {e}')
    try:
        c, d = fetch_signins_from_graph(bid, email, days)
        summary.append(f'{c} connexion(s) ({d} doublon(s) ignoré(s))')
    except Exception as e:
        errors.append(f'Connexions : {e}')
    try:
        c, d = fetch_audit_from_graph(bid, email, days)
        summary.append(f"{c} événement(s) d'audit ({d} doublon(s) ignoré(s))")
    except Exception as e:
        errors.append(f"Journal d'audit : {e}")
    try:
        c = fetch_inbox_rules_from_graph(bid, email)
        summary.append(f'{c} règle(s) de messagerie')
    except Exception as e:
        if not _is_no_mailbox_error(e):
            errors.append(f'Règles de messagerie : {e}')
    if summary:
        add_log('INFO', 'GRAPH', f'Import Microsoft Graph (auto) pour {email}', ', '.join(summary), bid)
    for err in errors:
        add_log('ERROR', 'GRAPH', f'Erreur import Microsoft Graph (auto) pour {email}', err, bid)

    # Analyse IA, si un fournisseur (Groq ou NVIDIA) est configure.
    if get_config('groq_api_key', '') or get_config('nvidia_api_key', ''):
        try:
            result_text, provider, model = run_ai_analysis(bid)
            now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            conn = get_db()
            conn.execute('''UPDATE boites_compromises SET
                ai_analysis=?, ai_analysis_at=?, ai_analysis_model=?, ai_analysis_provider=? WHERE id=?''',
                (result_text, now_iso, model, provider, bid))
            conn.commit()
            conn.close()
            add_log('INFO', 'IA', f"Analyse IA (auto) effectuée pour {email}", f'Fournisseur : {provider}, modèle : {model}', bid)
        except Exception as e:
            add_log('ERROR', 'IA', f"Échec de l'analyse IA (auto) pour {email}", str(e), bid)

    # Score/verdict recalcules sur les donnees fraichement importees dans la fiche (peuvent
    # differer legerement du scan rapide ephemere initial, qui ne portait que sur une
    # fenetre glissante sans les messages envoyes).
    analysis = analyze_compromise(bid)
    send_teams_alert(email, analysis['score'], analysis['verdict'], findings_summary, boite_id=bid)
    return bid


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

        result = quick_scan_mailbox(email, days=MONITORING_SCAN_WINDOW_DAYS)
        partial_note = ('Scan partiel : ' + ' / '.join(result['errors'])) if result.get('errors') else None

        findings = result['findings']
        max_shown = 8
        findings_summary = ' | '.join(f"[{f['severity'].upper()}] {f['title']}" for f in findings[:max_shown]) or None
        if findings_summary and len(findings) > max_shown:
            findings_summary += f' | (+{len(findings) - max_shown} autre(s))'

        conn.execute('''UPDATE monitored_mailboxes SET
            last_scan_at=?, last_scan_score=?, last_scan_verdict=?, last_scan_findings_count=?,
            last_scan_findings_summary=?, last_error=?
            WHERE id=?''',
            (now_iso, result['score'], result['verdict'], len(findings), findings_summary, partial_note, mailbox_row['id']))
        conn.commit()

        # Escalade automatique : seulement quand la boite "devient" compromise (transition
        # vers un score > seuil), pas a chaque scan tant qu'elle le reste deja — sinon une
        # nouvelle fiche/import/analyse IA serait relancee et un message Teams renvoye a
        # chaque passage. Cree la fiche d'incident, importe tout via Graph (avec messages),
        # lance l'analyse IA, puis alerte Teams avec le lien direct vers la fiche.
        threshold = get_teams_alert_threshold()
        previous_score = mailbox_row['last_scan_score']
        was_already_over_threshold = previous_score is not None and previous_score > threshold
        if result['score'] > threshold and not was_already_over_threshold:
            escalate_to_incident(email, result['score'], result['verdict'], findings_summary)

        level = 'WARNING' if (result['score'] >= 6 or partial_note) else 'INFO'
        details = f"{len(result['findings'])} signal(aux) détecté(s) sur les dernières 24h"
        if partial_note:
            details += f' — {partial_note}'
        add_log(level, 'MONITORING',
                f"Scan de surveillance pour {email} : score {result['score']}/10 ({result['verdict']})",
                details)
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


# Intervalle de rafraichissement du monitoring "connexions tenant" (voir /connexions) et
# duree de conservation des lignes recuperees, au-dela de laquelle elles sont purgees pour
# eviter une croissance illimitee de la table (ce flux n'est pas rattache a une boite
# precise, contrairement a signin_logs — c'est un instantane glissant, pas un historique
# d'investigation). Valeurs par defaut, reglables par un administrateur depuis la page
# /connexions — voir get_tenant_signins_refresh_minutes/get_tenant_signins_retention_hours.
TENANT_SIGNINS_REFRESH_MINUTES_DEFAULT = 5
TENANT_SIGNINS_RETENTION_HOURS_DEFAULT = 48


def get_tenant_signins_refresh_minutes():
    raw = get_config('tenant_signins_refresh_minutes', '').strip()
    try:
        value = int(raw)
        if 1 <= value <= 1440:
            return value
    except ValueError:
        pass
    return TENANT_SIGNINS_REFRESH_MINUTES_DEFAULT


def get_tenant_signins_retention_hours():
    raw = get_config('tenant_signins_retention_hours', '').strip()
    try:
        value = int(raw)
        if 1 <= value <= 24 * 30:
            return value
    except ValueError:
        pass
    return TENANT_SIGNINS_RETENTION_HOURS_DEFAULT


# Pays de reference ("chez nous") pour le score de confiance des connexions — par defaut la
# France, reglable depuis /connexions. Une connexion depuis ce pays n'est pas penalisee sur
# le critere geographique ; le reste du monde est note par palier de proximite.
HOME_COUNTRY_CODE_DEFAULT = 'FR'

# Pays d'Europe (UE/EEE + Royaume-Uni + Suisse + Norvege/Islande/Liechtenstein), code
# ISO 3166-1 alpha-2 : une connexion depuis l'un de ces pays (hors pays de reference) est
# consideree moyennement proche geographiquement — ni "chez nous", ni "loin".
EUROPE_COUNTRY_CODES = {
    'FR', 'DE', 'BE', 'NL', 'LU', 'IT', 'ES', 'PT', 'IE', 'AT', 'DK', 'SE', 'FI', 'PL',
    'CZ', 'SK', 'HU', 'RO', 'BG', 'GR', 'HR', 'SI', 'EE', 'LV', 'LT', 'CY', 'MT',
    'GB', 'CH', 'NO', 'IS', 'LI',
}


def get_home_country_code():
    raw = get_config('home_country_code', '').strip().upper()
    return raw if len(raw) == 2 else HOME_COUNTRY_CODE_DEFAULT


def compute_connection_trust_score(ip_payload, country_code, home=None):
    """Score de confiance 0-100 pour une connexion, combinant trois signaux :
    1. IP de confiance declaree (Ville...) : 100%, point final — c'est une IP connue.
    2. Proximite geographique du pays de connexion par rapport au pays de reference
       (voir get_home_country_code) : pays de reference > reste de l'Europe > ailleurs.
    3. Reputation de l'IP (VPN/proxy/Tor detecte, score d'abus AbuseIPDB) : penalise le
       score de base determine par la geographie.
    `ip_payload` est le dict retourne par ip_reputation_payload (peut etre None si la
    reputation n'a pas pu etre determinee — dans ce cas, seule la geographie compte).
    `home` permet de fournir le pays de reference deja resolu (evite une requete de
    configuration par appel quand on calcule le score en boucle)."""
    if ip_payload and ip_payload.get('is_trusted'):
        return 100

    cc = (country_code or '').strip().upper()
    home = home or get_home_country_code()
    if cc and cc == home:
        score = 90
    elif cc in EUROPE_COUNTRY_CODES:
        score = 60
    elif cc:
        score = 30
    else:
        score = 50  # pays inconnu/non renseigne : ni penalise a fond, ni traite comme fiable

    if ip_payload:
        if ip_payload.get('is_vpn'):
            score -= 25
        level = ip_payload.get('level')
        if level == 'orange':
            score -= 10
        elif level == 'red':
            score -= 40

    return max(0, min(100, score))


def refresh_tenant_signins():
    """Recupere TOUTES les connexions du tenant (reussies et echouees, tous utilisateurs
    confondus) depuis le dernier passage, en un seul appel Microsoft Graph pagine (pas de
    filtre par utilisateur) — a la difference du scan par boite qui doit interroger chaque
    utilisateur individuellement. Deduplique par request_id (identifiant Graph de
    l'evenement), purge les lignes plus vieilles que get_tenant_signins_retention_hours() heures."""
    from datetime import timedelta

    now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
    last_iso = get_config('tenant_signins_last_fetch_at', '')
    last_dt = _parse_iso(last_iso) if last_iso else None
    if last_dt:
        # Les connexions apparaissent avec un DELAI D'INGESTION dans auditLogs/signIns
        # (journalise jusqu'a ~2h apres l'evenement reel). Une marge de 10 minutes ne
        # suffit pas : une connexion arrivee dans l'API apres que le since soit reparti
        # serait PERDUE DEFINITIVEMENT. On repart donc 3h en arriere a chaque passage,
        # et la contrainte UNIQUE sur request_id deduplique sans risque de doublon.
        since_dt = last_dt - timedelta(hours=3)
    else:
        since_dt = now_dt - timedelta(hours=3)
    since = since_dt.strftime('%Y-%m-%dT%H:%M:%SZ')

    items = graph_get_all('/auditLogs/signIns', params={
        '$filter': f'createdDateTime ge {since}', '$top': '999'}, timeout=45, max_pages=25)
    mapped = [_map_graph_signin(it) for it in items]

    fetched_at = now_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    conn = get_db()
    before = conn.total_changes
    for m in mapped:
        conn.execute('''INSERT OR IGNORE INTO tenant_signins
            (request_id, date_utc, user_upn, user_display_name, ip_address, location, city, country,
             lat, lon, status, error_code, failure_reason, application, client_app, mfa_result, flagged, fetched_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (m['request_id'], m['date_utc'], m['user_upn'], m['user_display_name'], m['ip_address'],
             m['location'], m.get('city', ''), m['country'], m.get('lat'), m.get('lon'),
             m['status'], m['error_code'], m['failure_reason'],
             m['application'], m['client_app'], m['mfa_result'], m['flagged'], fetched_at))
    new_rows = conn.total_changes - before

    cutoff = (now_dt - timedelta(hours=get_tenant_signins_retention_hours())).strftime('%Y-%m-%dT%H:%M:%SZ')
    conn.execute('DELETE FROM tenant_signins WHERE date_utc < ?', (cutoff,))
    conn.commit()
    conn.close()

    set_config('tenant_signins_last_fetch_at', fetched_at)
    add_log('INFO', 'TENANT_SIGNINS',
            f'{new_rows} nouvelle(s) connexion(s) (tenant complet, {len(mapped)} récupérée(s))',
            f'depuis {since}')
    return new_rows


# ============================================================================
# Scan des regles de messagerie de TOUTES les boites du tenant (/monitoring/rules) : a la
# demande, ou periodiquement si active (voir get_tenant_rules_scan_enabled). Contrairement
# aux connexions (refresh_tenant_signins, un seul appel Graph tenant-wide), il n'existe pas
# d'endpoint tenant-wide pour les regles de messagerie : chaque compte doit etre interroge
# individuellement (/users/{upn}/mailFolders/inbox/messageRules), ce qui peut prendre
# plusieurs minutes sur un tenant de grande taille — execute donc toujours dans un thread
# dedie (jamais dans la boucle du planificateur elle-meme), avec suivi de progression dans
# tenant_rule_scans pour que /monitoring/rules puisse afficher une barre de progression.
# ============================================================================

TENANT_RULES_SCAN_INTERVAL_MINUTES_DEFAULT = 360  # 6h : un scan complet interroge chaque
# compte individuellement, contrairement aux connexions — intervalle par defaut plus long
# pour limiter la charge sur Microsoft Graph.
TENANT_RULES_SCAN_RETENTION = 10  # nombre de scans (et leurs regles) conserves en base

_tenant_rules_scan_lock = threading.Lock()
_tenant_rules_scan_running = False


def get_tenant_rules_scan_enabled():
    return get_config('tenant_rules_scan_enabled', 'false') == 'true'


def get_tenant_rules_scan_interval_minutes():
    raw = get_config('tenant_rules_scan_interval_minutes', '').strip()
    try:
        value = int(raw)
        if 30 <= value <= 10080:
            return value
    except ValueError:
        pass
    return TENANT_RULES_SCAN_INTERVAL_MINUTES_DEFAULT


def _latest_suspicious_rule_keys():
    """Cle (user_upn::rule_id) de chaque regle suspecte trouvee lors du dernier scan
    tenant TERMINE — sert a reperer les regles NOUVELLEMENT suspectes d'un scan a l'autre
    (voir scan_tenant_mailbox_rules) pour ne relever/alerter que les vraies nouveautes."""
    conn = get_db()
    prev = conn.execute("SELECT id FROM tenant_rule_scans WHERE status='done' ORDER BY id DESC LIMIT 1").fetchone()
    if not prev:
        conn.close()
        return set()
    rows = conn.execute(
        "SELECT user_upn, rule_id FROM tenant_mailbox_rules WHERE scan_id=? AND is_suspicious='true'",
        (prev['id'],)).fetchall()
    conn.close()
    return {f"{r['user_upn']}::{r['rule_id']}" for r in rows}


def send_teams_rule_alert(new_suspicious):
    """Poste une alerte Teams quand un scan tenant des regles de messagerie decouvre de
    NOUVELLES regles suspectes (absentes du scan precedent) — reutilise le webhook deja
    configure pour les alertes de compromission (cle 'teams_webhook_url', voir
    send_teams_alert). `new_suspicious` : liste de tuples (upn, display_name, rule_dict)."""
    import urllib.request

    webhook_url = get_config('teams_webhook_url', '').strip()
    if not webhook_url:
        return False

    lines = []
    for upn, display_name, d in new_suspicious[:10]:
        who = display_name or upn
        detail = f"transfert vers {d['forwards_to']}" if d['forwards_to'] else (d['actions_summary'] or '')
        lines.append(f"- **{who}** ({upn}) : « {d['display_name']} » — {detail}")
    if len(new_suspicious) > 10:
        lines.append(f"- (+{len(new_suspicious) - 10} autre(s))")

    base = get_config('public_base_url', '').strip().rstrip('/')
    try:
        path = url_for('view_tenant_rules')
        lien = (base + path) if base else path
    except Exception:
        lien = None

    text = (f"**{len(new_suspicious)} nouvelle(s) règle(s) de messagerie suspecte(s) détectée(s) "
            f"sur le tenant**\n\n" + '\n'.join(lines))
    if lien:
        text += f"\n\n[Voir le détail]({lien})"

    payload = {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        'summary': f'{len(new_suspicious)} règle(s) de messagerie suspecte(s)',
        'themeColor': 'D9534F',
        'title': '🚨 Règle(s) de messagerie suspecte(s) détectée(s)',
        'text': text,
    }
    try:
        req = urllib.request.Request(
            webhook_url, data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(req, timeout=10) as response:
            response.read()
        add_log('WARNING', 'TEAMS', f"Alerte Teams envoyée ({len(new_suspicious)} nouvelle(s) règle(s) suspecte(s))")
        return True
    except Exception as e:
        add_log('ERROR', 'TEAMS', "Échec de l'envoi de l'alerte Teams (règles suspectes)", str(e))
        return False


def scan_tenant_mailbox_rules(triggered_by='scheduler'):
    """Parcourt TOUS les comptes actifs du tenant et recupere leurs regles de messagerie
    (boite de reception) via Microsoft Graph, un compte a la fois. Remplace entierement
    l'instantane precedent en creant un nouveau scan (tenant_rule_scans +
    tenant_mailbox_rules) ; les scans au-dela de TENANT_RULES_SCAN_RETENTION sont purges.
    Alerte Teams (send_teams_rule_alert) sur toute regle suspecte NOUVELLE par rapport au
    scan precedent. Ne fait rien (retourne None) si un scan est deja en cours."""
    global _tenant_rules_scan_running
    with _tenant_rules_scan_lock:
        if _tenant_rules_scan_running:
            return None
        _tenant_rules_scan_running = True

    try:
        now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        conn = get_db()
        conn.execute("INSERT INTO tenant_rule_scans (started_at, status, triggered_by) VALUES (?, 'running', ?)",
                     (now_iso, triggered_by))
        conn.commit()
        scan_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()

        previous_suspicious = _latest_suspicious_rule_keys()

        try:
            users = graph_list_tenant_mailbox_users()
            conn = get_db()
            conn.execute('UPDATE tenant_rule_scans SET total_accounts=? WHERE id=?', (len(users), scan_id))
            conn.commit()
            conn.close()

            scanned, with_rules, suspicious_count, error_count = 0, 0, 0, 0
            new_suspicious = []
            for u in users:
                upn = u['userPrincipalName']
                try:
                    items = graph_get_all(f'/users/{_graph_quote(upn)}/mailFolders/inbox/messageRules',
                                           timeout=20, max_pages=5, retries=0)
                    if items:
                        with_rules += 1
                        conn = get_db()
                        for item in items:
                            d = _map_graph_rule(item)
                            conn.execute('''INSERT INTO tenant_mailbox_rules
                                (scan_id, user_upn, user_display_name, rule_id, display_name, is_enabled,
                                 sequence, conditions_summary, actions_summary, forwards_to, is_suspicious, raw_json)
                                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                                (scan_id, upn, u.get('displayName', ''), d['rule_id'], d['display_name'],
                                 d['is_enabled'], d['sequence'], d['conditions_summary'], d['actions_summary'],
                                 d['forwards_to'], d['is_suspicious'], json.dumps(item, ensure_ascii=False)))
                            if d['is_suspicious'] == 'true':
                                suspicious_count += 1
                                key = f"{upn}::{d['rule_id']}"
                                if key not in previous_suspicious:
                                    new_suspicious.append((upn, u.get('displayName', ''), d))
                        conn.commit()
                        conn.close()
                except Exception as e:
                    if not _is_no_mailbox_error(e):
                        error_count += 1
                scanned += 1
                if scanned % 10 == 0 or scanned == len(users):
                    conn = get_db()
                    conn.execute('UPDATE tenant_rule_scans SET scanned_accounts=? WHERE id=?', (scanned, scan_id))
                    conn.commit()
                    conn.close()

            finished_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            conn = get_db()
            conn.execute('''UPDATE tenant_rule_scans SET finished_at=?, status='done', scanned_accounts=?,
                accounts_with_rules=?, suspicious_count=?, error_count=? WHERE id=?''',
                (finished_iso, scanned, with_rules, suspicious_count, error_count, scan_id))
            old_ids = [r['id'] for r in conn.execute(
                'SELECT id FROM tenant_rule_scans ORDER BY id DESC LIMIT -1 OFFSET ?',
                (TENANT_RULES_SCAN_RETENTION,)).fetchall()]
            if old_ids:
                placeholders = ','.join('?' * len(old_ids))
                conn.execute(f'DELETE FROM tenant_mailbox_rules WHERE scan_id IN ({placeholders})', old_ids)
                conn.execute(f'DELETE FROM tenant_rule_scans WHERE id IN ({placeholders})', old_ids)
            conn.commit()
            conn.close()

            set_config('tenant_rules_scan_last_run_at', finished_iso)
            add_log('WARNING' if suspicious_count else 'INFO', 'TENANT_RULES',
                    f"Scan des règles de messagerie (tenant complet) : {scanned} compte(s), "
                    f"{suspicious_count} règle(s) suspecte(s)",
                    f"{with_rules} compte(s) avec au moins une règle, {error_count} erreur(s)")

            if new_suspicious:
                send_teams_rule_alert(new_suspicious)

            return scan_id
        except Exception as e:
            conn = get_db()
            conn.execute("UPDATE tenant_rule_scans SET status='error', last_error=?, finished_at=? WHERE id=?",
                         (str(e), datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), scan_id))
            conn.commit()
            conn.close()
            add_log('ERROR', 'TENANT_RULES', 'Échec du scan des règles de messagerie (tenant complet)', str(e))
            return scan_id
    finally:
        with _tenant_rules_scan_lock:
            _tenant_rules_scan_running = False


def monitoring_scheduler_tick():
    """Un passage du planificateur :
    1. resynchronise les motifs de decouverte automatique actifs dont l'intervalle est
       ecoule (ex: 'adm-*') pour ajouter les nouvelles boites correspondantes ;
    2. scanne toutes les boites surveillees actives dont l'intervalle est ecoule ;
    3. rafraichit le flux de connexions tenant (voir /connexions) toutes les
       get_tenant_signins_refresh_minutes() minutes ;
    4. si active (voir get_tenant_rules_scan_enabled), lance un scan complet des regles
       de messagerie de tout le tenant (voir /monitoring/rules) toutes les
       get_tenant_rules_scan_interval_minutes() minutes — dans un thread dedie, ce scan
       pouvant prendre plusieurs minutes (une requete Graph par compte).
    Ne fait rien si la configuration Microsoft Graph est incomplete."""
    if not (get_config('graph_tenant_id', '') and get_config('graph_client_id', '') and get_config('graph_client_secret', '')):
        return
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    last_signins_refresh = get_config('tenant_signins_last_fetch_at', '')
    signins_due = True
    if last_signins_refresh:
        last = _parse_iso(last_signins_refresh)
        if last:
            signins_due = (now - last).total_seconds() / 60 >= get_tenant_signins_refresh_minutes()
    if signins_due:
        try:
            refresh_tenant_signins()
        except Exception as e:
            add_log('ERROR', 'TENANT_SIGNINS', 'Échec du rafraîchissement des connexions (tenant)', str(e))

    conn = get_db()
    patterns = conn.execute('SELECT * FROM monitoring_patterns WHERE is_active=1').fetchall()
    conn.close()
    for pattern in patterns:
        due = True
        if pattern['last_sync_at']:
            last = _parse_iso(pattern['last_sync_at'])
            if last:
                due = (now - last).total_seconds() / 60 >= (pattern['interval_minutes'] or 60)
        if due:
            try:
                sync_monitoring_pattern(pattern)
            except Exception:
                pass  # deja journalise dans sync_monitoring_pattern

    conn = get_db()
    rows = conn.execute('SELECT * FROM monitored_mailboxes WHERE is_active=1').fetchall()
    conn.close()
    for row in rows:
        if _monitoring_scan_due(row, now):
            run_monitoring_scan(row)

    if get_tenant_rules_scan_enabled() and not _tenant_rules_scan_running:
        last_rules_scan = get_config('tenant_rules_scan_last_run_at', '')
        rules_due = True
        if last_rules_scan:
            last = _parse_iso(last_rules_scan)
            if last:
                rules_due = (now - last).total_seconds() / 60 >= get_tenant_rules_scan_interval_minutes()
        if rules_due:
            threading.Thread(target=scan_tenant_mailbox_rules, kwargs={'triggered_by': 'scheduler'},
                              daemon=True, name='tenant-rules-scan').start()


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
    patterns = conn.execute('SELECT * FROM monitoring_patterns ORDER BY prefix').fetchall()
    conn.close()
    graph_configured = bool(get_config('graph_tenant_id', '') and get_config('graph_client_id', '') and get_config('graph_client_secret', ''))
    return render_template('monitoring.html', mailboxes=mailboxes, patterns=patterns, graph_configured=graph_configured)


@app.route('/connexions')
@admin_required
def view_tenant_signins():
    """Monitoring des connexions de tout le tenant (reussies et echouees), sans se limiter
    aux boites deja suivies — alimente automatiquement toutes les get_tenant_signins_refresh_minutes()
    minutes par le planificateur (voir refresh_tenant_signins/monitoring_scheduler_tick).
    Chaque connexion est accompagnee d'un score de confiance 0-100 (voir
    compute_connection_trust_score) combinant IP de confiance, geographie et reputation."""
    ALLOWED_PAGE_SIZES = (10, 25, 50, 100, 200, 500, 1000)
    try:
        raw_per = request.args.get('per_page', '100')
        if raw_per.lower() in ('all', '0', ''):
            page_size = 0  # 0 = toutes les lignes
        else:
            page_size = int(raw_per)
            if page_size not in ALLOWED_PAGE_SIZES:
                page_size = 100
    except (TypeError, ValueError):
        page_size = 100

    try:
        page = max(1, int(request.args.get('page', 1)))
    except (TypeError, ValueError):
        page = 1

    q = (request.args.get('q', '') or '').strip()
    status_filter = request.args.get('status', '').strip()
    if status_filter not in ('', 'Success', 'Failure'):
        status_filter = ''
    _pays_raw = request.args.get('pays', '').strip()
    cnx_type = request.args.get('type', '').strip()
    if cnx_type not in ('', 'fixe', 'mobile', 'vpn', 'dc', 'trusted', 'autre'):
        cnx_type = ''

    conn = get_db()
    countries = [dict(r) for r in conn.execute(
        "SELECT country, COUNT(*) as nb FROM tenant_signins WHERE country IS NOT NULL AND country != '' GROUP BY country ORDER BY nb DESC").fetchall()]
    _valid_pays = {c['country'] for c in countries}
    if _pays_raw and _pays_raw not in ('FR', 'hors_france', 'inconnu') and _pays_raw not in _valid_pays:
        if not re.fullmatch(r'[A-Z]{2}', _pays_raw):
            _pays_raw = ''  # code pays invalide (ni ISO 2 lettres ni special) : on ignore
    pays_filter = _pays_raw

    where = []
    params = []
    if q:
        like = f'%{q}%'
        where.append('(user_display_name LIKE ? OR user_upn LIKE ? OR ip_address LIKE ? OR location LIKE ? OR application LIKE ? OR failure_reason LIKE ?)')
        params += [like] * 6
    if status_filter == 'Failure':
        where.append("status != 'Success'")
    elif status_filter == 'Success':
        where.append("status = 'Success'")

    join_ip = False
    if pays_filter in ('FR', 'hors_france') or cnx_type in ('fixe', 'mobile', 'vpn', 'dc', 'autre'):
        join_ip = True
    if pays_filter == 'FR':
        where.append("tenant_signins.country = 'FR'")
    elif pays_filter == 'hors_france':
        where.append("tenant_signins.country IS NOT NULL AND tenant_signins.country != '' AND tenant_signins.country != 'FR'")
    elif pays_filter == 'inconnu':
        where.append("(tenant_signins.country IS NULL OR tenant_signins.country = '')")
    elif pays_filter:
        where.append('tenant_signins.country = ?')
        params.append(pays_filter)

    if cnx_type == 'fixe':
        where.append("ip_info.usage_type LIKE '%fixed%'")
    elif cnx_type == 'mobile':
        where.append("ip_info.usage_type LIKE '%mobile%'")
    elif cnx_type == 'vpn':
        where.append('ip_info.is_vpn = 1')
    elif cnx_type == 'dc':
        # Miroire du badge is_datacenter (ip_reputation_payload) : une IP de confiance
        # (ex: IP du tenant hebergee chez un prestataire) n'est PAS un signal de
        # datacenter suspect, meme si AbuseIPDB la classe ainsi.
        where.append("""(ip_info.usage_type LIKE '%data center%')
             AND tenant_signins.ip_address NOT IN (SELECT ip FROM trusted_ips)""")
    elif cnx_type == 'trusted':
        where.append('tenant_signins.ip_address IN (SELECT ip FROM trusted_ips)')
    elif cnx_type == 'autre':
        where.append("""(COALESCE(ip_info.usage_type, '') = ''
             OR (ip_info.usage_type NOT LIKE '%fixed%' AND ip_info.usage_type NOT LIKE '%mobile%'
                 AND ip_info.usage_type NOT LIKE '%data center%'))
             AND COALESCE(ip_info.is_vpn, 0) != 1
             AND tenant_signins.ip_address NOT IN (SELECT ip FROM trusted_ips)""")

    from_sql = ('FROM tenant_signins LEFT JOIN ip_info ON ip_info.ip = tenant_signins.ip_address' if join_ip else 'FROM tenant_signins')
    where_sql = ('WHERE ' + ' AND '.join(where)) if where else ''
    # La jointure peut creer des doublons si ip_info n'est pas unique — jamais le cas ici
    # (ip_info.ip est PRIMARY KEY), mais on garde SELECT DISTINCT en plus du join par securite
    # sur les lignes, pas sur les comptes.

    conn = get_db()
    nb_total = conn.execute(f'SELECT COUNT(*) as c {from_sql} {where_sql}', params).fetchone()['c']
    nb_all = conn.execute('SELECT COUNT(*) as c FROM tenant_signins').fetchone()['c']
    failure_where = ' AND '.join(where + ["status != 'Success'"]) if where else "status != 'Success'"
    nb_failed = conn.execute(f'SELECT COUNT(*) as c {from_sql} WHERE {failure_where}', params).fetchone()['c']

    if page_size == 0:
        nb_pages = 1
        page = 1
        offset = 0
        limit_sql = ''
        page_params = params
    else:
        nb_pages = max(1, (nb_total + page_size - 1) // page_size)
        page = min(page, nb_pages)
        offset = (page - 1) * page_size
        limit_sql = ' LIMIT ? OFFSET ?'
        page_params = params + [page_size, offset]
    rows = conn.execute(f'SELECT tenant_signins.* {from_sql} {where_sql} ORDER BY date_utc DESC{limit_sql}', page_params).fetchall()
    conn.close()

    rows_with_trust = []
    for r in rows:
        try:
            ip_payload = ip_reputation_payload(r['ip_address'])
        except Exception:
            ip_payload = None
        trust = compute_connection_trust_score(ip_payload, r['country'])
        try:
            display_location = get_display_location(r['ip_address'], r['location'])
        except Exception:
            display_location = r['location']
        rows_with_trust.append({'row': r, 'trust': trust, 'display_location': display_location})

    # Masquage des noms : les UPNs ayant au moins une connexion echouee dans la page
    # courante sont exposes (nom visible). Les autres sont verifies dans RH Studio :
    # s'ils sont partis ou introuvables, ils sont aussi exposes (signalent une
    # compromission potentielle). Les super-administrateurs voient tout.
    exposed_upns = set()
    for item in rows_with_trust:
        r = item['row']
        if r['status'] != 'Success':
            exposed_upns.add(r['user_upn'])
    non_exposed = {item['row']['user_upn'] for item in rows_with_trust} - exposed_upns
    rh_status = rh_studio_batch_check(non_exposed)
    for upn, info in rh_status.items():
        if info.get('status') in ('parti', 'not_found'):
            exposed_upns.add(upn)

    graph_configured = bool(get_config('graph_tenant_id', '') and get_config('graph_client_id', '') and get_config('graph_client_secret', ''))
    last_refresh = get_config('tenant_signins_last_fetch_at', '')
    return render_template('tenant_signins.html', rows=rows_with_trust, nb_total=nb_total, nb_all=nb_all, nb_failed=nb_failed,
                            graph_configured=graph_configured, last_refresh=last_refresh,
                            refresh_minutes=get_tenant_signins_refresh_minutes(),
                            retention_hours=get_tenant_signins_retention_hours(),
                            home_country_code=get_home_country_code(),
                            page=page, nb_pages=nb_pages, page_size=page_size,
                            q=q, status_filter=status_filter, pays_filter=pays_filter, cnx_type=cnx_type,
                            countries=countries, exposed_upns=exposed_upns)


@app.route('/connexions/settings', methods=['POST'])
@admin_required
def update_tenant_signins_settings():
    def _save_int(field, config_key, lo, hi):
        raw = request.form.get(field, '').strip()
        try:
            value = int(raw)
            if lo <= value <= hi:
                set_config(config_key, str(value))
                return True
        except ValueError:
            pass
        return False

    ok = True
    ok &= _save_int('refresh_minutes', 'tenant_signins_refresh_minutes', 1, 1440)
    ok &= _save_int('retention_hours', 'tenant_signins_retention_hours', 1, 24 * 30)
    home_country = request.form.get('home_country_code', '').strip().upper()
    if len(home_country) == 2:
        set_config('home_country_code', home_country)
    elif home_country:
        ok = False

    flash('Paramètres enregistrés' if ok else 'Paramètres enregistrés (certaines valeurs invalides ont été ignorées)')
    return redirect(url_for('view_tenant_signins'))


@app.route('/api/signin-ack', methods=['POST'])
@login_required
def signin_ack():
    """Acquitte un lieu suspect de la carte des connexions (voir compute_dashboard_kpis) :
    enregistre que <utilisateur connecte> a examine/valide les connexions de ce lieu. Le
    point passe alors en rouge fixe reduit (plus d'animation de clignotement) et le popup
    affiche "vérifié par X". La cle est identique au bucketing de la carte : (ville, code
    pays). Renvoie un JSON decrivant l'acquittement cree, pour la mise a jour de la carte
    sans rechargement."""
    data = request.get_json(silent=True) or {}
    city = (data.get('city') or '').strip()[:200]
    country_code = (data.get('country_code') or '').strip().upper()[:10]
    by = session.get('username') or 'utilisateur inconnu'
    conn = get_db()
    conn.execute('''INSERT INTO signin_acks (city, country_code, acknowledged_by)
                    VALUES (?, ?, ?)
                    ON CONFLICT(city, country_code) DO UPDATE SET acknowledged_by=excluded.acknowledged_by,
                        acknowledged_at=CURRENT_TIMESTAMP''', (city, country_code, by))
    conn.commit()
    ack = conn.execute('SELECT * FROM signin_acks WHERE city=? AND country_code=?',
                       (city, country_code)).fetchone()
    conn.close()
    return jsonify({'success': True, 'acked': dict(ack) if ack else None})


@app.route('/connexions/refresh', methods=['POST'])
@admin_required
def refresh_tenant_signins_now():
    if not (get_config('graph_tenant_id', '') and get_config('graph_client_id', '') and get_config('graph_client_secret', '')):
        flash("Configuration Microsoft Graph incomplète — voir Configuration")
        return redirect(url_for('view_tenant_signins'))
    try:
        new_rows = refresh_tenant_signins()
        flash(f"Rafraîchi : {new_rows} nouvelle(s) connexion(s)")
    except Exception as e:
        flash(f"Échec du rafraîchissement : {e}")
    return redirect(url_for('view_tenant_signins'))


@app.route('/monitoring/rules')
@admin_required
def view_tenant_rules():
    """Regles de messagerie de TOUTES les boites du tenant (dernier scan termine — voir
    scan_tenant_mailbox_rules), avec detection des regles dangereuses (transfert externe
    sans condition, suppression automatique de courrier lie a la securite... — voir
    _map_graph_rule). Le scan peut etre lance a la demande (/monitoring/rules/scan) ou
    periodiquement (voir /monitoring/rules/settings)."""
    conn = get_db()
    latest_scan = conn.execute(
        "SELECT * FROM tenant_rule_scans WHERE status IN ('done','error') ORDER BY id DESC LIMIT 1").fetchone()
    running_scan = conn.execute(
        "SELECT * FROM tenant_rule_scans WHERE status='running' ORDER BY id DESC LIMIT 1").fetchone()
    rules = []
    if latest_scan:
        rules = conn.execute(
            'SELECT * FROM tenant_mailbox_rules WHERE scan_id=? ORDER BY is_suspicious DESC, user_upn ASC',
            (latest_scan['id'],)).fetchall()
    conn.close()

    # Masquage des noms : seules les regles suspectes et les utilisateurs partis/
    # introuvables dans RH Studio sont exposes. Les super-administrateurs voient tout.
    exposed_upns = set()
    non_suspicious_upns = set()
    for r in rules:
        if r['is_suspicious'] == 'true':
            exposed_upns.add(r['user_upn'])
        else:
            non_suspicious_upns.add(r['user_upn'])
    rh_status = rh_studio_batch_check(non_suspicious_upns)
    for upn, info in rh_status.items():
        if info.get('status') in ('parti', 'not_found'):
            exposed_upns.add(upn)

    # Historique des regles meme si elles ont disparu du scan courant
    processed_rules = []
    conn2 = get_db()
    processed_rules = conn2.execute(
        'SELECT * FROM tenant_rule_processed ORDER BY processed_at DESC LIMIT 200').fetchall()
    conn2.close()

    graph_configured = bool(get_config('graph_tenant_id', '') and get_config('graph_client_id', '') and get_config('graph_client_secret', ''))
    return render_template('tenant_rules.html', rules=rules, latest_scan=latest_scan, running_scan=running_scan,
                            graph_configured=graph_configured,
                            scan_enabled=get_tenant_rules_scan_enabled(),
                            scan_interval=get_tenant_rules_scan_interval_minutes(),
                            exposed_upns=exposed_upns,
                            processed_rules=processed_rules)


@app.route('/monitoring/rules/scan', methods=['POST'])
@admin_required
def scan_tenant_rules_now():
    if not (get_config('graph_tenant_id', '') and get_config('graph_client_id', '') and get_config('graph_client_secret', '')):
        return jsonify({'error': 'Configuration Microsoft Graph incomplète — voir Configuration'}), 400
    if _tenant_rules_scan_running:
        return jsonify({'error': 'Un scan est déjà en cours'}), 409
    threading.Thread(target=scan_tenant_mailbox_rules, kwargs={'triggered_by': session.get('username', 'admin')},
                      daemon=True, name='tenant-rules-scan-manual').start()
    return jsonify({'started': True})


@app.route('/monitoring/rules/status')
@admin_required
def tenant_rules_scan_status():
    """Etat du dernier scan (en cours ou termine), interroge en polling par la page
    /monitoring/rules pendant un scan pour afficher une barre de progression."""
    conn = get_db()
    row = conn.execute('SELECT * FROM tenant_rule_scans ORDER BY id DESC LIMIT 1').fetchone()
    conn.close()
    if not row:
        return jsonify({'status': 'none'})
    return jsonify({
        'status': row['status'],
        'total_accounts': row['total_accounts'],
        'scanned_accounts': row['scanned_accounts'],
        'suspicious_count': row['suspicious_count'],
        'started_at': row['started_at'],
        'finished_at': row['finished_at'],
        'last_error': row['last_error'],
    })


@app.route('/monitoring/rules/settings', methods=['POST'])
@admin_required
def update_tenant_rules_settings():
    set_config('tenant_rules_scan_enabled', 'true' if request.form.get('enabled') == 'on' else 'false')
    try:
        interval = int(request.form.get('interval_minutes', str(TENANT_RULES_SCAN_INTERVAL_MINUTES_DEFAULT)))
        if 30 <= interval <= 10080:
            set_config('tenant_rules_scan_interval_minutes', str(interval))
    except ValueError:
        pass
    flash('Paramètres enregistrés')
    return redirect(url_for('view_tenant_rules'))


@app.route('/api/rule-ack', methods=['POST'])
@admin_required
def rule_ack():
    """Marque une regle de messagerie comme « traitee » par un administrateur.
    Historise le commentaire et l'auteur, persiste meme si la regle disparaît
    du scan suivant (suppression, modification)."""
    data = request.get_json(silent=True) or {}
    user_upn = (data.get('user_upn') or '').strip()
    rule_id = (data.get('rule_id') or '').strip()
    rule_display_name = (data.get('rule_display_name') or '').strip()[:300]
    comment = (data.get('comment') or '').strip()[:1000]
    if not user_upn or not rule_id:
        return jsonify({'error': 'user_upn et rule_id requis'}), 400
    by = session.get('username', 'admin')
    conn = get_db()
    conn.execute('''INSERT INTO tenant_rule_processed
                    (user_upn, rule_id, rule_display_name, comment, processed_by)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(user_upn, rule_id) DO UPDATE SET
                        comment=excluded.comment,
                        processed_by=excluded.processed_by,
                        processed_at=CURRENT_TIMESTAMP,
                        rule_display_name=excluded.rule_display_name''',
                 (user_upn, rule_id, rule_display_name, comment, by))
    conn.commit()
    processed = conn.execute(
        'SELECT * FROM tenant_rule_processed WHERE user_upn=? AND rule_id=?',
        (user_upn, rule_id)).fetchone()
    conn.close()
    add_log('INFO', 'TENANT_RULES', f'Regle marquée comme traitée par {by}',
            f'Compte: {user_upn}, règle: {rule_display_name or rule_id}, commentaire: {comment or "(aucun)"}')
    return jsonify({'success': True, 'processed': dict(processed) if processed else None})


@app.route('/admin/compte', methods=['GET'])
@admin_required
def account_firstaid_search():
    """Formulaire de recherche du menu "Premiers secours" — saisie de l'UPN/email d'un
    compte pour acceder directement a sa fiche (/admin/compte/<upn>)."""
    q = request.args.get('q', '').strip()
    if q:
        return redirect(url_for('account_firstaid', upn=q))
    return render_template('account_firstaid.html', upn=None, graph_configured=bool(
        get_config('graph_tenant_id', '') and get_config('graph_client_id', '') and get_config('graph_client_secret', '')))


@app.route('/admin/compte/<upn>')
@admin_required
def account_firstaid(upn):
    """Fiche "premiers secours" d'un compte : infos cles issues de Microsoft Graph
    (statut, derniere connexion, licences, methodes MFA enregistrees) et actions
    d'urgence (desactivation, revocation des sessions, reinitialisation du mot de passe,
    MFA). Fonctionne pour n'importe quel UPN du tenant, meme sans fiche d'incident.

    Toute consultation est journalisee (qui a recherche/consulte quel compte, et quand) —
    la fiche donne acces a des informations sensibles (derniere connexion, methodes MFA
    enregistrees...) qui pourraient sinon etre consultees sans tracabilite."""
    add_log('INFO', 'PREMIERS_SECOURS', f'Consultation du compte : {upn}', recipient=upn, username=session.get('username'))

    graph_configured = bool(get_config('graph_tenant_id', '') and get_config('graph_client_id', '') and get_config('graph_client_secret', ''))
    account, auth_methods, error, auth_methods_error = None, [], None, None
    has_real_mfa = False
    mfa_governance = {
        'security_defaults': None, 'security_defaults_error': None,
        'ca_policies': None, 'ca_policies_error': None,
        'per_user_state': None, 'per_user_state_error': None,
    }
    if graph_configured:
        try:
            account = graph_get_account_overview(upn)
            if not account.get('id'):
                error = "Compte introuvable dans l'annuaire Microsoft Entra ID."
        except Exception as e:
            error = str(e)
        if account and account.get('id'):
            try:
                auth_methods = graph_get_auth_methods(upn)
                has_real_mfa = _has_real_mfa(auth_methods)
                if not has_real_mfa:
                    registered = ', '.join(m['type'] for m in auth_methods) or 'aucune'
                    add_log('WARNING', 'PREMIERS_SECOURS', f'Aucun MFA réel enregistré : {upn}',
                            f'Méthodes enregistrées : {registered}', recipient=upn, username=session.get('username'))
            except Exception as e:
                auth_methods_error = str(e)

            # D'ou vient l'obligation de MFA (ou son absence) pour ce compte : trois
            # mecanismes independants et cumulables cote Entra ID. Chacun est recupere
            # separement (Policy.Read.All requis pour les deux premiers, distincte des
            # permissions deja utilisees) : l'echec de l'un n'empeche pas d'afficher les
            # autres — voir mfa_governance dans le template.
            try:
                mfa_governance['security_defaults'] = graph_get_security_defaults_enabled()
            except Exception as e:
                mfa_governance['security_defaults_error'] = str(e)
            try:
                mfa_governance['ca_policies'] = graph_get_conditional_access_mfa_policies()
            except Exception as e:
                mfa_governance['ca_policies_error'] = str(e)
            try:
                mfa_governance['per_user_state'] = graph_get_per_user_mfa_state(upn)
            except Exception as e:
                mfa_governance['per_user_state_error'] = str(e)
    else:
        error = "Configuration Microsoft Graph incomplète — voir Configuration."

    conn = get_db()
    boite = conn.execute(
        'SELECT * FROM boites_compromises WHERE user_email=? ORDER BY created_at DESC LIMIT 1', (upn,)).fetchone()
    monitored = conn.execute('SELECT * FROM monitored_mailboxes WHERE user_email=?', (upn,)).fetchone()
    recent_actions = conn.execute(
        "SELECT * FROM logs WHERE category='PREMIERS_SECOURS' AND recipient=? ORDER BY timestamp DESC LIMIT 20",
        (upn,)).fetchall()
    conn.close()

    return render_template('account_firstaid.html', upn=upn, account=account, error=error,
                            auth_methods=auth_methods, auth_methods_error=auth_methods_error,
                            has_real_mfa=has_real_mfa, mfa_governance=mfa_governance,
                            boite=boite, monitored=monitored,
                            recent_actions=recent_actions, graph_configured=graph_configured)


@app.route('/admin/compte/<upn>/disable', methods=['POST'])
@admin_required
def account_firstaid_disable(upn):
    try:
        graph_set_account_enabled(upn, False)
        add_log('WARNING', 'PREMIERS_SECOURS', f'Compte désactivé : {upn}', recipient=upn, username=session.get('username'))
        flash(f'Compte {upn} désactivé.')
    except Exception as e:
        flash(f'Échec de la désactivation : {e}')
    return redirect(url_for('account_firstaid', upn=upn))


@app.route('/admin/compte/<upn>/enable', methods=['POST'])
@admin_required
def account_firstaid_enable(upn):
    try:
        graph_set_account_enabled(upn, True)
        add_log('WARNING', 'PREMIERS_SECOURS', f'Compte réactivé : {upn}', recipient=upn, username=session.get('username'))
        flash(f'Compte {upn} réactivé.')
    except Exception as e:
        flash(f'Échec de la réactivation : {e}')
    return redirect(url_for('account_firstaid', upn=upn))


@app.route('/admin/compte/<upn>/revoke-sessions', methods=['POST'])
@admin_required
def account_firstaid_revoke(upn):
    try:
        graph_revoke_sessions(upn)
        add_log('WARNING', 'PREMIERS_SECOURS', f'Sessions révoquées : {upn}', recipient=upn, username=session.get('username'))
        flash(f'Toutes les sessions de {upn} ont été révoquées (déconnexion forcée partout, jetons invalidés).')
    except Exception as e:
        flash(f'Échec de la révocation des sessions : {e}')
    return redirect(url_for('account_firstaid', upn=upn))


@app.route('/admin/compte/<upn>/reset-password', methods=['POST'])
@admin_required
def account_firstaid_reset_password(upn):
    # Le champ 'password' reste dans le formulaire meme quand le mode "aleatoire" est
    # selectionne (juste masque en CSS) : ne l'utiliser que si le mode "custom" est
    # explicitement choisi, sinon un texte laisse par erreur dans le champ (puis le
    # formulaire soumis en mode aleatoire) serait pris a tort pour le mot de passe voulu.
    custom_mode = request.form.get('password_mode') == 'custom'
    custom_password = request.form.get('password', '').strip() if custom_mode else ''
    if custom_mode and len(custom_password) < 8:
        flash('Le mot de passe saisi doit faire au moins 8 caractères.')
        return redirect(url_for('account_firstaid', upn=upn))
    try:
        temp_password, was_generated = graph_reset_password(upn, password=custom_password or None)
        details = 'Mot de passe généré aléatoirement' if was_generated else "Mot de passe saisi manuellement par l'administrateur"
        add_log('WARNING', 'PREMIERS_SECOURS', f'Mot de passe réinitialisé : {upn}', details, recipient=upn, username=session.get('username'))
        if was_generated:
            flash(f"Mot de passe réinitialisé pour {upn}. Mot de passe temporaire (à communiquer de façon "
                  f"sécurisée — il ne sera plus jamais affiché) : {temp_password}")
        else:
            flash(f'Mot de passe réinitialisé pour {upn} avec le mot de passe saisi (changement exigé à la prochaine connexion).')
    except Exception as e:
        flash(f'Échec de la réinitialisation du mot de passe : {e}')
    return redirect(url_for('account_firstaid', upn=upn))


@app.route('/admin/compte/<upn>/mfa/require', methods=['POST'])
@admin_required
def account_firstaid_require_mfa(upn):
    try:
        graph_set_per_user_mfa_state(upn, 'enforced')
        add_log('WARNING', 'PREMIERS_SECOURS', f'MFA par utilisateur forcé : {upn}', recipient=upn, username=session.get('username'))
        flash(f"MFA par utilisateur (mécanisme historique) activé pour {upn} — sans effet si votre tenant "
              f"applique le MFA via l'Accès conditionnel ou les Défauts de sécurité.")
    except Exception as e:
        flash(f"Échec (probablement non applicable à votre configuration Azure AD) : {e}")
    return redirect(url_for('account_firstaid', upn=upn))


@app.route('/monitoring/patterns/add', methods=['POST'])
@admin_required
def add_monitoring_pattern():
    prefix = request.form.get('prefix', '').strip()
    try:
        interval = max(5, min(int(request.form.get('interval_minutes', '60')), 10080))
    except ValueError:
        interval = 60
    if not prefix:
        flash('Préfixe invalide')
        return redirect(url_for('view_monitoring'))

    conn = get_db()
    try:
        conn.execute('''INSERT INTO monitoring_patterns (prefix, interval_minutes, created_by)
            VALUES (?, ?, ?)''', (prefix, interval, session.get('username', '')))
        conn.commit()
        pattern_row = conn.execute('SELECT * FROM monitoring_patterns WHERE prefix=?', (prefix,)).fetchone()
    except sqlite3.IntegrityError:
        conn.close()
        flash(f'Le motif "{prefix}*" existe déjà')
        return redirect(url_for('view_monitoring'))
    conn.close()

    try:
        added = sync_monitoring_pattern(pattern_row)
        flash(f'Motif "{prefix}*" ajouté — {added} boîte(s) découverte(s) et ajoutée(s) à la surveillance')
    except Exception as e:
        flash(f'Motif "{prefix}*" ajouté, mais la découverte initiale a échoué : {e}')
    return redirect(url_for('view_monitoring'))


@app.route('/monitoring/patterns/<int:pattern_id>/sync', methods=['POST'])
@admin_required
def sync_monitoring_pattern_now(pattern_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM monitoring_patterns WHERE id=?', (pattern_id,)).fetchone()
    conn.close()
    if not row:
        flash('Motif non trouvé')
        return redirect(url_for('view_monitoring'))
    try:
        added = sync_monitoring_pattern(row)
        flash(f"Synchronisation de \"{row['prefix']}*\" effectuée — {added} nouvelle(s) boîte(s) ajoutée(s)")
    except Exception as e:
        flash(f'Erreur lors de la synchronisation : {e}')
    return redirect(url_for('view_monitoring'))


@app.route('/monitoring/patterns/<int:pattern_id>/toggle', methods=['POST'])
@admin_required
def toggle_monitoring_pattern(pattern_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM monitoring_patterns WHERE id=?', (pattern_id,)).fetchone()
    if row:
        conn.execute('UPDATE monitoring_patterns SET is_active=? WHERE id=?', (0 if row['is_active'] else 1, pattern_id))
        conn.commit()
    conn.close()
    return redirect(url_for('view_monitoring'))


@app.route('/monitoring/patterns/<int:pattern_id>/delete', methods=['POST'])
@admin_required
def delete_monitoring_pattern(pattern_id):
    conn = get_db()
    conn.execute('DELETE FROM monitoring_patterns WHERE id=?', (pattern_id,))
    conn.commit()
    conn.close()
    flash('Motif supprimé (les boîtes déjà découvertes restent surveillées)')
    return redirect(url_for('view_monitoring'))


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


@app.route('/boite/<int:bid>/graph/fetch/start', methods=['POST'])
def graph_fetch_start(bid):
    """Lance l'import Microsoft Graph (connexions/audit/regles, messages en option) en
    tache de fond et retourne un identifiant de job pour suivre la progression par
    source via /jobs/<job_id>/poll (voir quick_scan_start pour le meme principe)."""
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    conn.close()
    if not boite:
        return jsonify({'error': 'Boîte non trouvée'}), 404

    try:
        days = max(1, min(int(request.form.get('days', '30')), 90))
    except ValueError:
        days = 30
    include_messages = request.form.get('include_messages') == 'on'
    email = boite['user_email']

    steps = (['messages'] if include_messages else []) + ['signins', 'audit', 'rules']
    job_id = _job_create(steps)

    def worker():
        summary = []
        errors = []

        if include_messages:
            _job_step(job_id, 'messages', 'running')
            try:
                c, d = fetch_sent_messages_from_graph(bid, email, days)
                summary.append(f'{c} message(s) envoyé(s) ({d} doublon(s) ignoré(s))')
                _job_step(job_id, 'messages', 'done')
            except Exception as e:
                errors.append(f'Messages envoyés : {e}')
                _job_step(job_id, 'messages', 'error')

        _job_step(job_id, 'signins', 'running')
        try:
            c, d = fetch_signins_from_graph(bid, email, days)
            summary.append(f'{c} connexion(s) ({d} doublon(s) ignoré(s))')
            _job_step(job_id, 'signins', 'done')
        except Exception as e:
            errors.append(f'Connexions : {e}')
            _job_step(job_id, 'signins', 'error')

        _job_step(job_id, 'audit', 'running')
        try:
            c, d = fetch_audit_from_graph(bid, email, days)
            summary.append(f"{c} événement(s) d'audit ({d} doublon(s) ignoré(s))")
            _job_step(job_id, 'audit', 'done')
        except Exception as e:
            errors.append(f"Journal d'audit : {e}")
            _job_step(job_id, 'audit', 'error')

        _job_step(job_id, 'rules', 'running')
        try:
            c = fetch_inbox_rules_from_graph(bid, email)
            summary.append(f'{c} règle(s) de messagerie')
            _job_step(job_id, 'rules', 'done')
        except Exception as e:
            if not _is_no_mailbox_error(e):
                errors.append(f'Règles de messagerie : {e}')
            _job_step(job_id, 'rules', 'done')

        if summary:
            add_log('INFO', 'GRAPH', f'Import Microsoft Graph pour {email}', ', '.join(summary), bid)
        for err in errors:
            add_log('ERROR', 'GRAPH', f'Erreur import Microsoft Graph pour {email}', err, bid)

        _job_finish(job_id, redirect=f'/boite/{bid}', result={'summary': summary, 'errors': errors})

    threading.Thread(target=worker, daemon=True, name=f'graph-fetch-{job_id[:8]}').start()
    return jsonify({'job_id': job_id})


@app.route('/boite/<int:bid>/ai-analyze/start', methods=['POST'])
def ai_analyze_start(bid):
    """Lance l'analyse IA d'une boite en tache de fond (appel reseau potentiellement long,
    Groq puis repli NVIDIA si besoin — voir run_ai_analysis) et retourne un identifiant de
    job suivi via /jobs/<job_id>/poll, meme principe que le scan rapide et l'import Graph."""
    conn = get_db()
    boite = conn.execute('SELECT user_email FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    conn.close()
    if not boite:
        return jsonify({'error': 'Boîte non trouvée'}), 404
    if not any(m['active'] for m in get_all_ai_models()):
        return jsonify({'error': "Aucun fournisseur IA configuré (Groq, NVIDIA ou Ollama) — demandez à un administrateur de le renseigner dans Configuration."}), 400

    # Modèle choisi dans le formulaire (le champ 'request' n'est plus accessible une
    # fois dans le thread de fond, on le lit donc avant de le lancer).
    preferred_model_key = request.form.get('model_key', '').strip()

    job_id = _job_create(['ai'])

    def worker():
        _job_step(job_id, 'ai', 'running')
        try:
            result_text, provider, model = run_ai_analysis(bid, preferred_model_key=preferred_model_key)
            now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            conn2 = get_db()
            conn2.execute('''UPDATE boites_compromises SET
                ai_analysis=?, ai_analysis_at=?, ai_analysis_model=?, ai_analysis_provider=? WHERE id=?''',
                          (result_text, now_iso, model, provider, bid))
            conn2.commit()
            conn2.close()
            add_log('INFO', 'IA', f"Analyse IA effectuée pour {boite['user_email']}", f'Fournisseur : {provider}, modèle : {model}', bid)
            _job_step(job_id, 'ai', 'done')
            _job_finish(job_id, redirect=f'/boite/{bid}#ai-analysis')
        except Exception as e:
            add_log('ERROR', 'IA', f"Échec de l'analyse IA pour {boite['user_email']}", str(e), bid)
            _job_step(job_id, 'ai', 'error')
            _job_finish(job_id, error=f"Erreur lors de l'analyse IA : {e}")

    threading.Thread(target=worker, daemon=True, name=f'ai-analyze-{job_id[:8]}').start()
    return jsonify({'job_id': job_id})


@app.route('/boite/<int:bid>/rules')
def view_rules(bid):
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    if not boite:
        conn.close()
        flash('Boîte non trouvée')
        return redirect(url_for('list_boites'))
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
        return redirect(url_for('list_boites'))
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
        return redirect(url_for('list_boites'))
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
    'inboxrule', 'transportrule', 'forwardingsmtpaddress', 'forward', 'redirect',
    'password', 'credential', 'authenticationmethod', 'strongauthentication', 'mfa',
    'phonenumber', 'securityinfo', 'federation', 'membertorole', 'stsrefreshtokenvalidfrom',
]
# Volontairement EXCLUS malgre leur air alarmant : 'consent', 'serviceprincipal',
# 'approleassignment', 'addowner', 'permission', 'roleassignment' (hors 'membertorole'),
# 'admin', 'delegate'. Ces termes correspondent en tres grande majorite a de la gestion
# d'application/API tout a fait routiniere (creation d'un App Registration, octroi de
# permissions Graph...) — exactement le type d'action qu'un compte "adm-*" dedie
# effectue en permanence. Les inclure noyait la detection sous des dizaines de faux
# positifs a chaque configuration d'outil ou d'integration.

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
@admin_required
def delete_boite(bid):
    conn = get_db()
    conn.execute('DELETE FROM messages WHERE boite_id=?', (bid,))
    conn.execute('DELETE FROM signin_logs WHERE boite_id=?', (bid,))
    conn.execute('DELETE FROM audit_logs WHERE boite_id=?', (bid,))
    conn.execute('DELETE FROM dsi_actions WHERE boite_id=?', (bid,))
    conn.execute('DELETE FROM boites_compromises WHERE id=?', (bid,))
    conn.commit()
    conn.close()
    flash('Boîte supprimée')
    return redirect(url_for('list_boites'))


@app.route('/boite/<int:bid>/dsi-actions/add', methods=['POST'])
def add_dsi_action(bid):
    """Enregistre une action de remediation deja realisee par la DSI sur cette boite
    (ex: mot de passe reinitialise). Visible sur la fiche de la boite, et injectee dans
    le prompt d'analyse IA (voir build_ai_analysis_prompt) pour que l'IA en tienne compte
    plutot que de re-recommander des actions deja effectuees."""
    conn = get_db()
    boite = conn.execute('SELECT id FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    if not boite:
        conn.close()
        flash('Boîte non trouvée')
        return redirect(url_for('list_boites'))
    action_text = request.form.get('action_text', '').strip()
    # Date/heure de l'action : saisie librement par l'utilisateur (champ datetime-local,
    # donc deja en heure locale) — a defaut, on prend la date/heure actuelle, pour ne pas
    # obliger a la renseigner a chaque fois.
    action_at = request.form.get('action_at', '').strip() or _now_local_datetime_input()
    if action_text:
        now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        conn.execute('''INSERT INTO dsi_actions (boite_id, action_text, action_at, created_by, created_at)
                         VALUES (?, ?, ?, ?, ?)''',
                     (bid, action_text, action_at, session.get('username', ''), now_iso))
        conn.commit()
    conn.close()
    return redirect(url_for('view_boite', bid=bid) + '#dsi-actions')


@app.route('/boite/<int:bid>/dsi-actions/<int:action_id>/edit', methods=['POST'])
def edit_dsi_action(bid, action_id):
    """Permet de corriger le texte et/ou la date/heure d'une action DSI deja enregistree
    (ex: erreur de saisie, date approximative a preciser apres coup)."""
    conn = get_db()
    action = conn.execute('SELECT * FROM dsi_actions WHERE id=? AND boite_id=?', (action_id, bid)).fetchone()
    if not action:
        conn.close()
        flash('Action non trouvée')
        return redirect(url_for('view_boite', bid=bid) + '#dsi-actions')

    action_text = request.form.get('action_text', '').strip()
    action_at = request.form.get('action_at', '').strip()
    if action_text:
        now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        conn.execute('''UPDATE dsi_actions SET action_text=?, action_at=?, updated_by=?, updated_at=?
                         WHERE id=? AND boite_id=?''',
                     (action_text, action_at or action['action_at'], session.get('username', ''), now_iso,
                      action_id, bid))
        conn.commit()
    conn.close()
    return redirect(url_for('view_boite', bid=bid) + '#dsi-actions')


@app.route('/boite/<int:bid>/dsi-actions/<int:action_id>/delete', methods=['POST'])
def delete_dsi_action(bid, action_id):
    conn = get_db()
    conn.execute('DELETE FROM dsi_actions WHERE id=? AND boite_id=?', (action_id, bid))
    conn.commit()
    conn.close()
    return redirect(url_for('view_boite', bid=bid) + '#dsi-actions')


@app.route('/boite/<int:bid>/messages/clear', methods=['POST'])
@admin_required
def clear_messages(bid):
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    if not boite:
        conn.close()
        flash('Boîte non trouvée')
        return redirect(url_for('list_boites'))
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
        return redirect(url_for('list_boites'))
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
        return redirect(url_for('list_boites'))
    cnt = conn.execute('SELECT COUNT(*) as c FROM audit_logs WHERE boite_id=?', (bid,)).fetchone()['c']
    conn.execute('DELETE FROM audit_logs WHERE boite_id=?', (bid,))
    conn.commit()
    conn.close()
    add_log('INFO', 'IMPORT', f'Événements d\'audit importés effacés pour la boîte {bid} ({boite["user_email"]})', f'{cnt} événement(s) supprimé(s)', bid)
    flash(f'{cnt} événement(s) d\'audit importé(s) effacé(s)')
    return redirect(url_for('view_boite', bid=bid))

@app.route('/logs')
@superadmin_required
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
        query += ' AND (message LIKE ? OR details LIKE ? OR recipient LIKE ? OR username LIKE ?)'
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%'])

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
        count_query += ' AND (message LIKE ? OR details LIKE ? OR recipient LIKE ? OR username LIKE ?)'
        count_params.extend([f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%'])

    total = conn.execute(count_query, count_params).fetchone()['cnt']
    total_pages = (total + per_page - 1) // per_page

    levels = conn.execute('SELECT DISTINCT level FROM logs ORDER BY level').fetchall()
    categories = conn.execute('SELECT DISTINCT category FROM logs ORDER BY category').fetchall()

    conn.close()
    return render_template('logs.html', logs=logs, page=page, total_pages=total_pages,
                           levels=levels, categories=categories,
                           level_filter=level_filter, category_filter=category_filter, search=search)

@app.route('/logs/clear', methods=['POST'])
@superadmin_required
def clear_logs():
    conn = get_db()
    conn.execute('DELETE FROM logs')
    conn.commit()
    conn.close()
    flash('Logs supprimés')
    return redirect(url_for('view_logs'))

@app.route('/log/<int:log_id>')
@superadmin_required
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
@admin_required
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
            set_config('public_base_url', request.form.get('public_base_url', '').strip())
            _graph_token_cache['token'] = None
            flash('Configuration Microsoft Graph enregistrée avec succès')
        elif 'groq_api_key' in request.form or 'nvidia_api_key' in request.form:
            # Ne pas ecraser les cles existantes si les champs sont laisses vides (meme
            # logique que pour le secret Graph : evite d'effacer accidentellement une cle
            # deja enregistre lors d'une simple mise a jour du modele/prompt).
            # ON NE SAUVEGARDE LA CLE QUE SI ELLE A UNE VALEUR REELLE (non vide)
            new_groq_key = request.form.get('groq_api_key', '')
            if new_groq_key:
                set_config('groq_api_key', new_groq_key.strip())
            new_nvidia_key = request.form.get('nvidia_api_key', '')
            if new_nvidia_key:
                set_config('nvidia_api_key', new_nvidia_key.strip())

            # Listes de modèles (une par fournisseur), construites côté client en JSON par
            # la page de configuration : [{'id':..., 'name':..., 'model':...}, ...].
            for provider in ('groq', 'nvidia', 'ollama'):
                raw = request.form.get(f'{provider}_models_json', '').strip()
                if not raw:
                    continue
                try:
                    parsed = json.loads(raw)
                except (ValueError, TypeError):
                    flash(f"Liste de modèles {PROVIDER_LABELS[provider]} invalide — non enregistrée")
                    continue
                if not isinstance(parsed, list):
                    continue
                cleaned = []
                for m in parsed:
                    name = str(m.get('name', '')).strip()
                    model = str(m.get('model', '')).strip()
                    if not model:
                        continue
                    cleaned.append({
                        'id': str(m.get('id') or uuid.uuid4().hex[:8]),
                        'name': name or model,
                        'model': model,
                    })
                _save_provider_models(provider, cleaned)

            # Modèle par défaut global (un seul, tous fournisseurs confondus), ex: "nvidia:ab12cd34"
            new_default = request.form.get('ai_default_model', '').strip()
            if new_default:
                set_config('ai_default_model', new_default)

            # Ollama : activation + URL (dans le meme formulaire que Groq/NVIDIA)
            new_ollama_enabled = request.form.get('ollama_enabled', '')
            if new_ollama_enabled not in ('0', '1'):
                new_ollama_enabled = '1'
            set_config('ollama_enabled', new_ollama_enabled)
            new_ollama_url = request.form.get('ollama_url', '')
            if new_ollama_url:
                set_config('ollama_url', new_ollama_url.strip())

            # Ne pas ecraser le prompt si vide
            new_prompt = request.form.get('groq_prompt_template', '').strip()
            if new_prompt:
                set_config('groq_prompt_template', new_prompt)
            flash('Configuration IA enregistrée avec succès')
        # L'ancienne condition elif 'ollama_enabled' in request.form... est maintenant inutile :
        # Ollama fait partie du meme formulaire IA que Groq/NVIDIA, géré ci-dessus.
        # On saute directement à la section Teams.
        elif 'teams_webhook_url' in request.form:
            set_config('teams_webhook_url', request.form.get('teams_webhook_url', '').strip())
            threshold_raw = request.form.get('teams_alert_score_threshold', '').strip()
            try:
                threshold_value = int(threshold_raw)
                if not (0 <= threshold_value <= 10):
                    raise ValueError
                set_config('teams_alert_score_threshold', str(threshold_value))
            except ValueError:
                flash('Seuil invalide (nombre entier entre 0 et 10 attendu) — non modifié')
            flash('Configuration Teams enregistrée avec succès')
        elif 'abuseipdb_api_key' in request.form:
            new_key = request.form.get('abuseipdb_api_key', '')
            if new_key:
                set_config('abuseipdb_api_key', new_key.strip())
            flash("Configuration de réputation IP enregistrée avec succès")
        elif 'rh_studio_url' in request.form or 'rh_studio_api_key' in request.form:
            set_config('rh_studio_url', request.form.get('rh_studio_url', '').strip())
            new_rh_key = request.form.get('rh_studio_api_key', '')
            if new_rh_key:
                set_config('rh_studio_api_key', new_rh_key.strip())
            flash('Configuration RH Studio enregistrée avec succès')
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
        graph_client_secret_set=bool(get_config('graph_client_secret', '')),
        public_base_url=get_config('public_base_url', ''),
        microsoft_redirect_uri=_microsoft_redirect_uri(),
        microsoft_redirect_uri_auto=url_for('microsoft_callback', _external=True),
        groq_api_key_set=bool(get_config('groq_api_key', '')),
        groq_default_model=GROQ_DEFAULT_MODEL,
        groq_available_models=GROQ_AVAILABLE_MODELS,
        nvidia_api_key_set=bool(get_config('nvidia_api_key', '')),
        nvidia_default_model=NVIDIA_DEFAULT_MODEL,
        groq_prompt_template=get_config('groq_prompt_template', '') or GROQ_DEFAULT_PROMPT_TEMPLATE,
        teams_webhook_url=get_config('teams_webhook_url', ''),
        teams_alert_score_threshold=get_teams_alert_threshold(),
        abuseipdb_api_key_set=bool(get_config('abuseipdb_api_key', '')),
        rh_studio_url=get_config('rh_studio_url', ''),
        rh_studio_api_key_set=bool(get_config('rh_studio_api_key', '')),
        ollama_enabled=get_config('ollama_enabled', '1'),
        ollama_url=get_config('ollama_url', '') or OLLAMA_DEFAULT_URL,
        ollama_default_model=OLLAMA_DEFAULT_MODEL,
        # Modèles multiples : chaque fournisseur a sa propre liste [{'id','name','model'}, ...],
        # rendue en JSON pour l'initialisation JS de la page (édition/suppression/test en direct)
        # et en objets Python pour l'affichage serveur initial (pas de flash de contenu vide).
        groq_models_list=_load_provider_models('groq'),
        nvidia_models_list=_load_provider_models('nvidia'),
        ollama_models_list=_load_provider_models('ollama'),
        ai_default_model_key=next((m['key'] for m in get_all_ai_models() if m['is_default']), ''))

@app.route('/api/diag/proxy-headers')
@admin_required
def diag_proxy_headers():
    """Diagnostic pour les problemes de reverse proxy (ex: AADSTS50011 avec une URI de
    redirection en http:// alors que l'acces se fait en https://) : affiche exactement ce
    que Flask/ProxyFix voient de la requete en cours, pour distinguer "l'en-tete
    X-Forwarded-Proto n'arrive pas du tout" (probleme cote reverse proxy) de "l'en-tete
    arrive mais le schema calcule reste http" (ProxyFix absent/mal configure, ou code non
    a jour dans le conteneur deploye — la simple existence de cette route en est deja un
    indice, une version anterieure du code n'aurait pas cette route)."""
    return jsonify({
        'computed_scheme (request.scheme)': request.scheme,
        'redirect_uri_auto (ProxyFix/headers)': url_for('microsoft_callback', _external=True),
        'redirect_uri_effective (utilisée réellement, tient compte de public_base_url si défini)': _microsoft_redirect_uri(),
        'public_base_url_configured': get_config('public_base_url', '') or None,
        'wsgi.url_scheme': request.environ.get('wsgi.url_scheme'),
        'header_Host': request.headers.get('Host'),
        'header_X-Forwarded-Proto': request.headers.get('X-Forwarded-Proto'),
        'header_X-Forwarded-Host': request.headers.get('X-Forwarded-Host'),
        'header_X-Forwarded-For': request.headers.get('X-Forwarded-For'),
        'remote_addr': request.remote_addr,
    })

@app.route('/api/test-graph')
@admin_required
def test_api_graph():
    try:
        get_graph_token(force_refresh=True)
        orgs = graph_get_all('/organization')
        org_name = orgs[0].get('displayName') if orgs else 'N/A'
        return jsonify({'success': True, 'message': f"Connexion Microsoft Graph réussie (tenant : {org_name})"})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/test-ai-model', methods=['POST'])
@admin_required
def test_api_ai_model():
    """Teste un modèle précis (bouton « Tester » sur chaque ligne de la page Configuration).
    Fonctionne même si la ligne n'a pas encore été enregistrée : si la clé API / l'URL n'est
    pas fournie dans la requête, on retombe sur celle déjà enregistrée en base."""
    data = request.get_json(silent=True) or {}
    provider = (data.get('provider') or '').strip().lower()
    model = (data.get('model') or '').strip()
    if provider not in ('groq', 'nvidia', 'ollama'):
        return jsonify({'success': False, 'message': 'Fournisseur inconnu'}), 400
    if not model:
        return jsonify({'success': False, 'message': "Identifiant technique du modèle manquant"}), 400

    try:
        if provider == 'groq':
            api_key = (data.get('api_key') or '').strip() or get_config('groq_api_key', '')
            if not api_key:
                return jsonify({'success': False, 'message': 'Clé API Groq non renseignée'})
            reply = call_groq_chat("Réponds uniquement par : OK", api_key=api_key, model=model)
            label = 'Groq'
        elif provider == 'nvidia':
            api_key = (data.get('api_key') or '').strip() or get_config('nvidia_api_key', '')
            if not api_key:
                return jsonify({'success': False, 'message': 'Clé API NVIDIA non renseignée'})
            reply = call_nvidia_chat("Réponds uniquement par : OK", api_key=api_key, model=model)
            label = 'NVIDIA'
        else:
            url = (data.get('url') or '').strip() or get_config('ollama_url', '') or OLLAMA_DEFAULT_URL
            reply = call_ollama_chat("Réponds uniquement par : OK", url=url, model=model)
            label = 'Ollama'
        return jsonify({'success': True, 'message': f"{label} — modèle « {model} » opérationnel, réponse : {reply.strip()[:200]}"})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/test-teams')
@admin_required
def test_teams_webhook():
    webhook_url = get_config('teams_webhook_url', '').strip()
    if not webhook_url:
        return jsonify({'success': False, 'message': "URL du webhook Teams non configurée"})
    ok = send_teams_alert(
        email='test@exemple.fr',
        score=10,
        verdict='compromise_likely',
        findings_summary="[TEST] Ceci est un message de test envoyé depuis la page Configuration",
    )
    if ok:
        return jsonify({'success': True, 'message': 'Message de test envoyé — vérifiez le canal Teams configuré'})
    return jsonify({'success': False, 'message': "Échec de l'envoi — voir les logs (catégorie TEAMS) pour le détail"})

@app.route('/api/test-abuseipdb')
@admin_required
def test_abuseipdb():
    api_key = get_config('abuseipdb_api_key', '').strip()
    if not api_key:
        return jsonify({'success': False, 'message': 'Clé AbuseIPDB non configurée'})
    try:
        # 1.1.1.1 (Cloudflare) : IP stable et publique, pratique pour un test de connexion.
        data = _fetch_abuseipdb('1.1.1.1', api_key)
        return jsonify({'success': True, 'message': (
            f"Connexion à AbuseIPDB réussie — score d'abus pour 1.1.1.1 : "
            f"{data.get('abuseConfidenceScore')}/100 ({data.get('usageType') or 'type inconnu'})")})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/test-ville')
@admin_required
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

@app.route('/api/test-rhstudio')
@admin_required
def test_api_rhstudio():
    import urllib.error, urllib.parse, ssl
    api_url = get_config('rh_studio_url', '').rstrip('/')
    api_key = get_config('rh_studio_api_key', '')
    if not api_url:
        return jsonify({'success': False, 'message': 'URL de l\'API RH Studio non configurée'})
    if not api_key:
        return jsonify({'success': False, 'message': 'Clé API RH Studio non configurée'})
    email = request.args.get('email', '').strip()
    if not email:
        return jsonify({'success': False, 'message': 'Adresse email requise pour tester un utilisateur'})
    base = api_url
    if base.endswith('/api'):
        base = base[:-4]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _rh_studio_request(params):
        qs = urllib.parse.urlencode(params)
        url = f"{base}/api/agents/presence?{qs}"
        req = urllib.request.Request(url, headers={
            'X-Api-Key': api_key,
            'Accept': 'application/json',
        })
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            raw = resp.read().decode('utf-8')
            return json.loads(raw) if raw.strip() else {}

    result_data = {'graph': None, 'rh_studio_email': None, 'rh_studio_name': None}
    nom, prenom = None, None
    try:
        graph_user = graph_get_account_overview(email)
        if graph_user and graph_user.get('displayName'):
            result_data['graph'] = {
                'displayName': graph_user.get('displayName', ''),
                'mail': graph_user.get('mail', ''),
                'jobTitle': graph_user.get('jobTitle', ''),
                'department': graph_user.get('department', ''),
                'accountEnabled': graph_user.get('accountEnabled'),
            }
            parts = graph_user['displayName'].strip().split()
            if len(parts) >= 2:
                prenom = parts[0]
                nom = ' '.join(parts[1:])
            elif len(parts) == 1:
                nom = parts[0]
    except Exception as e:
        result_data['graph'] = {'error': str(e)}

    try:
        result_data['rh_studio_email'] = _rh_studio_request({'email': email})
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8') if e.fp else ''
        result_data['rh_studio_email'] = {'_http_error': e.code, '_body': error_body[:1000]}
    except Exception as e:
        result_data['rh_studio_email'] = {'_error': str(e)}

    if nom:
        try:
            params = {'nom': nom}
            if prenom:
                params['prenom'] = prenom
            result_data['rh_studio_name'] = _rh_studio_request(params)
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8') if e.fp else ''
            result_data['rh_studio_name'] = {'_http_error': e.code, '_body': error_body[:1000]}
        except Exception as e:
            result_data['rh_studio_name'] = {'_error': str(e)}

    return jsonify({
        'success': True,
        'message': f'Résultats pour {email}',
        'response': json.dumps(result_data, ensure_ascii=False, indent=2)
    })

@app.route('/api/test-send')
@admin_required
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
@admin_required
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

@app.route('/boite/<int:bid>/rhstudio-check', methods=['POST'])
@login_required
def rhstudio_check_recipients(bid):
    """Interroge RH Studio pour chaque destinataire unique de la boîte et renvoie
    les résultats (statut de présence). Utilisé en AJAX depuis view_boite.html."""
    api_url = get_config('rh_studio_url', '')
    api_key = get_config('rh_studio_api_key', '')
    if not api_url or not api_key:
        return jsonify({'success': False, 'message': 'RH Studio non configuré (URL ou clé API manquante)'})
    conn = get_db()
    try:
        rows = conn.execute(
            'SELECT DISTINCT recipient_address FROM messages WHERE boite_id=?',
            (bid,)
        ).fetchall()
    finally:
        conn.close()
    results = []
    errors = 0
    for row in rows:
        email = row['recipient_address']
        try:
            resp = rh_studio_check_presence(email=email)
            agent = resp.get('agent')
            status = agent.get('status', 'unknown') if agent else 'not_found'
            status_label = agent.get('statusLabel', 'Non trouvé') if agent else 'Non trouvé'
            results.append({
                'email': email,
                'found': resp.get('found', False),
                'status': status,
                'statusLabel': status_label,
                'agent': {
                    'nom': agent.get('nom', ''),
                    'prenom': agent.get('prenom', ''),
                    'service': agent.get('service', ''),
                    'direction': agent.get('direction', ''),
                    'fonction': agent.get('fonction', ''),
                } if agent else None
            })
        except Exception:
            errors += 1
            results.append({
                'email': email,
                'found': False,
                'status': 'error',
                'statusLabel': 'Erreur',
                'agent': None
            })
    return jsonify({'success': True, 'results': results, 'errors': errors})

@app.route('/api/rh-batch-status', methods=['POST'])
@login_required
def rh_batch_status():
    """Recoit une liste d'emails ET de noms (nom/prenom) en POST JSON et renvoie le
    statut RH Studio de chacun. Utilise en AJAX par le script automatique de pastilles."""
    api_url = get_config('rh_studio_url', '').rstrip('/')
    api_key = get_config('rh_studio_api_key', '')
    if not api_url or not api_key:
        return jsonify({})
    data = request.get_json(silent=True) or {}
    results = {}

    def _extract_agent(email_key, resp):
        agent = resp.get('agent')
        if not agent:
            return {'found': False, 'status': 'not_found', 'statusLabel': 'Non trouvé'}
        info = {
            'found': True,
            'status': agent.get('status', 'unknown'),
            'statusLabel': agent.get('statusLabel', ''),
        }
        for f in ('dateArrivee', 'dateDepart', 'date_arrivee', 'date_depart',
                   'arrivalDate', 'departureDate', 'startDate', 'endDate',
                   'datePriseDePoste', 'dateSortie'):
            val = agent.get(f)
            if val:
                info[f] = val
        return info

    for email in (data.get('emails') or [])[:50]:
        if email in results:
            continue
        try:
            results[email] = _extract_agent(email, rh_studio_check_presence(email=email))
        except Exception:
            results[email] = {'found': False, 'status': 'error', 'statusLabel': 'Erreur'}
    for item in (data.get('names') or [])[:50]:
        nom = item.get('nom', '').strip()
        prenom = item.get('prenom', '').strip()
        key = f"{nom} {prenom}".strip()
        if not nom or key in results:
            continue
        try:
            results[key] = _extract_agent(key, rh_studio_check_presence(nom=nom, prenom=prenom or None))
        except Exception:
            results[key] = {'found': False, 'status': 'error', 'statusLabel': 'Erreur'}
    return jsonify(results)

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
        return redirect(url_for('list_boites'))
    
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
@admin_required
def export_messages(bid):
    import io
    conn = get_db()
    boite = conn.execute('SELECT user_email FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    if not boite:
        conn.close()
        flash('Boîte non trouvée')
        return redirect(url_for('list_boites'))
    
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


# ============================================================================
# API externe (/api/v1/*) : permet a des applications tierces (SOC, dashboard...) de
# consulter les donnees de compromission via des cles d'API delivrees par un
# administrateur (page /admin/api-keys), plutot que par les comptes utilisateurs normaux.
# Chaque cle a une duree de validite optionnelle, peut etre mise en pause sans etre
# supprimee, et chaque appel est journalise (table api_key_usage) pour audit.
# Documentation interactive : /api/docs (Swagger UI, spec generee par /api/v1/openapi.json).
# ============================================================================

API_KEY_PREFIX = 'am_'


def _generate_api_key():
    """Genere une nouvelle cle d'API. Retourne (cle_en_clair, prefixe_affichable, hash).
    La cle en clair n'est renvoyee qu'une fois a la creation : seul le hash est conserve."""
    raw = API_KEY_PREFIX + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw.encode('utf-8')).hexdigest()
    display_prefix = raw[:len(API_KEY_PREFIX) + 8] + '…'
    return raw, display_prefix, key_hash


def _log_api_usage(api_key_id, endpoint, method, status_code):
    try:
        conn = get_db()
        conn.execute('''INSERT INTO api_key_usage (api_key_id, endpoint, method, status_code, ip_address)
                         VALUES (?, ?, ?, ?, ?)''',
                     (api_key_id, endpoint, method, status_code, request.remote_addr))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Erreur log usage API: {e}")


def require_api_key(f):
    """Protege une route /api/v1/* : verifie l'en-tete X-API-Key (cle valide, ni revoquee,
    ni en pause, ni expiree), journalise l'appel (succes ou echec) dans api_key_usage, et
    met a jour last_used_at. La cle validee est exposee via g.api_key pendant la requete."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        supplied = request.headers.get('X-API-Key', '').strip()
        if not supplied:
            _log_api_usage(None, request.path, request.method, 401)
            return jsonify({'error': "Clé API manquante (en-tête 'X-API-Key' requis)"}), 401

        key_hash = hashlib.sha256(supplied.encode('utf-8')).hexdigest()
        conn = get_db()
        row = conn.execute('SELECT * FROM api_keys WHERE key_hash=?', (key_hash,)).fetchone()

        if not row:
            conn.close()
            _log_api_usage(None, request.path, request.method, 401)
            return jsonify({'error': 'Clé API invalide'}), 401
        if row['is_revoked']:
            conn.close()
            _log_api_usage(row['id'], request.path, request.method, 403)
            return jsonify({'error': 'Clé API révoquée'}), 403
        if row['is_paused']:
            conn.close()
            _log_api_usage(row['id'], request.path, request.method, 403)
            return jsonify({'error': 'Clé API en pause'}), 403
        if row['expires_at']:
            expiry = _parse_iso(row['expires_at'])
            if expiry and datetime.now(timezone.utc).replace(tzinfo=None) > expiry:
                conn.close()
                _log_api_usage(row['id'], request.path, request.method, 403)
                return jsonify({'error': 'Clé API expirée'}), 403

        now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        conn.execute('UPDATE api_keys SET last_used_at=? WHERE id=?', (now_iso, row['id']))
        conn.commit()
        conn.close()

        g.api_key = row
        try:
            response = f(*args, **kwargs)
        except Exception:
            _log_api_usage(row['id'], request.path, request.method, 500)
            raise
        status_code = response[1] if isinstance(response, tuple) and len(response) > 1 else getattr(response, 'status_code', 200)
        _log_api_usage(row['id'], request.path, request.method, status_code)
        return response
    return decorated_function


# --- Gestion des cles (reservee aux administrateurs) ------------------------------------

@app.route('/admin/api-keys')
@admin_required
def list_api_keys():
    conn = get_db()
    keys = conn.execute('SELECT * FROM api_keys ORDER BY created_at DESC').fetchall()
    usage_counts = {r['api_key_id']: r['c'] for r in conn.execute(
        'SELECT api_key_id, COUNT(*) as c FROM api_key_usage GROUP BY api_key_id').fetchall()}
    conn.close()
    now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    return render_template('api_keys.html', keys=keys, usage_counts=usage_counts, now_iso=now_iso)


@app.route('/admin/api-keys/add', methods=['POST'])
@admin_required
def add_api_key():
    name = request.form.get('name', '').strip()
    if not name:
        flash("Un nom (usage prévu) est requis pour créer une clé d'API")
        return redirect(url_for('list_api_keys'))

    duration_days = request.form.get('duration_days', '').strip()
    expires_at = None
    if duration_days:
        try:
            days = int(duration_days)
            if days > 0:
                from datetime import timedelta
                expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            flash('Durée de validité invalide (nombre de jours attendu)')
            return redirect(url_for('list_api_keys'))

    raw_key, display_prefix, key_hash = _generate_api_key()
    conn = get_db()
    conn.execute('''INSERT INTO api_keys (name, key_prefix, key_hash, expires_at, created_by)
                     VALUES (?, ?, ?, ?, ?)''',
                 (name, display_prefix, key_hash, expires_at, session.get('username')))
    conn.commit()
    conn.close()
    add_log('INFO', 'API_KEY', f"Clé d'API créée : {name}", f"Expiration : {expires_at or 'jamais'}")
    # La cle en clair n'est affichee qu'une seule fois, juste apres sa creation.
    flash(f"Clé créée : {raw_key} — copiez-la maintenant, elle ne sera plus jamais affichée en entier.")
    return redirect(url_for('list_api_keys'))


@app.route('/admin/api-keys/<int:key_id>/toggle', methods=['POST'])
@admin_required
def toggle_api_key(key_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM api_keys WHERE id=?', (key_id,)).fetchone()
    if not row:
        conn.close()
        flash('Clé non trouvée')
        return redirect(url_for('list_api_keys'))
    new_paused = 0 if row['is_paused'] else 1
    conn.execute('UPDATE api_keys SET is_paused=? WHERE id=?', (new_paused, key_id))
    conn.commit()
    conn.close()
    add_log('INFO', 'API_KEY', f"Clé « {row['name']} » {'mise en pause' if new_paused else 'réactivée'}")
    return redirect(url_for('list_api_keys'))


@app.route('/admin/api-keys/<int:key_id>/revoke', methods=['POST'])
@admin_required
def revoke_api_key(key_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM api_keys WHERE id=?', (key_id,)).fetchone()
    if not row:
        conn.close()
        flash('Clé non trouvée')
        return redirect(url_for('list_api_keys'))
    conn.execute('UPDATE api_keys SET is_revoked=1, is_paused=0 WHERE id=?', (key_id,))
    conn.commit()
    conn.close()
    add_log('WARNING', 'API_KEY', f"Clé « {row['name']} » révoquée définitivement")
    flash(f"Clé « {row['name']} » révoquée")
    return redirect(url_for('list_api_keys'))


@app.route('/admin/api-keys/<int:key_id>/delete', methods=['POST'])
@admin_required
def delete_api_key(key_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM api_keys WHERE id=?', (key_id,)).fetchone()
    if row:
        conn.execute('DELETE FROM api_key_usage WHERE api_key_id=?', (key_id,))
        conn.execute('DELETE FROM api_keys WHERE id=?', (key_id,))
        conn.commit()
        add_log('INFO', 'API_KEY', f"Clé « {row['name']} » supprimée")
    conn.close()
    return redirect(url_for('list_api_keys'))


@app.route('/admin/api-keys/<int:key_id>/usage')
@admin_required
def api_key_usage_detail(key_id):
    conn = get_db()
    key = conn.execute('SELECT * FROM api_keys WHERE id=?', (key_id,)).fetchone()
    if not key:
        conn.close()
        flash('Clé non trouvée')
        return redirect(url_for('list_api_keys'))
    usage = conn.execute('''SELECT * FROM api_key_usage WHERE api_key_id=?
                             ORDER BY created_at DESC LIMIT 200''', (key_id,)).fetchall()
    conn.close()
    return render_template('api_key_usage.html', key=key, usage=usage)


# --- IPs de confiance (ex: IPs de la ville elle-meme) : toujours vertes, badge dedie ------

@app.route('/admin/trusted-ips')
@admin_required
def list_trusted_ips():
    conn = get_db()
    ips = conn.execute('SELECT * FROM trusted_ips ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('trusted_ips.html', ips=ips)


@app.route('/admin/trusted-ips/add', methods=['POST'])
@admin_required
def add_trusted_ip():
    ip = request.form.get('ip', '').strip()
    label = request.form.get('label', '').strip() or 'Ville'
    note = request.form.get('note', '').strip()
    city = request.form.get('city', '').strip()
    lat_raw = request.form.get('lat', '').strip()
    lon_raw = request.form.get('lon', '').strip()
    if not ip:
        flash('Une adresse IP est requise')
        return redirect(url_for('list_trusted_ips'))

    lat = lon = None
    if lat_raw or lon_raw:
        try:
            lat = float(lat_raw)
            lon = float(lon_raw)
        except ValueError:
            flash('Latitude/longitude invalides (nombres décimaux attendus) — IP non ajoutée')
            return redirect(url_for('list_trusted_ips'))

    conn = get_db()
    try:
        conn.execute('INSERT INTO trusted_ips (ip, label, note, city, lat, lon, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (ip, label, note, city or None, lat, lon, session.get('username')))
        conn.commit()
        # Le prochain affichage de cette IP doit refleter immediatement son nouveau statut
        # de confiance plutot que d'attendre l'expiration du cache de reputation existant.
        conn.execute('UPDATE ip_info SET reputation_checked_at=NULL WHERE ip=?', (ip,))
        conn.commit()
        add_log('INFO', 'TRUSTED_IP', f"IP de confiance ajoutée : {ip} ({label})")
        flash(f"IP {ip} ajoutée comme IP de confiance")
    except sqlite3.IntegrityError:
        flash(f"L'IP {ip} est déjà déclarée comme IP de confiance")
    finally:
        conn.close()
    return redirect(url_for('list_trusted_ips'))


@app.route('/admin/trusted-ips/<int:trusted_id>/delete', methods=['POST'])
@admin_required
def delete_trusted_ip(trusted_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM trusted_ips WHERE id=?', (trusted_id,)).fetchone()
    if row:
        conn.execute('DELETE FROM trusted_ips WHERE id=?', (trusted_id,))
        conn.execute('UPDATE ip_info SET reputation_checked_at=NULL WHERE ip=?', (row['ip'],))
        conn.commit()
        add_log('INFO', 'TRUSTED_IP', f"IP de confiance retirée : {row['ip']}")
    conn.close()
    return redirect(url_for('list_trusted_ips'))


# --- Endpoints exposes aux applications externes (authentification par cle d'API) -------

@app.route('/api/v1/health')
@require_api_key
def api_v1_health():
    return jsonify({'status': 'ok', 'time': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')})


@app.route('/api/v1/monitored-mailboxes')
@require_api_key
def api_v1_monitored_mailboxes():
    conn = get_db()
    rows = conn.execute('SELECT * FROM monitored_mailboxes ORDER BY user_email').fetchall()
    conn.close()
    return jsonify([{
        'id': r['id'],
        'user_email': r['user_email'],
        'is_active': bool(r['is_active']),
        'interval_minutes': r['interval_minutes'],
        'last_scan_at': r['last_scan_at'],
        'last_scan_score': r['last_scan_score'],
        'last_scan_verdict': r['last_scan_verdict'],
        'last_scan_findings_count': r['last_scan_findings_count'],
        'last_scan_findings_summary': r['last_scan_findings_summary'],
        'last_error': r['last_error'],
    } for r in rows])


@app.route('/api/v1/monitored-mailboxes/<int:mailbox_id>')
@require_api_key
def api_v1_monitored_mailbox_detail(mailbox_id):
    conn = get_db()
    r = conn.execute('SELECT * FROM monitored_mailboxes WHERE id=?', (mailbox_id,)).fetchone()
    conn.close()
    if not r:
        return jsonify({'error': 'Boîte surveillée non trouvée'}), 404
    return jsonify({
        'id': r['id'],
        'user_email': r['user_email'],
        'is_active': bool(r['is_active']),
        'interval_minutes': r['interval_minutes'],
        'last_scan_at': r['last_scan_at'],
        'last_scan_score': r['last_scan_score'],
        'last_scan_verdict': r['last_scan_verdict'],
        'last_scan_findings_count': r['last_scan_findings_count'],
        'last_scan_findings_summary': r['last_scan_findings_summary'],
        'last_error': r['last_error'],
    })


@app.route('/api/v1/boites')
@require_api_key
def api_v1_boites():
    email = request.args.get('email', '').strip().lower()
    conn = get_db()
    if email:
        rows = conn.execute('SELECT * FROM boites_compromises WHERE lower(user_email)=? ORDER BY created_at DESC', (email,)).fetchall()
    else:
        rows = conn.execute('SELECT * FROM boites_compromises ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify([{
        'id': r['id'],
        'user_email': r['user_email'],
        'date_compromission': r['date_compromission'],
        'heure_compromission': r['heure_compromission'],
        'date_decouverte': r['date_decouverte'],
        'created_at': r['created_at'],
    } for r in rows])


@app.route('/api/v1/boites/<int:bid>')
@require_api_key
def api_v1_boite_detail(bid):
    conn = get_db()
    boite = conn.execute('SELECT * FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    conn.close()
    if not boite:
        return jsonify({'error': 'Boîte non trouvée'}), 404
    analysis = analyze_compromise(bid)
    return jsonify({
        'id': boite['id'],
        'user_email': boite['user_email'],
        'date_compromission': boite['date_compromission'],
        'heure_compromission': boite['heure_compromission'],
        'date_decouverte': boite['date_decouverte'],
        'notes': boite['notes'],
        'created_at': boite['created_at'],
        'risk_score': analysis['score'],
        'risk_verdict': analysis['verdict'],
        'findings': [{'severity': f['severity'], 'title': f['title'], 'description': f['description']}
                     for f in analysis['findings']],
        'ai_analysis': boite['ai_analysis'],
        'ai_analysis_model': boite['ai_analysis_model'],
        'ai_analysis_provider': boite['ai_analysis_provider'],
        'ai_analysis_at': boite['ai_analysis_at'],
    })


@app.route('/api/v1/boites/<int:bid>/ai-analyze', methods=['POST'])
@require_api_key
def api_v1_boite_ai_analyze(bid):
    """Lance (ou relance) l'analyse IA d'une boîte compromise pour une application
    externe (ex: PGC) qui n'a pas de session utilisateur et ne peut donc pas utiliser
    le bouton "Analyser avec l'IA" de l'interface ni /jobs/<job_id>/poll (protégés par
    connexion, pas par clé API — voir le before_request qui exempte uniquement
    /api/v1/*). Même moteur que ai_analyze_start, suivi via /api/v1/jobs/<job_id>.
    Sans cet endpoint, une application externe ne pouvait QUE lire ai_analysis s'il
    avait déjà été généré depuis l'interface — jamais le déclencher elle-même, ce qui
    le laissait indéfiniment vide côté intégrations tierces."""
    conn = get_db()
    boite = conn.execute('SELECT user_email FROM boites_compromises WHERE id=?', (bid,)).fetchone()
    conn.close()
    if not boite:
        return jsonify({'error': 'Boîte non trouvée'}), 404
    if not any(m['active'] for m in get_all_ai_models()):
        return jsonify({'error': "Aucun fournisseur IA configuré (Groq, NVIDIA ou Ollama) — demandez à un administrateur de le renseigner dans Configuration."}), 400

    job_id = _job_create(['ai'])

    def worker():
        _job_step(job_id, 'ai', 'running')
        try:
            result_text, provider, model = run_ai_analysis(bid)
            now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            conn2 = get_db()
            conn2.execute('''UPDATE boites_compromises SET
                ai_analysis=?, ai_analysis_at=?, ai_analysis_model=?, ai_analysis_provider=? WHERE id=?''',
                          (result_text, now_iso, model, provider, bid))
            conn2.commit()
            conn2.close()
            add_log('INFO', 'IA', f"Analyse IA (API externe) effectuée pour {boite['user_email']}", f'Fournisseur : {provider}, modèle : {model}', bid)
            _job_step(job_id, 'ai', 'done')
            _job_finish(job_id, result={'ok': True})
        except Exception as e:
            add_log('ERROR', 'IA', f"Échec de l'analyse IA (API externe) pour {boite['user_email']}", str(e), bid)
            _job_step(job_id, 'ai', 'error')
            _job_finish(job_id, error=str(e))

    threading.Thread(target=worker, daemon=True, name=f'api-ai-analyze-{bid}').start()
    return jsonify({'job_id': job_id})


@app.route('/api/v1/jobs/<job_id>')
@require_api_key
def api_v1_job_status(job_id):
    """Etat d'un job en arrière-plan déclenché via l'API externe (ex:
    /api/v1/boites/<bid>/ai-analyze) — équivalent de /jobs/<job_id>/poll mais
    protégé par clé API au lieu d'une session utilisateur."""
    job = _job_get(job_id)
    if not job:
        return jsonify({'error': 'not_found'}), 404
    return jsonify({'status': job['status'], 'steps': job['steps'], 'order': job['order'], 'error': job['error']})


@app.route('/api/v1/ip/<ip>')
@require_api_key
def api_v1_ip_reputation(ip):
    """Reputation d'une IP (score d'abus, type d'usage, geolocalisation...) pour les
    applications externes — meme donnee que la pastille affichee dans l'interface
    (voir ip_reputation_payload), servie depuis le cache local (rafraichi toutes les
    IP_REPUTATION_CACHE_HOURS heures) plutot que d'interroger AbuseIPDB a chaque appel."""
    payload = ip_reputation_payload(ip)
    if not payload:
        return jsonify({'error': 'IP invalide ou réputation indisponible'}), 404
    return jsonify(payload)


@app.route('/api/v1/kpis')
@require_api_key
def api_v1_kpis():
    """KPI du tableau de bord pour les applications externes — memes chiffres que la page
    d'accueil (voir compute_dashboard_kpis, source unique partagee par les deux)."""
    kpis = compute_dashboard_kpis()
    kpis['generated_at'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    return jsonify(kpis)


@app.route('/api/v1/openapi.json')
def api_v1_openapi():
    """Specification OpenAPI 3.0 de l'API externe (/api/v1/*), consommee par la page
    /api/docs (Swagger UI). Non protegee par cle d'API (c'est une simple documentation)."""
    base = get_config('public_base_url', '').strip().rstrip('/')
    servers = [{'url': (base + '/api/v1') if base else '/api/v1'}]
    verdict_enum = list(VERDICT_LABELS.keys())

    mailbox_schema = {
        'type': 'object',
        'properties': {
            'id': {'type': 'integer'},
            'user_email': {'type': 'string', 'format': 'email'},
            'is_active': {'type': 'boolean'},
            'interval_minutes': {'type': 'integer'},
            'last_scan_at': {'type': 'string', 'format': 'date-time', 'nullable': True},
            'last_scan_score': {'type': 'integer', 'nullable': True, 'minimum': 0, 'maximum': 10},
            'last_scan_verdict': {'type': 'string', 'enum': verdict_enum, 'nullable': True},
            'last_scan_findings_count': {'type': 'integer', 'nullable': True},
            'last_scan_findings_summary': {'type': 'string', 'nullable': True},
            'last_error': {'type': 'string', 'nullable': True},
        }
    }
    boite_schema = {
        'type': 'object',
        'properties': {
            'id': {'type': 'integer'},
            'user_email': {'type': 'string', 'format': 'email'},
            'date_compromission': {'type': 'string', 'nullable': True},
            'heure_compromission': {'type': 'string', 'nullable': True},
            'date_decouverte': {'type': 'string', 'nullable': True},
            'created_at': {'type': 'string'},
        }
    }
    boite_detail_schema = {
        'allOf': [boite_schema, {'type': 'object', 'properties': {
            'notes': {'type': 'string', 'nullable': True},
            'risk_score': {'type': 'integer', 'minimum': 0, 'maximum': 10},
            'risk_verdict': {'type': 'string', 'enum': verdict_enum},
            'findings': {'type': 'array', 'items': {'type': 'object', 'properties': {
                'severity': {'type': 'string', 'enum': ['low', 'medium', 'high', 'critical']},
                'title': {'type': 'string'},
                'description': {'type': 'string'},
            }}},
        }}]
    }
    error_response = {
        'description': "Erreur (clé manquante, invalide, en pause, révoquée ou expirée)",
        'content': {'application/json': {'schema': {'type': 'object', 'properties': {
            'error': {'type': 'string'}}}}},
    }
    ip_reputation_schema = {
        'type': 'object',
        'properties': {
            'ip': {'type': 'string'},
            'level': {'type': 'string', 'enum': ['green', 'orange', 'red']},
            'level_label': {'type': 'string'},
            'basis_label': {'type': 'string'},
            'country': {'type': 'string'},
            'city': {'type': 'string'},
            'isp': {'type': 'string'},
            'org': {'type': 'string'},
            'asn': {'type': 'string'},
            'hostname': {'type': 'string'},
            'usage_type': {'type': 'string'},
            'domain': {'type': 'string'},
            'abuse_score': {'type': 'integer', 'nullable': True, 'minimum': 0, 'maximum': 100},
            'total_reports': {'type': 'integer', 'nullable': True},
            'is_whitelisted': {'type': 'boolean'},
            'last_reported_at': {'type': 'string', 'nullable': True},
            'is_vpn': {'type': 'boolean'},
            'is_trusted': {'type': 'boolean', 'description': "IP déclarée de confiance par un administrateur (page IPs de confiance)."},
            'trusted_label': {'type': 'string'},
            'is_datacenter': {'type': 'boolean', 'description': (
                "Type d'usage \"Data Center/Web Hosting/Transit\" — jamais vrai pour une IP de confiance.")},
            'is_fixed_line_isp': {'type': 'boolean', 'description': 'Type d\'usage "Fixed Line ISP".'},
            'is_mobile_isp': {'type': 'boolean', 'description': 'Type d\'usage "Mobile ISP".'},
        }
    }

    geo_point_schema = {
        'type': 'object',
        'description': 'Connexions agrégées pour un lieu (ville), destiné à un affichage cartographique.',
        'properties': {
            'city': {'type': 'string'}, 'country': {'type': 'string'}, 'country_code': {'type': 'string'},
            'count': {'type': 'integer'}, 'fail_count': {'type': 'integer'},
            'trust_score': {'type': 'integer', 'minimum': 0, 'maximum': 100},
            'is_suspicious': {'type': 'boolean'},
            'lat': {'type': 'number'}, 'lon': {'type': 'number'},
        }
    }

    kpis_schema = {
        'type': 'object',
        'description': "Memes chiffres que la page d'accueil de l'application (tableau de bord).",
        'properties': {
            'nb_boites_total': {'type': 'integer', 'description': 'Nombre total d\'incidents confirmés.'},
            'incidents_by_month': {'type': 'array', 'items': {'type': 'object', 'properties': {
                'month': {'type': 'string', 'example': '2026-01'}, 'c': {'type': 'integer'}}}},
            'verdict_counts': {'type': 'object', 'description': (
                "Répartition du niveau de signal détecté sur les incidents les plus récents "
                "(scored_boites_count), à partir des preuves déjà importées — pas si l'incident "
                "est réel (il l'est déjà, par définition)."),
                'properties': {
                    'compromise_likely': {'type': 'integer'}, 'signals_to_check': {'type': 'integer'},
                    'no_strong_signal': {'type': 'integer'}}},
            'scored_boites_count': {'type': 'integer'},
            'shared_ips': {'type': 'array', 'items': {'type': 'object', 'properties': {
                'ip': {'type': 'string'}, 'nb_boites': {'type': 'integer'}}},
                'description': 'IPs présentes sur plusieurs boîtes différentes (signal de compromission croisée).'},
            'top_recipients': {'type': 'array', 'items': {'type': 'object', 'properties': {
                'recipient_address': {'type': 'string'}, 'c': {'type': 'integer'}}}},
            'nb_monitored_total': {'type': 'integer'},
            'nb_monitored_active': {'type': 'integer'},
            'nb_monitored_errors': {'type': 'integer'},
            'monitored_verdict_counts': {'type': 'object', 'properties': {
                'compromise_likely': {'type': 'integer'}, 'signals_to_check': {'type': 'integer'},
                'no_strong_signal': {'type': 'integer'}, 'not_scanned': {'type': 'integer'}}},
            'signins_window_hours': {'type': 'integer'},
            'nb_signins_window': {'type': 'integer'},
            'nb_signins_failed_window': {'type': 'integer'},
            'signin_failure_rate': {'type': 'integer', 'description': 'Pourcentage (0-100).'},
            'top_failed_users': {'type': 'array', 'items': {'type': 'object', 'properties': {
                'user_upn': {'type': 'string'}, 'c': {'type': 'integer'}}}},
            'nb_signins_foreign': {'type': 'integer', 'description': 'Connexions hors du pays de référence.'},
            'home_country_code': {'type': 'string', 'example': 'FR'},
            'avg_trust_score': {'type': 'integer', 'nullable': True, 'minimum': 0, 'maximum': 100},
            'nb_low_trust': {'type': 'integer', 'description': 'Connexions à score de confiance < 50.'},
            'connections_geo_world': {'type': 'array', 'description': 'Connexions groupées par ville, pour affichage sur une carte.',
                'items': {'$ref': '#/components/schemas/GeoPoint'}},
            'connections_geo_home': {'type': 'array', 'description': 'Sous-ensemble de connections_geo_world limité au pays de référence.',
                'items': {'$ref': '#/components/schemas/GeoPoint'}},
            'generated_at': {'type': 'string', 'format': 'date-time'},
        }
    }

    spec = {
        'openapi': '3.0.3',
        'info': {
            'title': 'Analyse-Mail API',
            'description': (
                "API en lecture seule permettant à une application externe de consulter l'état de "
                "compromission des boîtes surveillées et des incidents déjà investigués. "
                "Authentification par clé d'API (en-tête `X-API-Key`), délivrée depuis la page "
                "d'administration **Clés d'API**."
            ),
            'version': '1.0.0',
        },
        'servers': servers,
        'security': [{'ApiKeyAuth': []}],
        'components': {
            'securitySchemes': {
                'ApiKeyAuth': {'type': 'apiKey', 'in': 'header', 'name': 'X-API-Key'},
            },
            'schemas': {
                'MonitoredMailbox': mailbox_schema,
                'Boite': boite_schema,
                'BoiteDetail': boite_detail_schema,
                'IpReputation': ip_reputation_schema,
                'Kpis': kpis_schema,
                'GeoPoint': geo_point_schema,
            },
            'responses': {
                'Unauthorized': error_response,
            },
        },
        'paths': {
            '/health': {'get': {
                'summary': "Vérifie que la clé d'API est valide",
                'operationId': 'getHealth',
                'responses': {
                    '200': {'description': 'OK', 'content': {'application/json': {'schema': {
                        'type': 'object', 'properties': {'status': {'type': 'string'}, 'time': {'type': 'string'}}}}}},
                    '401': {'$ref': '#/components/responses/Unauthorized'},
                },
            }},
            '/monitored-mailboxes': {'get': {
                'summary': 'Liste les boîtes surveillées et leur dernier résultat de scan',
                'operationId': 'listMonitoredMailboxes',
                'responses': {
                    '200': {'description': 'OK', 'content': {'application/json': {'schema': {
                        'type': 'array', 'items': {'$ref': '#/components/schemas/MonitoredMailbox'}}}}},
                    '401': {'$ref': '#/components/responses/Unauthorized'},
                },
            }},
            '/monitored-mailboxes/{id}': {'get': {
                'summary': 'Détail d\'une boîte surveillée',
                'operationId': 'getMonitoredMailbox',
                'parameters': [{'name': 'id', 'in': 'path', 'required': True, 'schema': {'type': 'integer'}}],
                'responses': {
                    '200': {'description': 'OK', 'content': {'application/json': {'schema': {
                        '$ref': '#/components/schemas/MonitoredMailbox'}}}},
                    '401': {'$ref': '#/components/responses/Unauthorized'},
                    '404': {'description': 'Non trouvée'},
                },
            }},
            '/boites': {'get': {
                'summary': "Liste les incidents de compromission (fiches d'investigation)",
                'operationId': 'listBoites',
                'responses': {
                    '200': {'description': 'OK', 'content': {'application/json': {'schema': {
                        'type': 'array', 'items': {'$ref': '#/components/schemas/Boite'}}}}},
                    '401': {'$ref': '#/components/responses/Unauthorized'},
                },
            }},
            '/boites/{id}': {'get': {
                'summary': "Détail d'un incident, avec score de risque et signaux détectés",
                'operationId': 'getBoite',
                'parameters': [{'name': 'id', 'in': 'path', 'required': True, 'schema': {'type': 'integer'}}],
                'responses': {
                    '200': {'description': 'OK', 'content': {'application/json': {'schema': {
                        '$ref': '#/components/schemas/BoiteDetail'}}}},
                    '401': {'$ref': '#/components/responses/Unauthorized'},
                    '404': {'description': 'Non trouvée'},
                },
            }},
            '/ip/{ip}': {'get': {
                'summary': "Réputation d'une IP (score d'abus, type d'usage, géolocalisation...)",
                'operationId': 'getIpReputation',
                'parameters': [{'name': 'ip', 'in': 'path', 'required': True, 'schema': {'type': 'string'}, 'example': '1.1.1.1'}],
                'responses': {
                    '200': {'description': 'OK', 'content': {'application/json': {'schema': {
                        '$ref': '#/components/schemas/IpReputation'}}}},
                    '401': {'$ref': '#/components/responses/Unauthorized'},
                    '404': {'description': 'IP invalide ou réputation indisponible'},
                },
            }},
            '/kpis': {'get': {
                'summary': "KPI du tableau de bord (incidents, surveillance, connexions)",
                'operationId': 'getKpis',
                'responses': {
                    '200': {'description': 'OK', 'content': {'application/json': {'schema': {
                        '$ref': '#/components/schemas/Kpis'}}}},
                    '401': {'$ref': '#/components/responses/Unauthorized'},
                },
            }},
        },
    }
    return jsonify(spec)


@app.route('/api/docs')
@admin_required
def api_docs():
    return render_template('api_docs.html')


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
