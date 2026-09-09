"""KPI du tableau de bord : cohérence page d'accueil / API externe."""
import re

from conftest import login_as_default_admin


def _extract_raw_key(html):
    m = re.search(r'Cl\xc3\xa9 cr\xc3\xa9\xc3\xa9e ?: ?(am_[A-Za-z0-9_\-]+)', html)
    if not m:
        m = re.search(r'Cl.{1,3} cr.{1,3}e ?: ?(am_[A-Za-z0-9_\-]+)', html)
    assert m
    return m.group(1)


def test_homepage_is_dashboard(client):
    login_as_default_admin(client)
    r = client.get('/')
    assert r.status_code == 200
    assert 'Incidents confirmés'.encode('utf-8') in r.data


def test_boites_list_moved_to_boites(client):
    login_as_default_admin(client)
    r = client.get('/boites')
    assert r.status_code == 200


def test_kpis_endpoint_requires_api_key(client):
    r = client.get('/api/v1/kpis')
    assert r.status_code == 401


def test_kpis_endpoint_matches_dashboard_numbers(client, app_module):
    login_as_default_admin(client)
    client.post('/boite/add', data={
        'user_email': 'victime@example.fr', 'date_compromission': '2026-01-01',
        'heure_compromission': '10:00', 'date_decouverte': '2026-01-02', 'notes': '',
    })

    r = client.post('/admin/api-keys/add', data={'name': 'Test', 'duration_days': ''}, follow_redirects=True)
    raw_key = _extract_raw_key(r.get_data(as_text=True))

    api_resp = client.get('/api/v1/kpis', headers={'X-API-Key': raw_key})
    assert api_resp.status_code == 200
    data = api_resp.get_json()
    assert data['nb_boites_total'] == 1
    assert 'generated_at' in data

    # Meme source de verite que la page d'accueil.
    dashboard_kpis = app_module.compute_dashboard_kpis()
    assert data['nb_boites_total'] == dashboard_kpis['nb_boites_total']
    assert data['nb_monitored_total'] == dashboard_kpis['nb_monitored_total']


def test_connections_geo_groups_by_city_and_flags_suspicious(app_module, monkeypatch):
    """Regression : les lieux avec beaucoup d'echecs (ou une confiance moyenne faible)
    doivent ressortir marques 'is_suspicious' pour clignoter sur la carte, les autres non."""
    conn = app_module.get_db()
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    conn.execute("INSERT OR REPLACE INTO ip_info (ip, country, country_code, city, lat, lon) VALUES "
                 "('1.1.1.1', 'France', 'FR', 'Paris', 48.85, 2.35)")
    conn.execute("INSERT OR REPLACE INTO ip_info (ip, country, country_code, city, lat, lon) VALUES "
                 "('2.2.2.2', 'Nowhereland', 'XX', 'Nowhere City', 10.0, 10.0)")
    for i in range(2):
        conn.execute("INSERT INTO tenant_signins (request_id, date_utc, ip_address, country, status, fetched_at) "
                     "VALUES (?, ?, '1.1.1.1', 'FR', 'Success', ?)", (f'ok-{i}', now, now))
    for i in range(3):
        conn.execute("INSERT INTO tenant_signins (request_id, date_utc, ip_address, country, status, fetched_at) "
                     "VALUES (?, ?, '2.2.2.2', 'XX', 'Failure', ?)", (f'bad-{i}', now, now))
    conn.commit()
    conn.close()

    kpis = app_module.compute_dashboard_kpis()
    by_city = {p['city']: p for p in kpis['connections_geo_world']}

    assert by_city['Paris']['count'] == 2
    assert by_city['Paris']['is_suspicious'] is False

    assert by_city['Nowhere City']['count'] == 3
    assert by_city['Nowhere City']['fail_count'] == 3
    assert by_city['Nowhere City']['is_suspicious'] is True

    # connections_geo_home ne garde que le pays de reference (FR par defaut).
    home_cities = {p['city'] for p in kpis['connections_geo_home']}
    assert 'Paris' in home_cities
    assert 'Nowhere City' not in home_cities
