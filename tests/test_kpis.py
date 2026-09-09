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
