"""Cles d'API externes : creation, authentification, pause/revocation."""
import re

from conftest import login_as_default_admin


def _extract_raw_key(html):
    m = re.search(r'Cl\xc3\xa9 cr\xc3\xa9\xc3\xa9e ?: ?(am_[A-Za-z0-9_\-]+)', html)
    if not m:
        m = re.search(r'Cl.{1,3} cr.{1,3}e ?: ?(am_[A-Za-z0-9_\-]+)', html)
    assert m, "impossible d'extraire la cle en clair depuis le message flash"
    return m.group(1)


def test_health_requires_a_valid_key(client):
    r = client.get('/api/v1/health')
    assert r.status_code == 401

    r2 = client.get('/api/v1/health', headers={'X-API-Key': 'bogus'})
    assert r2.status_code == 401


def test_key_lifecycle(client):
    login_as_default_admin(client)
    r = client.post('/admin/api-keys/add', data={'name': 'Test App', 'duration_days': ''}, follow_redirects=True)
    raw_key = _extract_raw_key(r.get_data(as_text=True))

    r2 = client.get('/api/v1/health', headers={'X-API-Key': raw_key})
    assert r2.status_code == 200
    assert r2.get_json()['status'] == 'ok'

    import app as appmod
    conn = appmod.get_db()
    key_id = conn.execute('SELECT id FROM api_keys ORDER BY id DESC LIMIT 1').fetchone()['id']
    conn.close()

    # Pause -> 403
    client.post(f'/admin/api-keys/{key_id}/toggle', follow_redirects=True)
    r3 = client.get('/api/v1/health', headers={'X-API-Key': raw_key})
    assert r3.status_code == 403

    # Reactivation -> 200
    client.post(f'/admin/api-keys/{key_id}/toggle', follow_redirects=True)
    r4 = client.get('/api/v1/health', headers={'X-API-Key': raw_key})
    assert r4.status_code == 200

    # Revocation -> 403 de facon permanente
    client.post(f'/admin/api-keys/{key_id}/revoke', follow_redirects=True)
    r5 = client.get('/api/v1/health', headers={'X-API-Key': raw_key})
    assert r5.status_code == 403


def test_usage_is_logged(client):
    login_as_default_admin(client)
    r = client.post('/admin/api-keys/add', data={'name': 'Test App 2', 'duration_days': ''}, follow_redirects=True)
    raw_key = _extract_raw_key(r.get_data(as_text=True))
    client.get('/api/v1/health', headers={'X-API-Key': raw_key})

    import app as appmod
    conn = appmod.get_db()
    count = conn.execute('SELECT COUNT(*) as c FROM api_key_usage').fetchone()['c']
    conn.close()
    assert count >= 1
