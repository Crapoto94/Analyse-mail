"""Scan rapide a la demande via l'API externe (/api/v1/scan)."""
import re
import time

from conftest import login_as_default_admin


def _extract_raw_key(html):
    m = re.search(r'Cl\xc3\xa9 cr\xc3\xa9\xc3\xa9e ?: ?(am_[A-Za-z0-9_\-]+)', html)
    if not m:
        m = re.search(r'Cl.{1,3} cr.{1,3}e ?: ?(am_[A-Za-z0-9_\-]+)', html)
    assert m, "impossible d'extraire la cle en clair depuis le message flash"
    return m.group(1)


def _make_key(client):
    login_as_default_admin(client)
    r = client.post('/admin/api-keys/add', data={'name': 'Scan App', 'duration_days': ''}, follow_redirects=True)
    return _extract_raw_key(r.get_data(as_text=True))


def test_scan_requires_key(client):
    r = client.post('/api/v1/scan', json={'email': 'a@b.fr'})
    assert r.status_code == 401


def test_scan_validates_email(client):
    key = _make_key(client)
    r = client.post('/api/v1/scan', json={'email': 'not-an-email'}, headers={'X-API-Key': key})
    assert r.status_code == 400


def test_scan_job_and_result(client, app_module, monkeypatch):
    key = _make_key(client)

    def fake_scan(email, days=7, on_step=None):
        return {'score': 7, 'verdict': 'compromise_likely', 'findings': [
            {'severity': 'critical', 'title': 'T', 'description': 'D'}],
            'nb_signins': 3, 'nb_audit': 1, 'nb_rules': 0, 'days': days, 'errors': []}

    monkeypatch.setattr(app_module, 'quick_scan_mailbox', fake_scan)

    r = client.post('/api/v1/scan', json={'email': 'victime@ivry.fr'}, headers={'X-API-Key': key})
    assert r.status_code == 202
    job_id = r.get_json()['job_id']

    data = None
    for _ in range(100):
        rr = client.get(f'/api/v1/jobs/{job_id}', headers={'X-API-Key': key})
        data = rr.get_json()
        if data['status'] != 'running':
            break
        time.sleep(0.05)

    assert data['status'] == 'done'
    assert data['result']['score'] == 7
    assert data['result']['verdict_label'] == 'Compromission probable'
    assert data['result']['findings'][0]['severity'] == 'critical'
