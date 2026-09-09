"""Actions DSI : ajout avec date/heure, edition (texte + date/heure), tracabilite."""
from conftest import login_as_default_admin


def _create_boite(client):
    client.post('/boite/add', data={
        'user_email': 'victime@example.fr',
        'date_compromission': '2026-01-01',
        'heure_compromission': '10:00',
        'date_decouverte': '2026-01-02',
        'notes': '',
    }, follow_redirects=True)
    import app as appmod
    conn = appmod.get_db()
    bid = conn.execute('SELECT id FROM boites_compromises ORDER BY id DESC LIMIT 1').fetchone()['id']
    conn.close()
    return bid


def test_add_dsi_action_with_custom_datetime(client):
    login_as_default_admin(client)
    bid = _create_boite(client)

    client.post(f'/boite/{bid}/dsi-actions/add', data={
        'action_text': 'Mot de passe réinitialisé',
        'action_at': '2026-09-01T10:30',
    }, follow_redirects=True)

    import app as appmod
    conn = appmod.get_db()
    row = conn.execute('SELECT * FROM dsi_actions WHERE boite_id=?', (bid,)).fetchone()
    conn.close()
    assert row is not None
    assert row['action_text'] == 'Mot de passe réinitialisé'
    assert row['action_at'] == '2026-09-01T10:30'


def test_add_dsi_action_without_datetime_defaults_to_now(client):
    login_as_default_admin(client)
    bid = _create_boite(client)
    client.post(f'/boite/{bid}/dsi-actions/add', data={'action_text': 'MFA renforcé'}, follow_redirects=True)

    import app as appmod
    conn = appmod.get_db()
    row = conn.execute('SELECT * FROM dsi_actions WHERE boite_id=?', (bid,)).fetchone()
    conn.close()
    assert row['action_at']  # une valeur par defaut a bien ete posee, pas de champ vide


def test_edit_dsi_action_updates_text_and_datetime(client):
    login_as_default_admin(client)
    bid = _create_boite(client)
    client.post(f'/boite/{bid}/dsi-actions/add', data={
        'action_text': 'Texte initial', 'action_at': '2026-09-01T10:00',
    }, follow_redirects=True)

    import app as appmod
    conn = appmod.get_db()
    action_id = conn.execute('SELECT id FROM dsi_actions WHERE boite_id=?', (bid,)).fetchone()['id']
    conn.close()

    client.post(f'/boite/{bid}/dsi-actions/{action_id}/edit', data={
        'action_text': 'Texte corrigé', 'action_at': '2026-09-02T08:00',
    }, follow_redirects=True)

    conn = appmod.get_db()
    row = conn.execute('SELECT * FROM dsi_actions WHERE id=?', (action_id,)).fetchone()
    conn.close()
    assert row['action_text'] == 'Texte corrigé'
    assert row['action_at'] == '2026-09-02T08:00'
    assert row['updated_by'] == 'admin'
    assert row['updated_at']
