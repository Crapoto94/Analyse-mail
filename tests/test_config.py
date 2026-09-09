"""Parametres de configuration reglables depuis l'UI admin (Configuration)."""
from conftest import login_as_default_admin


def test_teams_alert_threshold_default(app_module):
    assert app_module.get_teams_alert_threshold() == app_module.TEAMS_ALERT_SCORE_THRESHOLD_DEFAULT


def test_teams_alert_threshold_is_saveable(client, app_module):
    login_as_default_admin(client)
    client.post('/config', data={'teams_webhook_url': '', 'teams_alert_score_threshold': '7'}, follow_redirects=True)
    assert app_module.get_teams_alert_threshold() == 7


def test_teams_alert_threshold_rejects_invalid_value(client, app_module):
    login_as_default_admin(client)
    client.post('/config', data={'teams_webhook_url': '', 'teams_alert_score_threshold': '3'}, follow_redirects=True)
    assert app_module.get_teams_alert_threshold() == 3
    client.post('/config', data={'teams_webhook_url': '', 'teams_alert_score_threshold': 'not-a-number'}, follow_redirects=True)
    # Valeur invalide : la precedente doit etre conservee, pas de crash.
    assert app_module.get_teams_alert_threshold() == 3
