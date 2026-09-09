"""Score de confiance des connexions (page /connexions)."""


def test_trusted_ip_scores_100(app_module):
    payload = {'is_trusted': True, 'is_vpn': False, 'level': 'green'}
    assert app_module.compute_connection_trust_score(payload, 'US') == 100


def test_home_country_scores_higher_than_europe_and_elsewhere(app_module):
    f = app_module.compute_connection_trust_score
    home = f(None, 'FR')
    europe = f(None, 'DE')
    elsewhere = f(None, 'US')
    assert home > europe > elsewhere


def test_vpn_and_bad_reputation_lower_the_score(app_module):
    f = app_module.compute_connection_trust_score
    baseline = f({'is_vpn': False, 'level': 'green'}, 'FR')
    with_vpn = f({'is_vpn': True, 'level': 'green'}, 'FR')
    with_red = f({'is_vpn': False, 'level': 'red'}, 'FR')
    assert with_vpn < baseline
    assert with_red < baseline


def test_score_is_clamped_between_0_and_100(app_module):
    f = app_module.compute_connection_trust_score
    score = f({'is_vpn': True, 'level': 'red'}, 'XX')
    assert 0 <= score <= 100


def test_home_country_configurable(app_module, client):
    from conftest import login_as_default_admin
    login_as_default_admin(client)
    client.post('/connexions/settings', data={
        'refresh_minutes': '5', 'retention_hours': '48', 'home_country_code': 'DE',
    })
    assert app_module.get_home_country_code() == 'DE'
    assert app_module.compute_connection_trust_score(None, 'DE') > app_module.compute_connection_trust_score(None, 'FR')
