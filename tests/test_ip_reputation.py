"""Reputation IP : seuils de couleur, repli heuristique, IPs de confiance.

Tests unitaires purs sur _compute_reputation_level (aucun acces reseau/DB) + tests
d'integration sur ip_reputation_payload avec get_ip_info mocke (jamais d'appel reseau
reel dans la suite de tests)."""
from conftest import login_as_default_admin


def test_reputation_level_thresholds(app_module):
    f = app_module._compute_reputation_level
    assert f(0, '', False) == ('green', 'abuseipdb')
    assert f(24, '', False) == ('green', 'abuseipdb')
    assert f(25, '', False) == ('orange', 'abuseipdb')
    assert f(74, '', False) == ('orange', 'abuseipdb')
    assert f(75, '', False) == ('red', 'abuseipdb')
    assert f(100, '', False) == ('red', 'abuseipdb')


def test_datacenter_usage_type_no_longer_forces_orange(app_module):
    """Regression : une IP a faible score d'abus hebergee en datacenter (ex: Microsoft
    365 lui-meme) doit rester verte tant qu'elle n'est pas detectee VPN/proxy/Tor —
    c'etait un faux positif signale par l'utilisateur avant ce correctif."""
    level, _ = app_module._compute_reputation_level(0, 'Data Center/Web Hosting/Transit', False)
    assert level == 'green'


def test_vpn_detection_bumps_to_orange(app_module):
    level, _ = app_module._compute_reputation_level(0, '', True)
    assert level == 'orange'


def test_no_score_falls_back_to_heuristic(app_module):
    f = app_module._compute_reputation_level
    assert f(None, '', False) == ('green', 'estimation')
    assert f(None, '', True) == ('orange', 'estimation')


def test_trusted_ip_forces_green_and_skips_abuseipdb(app_module, client, monkeypatch):
    login_as_default_admin(client)
    client.post('/admin/trusted-ips/add', data={'ip': '203.0.113.5', 'label': 'Ville', 'note': ''})

    calls = []
    monkeypatch.setattr(app_module, 'get_ip_info', lambda ip: (calls.append(ip), {'ip': ip, 'country': 'France'})[1])
    monkeypatch.setattr(app_module, '_fetch_abuseipdb', lambda ip, key: (_ for _ in ()).throw(
        AssertionError('AbuseIPDB ne doit jamais etre interroge pour une IP de confiance')))

    payload = app_module.ip_reputation_payload('203.0.113.5')
    assert payload['level'] == 'green'
    assert payload['is_trusted'] is True
    assert payload['trusted_label'] == 'Ville'
    assert calls == ['203.0.113.5']  # geolocalisation toujours recuperee, pour l'affichage


def test_compute_risk_score_caps_at_ten(app_module):
    findings = [{'severity': 'critical'} for _ in range(20)]
    assert app_module.compute_risk_score(findings) <= 10


def test_trusted_ip_city_override_corrects_imprecise_geolocation(app_module, client, monkeypatch):
    """Regression : la geolocalisation automatique par bloc IP place souvent une IP de
    confiance dans la grande ville la plus proche (ex: Paris) plutot que la commune
    exacte (ex: Ivry-sur-Seine) — un administrateur doit pouvoir corriger."""
    login_as_default_admin(client)
    client.post('/admin/trusted-ips/add', data={
        'ip': '203.0.113.9', 'label': 'Ville', 'note': '',
        'city': 'Ivry-sur-Seine', 'lat': '48.8137', 'lon': '2.3872',
    })

    monkeypatch.setattr(app_module, 'get_ip_info',
                         lambda ip: {'ip': ip, 'city': 'Paris', 'country': 'France', 'lat': 48.8566, 'lon': 2.3522})

    payload = app_module.ip_reputation_payload('203.0.113.9')
    assert payload['city'] == 'Ivry-sur-Seine'

    geo = app_module.get_ip_geo('203.0.113.9')
    assert geo['city'] == 'Ivry-sur-Seine'
    assert geo['lat'] == 48.8137
    assert geo['lon'] == 2.3872

    assert app_module.get_display_location('203.0.113.9', 'Paris, Paris, FR') == 'Ivry-sur-Seine, France'


def test_display_location_unchanged_for_ip_without_override(app_module):
    assert app_module.get_display_location('198.51.100.1', 'Berlin, Berlin, DE') == 'Berlin, Berlin, DE'
