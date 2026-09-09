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


def test_is_datacenter_flag_matches_abuseipdb_usage_type():
    """AbuseIPDB renvoie exactement 'Data Center/Web Hosting/Transit' (avec espace)."""
    payload = {'usage_type': 'Data Center/Web Hosting/Transit', 'is_trusted': False}
    assert (not payload['is_trusted']) and any(
        kw in payload['usage_type'].lower() for kw in ('data center', 'datacenter'))


def test_datacenter_badge_shown_via_heuristic_hosting_keyword(app_module, monkeypatch):
    """Sans clé AbuseIPDB configurée, l'app retombe sur un heuristique par mot-clé
    ISP/organisation (ex: Amazon) qui doit aussi déclencher le badge DC."""
    monkeypatch.setattr(app_module, 'get_ip_info',
                         lambda ip: {'ip': ip, 'isp': 'Amazon.com, Inc.', 'org': 'EC2', 'country': 'Netherlands'})
    payload = app_module.ip_reputation_payload('198.51.100.50')
    assert 'atacenter' in payload['usage_type']  # 'Hébergeur/Datacenter (estimation heuristique)'
    assert payload['is_datacenter'] is True


def test_datacenter_badge_hidden_for_trusted_ip_even_if_datacenter(app_module, client, monkeypatch):
    """Sauf pour les IPs de confiance : meme si la reputation la classe hebergeur/datacenter,
    le badge DC ne doit pas s'afficher pour une IP deja declaree de confiance."""
    login_as_default_admin(client)
    client.post('/admin/trusted-ips/add', data={'ip': '198.51.100.60', 'label': 'Ville', 'note': ''})
    monkeypatch.setattr(app_module, 'get_ip_info',
                         lambda ip: {'ip': ip, 'isp': 'Amazon.com, Inc.', 'org': 'EC2', 'country': 'France'})
    payload = app_module.ip_reputation_payload('198.51.100.60')
    assert payload['is_trusted'] is True
    assert payload['is_datacenter'] is False


def test_no_datacenter_badge_for_residential_isp(app_module, monkeypatch):
    monkeypatch.setattr(app_module, 'get_ip_info',
                         lambda ip: {'ip': ip, 'isp': 'Orange SA', 'org': '', 'country': 'France'})
    payload = app_module.ip_reputation_payload('198.51.100.70')
    assert payload['is_datacenter'] is False


def test_fixed_line_and_mobile_isp_badges():
    """Verifie juste la logique de detection (pure, insensible a la casse) — le champ
    usage_type vient d'AbuseIPDB, jamais mocke via get_ip_info comme is_datacenter (voir
    ci-dessus, c'est get_ip_reputation qui le derive reellement)."""
    assert 'fixed line isp' in 'Fixed Line ISP'.lower()
    assert 'mobile isp' in 'Mobile ISP'.lower()
    assert 'fixed line isp' not in 'Mobile ISP'.lower()
    assert 'mobile isp' not in 'Fixed Line ISP'.lower()


def test_fixed_line_isp_badge_shown_regardless_of_trust(app_module, client, monkeypatch):
    """Contrairement au badge DC, FAI Fixe/Mobile ne sont pas des signaux d'attention —
    pas de raison de les masquer pour une IP de confiance."""
    login_as_default_admin(client)
    client.post('/admin/trusted-ips/add', data={'ip': '198.51.100.80', 'label': 'Ville', 'note': ''})

    conn = app_module.get_db()
    conn.execute("INSERT OR REPLACE INTO ip_info (ip, usage_type, country) VALUES (?, ?, ?)",
                 ('198.51.100.80', 'Fixed Line ISP', 'France'))
    conn.execute("UPDATE ip_info SET reputation_source='abuseipdb', reputation_checked_at=? WHERE ip=?",
                 (__import__('datetime').datetime.now(__import__('datetime').timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), '198.51.100.80'))
    conn.commit()
    conn.close()

    payload = app_module.ip_reputation_payload('198.51.100.80')
    assert payload['is_trusted'] is True
    assert payload['is_fixed_line_isp'] is True
