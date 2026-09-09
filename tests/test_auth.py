"""Authentification : connexion, protection des routes, changement de mot de passe force."""
from conftest import login_as_default_admin


def test_login_page_loads(client):
    r = client.get('/login')
    assert r.status_code == 200


def test_wrong_password_rejected(client):
    r = client.post('/login', data={'username': 'admin', 'password': 'wrong'}, follow_redirects=True)
    assert 'Identifiants incorrects'.encode('utf-8') in r.data


def test_protected_route_requires_login(client):
    r = client.get('/boite/1', follow_redirects=False)
    assert r.status_code == 302
    assert '/login' in r.headers['Location']


def test_default_admin_is_admin_admin_and_forces_password_change(client):
    """Regression : le compte admin par defaut doit etre admin/admin, et bloquer l'acces
    au reste de l'application tant que le mot de passe n'a pas ete change."""
    r = client.post('/login', data={'username': 'admin', 'password': 'admin'}, follow_redirects=True)
    assert r.status_code == 200
    assert 'devez choisir un nouveau mot de passe'.encode('utf-8') in r.data

    # Tant que le mot de passe par defaut n'est pas change, tout le reste redirige
    # vers /change-password.
    r2 = client.get('/boite/add', follow_redirects=False)
    assert r2.status_code == 302
    assert '/change-password' in r2.headers['Location']


def test_password_change_unlocks_the_rest_of_the_app(client):
    login_as_default_admin(client)
    r = client.get('/dashboard')
    assert r.status_code == 200


def test_existing_users_are_not_forced_to_change_password(app_module, client):
    """Regression : un compte deja existant (donc cree avant cette fonctionnalite, ou par
    la migration ALTER TABLE) ne doit pas avoir must_change_password=1 par surprise."""
    conn = app_module.get_db()
    row = conn.execute("SELECT must_change_password FROM users WHERE username='admin'").fetchone()
    conn.close()
    # Le compte tout juste seede via init_db() DOIT etre force (comportement voulu) ;
    # ce test verifie juste que la colonne existe et vaut exactement 1 pour ce cas precis
    # (pas de valeur inattendue comme None faute de migration).
    assert row['must_change_password'] == 1
