"""Fixtures partagees pour la suite de tests.

Chaque test tourne contre une base SQLite temporaire (jamais compromis.db) :
on redirige app.DB_PATH vers un fichier sous tmp_path AVANT d'appeler
init_db(), ce qui garantit une isolation totale entre les tests et vis-a-vis
de la base reelle, quel que soit le repertoire de travail courant du process
qui execute pytest.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest


@pytest.fixture()
def app_module(tmp_path, monkeypatch):
    """Le module app, avec DB_PATH redirige vers une base SQLite temporaire et
    fraichement initialisee (schema + compte admin par defaut seede)."""
    import app as appmod

    db_path = str(tmp_path / 'test_compromis.db')
    monkeypatch.setattr(appmod, 'DB_PATH', db_path)
    appmod.init_db()
    appmod.app.config['TESTING'] = True
    yield appmod


@pytest.fixture()
def client(app_module):
    with app_module.app.test_client() as c:
        yield c


def login_as_default_admin(client):
    """Connecte le client de test avec le compte admin par defaut (admin/admin), puis
    change immediatement le mot de passe (must_change_password force sinon l'acces au
    reste de l'application) pour que les tests suivants naviguent librement."""
    client.post('/login', data={'username': 'admin', 'password': 'admin'}, follow_redirects=True)
    client.post('/change-password', data={
        'current_password': 'admin',
        'new_password': 'TestPassword1234',
        'confirm_password': 'TestPassword1234',
    }, follow_redirects=True)
