# CONTEXT - Analyse de Compromission

## État de la session - 2026-04-29

### Projet
Application web d'analyse de compromission de boîtes email (investigation de sécurité).

### Stack technique
- **Backend** : Python 3.11 / Flask 3.0.0
- **Base de données** : SQLite (compromis.db)
- **Frontend** : Bootstrap 5.3.0, templates Jinja2
- **Déploiement** : Docker / docker-compose
- **API externe** : API Ville (Toulouse) pour envoi d'emails

### Objectif en cours
Analyse et gestion d'incidents de compromission de boîtes email :
- Import de logs CSV (格式 Microsoft 365 / Exchange)
- Analyse temporelle, géographique (IPs), domaines
- Envoi d'emails de remédiation aux destinataires
- Suivi via système de logs

### Ce qui a été fait
- Création de l'application Flask avec auth basic (admin/Admin94200!!!2025)
- Import CSV avec détection automatique du délimiteur (; ou ,)
- Timeline par tranches de 15 min
- Géolocalisation des IPs via ipwho.is
- Vérification SPF/DKIM/DMARC
- Système de logs (table logs, route /logs)
- Envoi d'emails via API Ville (route /boite/<id>/send-emails)
- Configuration personnalisée des messages (route /config)
- Export CSV, comparaison de boîtes
- Correction du filtre adresses (commit 2955310)
- **Dernier commit (47cd055)** : Ajout système de logs avec interface

### Modifications en cours (non committées)
**Fichier : app.py**
- Modification de la route `/boite/<int:bid>` (view_boite)
- Ajout d'un bloc try/except et gestion de fermeture de connexion
- **⚠️ INCOHÉRENCE DÉTECTÉE** : Le code après le `if not boite:` n'est PAS dans le bloc try. Si une erreur survient plus loin, la connexion DB ne sera pas fermée correctement.

```python
# Code actuel (problématique) :
try:
    conn = get_db()
    boite = conn.execute(...).fetchone()
    if not boite:
        conn.close()
        flash(...)
        return redirect(...)
# <-- Le bloc try se termine ici implicitement
messages = conn.execute(...)  # Hors du try !
```

### Ce qui reste à faire
1. **Corriger l'incohérence dans view_boite** (fermeture correcte de la connexion)
2. Tester l'envoi d'emails avec l'API Ville
3. Vérifier que tous les handlers de route ferment correctement les connexions DB
4. Documenter l'API Ville (endpoints disponibles)

### Hypothèses de travail
- Les CSV importés proviennent de Microsoft 365 (champs : MessageId, Received, SenderAddress, RecipientAddress, etc.)
- L'API Ville est une API municipale d'envoi d'emails (endpoint : /api/v1/mail/send)
- La base contient des données de test (Compromission_test.csv, etc.)

### Risques et points bloquants
- **Risque majeur** : Fuite de connexions DB dans view_boite (modification en cours)
- **Risque** : Pas de gestion d'erreur globale pour les connexions DB
- **Point bloquant** : Nécessite des identifiants API Ville valides pour tester l'envoi d'emails
- **Todo** : Vérifier si d'autres routes ont le même problème de gestion de connexion

### Fichiers clés
- `app.py` (910 lignes) - Application principale
- `templates/` - 7 templates HTML (base, index, view_boite, upload, config, logs, compare, add_boite)
- `compromis.db` - Base SQLite (1 MB environ)
- `requirements.txt` - 4 dépendances (Flask, Werkzeug, waitress, flask-httpauth)
- `docker-compose.yml` - Déploiement sur port 5050

### Décisions prises
- Auth basic plutôt que session-based (simplicité)
- Stockage config dans la DB (table config)
- Géolocalisation via ipwho.is (pas de clé API requise)
- Timeline par tranches de 15 min (commit 2955310)

### Prochaine action recommandée
1. Lire la suite de app.py (lignes 850-910) pour comprendre la fin des routes
2. Corriger le bloc try/except dans view_boite
3. Committer les modifications avec un message clair

### Questions bloquantes éventuelles
- L'API Ville fonctionne-t-elle avec l'URL par défaut (https://api-ville.toulouse.fr/api) ?
- Faut-il committer les modifications de app.py actuelles ou les corriger d'abord ?
