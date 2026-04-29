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
- Import de logs CSV (format Microsoft 365 / Exchange)
- Analyse temporelle, géographique (IPs), domaines
- Envoi d'emails de remédiation aux destinataires
- Suivi via système de logs détaillés

### Ce qui a été fait
- Création de l'application Flask avec auth basic (admin/Admin94200!!!2025)
- Import CSV avec détection automatique du délimiteur (; ou ,)
- Timeline par tranches de 15 min
- Géolocalisation des IPs via ipwho.is
- Vérification SPF/DKIM/DMARC (nécessite dnspython)
- Système de logs (table logs, route /logs, /log/<id>)
- Envoi d'emails via API Ville (route /boite/<id>/send-emails)
- Configuration personnalisée des messages (route /config)
- Export CSV, comparaison de boîtes
- **Dernier commit (c26bf64)** : Vue détaillée des logs + logs cliquables

### Modifications récentes (committées et poussées)
1. **Fix critique (cfcd977)** : Correction bloc try/except dans view_boite (SyntaxError)
2. **Fix Docker (2b86100)** : Dockerfile avec waitress-serve écoutant sur 0.0.0.0
3. **Fix docker-compose (24bab8f)** : Retrait montage compromis.db (cause REFUSED)
4. **Ajout dnspython (73562b3)** : Résout erreur 500 sur /boite/x en Docker
5. **Logs détaillés (c26bf64)** : Nouvelle route /log/<id>, template cliquable

### Ce qui reste à faire
1. **Tester l'envoi d'emails en Docker** (actuellement KO, URL API tronquée dans logs)
2. Vérifier que tous les handlers de route ferment correctement les connexions DB
3. Documenter l'API Ville (endpoints disponibles)

### Problème actuel : Envoi d'emails KO en Docker
- Les logs affichent l'URL tronquée : `API: https://api.`
- Cela indique que `api_url` est vide ou mal configurée dans le conteneur
- **Solution** : Vérifier la config dans la base ou passer via variables d'environnement

### Hypothèses de travail
- Les CSV importés proviennent de Microsoft 365
- L'API Ville est une API municipale (endpoint : /api/v1/mail/send)
- La base contient des données de test

### Risques et points bloquants
- **Point bloquant** : Envoi d'emails échoue en Docker (config API manquante ?)
- **Risque** : Pas de gestion d'erreur globale pour les connexions DB

### Fichiers clés
- `app.py` (909 lignes) - Application principale
- `templates/` - 8 templates HTML (dont log_detail.html nouveau)
- `compromis.db` - Base SQLite
- `requirements.txt` - 5 dépendances (ajout dnspython)
- `docker-compose.yml` - Déploiement sur port 5050

### Décisions prises
- Auth basic (simplicité)
- Stockage config dans la DB (table config)
- Géolocalisation via ipwho.is (pas de clé API)
- Timeline par tranches de 15 min

### Prochaine action recommandée
1. Debugger l'envoi d'emails en Docker : vérifier la valeur de `api_ville_url` dans la base
2. Si nécessaire, passer l'URL via variable d'environnement dans docker-compose.yml

### Questions bloquantes éventuelles
- La variable d'environnement `API_VILLE_URL` est-elle correctement passée au conteneur ?
- La config en base est-elle correcte (table config, key='api_ville_url') ?
