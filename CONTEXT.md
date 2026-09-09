# CONTEXT - Analyse de Compromission

## État de la session - 2026-09-09

### Ajout : import et analyse AuditLogs / InteractiveSignIns (Microsoft Entra ID)
- Nouvelles tables SQLite `signin_logs` et `audit_logs` (liées à `boites_compromises` par `boite_id`), avec conservation de la ligne brute en JSON (`raw_json`) pour l'export CSV français d'Entra ID.
- Page `/boite/<id>/upload` : un seul formulaire avec 3 champs fichiers indépendants (Messages / Journal d'audit / Connexions interactives), tous optionnels, importables en une fois.
- Parsing tolérant aux variations d'export (accents, apostrophes typographiques, espaces insécables) via `_normalize_header()` + tables de correspondance `SIGNIN_FIELD_CANDIDATES` / `AUDIT_FIELD_CANDIDATES`.
- Nouvelles pages d'analyse :
  - `/boite/<id>/signins` : stats connexions (réussies/échouées, pays, applications, MFA), géolocalisation IP (réutilise `get_ip_info`), timeline 15 min, et détection heuristique de connexions à examiner (signalées par Entra ID, pays inhabituel par rapport au pays majoritaire du compte, échecs).
  - `/boite/<id>/audit` : stats par activité/résultat/acteur, timeline, détection heuristique d'activités sensibles par mot-clé (règles de messagerie/transfert, délégation, consentement d'appli, mot de passe, MFA, rôles/permissions...).
  - Détail brut d'une ligne : `/signin/<id>` et `/auditevent/<id>` (template partagé `raw_detail.html`).
- `index.html` et `view_boite.html` affichent désormais les compteurs de connexions/événements d'audit par boîte.
- Testé (hors app Flask, en isolant les fonctions d'import) avec les 2 fichiers d'exemple fournis (`AuditLogs_2026-09-08.csv`, `InteractiveSignIns_2026-09-01_2026-09-08.csv`) : 21 événements d'audit / 50 connexions importés sans erreur, détection correcte d'un changement de mot de passe + connexions réussies depuis l'Espagne (pays inhabituel) dans le jeu de test.

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
