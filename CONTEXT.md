# CONTEXT - Analyse de Compromission

## État de la session - 2026-09-10 (suite : dashboard connexions + acquittement)

### Ajout : filtres serveur + pagination + acquittement des lieux suspects (carte dashboard)
- **Fix connexions perdues (délai d'ingestion Graph)** : `auditLogs/signIns` a jusqu'à ~2 h de
  retard d'ingestion. `refresh_tenant_signins` repart désormais **3 h en arrière** à chaque
  passage au lieu de 10 min (dédup par `request_id` UNIQUE). Backfill validé : +361 puis +44
  connexions (~579 au total). Bandeau explicatif ajouté sur `/connexions`.
- **Filtres 100 % SQL serveur sur `/connexions`** : `q` (LIKE sur user_display_name/user_upn/
  ip_address/location/application/failure_reason), `status` (Success/Failure), `pays` (FR,
  hors_france, inconnu, code ISO 2 lettres, ou pays du select dynamique avec comptes), `type`
  (fixe/mobile/vpn/dc/trusted/autre via `LEFT JOIN ip_info` ; `dc` exclut `trusted_ips`),
  `per_page` (10/25/50/100/200/500/1000/all). Lien de pagination clampé avant requête et
  conservant tous les filtres.
- **Acquittement des lieux suspects ("à examiner" rouge de la carte)** : bouton "**Acquitter**"
  dans l'infobulle d'un point suspect non validé → POST `/api/signin-ack` enregistre qui a
  acquitté (`username` de session) + horodatage dans la nouvelle table `signin_acks`
  (clé unique `(city, country_code)`, idem bucketing de la carte). Ensuite le point passe en
  **rouge fixe plus petit SANS animation** (classes `.pulse-marker.acked`, pas de halo ni de
  clignotement), taille toujours liée au volume (`6+sqrt(count)*2.2`), et l'infobulle affiche
  "**vérifié par X — date UTC**" au lieu de "à examiner". Mise à jour en direct via fetch sans
  rechargement (`ackLocation` + registres `markerData`/`mapMarkers`, `esc`/`escJs` pour
  l'échappement HTML/JS). `compute_dashboard_kpis` ajoute `is_acknowledged`,
  `acknowledged_by`, `acknowledged_at` à chaque point.
- **Header renommé "Mail Analyse"** : `.app-container` en `d-flex align-items-center flex-wrap`,
  brand à gauche, recherche + menu à droite sur la même ligne.
- RH Studio : le JS envoie par lots de 40 (`RH_BATCH_SIZE`) ; le serveur garde `[:50]` en
  sécurité.
- **Commits poussés sur `master`** (seule branche remote, pas de `main`) : `f058d68`
  (fix ingestion + pagination + lots RH + navbar), `16c022e` (filtres pays/type), `ab99305`
  (Mail Analyse + bandeau ingestion). Push : `git push origin master`.
- Prod Docker : `docker-compose up -d --build` pour déployer (DB persistée via
  `./compromis.db:/app/compromis.db`).
- Tests : `python -m pytest -q` → **41 passed** (+1 test acquittement dans
  `tests/test_kpis.py`).

## État de la session - 2026-09-10

### Ajout : scan des règles de messagerie de tout le tenant + menu "Premiers secours"
- **Règles de messagerie (tenant)** — `/monitoring/rules` : scanne (à la demande ou périodiquement,
  fréquence réglable) les règles de messagerie de TOUS les comptes actifs du tenant (pas seulement
  les boîtes déjà suivies), via `graph_list_tenant_mailbox_users` + un appel Graph par compte
  (`/users/{upn}/mailFolders/inbox/messageRules`, pas d'endpoint tenant-wide pour les règles,
  contrairement aux connexions). Moteur : `scan_tenant_mailbox_rules` (tourne toujours dans un thread
  dédié, jamais dans la boucle du planificateur — peut prendre plusieurs minutes), tables
  `tenant_rule_scans` (historique des passages, 10 derniers conservés) et `tenant_mailbox_rules`
  (règles du dernier scan). Réutilise la détection de règle suspecte déjà existante
  (`_map_graph_rule` : transfert/redirection sans condition, suppression définitive, suppression de
  courrier lié à la sécurité). Alerte Teams (`send_teams_rule_alert`) sur toute règle suspecte
  NOUVELLE par rapport au scan précédent. Toggle + fréquence dans `/monitoring/rules/settings`
  (config `tenant_rules_scan_enabled` / `tenant_rules_scan_interval_minutes`), branché dans
  `monitoring_scheduler_tick` (déjà existant, tick 60s). Page avec barre de progression en direct
  (polling `/monitoring/rules/status`) pendant un scan en cours.
- **Premiers secours** — `/admin/compte` (recherche) puis `/admin/compte/<upn>` : fiche de compte
  Microsoft Entra ID (statut actif/désactivé, dernière connexion, licences, méthodes MFA
  enregistrées via `graph_get_auth_methods`) + actions d'urgence : désactiver/réactiver le compte,
  révoquer toutes les sessions/jetons (`revokeSignInSessions`), réinitialiser le mot de passe (mot
  de passe temporaire généré, affiché une seule fois), forcer le MFA par utilisateur (mécanisme
  legacy, endpoint bêta `/authentication/requirements`, **sans effet si le tenant utilise l'Accès
  conditionnel** — documenté comme tel dans l'UI). Toute action est journalisée (`logs`, catégorie
  `PREMIERS_SECOURS`, `recipient`=UPN) et listée sur la fiche du compte. Accessible depuis la nav
  admin, depuis `/monitoring`, et depuis chaque fiche de boîte (`view_boite.html`).
- **Nouvelles permissions Graph nécessaires** (documentées dans `/config`) : `User.ReadWrite.All`
  (actions d'urgence — approuvé par l'utilisateur pour ajout côté App Registration Entra ID),
  `UserAuthenticationMethod.Read.All` / `.ReadWrite.All` (optionnelles, MFA — dégradation propre si
  absentes : message d'erreur Graph affiché plutôt que crash).
- Nouveau helper générique `graph_request` (PATCH/POST/DELETE, une seule requête, pas de pagination)
  à côté de `graph_get_all` (lecture, paginée) — toutes les actions d'écriture Graph passent par lui.
- Testé : suite pytest existante (40 tests) toujours verte : `python -m pytest -q` ; smoke-test manuel
  des nouvelles routes sur DB temporaire (voir historique de session) — pages s'affichent, garde-fous
  "config Graph incomplète" fonctionnent (pas de crash, message clair).

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
