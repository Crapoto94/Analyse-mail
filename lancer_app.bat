@echo off
REM Lance l'application Analyse Compromission en mode developpement.
REM Se place d'abord dans le dossier du script, pour que ca fonctionne
REM quel que soit l'endroit d'ou ce fichier est double-clique.
cd /d "%~dp0"

echo Lancement de l'application...
echo Une fois demarree, ouvrez votre navigateur sur : http://127.0.0.1:5050
echo (Utilisez 127.0.0.1 plutot que "localhost" si la connexion est refusee.)
echo.

python app.py --dev

echo.
echo L'application s'est arretee (ou n'a pas pu demarrer - voir le message d'erreur ci-dessus).
pause
