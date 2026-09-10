FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p uploads templates

EXPOSE 5050

# Execute app.py comme script (pas "from app import app" dans un -c) : c'est le bloc
# `if __name__ == '__main__':` en bas d'app.py qui demarre le planificateur de surveillance
# en tache de fond (start_monitoring_scheduler — scans periodiques des boites surveillees,
# rafraichissement des connexions tenant, scan des regles de messagerie...). Un simple
# import du module (comme faisait l'ancien CMD) execute bien l'appli via Waitress avec les
# memes parametres, mais sans jamais declencher ce bloc : aucun scan automatique ne tournait
# donc en production avec l'ancien CMD, seuls les scans a la demande fonctionnaient.
CMD ["python", "app.py"]