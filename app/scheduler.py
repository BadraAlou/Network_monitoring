import os
from apscheduler.schedulers.background import BackgroundScheduler
from app.utils.detector import detect_attacks

scheduler = None

def start():
    """
    Démarre le planificateur d'exécution automatique des tâches périodiques.
    La fonction `detect_attacks` est appelée toutes les 5 minutes.
    Cette fonction est conçue pour être appelée au démarrage du serveur Django.
    """
    global scheduler

    # Évite les redémarrages multiples du scheduler lors du lancement du serveur Django
    if scheduler is None and os.environ.get('RUN_MAIN') != 'true':
        scheduler = BackgroundScheduler()
        scheduler.add_job(detect_attacks, 'interval', minutes=5)
        scheduler.start()
        print("Scheduler APS démarré : détection d'attaques toutes les 5 minutes.")
