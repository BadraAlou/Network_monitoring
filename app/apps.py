from django.apps import AppConfig
import threading
from .utils.sniffer import start_sniffer

class PagesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app'

    def ready(self):
        thread = threading.Thread(target=start_sniffer, daemon=True)
        thread.start()

        import app.alerts.signals