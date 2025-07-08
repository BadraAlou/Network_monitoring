from django.utils import timezone
from datetime import timedelta

def detect_attacks():
    """
    Analyse intelligente des logs récents pour détecter des comportements suspects.
    Si une adresse IP est enregistrée plus de N fois dans les logs sur une courte période,
    une alerte est générée. Cela peut indiquer un scan de port, une attaque brute-force, etc.
    """
    from app.models import Log, Alert, Device

    # Paramètres configurables
    SEUIL_EVENEMENTS = 5
    FENETRE_MINUTES = 5

    now = timezone.now()
    window_start = now - timedelta(minutes=FENETRE_MINUTES)
    recent_logs = Log.objects.filter(scan_time__gte=window_start)

    scan_counts = {}
    for log in recent_logs:
        ip = log.device.ip_address
        scan_counts[ip] = scan_counts.get(ip, 0) + 1

    for ip, count in scan_counts.items():
        if count > SEUIL_EVENEMENTS:
            try:
                device = Device.objects.get(ip_address=ip)
                # Éviter de générer des alertes en doublon
                alerte_existante = Alert.objects.filter(
                    device=device,
                    alert_type="scan",
                    description__icontains="activité suspecte",
                    detected_on__gte=window_start
                ).exists()

                if not alerte_existante:
                    Alert.objects.create(
                        device=device,
                        severity="medium",
                        alert_type="scan",
                        source="automatique",
                        description=f"🛑 Activité suspecte : {count} événements en {FENETRE_MINUTES} minutes pour {ip}.",
                    )
                    print(f"[ALERTE] {ip} suspecte : {count} logs en {FENETRE_MINUTES}min")
            except Device.DoesNotExist:
                print(f"[ERREUR] Appareil avec IP {ip} introuvable pour générer une alerte.")
