import os
import time
import json
import django
import traceback
import ipaddress
import platform
import subprocess
import threading
import logging
from datetime import datetime, timedelta
from django.utils.timezone import make_aware
from dateutil import parser
from collections import defaultdict

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('suricata_watcher.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialisation Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Network_monitoring.settings")
django.setup()

# Imports internes Django
from app.models import Alert, Device, BlockedIP
from app.utils.ia_engine import analyser_alerte
from app.utils.network_disconnector import network_disconnector
from django.core.mail import send_mail
from django.conf import settings
from twilio.rest import Client

# Configuration
EVE_LOG_PATH = "C:\\Program Files\\Suricata\\log\\eve.json"
COOLDOWN_DURATION = timedelta(seconds=30)
MAX_ALERTS_PER_IP = 10
BLOCK_THRESHOLD_MINUTES = 5


# ==================== FONCTIONS D'ALERTE ====================

def envoyer_alerte_email(titre, description, destinataires=None):
    """Envoie une alerte par email aux administrateurs"""
    try:
        if not destinataires:
            # Utiliser les emails par défaut depuis settings
            destinataires = getattr(settings, 'ADMIN_EMAILS', ['admin@2iemsecurity.com'])

        sujet = f"🚨 2IEM Security - Alerte critique : {titre}"
        message = f"""
🚨 ALERTE CRITIQUE DÉTECTÉE 🚨

Titre: {titre}
Description: {description}
Heure: {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}

⚡ ACTION REQUISE:
Consultez immédiatement le tableau de bord 2IEM Security pour plus de détails.

🔗 Accès: {getattr(settings, 'DASHBOARD_URL', 'http://localhost:8000')}

---
2IEM Security - Protection Intelligente
        """

        send_mail(
            subject=sujet,
            message=message,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', None),
            recipient_list=destinataires,
            fail_silently=False
        )

        logger.info(f"✅ Email d'alerte envoyé à {len(destinataires)} destinataire(s)")
        return True

    except Exception as e:
        logger.error(f"❌ Erreur envoi email: {e}")
        return False


def envoyer_sms_alerte(titre, description, numero_destinataire=None):
    """Envoie une alerte SMS via Twilio"""
    try:
        # Vérifier la configuration Twilio
        if not all([
            getattr(settings, 'TWILIO_ACCOUNT_SID', None),
            getattr(settings, 'TWILIO_AUTH_TOKEN', None),
            getattr(settings, 'TWILIO_PHONE_NUMBER', None)
        ]):
            logger.warning("⚠️ Configuration Twilio manquante, SMS non envoyé")
            return False

        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)

        # Message SMS optimisé (limite 160 caractères)
        message_body = f"🚨 2IEM Security ALERTE: {titre[:50]} - {description[:80]}"

        to_number = numero_destinataire or getattr(settings, 'ADMIN_PHONE_NUMBER', None)

        if not to_number:
            logger.warning("⚠️ Numéro de téléphone admin non configuré")
            return False

        message = client.messages.create(
            body=message_body,
            from_=settings.TWILIO_PHONE_NUMBER,
            to=to_number
        )

        logger.info(f"✅ SMS envoyé avec succès: SID={message.sid}")
        return True

    except Exception as e:
        logger.error(f"❌ Erreur envoi SMS: {e}")
        return False


def analyser_alerte_complete(alert):
    """Analyse complète d'une alerte avec l'IA"""
    try:
        # Utiliser la fonction d'analyse IA existante
        analyse_ia = analyser_alerte(alert)

        # Sauvegarder l'analyse dans l'alerte
        alert.ia_analysis = analyse_ia
        alert.save()

        logger.info(f"🤖 Analyse IA complétée pour alerte {alert.id}")
        return analyse_ia

    except Exception as e:
        logger.error(f"❌ Erreur analyse IA pour alerte {alert.id}: {e}")
        return "Erreur lors de l'analyse IA"


def envoyer_notifications_critiques(alert, analyse_ia=None):
    """Envoie les notifications pour les alertes critiques"""
    try:
        # Vérifier si l'alerte nécessite des notifications
        if alert.severity not in ['critical', 'high']:
            return False

        # Types d'alertes nécessitant des notifications immédiates
        types_critiques = ['attaque', 'dos', 'malware', 'intrusion', 'bruteforce', 'exploit', 'fraude']

        if alert.alert_type not in types_critiques:
            return False

        # Préparer les informations de notification
        titre = f"{alert.alert_type.upper()} {alert.severity.upper()}"
        description = f"""
IP Source: {alert.src_ip}
IP Destination: {alert.dest_ip}
Type: {alert.alert_type}
Gravité: {alert.severity}
Description: {alert.description}
Heure: {alert.detected_on.strftime('%d/%m/%Y à %H:%M:%S')}
        """

        # Ajouter l'analyse IA si disponible
        if analyse_ia:
            description += f"\n\n🤖 ANALYSE IA:\n{analyse_ia[:300]}..."

        # Envoi des notifications
        notifications_sent = 0

        # Email
        if envoyer_alerte_email(titre, description):
            notifications_sent += 1

        # SMS pour les alertes très critiques
        if alert.severity == 'critical':
            if envoyer_sms_alerte(titre, f"IP {alert.src_ip} - {alert.alert_type}"):
                notifications_sent += 1

        logger.critical(f"🚨 {notifications_sent} notification(s) envoyée(s) pour alerte critique {alert.id}")
        return notifications_sent > 0

    except Exception as e:
        logger.error(f"❌ Erreur envoi notifications pour alerte {alert.id}: {e}")
        return False


# ==================== FONCTIONS DE BLOCAGE ====================

def force_block_ip(ip, reason="Activité suspecte détectée"):
    """Blocage renforcé d'une IP avec compatibilité Windows/Linux"""
    system = platform.system().lower()
    try:
        if "windows" in system:
            rule_in = f"2IEM_BLOCK_IN_{ip.replace('.', '_')}"
            rule_out = f"2IEM_BLOCK_OUT_{ip.replace('.', '_')}"

            block_cmd_in = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_in}", "dir=in", "action=block",
                f"remoteip={ip}", f"description=2IEM Security - INBOUND BLOCK {reason}"
            ]
            block_cmd_out = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_out}", "dir=out", "action=block",
                f"remoteip={ip}", f"description=2IEM Security - OUTBOUND BLOCK {reason}"
            ]

            subprocess.run(block_cmd_in, check=True, timeout=10)
            subprocess.run(block_cmd_out, check=True, timeout=10)

        elif "linux" in system:
            block_in = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            block_out = ["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"]
            subprocess.run(block_in, check=True, timeout=10)
            subprocess.run(block_out, check=True, timeout=10)
        else:
            logger.error(f"🛑 Système non supporté pour le blocage d'IP : {system}")
            return False

        logger.critical(f"🚫 IP {ip} bloquée (IN/OUT) avec raison : {reason}")
        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Échec du blocage renforcé IP {ip} : {e}")
        return False


# Correspondance des niveaux de sévérité Suricata
SURICATA_SEVERITY_MAP = {
    1: 'critical',
    2: 'high',
    3: 'medium',
    4: 'low',
    5: 'low'
}

# Cache et compteurs
last_alerts = {}
ip_alert_counter = defaultdict(list)
blocked_ips_cache = set()


def load_blocked_ips_cache():
    """Charge les IPs déjà bloquées en cache au démarrage"""
    global blocked_ips_cache
    blocked_ips_cache = set(BlockedIP.objects.values_list('ip_address', flat=True))
    logger.info(f"📦 Cache initialisé avec {len(blocked_ips_cache)} IPs bloquées")


def is_private_ip(ip):
    """Vérifie si une IP est privée"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback
    except ValueError:
        return False


def should_block_ip(src_ip, alert_type, severity):
    """Détermine si une IP doit être bloquée automatiquement"""
    critical_types = ['attaque', 'dos', 'malware', 'intrusion', 'bruteforce', 'exploit', 'fraude']

    # Blocage immédiat pour les attaques critiques
    if alert_type in critical_types and severity in ['critical', 'high']:
        return True, f"Blocage automatique - {alert_type} {severity}"

    # Comptage des alertes pour blocage progressif
    now = datetime.now()
    cutoff_time = now - timedelta(minutes=BLOCK_THRESHOLD_MINUTES)

    # Nettoie les anciennes entrées
    ip_alert_counter[src_ip] = [
        timestamp for timestamp in ip_alert_counter[src_ip]
        if timestamp > cutoff_time
    ]

    # Ajoute la nouvelle alerte
    ip_alert_counter[src_ip].append(now)

    # Vérifie si le seuil est atteint
    if len(ip_alert_counter[src_ip]) >= MAX_ALERTS_PER_IP:
        return True, f"Seuil d'alertes atteint ({MAX_ALERTS_PER_IP} alertes en {BLOCK_THRESHOLD_MINUTES}min)"

    return False, None


def block_ip(ip, reason=None, alert_instance=None):
    """Bloque une IP au niveau du pare-feu ET la déconnecte du réseau"""
    if ip in blocked_ips_cache:
        logger.debug(f"⚠️ IP {ip} déjà bloquée (cache)")
        return False

    system = platform.system().lower()
    try:
        # Vérification base de données
        if BlockedIP.objects.filter(ip_address=ip).exists():
            blocked_ips_cache.add(ip)
            logger.warning(f"⚠️ IP {ip} déjà présente dans BlockedIP")
            return False

        success = False

        # === DÉCONNEXION FORCÉE DU RÉSEAU ===
        logger.info(f"🚫 DÉCONNEXION FORCÉE INITIÉE POUR {ip}")
        disconnect_success = network_disconnector.force_disconnect_ip(ip, reason or "Menace détectée")

        if disconnect_success:
            logger.info(f"✅ IP {ip} DÉCONNECTÉE DU RÉSEAU")
            success = True
        else:
            logger.warning(f"⚠️ Déconnexion partielle pour {ip}, application du blocage pare-feu standard")

        # === BLOCAGE PARE-FEU STANDARD ===
        if "windows" in system:
            rule_name = f"2IEM_BLOCK_{ip.replace('.', '_')}"
            try:
                check_cmd = [
                    "netsh", "advfirewall", "firewall", "show", "rule",
                    f"name={rule_name}"
                ]
                result = subprocess.run(check_cmd, capture_output=True, text=True)

                if "No rules match" not in result.stdout:
                    logger.warning(f"⚠️ Règle pare-feu déjà présente pour {ip}")
                    success = True
                else:
                    block_cmd = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}",
                        "dir=in",
                        "action=block",
                        f"remoteip={ip}",
                        f"description=2IEM Security - {reason or 'Threat detected'}"
                    ]
                    subprocess.run(block_cmd, check=True, timeout=10)
                    logger.info(f"🛡️ IP bloquée via pare-feu Windows : {ip}")
                    success = True

            except subprocess.TimeoutExpired:
                logger.error(f"❌ Timeout lors du blocage Windows de {ip}")
            except subprocess.CalledProcessError as e:
                logger.error(f"❌ Erreur pare-feu Windows pour {ip}: {e}")

        elif "linux" in system:
            try:
                check_cmd = ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
                check_result = subprocess.run(
                    check_cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )

                if check_result.returncode == 0:
                    logger.warning(f"⚠️ Règle iptables déjà présente pour {ip}")
                    success = True
                else:
                    block_cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                    subprocess.run(block_cmd, check=True, timeout=10)
                    logger.info(f"🛡️ IP bloquée via iptables Linux : {ip}")
                    success = True

            except subprocess.TimeoutExpired:
                logger.error(f"❌ Timeout lors du blocage Linux de {ip}")
            except subprocess.CalledProcessError as e:
                logger.error(f"❌ Erreur iptables pour {ip}: {e}")
        else:
            logger.error(f"❌ Système non supporté pour le blocage : {system}")
            return False

        if success:
            # Enregistrement en base de données
            BlockedIP.objects.create(
                ip_address=ip,
                reason=reason or "Menace détectée automatiquement",
                alert=alert_instance
            )
            blocked_ips_cache.add(ip)
            logger.info(f"📦 IP {ip} enregistrée dans BlockedIP - Raison: {reason}")

            if disconnect_success:
                logger.critical(f"🚫 DÉCONNEXION FORCÉE COMPLÈTE: {ip} - PLUS AUCUN ACCÈS RÉSEAU")

            return True

        return False

    except Exception as e:
        logger.error(f"❌ Erreur critique lors du blocage de {ip}: {e}")
        return False


def detect_alert_type(signature: str, category: str, sid: int = None) -> str:
    """Détecte le type d'alerte basé sur la signature, catégorie et SID"""
    sig = signature.lower()
    cat = category.lower()

    # Détection basée sur nos nouvelles règles Suricata (SID 2000001-2000061)
    if sid and 2000001 <= sid <= 2000010:
        return "scan"
    elif sid and 2000011 <= sid <= 2000020:
        return "attaque"
    elif sid and 2000021 <= sid <= 2000028:
        return "bruteforce"
    elif sid and 2000029 <= sid <= 2000035:
        return "dos"
    elif sid and 2000036 <= sid <= 2000042:
        return "exfiltration"
    elif sid and 2000043 <= sid <= 2000050:
        return "malware"
    elif sid and 2000051 <= sid <= 2000054:
        return "fraude"
    elif sid and 2000055 <= sid <= 2000061:
        return "politique"

    # Détection par mots-clés (fallback)
    if any(word in sig for word in ["hping3", "hping", "flood", "dos", "ddos"]):
        return "dos"
    elif any(word in sig for word in ["bruteforce", "brute force", "password"]):
        return "bruteforce"
    elif any(word in sig for word in ["sql injection", "sqli", "union select", "or 1=1"]):
        return "attaque"
    elif any(word in sig for word in ["nmap", "portscan", "scan", "masscan", "rustscan"]):
        return "scan"
    elif any(word in sig for word in ["ransomware", "trojan", "malware", "virus", "backdoor"]):
        return "malware"
    elif any(word in sig for word in ["exploit", "overflow", "code execution", "rce"]):
        return "exploit"
    elif any(word in sig for word in ["exfiltration", "data theft", "dropbox", "pastebin"]):
        return "exfiltration"
    elif any(word in sig for word in ["mobile money", "fraud", "phishing"]):
        return "fraude"
    elif any(word in sig for word in ["intrusion", "suspicious", "anomaly"]):
        return "intrusion"
    else:
        return "autre"


def simplify_signature(signature: str, alert_type: str) -> str:
    """Simplifie la signature pour un affichage clair"""
    sig = signature.lower()

    type_messages = {
        "dos": "Attaque par déni de service (DoS/DDoS)",
        "bruteforce": "Tentative de force brute",
        "attaque": "Tentative d'injection SQL",
        "scan": "Scan de reconnaissance réseau",
        "malware": "Code malveillant détecté",
        "exploit": "Tentative d'exploitation",
        "exfiltration": "Tentative d'exfiltration de données",
        "fraude": "Activité frauduleuse détectée",
        "intrusion": "Tentative d'intrusion",
        "politique": "Violation de politique de sécurité"
    }

    # Détection spécifique
    if "hping3" in sig or "hping" in sig:
        return "Attaque DoS via Hping3 détectée"
    elif "nmap" in sig:
        return "Scan Nmap de reconnaissance"
    elif "rustscan" in sig:
        return "Scan RustScan ultra-rapide"
    elif "masscan" in sig:
        return "Scan Masscan à grande échelle"
    elif "union select" in sig:
        return "Injection SQL UNION SELECT"
    elif "or 1=1" in sig:
        return "Injection SQL bypass authentification"
    elif "ssh" in sig and "brute" in sig:
        return "Attaque brute force SSH"
    elif "mobile money" in sig:
        return "Tentative de fraude Mobile Money"
    elif "dropbox" in sig or "drive.google" in sig:
        return "Exfiltration vers service cloud"

    return type_messages.get(alert_type, signature.capitalize())


def get_device_or_create(src_ip):
    """Récupère ou crée un device basé sur l'IP source"""
    try:
        device = Device.objects.get(ip_address=src_ip)
        return device
    except Device.DoesNotExist:
        hostname = f"Device-{src_ip.replace('.', '-')}"
        device = Device.objects.create(
            ip_address=src_ip,
            hostname=hostname,
            status='suspect'
        )
        logger.info(f"📱 Nouveau device créé : {hostname} ({src_ip})")
        return device


def parse_alert_line(line):
    """Traite une ligne du fichier eve.json avec notifications intégrées"""
    try:
        data = json.loads(line.strip())

        if data.get("event_type") != "alert":
            return

        alert_info = data.get("alert", {})

        # Extraction des données
        severity_num = alert_info.get("severity", 3)
        severity = SURICATA_SEVERITY_MAP.get(severity_num, 'medium')
        signature = alert_info.get("signature", "Alerte inconnue")
        category = alert_info.get("category", "")
        sid = alert_info.get("signature_id")
        src_ip = data.get("src_ip", "")
        dest_ip = data.get("dest_ip", "")
        src_port = data.get("src_port", 0)
        dest_port = data.get("dest_port", 0)
        protocol = data.get("proto", "").upper()
        timestamp = data.get("timestamp")

        # Validation des données
        if not src_ip or not dest_ip:
            logger.debug("❌ Alerte ignorée : IP source ou destination manquante")
            return

        # Ignore les alertes d'IPs non privées
        if not is_private_ip(src_ip) and not is_private_ip(dest_ip):
            logger.debug(f"❌ Alerte ignorée : IPs externes {src_ip} -> {dest_ip}")
            return

        # Ignore si l'IP source est déjà bloquée
        if src_ip in blocked_ips_cache:
            return

        # Parse du timestamp
        try:
            detected_time = parser.parse(timestamp)
            if detected_time.tzinfo is None:
                detected_time = make_aware(detected_time)
        except Exception as e:
            logger.error(f"❌ Timestamp invalide '{timestamp}': {e}")
            detected_time = make_aware(datetime.now())

        # Détection du type d'alerte
        alert_type = detect_alert_type(signature, category, sid)
        description = simplify_signature(signature, alert_type)

        # Système anti-spam avec cooldown
        alert_key = f"{src_ip}-{sid or signature}-{alert_type}"
        if alert_key in last_alerts:
            time_diff = detected_time - last_alerts[alert_key]
            if time_diff < COOLDOWN_DURATION:
                logger.debug(f"🔄 Alerte en cooldown ignorée : {alert_key}")
                return

        last_alerts[alert_key] = detected_time

        # Récupération ou création du device
        device = get_device_or_create(src_ip)

        # Création de l'alerte en base
        alert = Alert.objects.create(
            device=device,
            severity=severity,
            alert_type=alert_type,
            description=description,
            signature=signature,
            category=category,
            src_ip=src_ip,
            dest_ip=dest_ip,
            protocol=protocol,
            detected_on=detected_time,
            source="automatique",
            titre=f"Alerte {alert_type.upper()} - {severity.upper()}"
        )

        logger.info(
            f"🚨 ALERTE CRÉÉE: {description} | {src_ip}:{src_port} -> {dest_ip}:{dest_port} | {severity.upper()}")

        # === ANALYSE IA COMPLÈTE ===
        try:
            analyse_ia = analyser_alerte_complete(alert)
            logger.info(f"🤖 Analyse IA complétée pour alerte {alert.id}")
        except Exception as e:
            logger.error(f"❌ Erreur analyse IA pour alerte {alert.id}: {e}")
            analyse_ia = None

        # === ENVOI DES NOTIFICATIONS ===
        try:
            notifications_sent = envoyer_notifications_critiques(alert, analyse_ia)
            if notifications_sent:
                logger.critical(f"📧 Notifications envoyées pour alerte critique {alert.id}")
        except Exception as e:
            logger.error(f"❌ Erreur envoi notifications pour alerte {alert.id}: {e}")

        # === DÉCISION DE BLOCAGE AUTOMATIQUE ===
        should_block, block_reason = should_block_ip(src_ip, alert_type, severity)
        if should_block:
            success = block_ip(src_ip, reason=block_reason, alert_instance=alert)
            if success:
                logger.warning(f"🛡️ IP {src_ip} BLOQUÉE AUTOMATIQUEMENT : {block_reason}")

                # Notification spéciale pour blocage automatique
                try:
                    titre_blocage = f"BLOCAGE AUTOMATIQUE - {src_ip}"
                    desc_blocage = f"L'IP {src_ip} a été automatiquement bloquée.\nRaison: {block_reason}\nType d'alerte: {alert_type}\nGravité: {severity}"

                    envoyer_alerte_email(titre_blocage, desc_blocage)

                    if severity == 'critical':
                        envoyer_sms_alerte(titre_blocage, f"IP {src_ip} bloquée - {alert_type}")

                    logger.critical(f"📧 Notifications de blocage envoyées pour {src_ip}")

                except Exception as e:
                    logger.error(f"❌ Erreur notifications blocage {src_ip}: {e}")
            else:
                logger.error(f"❌ Échec du blocage automatique de {src_ip}")

    except json.JSONDecodeError as e:
        logger.error(f"❌ Erreur JSON : {e}")
    except Exception as e:
        logger.error(f"❌ Erreur critique lors du traitement d'alerte : {e}")
        traceback.print_exc()


def tail_f(file_path):
    """Lecture en temps réel du fichier eve.json"""
    logger.info(f"📖 Lecture du fichier : {file_path}")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                parse_alert_line(line)
    except FileNotFoundError:
        logger.error(f"❌ Fichier introuvable : {file_path}")
    except PermissionError:
        logger.error(f"❌ Permissions insuffisantes pour lire : {file_path}")
    except Exception as e:
        logger.error(f"❌ Erreur lors de la lecture du fichier : {e}")


def cleanup_old_data():
    """Nettoie périodiquement les anciennes données en mémoire"""
    while True:
        try:
            time.sleep(300)  # Toutes les 5 minutes

            # Nettoie le cache des alertes anciennes
            cutoff_time = datetime.now() - COOLDOWN_DURATION * 2
            old_keys = [
                key for key, timestamp in last_alerts.items()
                if timestamp < make_aware(cutoff_time)
            ]
            for key in old_keys:
                del last_alerts[key]

            # Nettoie le compteur d'alertes par IP
            cutoff_time = datetime.now() - timedelta(minutes=BLOCK_THRESHOLD_MINUTES)
            for ip in list(ip_alert_counter.keys()):
                ip_alert_counter[ip] = [
                    timestamp for timestamp in ip_alert_counter[ip]
                    if timestamp > cutoff_time
                ]
                if not ip_alert_counter[ip]:
                    del ip_alert_counter[ip]

            logger.debug(f"🧹 Nettoyage effectué - Alertes en cache: {len(last_alerts)}")

        except Exception as e:
            logger.error(f"❌ Erreur lors du nettoyage : {e}")


if __name__ == "__main__":
    print("🚀 2IEM Security - Surveillance Suricata v3.0 avec Notifications")
    print("=" * 60)

    # Vérification de la configuration
    print("🔧 Vérification de la configuration...")

    # Vérifier la configuration email
    if hasattr(settings, 'EMAIL_BACKEND'):
        print("✅ Configuration email détectée")
    else:
        print("⚠️ Configuration email manquante")

    # Vérifier la configuration Twilio
    if all([
        getattr(settings, 'TWILIO_ACCOUNT_SID', None),
        getattr(settings, 'TWILIO_AUTH_TOKEN', None),
        getattr(settings, 'TWILIO_PHONE_NUMBER', None)
    ]):
        print("✅ Configuration Twilio détectée")
    else:
        print("⚠️ Configuration Twilio manquante (SMS désactivés)")

    # Chargement du cache des IPs bloquées
    load_blocked_ips_cache()

    # Démarrage du thread de nettoyage
    cleanup_thread = threading.Thread(target=cleanup_old_data, daemon=True)
    cleanup_thread.start()

    # Vérification de l'existence du fichier
    if not os.path.exists(EVE_LOG_PATH):
        logger.error(f"❌ Fichier eve.json introuvable : {EVE_LOG_PATH}")
        print("\n💡 Vérifiez que Suricata est démarré et configuré correctement.")
        exit(1)

    logger.info("📡 Surveillance des alertes en temps réel démarrée...")
    logger.info("📧 Notifications email/SMS activées pour alertes critiques")
    logger.info("🤖 Analyse IA automatique activée")
    logger.info("🛑 Appuyez sur Ctrl+C pour arrêter")

    try:
        tail_f(EVE_LOG_PATH)
    except KeyboardInterrupt:
        logger.info("🛑 Arrêt demandé par l'utilisateur")
        print("\n👋 Surveillance arrêtée. Au revoir !")
    except Exception as e:
        logger.error(f"❌ Erreur fatale : {e}")
        traceback.print_exc()