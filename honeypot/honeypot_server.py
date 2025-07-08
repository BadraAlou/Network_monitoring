import socket
import threading
import datetime
import os
import django
import sys
import time
import logging

# Configuration Django
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Network_monitoring.settings")
django.setup()

from app.models import HoneypotLog

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('honeypot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration complète des honeypots avec tous les protocoles standards
HONEYPOTS = [
    # Services SSH
    {
        "port": 22,
        "service": "SSH",
        "message": "🔐 SSH Access Denied - 2IEM_Security\n"
                   "Tentative de connexion SSH détectée et enregistrée.\n"
                   "Votre adresse IP a été signalée aux autorités compétentes.\n"
                   "Connection terminated.\n"
    },
    {
        "port": 2222,
        "service": "SSH",
        "message": "🔐 SSH Honeypot - 2IEM_Security\n"
                   "Tentative SSH détectée par notre système de sécurité.\n"
                   "Toutes vos tentatives sont enregistrées et analysées.\n"
                   "Vous ne passerez jamais notre protection.\n"
    },

    # Services FTP
    {
        "port": 21,
        "service": "FTP",
        "message": "220 2IEM_Security FTP Honeypot\r\n"
                   "📁 Tentative FTP piégée et enregistrée.\r\n"
                   "Vos mouvements sont surveillés en temps réel.\r\n"
                   "Accès refusé définitivement.\r\n"
                   "221 Goodbye.\r\n"
    },
    {
        "port": 2121,
        "service": "FTP",
        "message": "220 Alternative FTP - 2IEM_Security\r\n"
                   "📁 Service FTP alternatif - Accès non autorisé.\r\n"
                   "Tentative d'intrusion détectée et signalée.\r\n"
                   "221 Connection closed.\r\n"
    },

    # Services HTTP/HTTPS
    {
        "port": 80,
        "service": "HTTP",
        "message": "🌐 Tentative HTTP captée par 2IEM_Security.\n"
                   "Vous êtes observé et nos agents ouvrent une enquête.\n"
                   "Votre activité malveillante a été enregistrée.\n"
                   "Accès bloqué définitivement."
    },
    {
        "port": 8080,
        "service": "HTTP",
        "message": "🌐 HTTP Proxy - 2IEM_Security\n"
                   "Tentative d'accès au proxy HTTP détectée.\n"
                   "Votre IP est maintenant sous surveillance.\n"
                   "Toute activité suspecte sera signalée."
    },
    {
        "port": 443,
        "service": "HTTPS",
        "message": "🔒 HTTPS Service - 2IEM_Security\n"
                   "Tentative de connexion HTTPS non autorisée.\n"
                   "Certificat invalide - Connexion refusée.\n"
                   "Incident de sécurité enregistré."
    },
    {
        "port": 8443,
        "service": "HTTPS",
        "message": "🔒 Alternative HTTPS - 2IEM_Security\n"
                   "Service HTTPS alternatif - Accès interdit.\n"
                   "Tentative d'intrusion SSL/TLS détectée.\n"
                   "Connexion terminée par sécurité."
    },

    # Services TELNET
    {
        "port": 23,
        "service": "TELNET",
        "message": "📟 TELNET - 2IEM_Security\r\n"
                   "Tentative TELNET détectée - Protocole obsolète.\r\n"
                   "Connexion non sécurisée refusée.\r\n"
                   "Votre activité a été enregistrée.\r\n"
    },
    {
        "port": 2323,
        "service": "TELNET",
        "message": "📟 Alternative TELNET - 2IEM_Security\r\n"
                   "Service TELNET alternatif - Accès refusé.\r\n"
                   "Protocole non sécurisé détecté.\r\n"
                   "Connexion fermée par sécurité.\r\n"
    },

    # Services SMTP
    {
        "port": 25,
        "service": "SMTP",
        "message": "220 2IEM_Security SMTP Honeypot\r\n"
                   "📧 Tentative SMTP détectée et bloquée.\r\n"
                   "Service de messagerie protégé.\r\n"
                   "Votre IP a été signalée pour spam.\r\n"
                   "221 Bye\r\n"
    },
    {
        "port": 587,
        "service": "SMTP",
        "message": "220 SMTP Submission - 2IEM_Security\r\n"
                   "📧 Service SMTP submission - Accès refusé.\r\n"
                   "Authentification requise non fournie.\r\n"
                   "Tentative d'envoi de spam détectée.\r\n"
                   "221 Closing connection\r\n"
    },

    # Services POP3/IMAP
    {
        "port": 110,
        "service": "POP3",
        "message": "+OK 2IEM_Security POP3 Honeypot\r\n"
                   "📬 Tentative POP3 détectée - Accès refusé.\r\n"
                   "Service de messagerie protégé.\r\n"
                   "Votre tentative a été enregistrée.\r\n"
                   "+OK Bye\r\n"
    },
    {
        "port": 143,
        "service": "IMAP",
        "message": "* OK 2IEM_Security IMAP Honeypot\r\n"
                   "📮 Tentative IMAP détectée et bloquée.\r\n"
                   "Accès aux emails non autorisé.\r\n"
                   "Incident de sécurité enregistré.\r\n"
                   "* BYE Closing connection\r\n"
    },

    # Services DNS
    {
        "port": 53,
        "service": "DNS",
        "message": "🌐 DNS Service - 2IEM_Security\n"
                   "Tentative d'accès DNS détectée.\n"
                   "Requête DNS malveillante bloquée.\n"
                   "Votre activité a été signalée."
    },

    # Services de base de données
    {
        "port": 3306,
        "service": "MySQL",
        "message": "🗄️ MySQL Database - 2IEM_Security\n"
                   "Tentative d'accès MySQL détectée.\n"
                   "Base de données protégée - Accès refusé.\n"
                   "Tentative d'intrusion enregistrée."
    },
    {
        "port": 5432,
        "service": "PostgreSQL",
        "message": "🗄️ PostgreSQL Database - 2IEM_Security\n"
                   "Tentative d'accès PostgreSQL détectée.\n"
                   "Base de données sécurisée - Connexion refusée.\n"
                   "Incident de sécurité signalé."
    },
    {
        "port": 1433,
        "service": "MSSQL",
        "message": "🗄️ SQL Server - 2IEM_Security\n"
                   "Tentative d'accès SQL Server détectée.\n"
                   "Base de données Microsoft protégée.\n"
                   "Votre IP a été blacklistée."
    },
    {
        "port": 27017,
        "service": "MongoDB",
        "message": "🗄️ MongoDB Database - 2IEM_Security\n"
                   "Tentative d'accès MongoDB détectée.\n"
                   "Base NoSQL protégée - Accès interdit.\n"
                   "Activité malveillante enregistrée."
    },

    # Services de partage de fichiers
    {
        "port": 445,
        "service": "SMB",
        "message": "📂 SMB/CIFS Service - 2IEM_Security\n"
                   "Tentative d'accès SMB détectée.\n"
                   "Partage de fichiers protégé.\n"
                   "Tentative d'intrusion Windows signalée."
    },
    {
        "port": 139,
        "service": "NetBIOS",
        "message": "📂 NetBIOS Service - 2IEM_Security\n"
                   "Tentative NetBIOS détectée et bloquée.\n"
                   "Service de noms Windows protégé.\n"
                   "Votre activité a été enregistrée."
    },

    # Services VPN/Remote
    {
        "port": 1723,
        "service": "PPTP",
        "message": "🔐 PPTP VPN - 2IEM_Security\n"
                   "Tentative de connexion VPN PPTP détectée.\n"
                   "Service VPN protégé - Accès refusé.\n"
                   "Tentative d'intrusion VPN signalée."
    },
    {
        "port": 3389,
        "service": "RDP",
        "message": "🖥️ Remote Desktop - 2IEM_Security\n"
                   "Tentative RDP détectée et bloquée.\n"
                   "Bureau à distance protégé.\n"
                   "Tentative d'accès Windows signalée."
    },
    {
        "port": 5900,
        "service": "VNC",
        "message": "🖥️ VNC Service - 2IEM_Security\n"
                   "Tentative VNC détectée - Accès refusé.\n"
                   "Contrôle à distance protégé.\n"
                   "Incident de sécurité enregistré."
    },

    # Services de monitoring/gestion
    {
        "port": 161,
        "service": "SNMP",
        "message": "📊 SNMP Service - 2IEM_Security\n"
                   "Tentative SNMP détectée et bloquée.\n"
                   "Service de monitoring protégé.\n"
                   "Votre scan réseau a été détecté."
    },
    {
        "port": 162,
        "service": "SNMP-Trap",
        "message": "📊 SNMP Trap - 2IEM_Security\n"
                   "Tentative SNMP Trap détectée.\n"
                   "Service de notification protégé.\n"
                   "Activité suspecte enregistrée."
    },

    # Services de jeux/applications
    {
        "port": 25565,
        "service": "Minecraft",
        "message": "🎮 Minecraft Server - 2IEM_Security\n"
                   "Tentative d'accès serveur Minecraft.\n"
                   "Serveur de jeu protégé - Accès refusé.\n"
                   "Votre tentative a été enregistrée."
    },

    # Ports hauts couramment scannés
    {
        "port": 8000,
        "service": "HTTP-Alt",
        "message": "🌐 HTTP Alternative - 2IEM_Security\n"
                   "Service HTTP alternatif - Accès interdit.\n"
                   "Tentative de contournement détectée.\n"
                   "Votre IP est maintenant surveillée."
    },
    {
        "port": 9000,
        "service": "HTTP-Mgmt",
        "message": "🌐 HTTP Management - 2IEM_Security\n"
                   "Interface de gestion protégée.\n"
                   "Tentative d'accès administrateur détectée.\n"
                   "Incident de sécurité signalé."
    },
]


def handle_client(client_socket, address, port, service, message):
    """Gère chaque connexion client sur un honeypot"""
    ip = address[0]
    timestamp = datetime.datetime.now()

    logger.info(f"🔴 Tentative de connexion {service} de {ip}:{address[1]} sur port {port}")

    try:
        # Enregistrement en base de données
        HoneypotLog.objects.create(
            ip_address=ip,
            port=port,
            service=service,
            message_sent=message.strip(),
            detected_on=timestamp
        )
        logger.info(f"✅ Log enregistré pour {ip} ({service} port {port})")

    except Exception as e:
        logger.error(f"❌ Erreur d'enregistrement en base pour {ip}: {e}")

    try:
        # Envoi de la réponse selon le protocole
        if service in ["HTTP", "HTTP-Alt", "HTTP-Mgmt", "HTTPS"]:
            # Réponse HTTP formatée
            response = (
                f"HTTP/1.1 403 Forbidden\r\n"
                f"Server: 2IEM_Security_Honeypot\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: {len(message)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{message}"
            )
            client_socket.send(response.encode('utf-8'))

        elif service in ["FTP"]:
            # Réponse FTP avec codes de statut
            client_socket.send(message.encode('utf-8'))

        elif service in ["SMTP"]:
            # Réponse SMTP avec codes de statut
            client_socket.send(message.encode('utf-8'))

        elif service in ["POP3"]:
            # Réponse POP3 avec format correct
            client_socket.send(message.encode('utf-8'))

        elif service in ["IMAP"]:
            # Réponse IMAP avec format correct
            client_socket.send(message.encode('utf-8'))

        else:
            # Réponse générique pour autres services
            client_socket.send(message.encode('utf-8'))

        logger.info(f"📨 Message {service} envoyé à {ip}")

    except Exception as e:
        logger.warning(f"⚠️ Échec envoi message à {ip}: {e}")

    finally:
        try:
            client_socket.close()
        except:
            pass


def start_honeypot(port, service, message):
    """Démarre un honeypot sur un port spécifique"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(('0.0.0.0', port))
        server.listen(10)  # Augmenté pour plus de connexions simultanées
        logger.info(f"🎯 Honeypot {service} actif sur le port {port}")

    except Exception as e:
        logger.error(f"❌ Impossible de démarrer {service} sur port {port}: {e}")
        return

    while True:
        try:
            client, addr = server.accept()
            # Timeout pour éviter les connexions qui traînent
            client.settimeout(30)

            # Lancement du thread pour gérer le client
            client_thread = threading.Thread(
                target=handle_client,
                args=(client, addr, port, service, message),
                daemon=True
            )
            client_thread.start()

        except Exception as e:
            logger.error(f"❌ Erreur acceptation connexion sur {service}:{port}: {e}")
            time.sleep(1)  # Pause courte en cas d'erreur


def main():
    """Fonction principale de lancement des honeypots"""
    logger.info("🚀 Lancement du système Honeypot multi-services 2IEM_Security")
    logger.info(f"📊 Configuration de {len(HONEYPOTS)} honeypots")

    # Statistiques des services
    services_count = {}
    for honeypot in HONEYPOTS:
        service = honeypot["service"]
        services_count[service] = services_count.get(service, 0) + 1

    logger.info("📋 Services configurés:")
    for service, count in services_count.items():
        logger.info(f"   - {service}: {count} port(s)")

    # Lancement de tous les honeypots
    threads = []
    for honeypot in HONEYPOTS:
        thread = threading.Thread(
            target=start_honeypot,
            args=(honeypot["port"], honeypot["service"], honeypot["message"]),
            daemon=True
        )
        thread.start()
        threads.append(thread)
        time.sleep(0.1)  # Petite pause entre les démarrages

    logger.info("✅ Tous les honeypots sont démarrés")
    logger.info("🛡️ Système de surveillance actif - Appuyez sur Ctrl+C pour arrêter")

    try:
        # Maintenir le programme en vie
        while True:
            time.sleep(60)
            # Log périodique pour confirmer que le système fonctionne
            active_threads = sum(1 for t in threads if t.is_alive())
            logger.info(f"Système actif - {active_threads}/{len(threads)} honeypots en fonctionnement")

    except KeyboardInterrupt:
        logger.info("🛑 Arrêt du système honeypot demandé")
        logger.info("👋 2IEM_Security Honeypot System - Arrêt en cours...")


if __name__ == "__main__":
    main()