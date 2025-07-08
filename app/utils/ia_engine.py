import re
from datetime import datetime, timedelta
from django.utils import timezone


def analyser_alerte(alert):
    """
    Analyse intelligente d'une alerte de sécurité avec recommandations précises
    Basé sur les nouvelles règles Suricata 2IEM Security
    """

    # Extraction des données
    gravite = alert.severity.lower()
    type_alerte = alert.alert_type.lower()
    protocole = (alert.protocol or "").upper()
    description = (alert.description or "").lower()
    signature = (alert.signature or "").lower()
    src_ip = alert.src_ip
    dest_ip = alert.dest_ip

    # Analyse contextuelle
    verdict = ""
    recommandations = []
    niveau_risque = "FAIBLE"
    actions_immediates = []

    # === ANALYSE PAR TYPE D'ALERTE ===

    if type_alerte == "dos":
        niveau_risque = "CRITIQUE" if gravite in ["critical", "high"] else "ÉLEVÉ"
        verdict = "🚨 ATTAQUE DOS/DDOS DÉTECTÉE"

        if "hping3" in signature or "hping" in signature:
            verdict += " - Outil Hping3 utilisé pour saturer le réseau"
            recommandations.extend([
                "Bloquer immédiatement l'IP source",
                "Vérifier la bande passante disponible",
                "Activer la limitation de débit (rate limiting)",
                "Surveiller les autres IPs du même sous-réseau"
            ])
        elif "syn flood" in signature:
            verdict += " - Attaque SYN Flood détectée"
            recommandations.extend([
                "Activer SYN cookies sur les serveurs",
                "Configurer des timeouts TCP plus courts",
                "Implémenter un pare-feu anti-DDoS"
            ])
        elif "udp flood" in signature:
            verdict += " - Attaque UDP Flood en cours"
            recommandations.extend([
                "Filtrer le trafic UDP non essentiel",
                "Vérifier les services UDP exposés",
                "Implémenter des règles de limitation UDP"
            ])

        actions_immediates.extend([
            f"Bloquer l'IP {src_ip} immédiatement",
            "Alerter l'équipe réseau",
            "Documenter l'incident"
        ])

    elif type_alerte == "attaque":
        niveau_risque = "CRITIQUE"
        verdict = "🛑 TENTATIVE D'ATTAQUE APPLICATIVE"

        if "sql injection" in signature or "union select" in signature:
            verdict += " - Injection SQL détectée"
            recommandations.extend([
                "Vérifier les logs de l'application web",
                "Auditer les requêtes SQL récentes",
                "Implémenter des requêtes préparées",
                "Mettre à jour le WAF (Web Application Firewall)",
                "Effectuer un scan de vulnérabilités sur l'application"
            ])
            actions_immediates.extend([
                "Bloquer l'IP attaquante",
                "Vérifier l'intégrité de la base de données",
                "Changer les mots de passe des comptes de service"
            ])
        elif "or 1=1" in signature:
            verdict += " - Tentative de bypass d'authentification"
            recommandations.extend([
                "Auditer tous les formulaires de connexion",
                "Implémenter une validation stricte des entrées",
                "Activer la journalisation détaillée des tentatives de connexion"
            ])

    elif type_alerte == "bruteforce":
        niveau_risque = "ÉLEVÉ" if gravite == "high" else "MOYEN"
        verdict = "⚠️ ATTAQUE BRUTE FORCE DÉTECTÉE"

        if "ssh" in signature:
            verdict += " - Tentatives multiples sur SSH"
            recommandations.extend([
                "Désactiver l'authentification par mot de passe SSH",
                "Implémenter l'authentification par clés",
                "Changer le port SSH par défaut (22)",
                "Configurer fail2ban pour SSH",
                "Limiter les connexions SSH par IP"
            ])
        elif "ftp" in signature:
            verdict += " - Attaque sur service FTP"
            recommandations.extend([
                "Migrer vers SFTP ou FTPS",
                "Implémenter des comptes à privilèges limités",
                "Configurer des timeouts de session courts"
            ])
        elif "rdp" in signature:
            verdict += " - Tentatives sur Remote Desktop"
            recommandations.extend([
                "Activer l'authentification à deux facteurs",
                "Changer le port RDP par défaut (3389)",
                "Implémenter Network Level Authentication",
                "Restreindre l'accès RDP par IP"
            ])

        actions_immediates.extend([
            f"Bloquer temporairement l'IP {src_ip}",
            "Vérifier les logs d'authentification",
            "Alerter les administrateurs système"
        ])

    elif type_alerte == "scan":
        niveau_risque = "MOYEN" if gravite == "high" else "FAIBLE"
        verdict = "🔍 ACTIVITÉ DE RECONNAISSANCE DÉTECTÉE"

        if "nmap" in signature:
            verdict += " - Scan Nmap en cours"
            recommandations.extend([
                "Identifier les services exposés inutilement",
                "Fermer les ports non essentiels",
                "Configurer un IPS pour bloquer les scans",
                "Surveiller les tentatives de connexion ultérieures"
            ])
        elif "rustscan" in signature:
            verdict += " - Scan ultra-rapide RustScan"
            recommandations.extend([
                "Implémenter une détection de scan rapide",
                "Configurer des honeypots pour détecter les attaquants"
            ])
        elif "masscan" in signature:
            verdict += " - Scan à grande échelle Masscan"
            recommandations.extend([
                "Vérifier si d'autres IPs du réseau sont scannées",
                "Implémenter une détection de scan distribué"
            ])

    elif type_alerte == "malware":
        niveau_risque = "CRITIQUE"
        verdict = "🦠 CODE MALVEILLANT DÉTECTÉ"

        recommandations.extend([
            "Isoler immédiatement la machine infectée",
            "Effectuer un scan antivirus complet",
            "Vérifier les connexions réseau sortantes",
            "Analyser les processus en cours d'exécution",
            "Restaurer depuis une sauvegarde propre si nécessaire"
        ])
        actions_immediates.extend([
            "Déconnecter la machine du réseau",
            "Alerter l'équipe de sécurité",
            "Documenter tous les fichiers suspects"
        ])

    elif type_alerte == "exfiltration":
        niveau_risque = "CRITIQUE"
        verdict = "📤 TENTATIVE D'EXFILTRATION DE DONNÉES"

        if "dropbox" in signature or "drive.google" in signature:
            verdict += " - Upload vers service cloud détecté"
            recommandations.extend([
                "Bloquer l'accès aux services de stockage cloud",
                "Auditer les données potentiellement compromises",
                "Implémenter un DLP (Data Loss Prevention)",
                "Vérifier les permissions d'accès aux fichiers sensibles"
            ])
        elif "pastebin" in signature:
            verdict += " - Upload vers Pastebin détecté"
            recommandations.extend([
                "Bloquer l'accès aux sites de partage de code",
                "Vérifier si des secrets/mots de passe ont été exposés"
            ])

    elif type_alerte == "fraude":
        niveau_risque = "CRITIQUE"
        verdict = "💰 ACTIVITÉ FRAUDULEUSE DÉTECTÉE"

        if "mobile money" in signature:
            verdict += " - Tentative de fraude Mobile Money"
            recommandations.extend([
                "Alerter immédiatement les services financiers",
                "Bloquer toutes les transactions suspectes",
                "Vérifier l'intégrité des systèmes de paiement",
                "Contacter les autorités compétentes"
            ])

    elif type_alerte == "exploit":
        niveau_risque = "CRITIQUE"
        verdict = "💥 TENTATIVE D'EXPLOITATION DÉTECTÉE"

        recommandations.extend([
            "Identifier la vulnérabilité exploitée",
            "Appliquer les correctifs de sécurité",
            "Vérifier si l'exploitation a réussi",
            "Effectuer une analyse forensique"
        ])

    # === ANALYSE CONTEXTUELLE AVANCÉE ===

    # Analyse temporelle
    now = timezone.now()
    if alert.detected_on:
        if alert.detected_on.hour < 6 or alert.detected_on.hour > 22:
            verdict += " ⏰ [HORS HEURES OUVRABLES - SUSPECT]"
            niveau_risque = "ÉLEVÉ" if niveau_risque == "MOYEN" else niveau_risque

    # Analyse géographique (IP privées vs publiques)
    if src_ip and dest_ip:
        try:
            import ipaddress
            src_private = ipaddress.ip_address(src_ip).is_private
            dest_private = ipaddress.ip_address(dest_ip).is_private

            if not src_private and dest_private:
                verdict += " 🌐 [ATTAQUE EXTERNE VERS INTERNE]"
                niveau_risque = "CRITIQUE"
            elif src_private and not dest_private:
                verdict += " 📡 [TRAFIC SORTANT SUSPECT]"
        except:
            pass

    # Analyse protocolaire
    if protocole:
        if protocole in ["FTP", "TELNET", "HTTP"]:
            verdict += f" 🔓 [PROTOCOLE NON SÉCURISÉ: {protocole}]"
            recommandations.append(f"Migrer vers une version sécurisée de {protocole}")

    # === CONSTRUCTION DU RAPPORT FINAL ===

    rapport = f"""
🤖 === ANALYSE IA 2IEM SECURITY ===

🎯 VERDICT: {verdict}
📊 NIVEAU DE RISQUE: {niveau_risque}
🕒 ANALYSÉ LE: {now.strftime('%d/%m/%Y à %H:%M:%S')}

📋 DÉTAILS TECHNIQUES:
• IP Source: {src_ip}
• IP Destination: {dest_ip}
• Protocole: {protocole}
• Gravité: {gravite.upper()}
• Type: {type_alerte.upper()}

⚡ ACTIONS IMMÉDIATES:"""

    if actions_immediates:
        for action in actions_immediates:
            rapport += f"\n• {action}"
    else:
        rapport += "\n• Surveillance continue recommandée"

    rapport += "\n\n💡 RECOMMANDATIONS:"
    if recommandations:
        for rec in recommandations:
            rapport += f"\n• {rec}"
    else:
        rapport += "\n• Aucune action spécifique requise pour le moment"

    # Ajout de conseils généraux selon le niveau de risque
    if niveau_risque == "CRITIQUE":
        rapport += "\n\n🚨 ALERTE CRITIQUE: Intervention immédiate requise!"
    elif niveau_risque == "ÉLEVÉ":
        rapport += "\n\n⚠️ RISQUE ÉLEVÉ: Surveillance renforcée recommandée"
    elif niveau_risque == "MOYEN":
        rapport += "\n\n🔍 RISQUE MODÉRÉ: Vérification recommandée"
    else:
        rapport += "\n\n✅ RISQUE FAIBLE: Surveillance normale"

    rapport += "\n\n🛡️ 2IEM Security - Protection Intelligente"

    return rapport.strip()


def get_attack_trend_analysis(alert):
    """Analyse les tendances d'attaques pour une IP donnée"""
    try:
        from app.models import Alert
        from datetime import timedelta

        # Recherche des alertes similaires dans les dernières 24h
        recent_alerts = Alert.objects.filter(
            src_ip=alert.src_ip,
            detected_on__gte=timezone.now() - timedelta(hours=24)
        ).exclude(id=alert.id)

        if recent_alerts.count() > 5:
            return f"\n PATTERN DÉTECTÉ: {recent_alerts.count()} alertes similaires en 24h"
        elif recent_alerts.count() > 0:
            return f"\n HISTORIQUE: {recent_alerts.count()} alerte(s) récente(s) de cette IP"

        return ""
    except:
        return ""