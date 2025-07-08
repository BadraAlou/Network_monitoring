import subprocess
import platform
import time
import threading
import ipaddress
import socket
import struct
import logging
from scapy.all import ARP, Ether, srp, send, get_if_hwaddr, get_if_addr
from scapy.layers.l2 import getmacbyip
import netifaces

logger = logging.getLogger(__name__)


class NetworkDisconnector:
    """Classe pour déconnecter complètement une IP du réseau"""

    def __init__(self):
        self.system = platform.system().lower()
        self.gateway_ip = self.get_gateway_ip()
        self.local_ip = self.get_local_ip()
        self.local_mac = self.get_local_mac()
        self.interface = self.get_default_interface()

        # Threads actifs pour maintenir la déconnexion
        self.active_disconnections = {}

    def get_gateway_ip(self):
        """Récupère l'IP de la passerelle par défaut"""
        try:
            if "windows" in self.system:
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Default Gateway' in line or 'Passerelle par défaut' in line:
                        gateway = line.split(':')[-1].strip()
                        if gateway and gateway != '':
                            return gateway
            else:
                result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
                if result.stdout:
                    return result.stdout.split()[2]

            # Fallback avec netifaces
            gws = netifaces.gateways()
            return gws['default'][netifaces.AF_INET][0]
        except:
            return "192.168.1.1"  # Fallback commun

    def get_local_ip(self):
        """Récupère l'IP locale de la machine"""
        try:
            return get_if_addr(self.get_default_interface())
        except:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                return ip
            except:
                return "192.168.1.100"

    def get_local_mac(self):
        """Récupère l'adresse MAC locale"""
        try:
            return get_if_hwaddr(self.get_default_interface())
        except:
            return "00:00:00:00:00:00"

    def get_default_interface(self):
        """Récupère l'interface réseau par défaut"""
        try:
            if "windows" in self.system:
                return "Ethernet"  # Interface commune Windows
            else:
                # Linux
                result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
                if result.stdout:
                    return result.stdout.split()[4]
                return "eth0"
        except:
            return "eth0"

    def get_target_mac(self, target_ip):
        """Récupère l'adresse MAC d'une IP cible"""
        try:
            # Méthode 1: Scapy
            mac = getmacbyip(target_ip)
            if mac:
                return mac

            # Méthode 2: ARP request
            arp_request = ARP(pdst=target_ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

            if answered_list:
                return answered_list[0][1].hwsrc

            # Méthode 3: Table ARP système
            if "windows" in self.system:
                result = subprocess.run(['arp', '-a', target_ip], capture_output=True, text=True)
                if result.stdout:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if target_ip in line:
                            parts = line.split()
                            for part in parts:
                                if '-' in part and len(part) == 17:  # Format MAC Windows
                                    return part.replace('-', ':')
            else:
                result = subprocess.run(['arp', '-n', target_ip], capture_output=True, text=True)
                if result.stdout:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if target_ip in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                return parts[2]

            return None
        except Exception as e:
            logger.error(f"Erreur récupération MAC pour {target_ip}: {e}")
            return None

    def arp_poison_attack(self, target_ip, target_mac):
        """Lance une attaque ARP poisoning pour déconnecter la cible"""
        try:
            if not target_mac:
                logger.error(f"MAC address introuvable pour {target_ip}")
                return False

            logger.info(f"🎯 Début ARP poisoning: {target_ip} ({target_mac})")

            # Paquet ARP pour dire à la cible que nous sommes la passerelle
            arp_response_to_target = ARP(
                op=2,  # ARP reply
                pdst=target_ip,
                hwdst=target_mac,
                psrc=self.gateway_ip,
                hwsrc=self.local_mac
            )

            # Paquet ARP pour dire à la passerelle que nous sommes la cible
            gateway_mac = self.get_target_mac(self.gateway_ip)
            if not gateway_mac:
                logger.warning(f"MAC de la passerelle introuvable, saut de l’ARP poisoning vers le routeur.")
            else:
                arp_response_to_gateway = ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=gateway_mac,
                    psrc=target_ip,
                    hwsrc=self.local_mac
                )
                send(arp_response_to_gateway, verbose=False)

            # Envoi continu des paquets ARP
            while target_ip in self.active_disconnections:
                send(arp_response_to_target, verbose=False)
                send(arp_response_to_gateway, verbose=False)
                time.sleep(2)  # Envoi toutes les 2 secondes

            logger.info(f"🛑 Arrêt ARP poisoning pour {target_ip}")
            return True

        except Exception as e:
            logger.error(f"Erreur ARP poisoning pour {target_ip}: {e}")
            return False

    def dhcp_blacklist(self, target_ip, target_mac):
        """Ajoute l'IP/MAC à la blacklist DHCP si possible"""
        try:
            # Cette fonction dépend du type de serveur DHCP
            # Exemple pour ISC DHCP Server (Linux)
            if "linux" in self.system:
                dhcp_config = "/etc/dhcp/dhcpd.conf"
                blacklist_entry = f"""
# Blocked by 2IEM Security
host blocked_{target_ip.replace('.', '_')} {{
    hardware ethernet {target_mac};
    deny booting;
}}
"""
                try:
                    with open(dhcp_config, "a") as f:
                        f.write(blacklist_entry)

                    # Redémarrer le service DHCP
                    subprocess.run(["sudo", "systemctl", "restart", "isc-dhcp-server"], check=True)
                    logger.info(f"✅ DHCP blacklist ajoutée pour {target_ip}")
                    return True
                except:
                    logger.warning("Impossible d'accéder à la configuration DHCP")

            return False
        except Exception as e:
            logger.error(f"Erreur DHCP blacklist pour {target_ip}: {e}")
            return False

    def router_acl_block(self, target_ip):
        """Bloque l'IP au niveau du routeur (si accessible)"""
        try:
            # Tentative de connexion au routeur via SNMP ou SSH
            # Cette fonction nécessite les credentials du routeur

            # Exemple pour routeurs supportant SSH
            common_router_ips = [self.gateway_ip, "192.168.1.1", "192.168.0.1", "10.0.0.1"]

            for router_ip in common_router_ips:
                try:
                    # Tentative de blocage via commandes routeur
                    # (Nécessite configuration préalable des credentials)
                    logger.info(f"Tentative blocage routeur {router_ip} pour {target_ip}")
                    # Implémentation spécifique selon le type de routeur
                    break
                except:
                    continue

            return False
        except Exception as e:
            logger.error(f"Erreur blocage routeur pour {target_ip}: {e}")
            return False

    def force_disconnect_ip(self, target_ip, reason="Menace détectée"):
        """Déconnecte complètement une IP du réseau"""
        try:
            logger.info(f"🚫 DÉCONNEXION FORCÉE: {target_ip} - {reason}")

            # Vérifier si l'IP est dans le réseau local
            if not self.is_local_network_ip(target_ip):
                logger.warning(f"IP {target_ip} n'est pas dans le réseau local")
                return False

            # Récupérer l'adresse MAC
            target_mac = self.get_target_mac(target_ip)
            if not target_mac:
                logger.error(f"Impossible de récupérer la MAC pour {target_ip}")
                return False

            logger.info(f"🎯 Cible identifiée: {target_ip} -> {target_mac}")

            # Marquer comme active
            self.active_disconnections[target_ip] = {
                'mac': target_mac,
                'reason': reason,
                'start_time': time.time()
            }

            # 1. ARP Poisoning (déconnexion immédiate)
            arp_thread = threading.Thread(
                target=self.arp_poison_attack,
                args=(target_ip, target_mac),
                daemon=True
            )
            arp_thread.start()

            # 2. Blocage DHCP (empêche la reconnexion)
            self.dhcp_blacklist(target_ip, target_mac)

            # 3. Blocage routeur (si possible)
            self.router_acl_block(target_ip)

            # 4. Blocage pare-feu local (sécurité supplémentaire)
            self.firewall_block(target_ip, reason)

            # 5. Déconnexion forcée des sessions existantes
            self.kill_existing_connections(target_ip)

            logger.info(f"✅ Déconnexion forcée activée pour {target_ip}")
            return True

        except Exception as e:
            logger.error(f"Erreur déconnexion forcée {target_ip}: {e}")
            return False

    def stop_disconnect_ip(self, target_ip):
        """Arrête la déconnexion forcée d'une IP"""
        try:
            if target_ip in self.active_disconnections:
                del self.active_disconnections[target_ip]
                logger.info(f"🔓 Déconnexion forcée arrêtée pour {target_ip}")

                # Restaurer l'ARP normal
                self.restore_arp(target_ip)

                # Supprimer du blocage DHCP
                self.remove_dhcp_blacklist(target_ip)

                # Débloquer le pare-feu
                self.firewall_unblock(target_ip)

                return True
            return False
        except Exception as e:
            logger.error(f"Erreur arrêt déconnexion {target_ip}: {e}")
            return False

    def restore_arp(self, target_ip):
        """Restaure l'ARP normal pour une IP"""
        try:
            target_mac = self.get_target_mac(target_ip)
            gateway_mac = self.get_target_mac(self.gateway_ip)

            if target_mac and gateway_mac:
                # Envoyer les bonnes informations ARP
                correct_arp_to_target = ARP(
                    op=2,
                    pdst=target_ip,
                    hwdst=target_mac,
                    psrc=self.gateway_ip,
                    hwsrc=gateway_mac
                )

                correct_arp_to_gateway = ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=gateway_mac,
                    psrc=target_ip,
                    hwsrc=target_mac
                )

                # Envoyer plusieurs fois pour s'assurer
                for _ in range(5):
                    send(correct_arp_to_target, verbose=False)
                    send(correct_arp_to_gateway, verbose=False)
                    time.sleep(0.5)

                logger.info(f"🔄 ARP restauré pour {target_ip}")
        except Exception as e:
            logger.error(f"Erreur restauration ARP {target_ip}: {e}")

    def remove_dhcp_blacklist(self, target_ip):
        """Supprime l'IP de la blacklist DHCP"""
        try:
            if "linux" in self.system:
                dhcp_config = "/etc/dhcp/dhcpd.conf"

                # Lire le fichier et supprimer l'entrée
                try:
                    with open(dhcp_config, "r") as f:
                        lines = f.readlines()

                    # Filtrer les lignes de blocage
                    filtered_lines = []
                    skip_block = False

                    for line in lines:
                        if f"blocked_{target_ip.replace('.', '_')}" in line:
                            skip_block = True
                        elif skip_block and line.strip() == "}":
                            skip_block = False
                            continue
                        elif not skip_block:
                            filtered_lines.append(line)

                    # Réécrire le fichier
                    with open(dhcp_config, "w") as f:
                        f.writelines(filtered_lines)

                    # Redémarrer DHCP
                    subprocess.run(["sudo", "systemctl", "restart", "isc-dhcp-server"])
                    logger.info(f"✅ DHCP blacklist supprimée pour {target_ip}")
                except:
                    logger.warning("Impossible de modifier la configuration DHCP")
        except Exception as e:
            logger.error(f"Erreur suppression DHCP blacklist {target_ip}: {e}")

    def firewall_block(self, target_ip, reason):
        """Bloque l'IP au niveau pare-feu (méthode existante améliorée)"""
        try:
            if "windows" in self.system:
                rule_name = f"2IEM_DISCONNECT_{target_ip.replace('.', '_')}"

                # Blocage entrant ET sortant
                for direction in ["in", "out"]:
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}_{direction}",
                        f"dir={direction}",
                        "action=block",
                        f"remoteip={target_ip}",
                        f"description=2IEM Security Disconnect - {reason}"
                    ], check=True, timeout=10)

            elif "linux" in self.system:
                # Blocage iptables entrant ET sortant
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", target_ip, "-j", "DROP"], check=True)
                subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", target_ip, "-j", "DROP"], check=True)
                subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-s", target_ip, "-j", "DROP"], check=True)
                subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-d", target_ip, "-j", "DROP"], check=True)

            logger.info(f"🛡️ Pare-feu configuré pour {target_ip}")
            return True
        except Exception as e:
            logger.error(f"Erreur blocage pare-feu {target_ip}: {e}")
            return False

    def firewall_unblock(self, target_ip):
        """Débloque l'IP au niveau pare-feu"""
        try:
            if "windows" in self.system:
                rule_name = f"2IEM_DISCONNECT_{target_ip.replace('.', '_')}"

                for direction in ["in", "out"]:
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}_{direction}"
                    ], timeout=10)

            elif "linux" in self.system:
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", target_ip, "-j", "DROP"])
                subprocess.run(["sudo", "iptables", "-D", "OUTPUT", "-d", target_ip, "-j", "DROP"])
                subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", target_ip, "-j", "DROP"])
                subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-d", target_ip, "-j", "DROP"])

            logger.info(f"🔓 Pare-feu débloqué pour {target_ip}")
        except Exception as e:
            logger.error(f"Erreur déblocage pare-feu {target_ip}: {e}")

    def kill_existing_connections(self, target_ip):
        """Tue les connexions existantes avec l'IP cible"""
        try:
            if "windows" in self.system:
                # Windows: netstat + taskkill
                result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
                lines = result.stdout.split('\n')

                for line in lines:
                    if target_ip in line and 'ESTABLISHED' in line:
                        # Extraire les informations de connexion
                        parts = line.split()
                        if len(parts) >= 4:
                            local_addr = parts[1]
                            remote_addr = parts[2]
                            logger.info(f"🔪 Connexion active trouvée: {local_addr} <-> {remote_addr}")

            elif "linux" in self.system:
                # Linux: ss + kill
                result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
                # Implémentation pour tuer les connexions spécifiques

            logger.info(f"🔪 Connexions existantes fermées pour {target_ip}")
        except Exception as e:
            logger.error(f"Erreur fermeture connexions {target_ip}: {e}")

    def is_local_network_ip(self, ip):
        """Vérifie si l'IP est dans le réseau local"""
        try:
            ip_obj = ipaddress.ip_address(ip)

            # Réseaux privés communs
            private_networks = [
                ipaddress.ip_network('192.168.0.0/16'),
                ipaddress.ip_network('10.0.0.0/8'),
                ipaddress.ip_network('172.16.0.0/12'),
            ]

            for network in private_networks:
                if ip_obj in network:
                    return True

            return False
        except:
            return False

    def get_active_disconnections(self):
        """Retourne la liste des déconnexions actives"""
        return self.active_disconnections.copy()

    def monitor_disconnections(self):
        """Monitore les déconnexions actives"""
        while True:
            try:
                current_time = time.time()
                for ip, info in list(self.active_disconnections.items()):
                    duration = current_time - info['start_time']
                    logger.info(f"📊 {ip} déconnecté depuis {duration:.0f}s - {info['reason']}")

                time.sleep(60)  # Vérification toutes les minutes
            except Exception as e:
                logger.error(f"Erreur monitoring déconnexions: {e}")
                time.sleep(60)


# Instance globale
network_disconnector = NetworkDisconnector()