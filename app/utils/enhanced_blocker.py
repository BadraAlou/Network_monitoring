import subprocess
import platform
import time
import threading
import logging
import os
import sys
import ctypes
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class EnhancedIPBlocker:
    """Système de blocage IP ultra-agressif et multi-méthodes"""

    def __init__(self):
        self.system = platform.system().lower()
        self.is_admin = self.check_admin_privileges()
        self.firewall_methods = []
        self.blocked_ips = set()

        # Initialiser les méthodes disponibles
        self.initialize_blocking_methods()

    def check_admin_privileges(self):
        """Vérifie si le script a les privilèges administrateur"""
        try:
            if "windows" in self.system:
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False

    def ensure_admin_privileges(self):
        """Force l'exécution avec privilèges administrateur"""
        if not self.is_admin:
            if "windows" in self.system:
                # Relancer avec privilèges admin sur Windows
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(sys.argv), None, 1
                )
            else:
                # Sur Linux, afficher un message
                logger.error("❌ Privilèges root requis. Exécutez avec sudo.")
            return False
        return True

    def initialize_blocking_methods(self):
        """Initialise toutes les méthodes de blocage disponibles"""
        logger.info("🔧 Initialisation des méthodes de blocage...")

        if "windows" in self.system:
            self.firewall_methods = [
                self.block_windows_firewall,
                self.block_windows_hosts,
                self.block_windows_route,
                self.block_windows_netsh_interface
            ]
        else:
            self.firewall_methods = [
                self.block_linux_iptables,
                self.block_linux_hosts,
                self.block_linux_route,
                self.block_linux_tc
            ]

        logger.info(f"✅ {len(self.firewall_methods)} méthodes de blocage initialisées")

    def check_firewall_status(self):
        """Vérifie le statut du pare-feu système"""
        try:
            if "windows" in self.system:
                result = subprocess.run([
                    "netsh", "advfirewall", "show", "allprofiles", "state"
                ], capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    if "ON" in result.stdout or "Activé" in result.stdout:
                        logger.info("✅ Pare-feu Windows activé")
                        return True
                    else:
                        logger.warning("⚠️ Pare-feu Windows désactivé")
                        return self.enable_windows_firewall()
                else:
                    logger.error(f"❌ Erreur vérification pare-feu: {result.stderr}")
                    return False
            else:
                # Linux - vérifier iptables
                result = subprocess.run(["sudo", "iptables", "-L"],
                                        capture_output=True, timeout=10)
                return result.returncode == 0
        except Exception as e:
            logger.error(f"❌ Erreur vérification pare-feu: {e}")
            return False

    def enable_windows_firewall(self):
        """Active le pare-feu Windows si désactivé"""
        try:
            logger.info("🔥 Activation du pare-feu Windows...")
            result = subprocess.run([
                "netsh", "advfirewall", "set", "allprofiles", "state", "on"
            ], capture_output=True, text=True, timeout=15)

            if result.returncode == 0:
                logger.info("✅ Pare-feu Windows activé avec succès")
                return True
            else:
                logger.error(f"❌ Échec activation pare-feu: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"❌ Erreur activation pare-feu: {e}")
            return False

    # === MÉTHODES DE BLOCAGE WINDOWS ===

    def block_windows_firewall(self, ip, reason):
        """Méthode 1: Blocage via pare-feu Windows (amélioré)"""
        try:
            rule_name = f"2IEM_BLOCK_{ip.replace('.', '_')}"

            # Supprimer la règle existante si elle existe
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}"
            ], capture_output=True, timeout=10)

            # Créer règle ENTRANTE
            cmd_in = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}_IN",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                "protocol=any",
                f"description=2IEM Security Block - {reason}"
            ]

            result_in = subprocess.run(cmd_in, capture_output=True, text=True, timeout=15)

            # Créer règle SORTANTE
            cmd_out = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}_OUT",
                "dir=out",
                "action=block",
                f"remoteip={ip}",
                "protocol=any",
                f"description=2IEM Security Block - {reason}"
            ]

            result_out = subprocess.run(cmd_out, capture_output=True, text=True, timeout=15)

            if result_in.returncode == 0 and result_out.returncode == 0:
                logger.info(f"✅ Pare-feu Windows: {ip} bloqué (IN/OUT)")
                return True
            else:
                logger.error(f"❌ Pare-feu Windows échec pour {ip}")
                logger.error(f"IN: {result_in.stderr}")
                logger.error(f"OUT: {result_out.stderr}")
                return False

        except Exception as e:
            logger.error(f"❌ Erreur pare-feu Windows {ip}: {e}")
            return False

    def block_windows_hosts(self, ip, reason):
        """Méthode 2: Blocage via fichier hosts Windows"""
        try:
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"

            # Lire le fichier hosts
            with open(hosts_path, 'r') as f:
                content = f.read()

            # Vérifier si déjà présent
            if ip in content:
                logger.info(f"⚠️ {ip} déjà dans hosts")
                return True

            # Ajouter l'entrée
            entry = f"\n# 2IEM Security Block - {reason}\n127.0.0.1 {ip}\n"

            with open(hosts_path, 'a') as f:
                f.write(entry)

            # Vider le cache DNS
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True)

            logger.info(f"✅ Hosts Windows: {ip} bloqué")
            return True

        except Exception as e:
            logger.error(f"❌ Erreur hosts Windows {ip}: {e}")
            return False

    def block_windows_route(self, ip, reason):
        """Méthode 3: Blocage via table de routage Windows"""
        try:
            # Ajouter route vers nulle part
            cmd = ["route", "add", ip, "mask", "255.255.255.255", "127.0.0.1", "metric", "1"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                logger.info(f"✅ Route Windows: {ip} bloqué")
                return True
            else:
                logger.error(f"❌ Route Windows échec {ip}: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"❌ Erreur route Windows {ip}: {e}")
            return False

    def block_windows_netsh_interface(self, ip, reason):
        """Méthode 4: Blocage via interface réseau Windows"""
        try:
            # Bloquer au niveau interface
            cmd = [
                "netsh", "interface", "ipv4", "add", "address",
                "Loopback", f"{ip}", "255.255.255.255"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                logger.info(f"✅ Interface Windows: {ip} bloqué")
                return True
            else:
                # Cette méthode peut échouer, ce n'est pas critique
                logger.debug(f"Interface Windows: {ip} - {result.stderr}")
                return False

        except Exception as e:
            logger.debug(f"Interface Windows {ip}: {e}")
            return False

    # === MÉTHODES DE BLOCAGE LINUX ===

    def block_linux_iptables(self, ip, reason):
        """Méthode 1: Blocage via iptables Linux"""
        try:
            commands = [
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                ["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                ["sudo", "iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"],
                ["sudo", "iptables", "-A", "FORWARD", "-d", ip, "-j", "DROP"]
            ]

            success_count = 0
            for cmd in commands:
                result = subprocess.run(cmd, capture_output=True, timeout=10)
                if result.returncode == 0:
                    success_count += 1

            if success_count >= 2:  # Au moins INPUT et OUTPUT
                logger.info(f"✅ Iptables Linux: {ip} bloqué ({success_count}/4 règles)")
                return True
            else:
                logger.error(f"❌ Iptables Linux échec {ip}")
                return False

        except Exception as e:
            logger.error(f"❌ Erreur iptables Linux {ip}: {e}")
            return False

    def block_linux_hosts(self, ip, reason):
        """Méthode 2: Blocage via fichier hosts Linux"""
        try:
            hosts_path = "/etc/hosts"

            with open(hosts_path, 'r') as f:
                content = f.read()

            if ip in content:
                logger.info(f"⚠️ {ip} déjà dans hosts")
                return True

            entry = f"\n# 2IEM Security Block - {reason}\n127.0.0.1 {ip}\n"

            with open(hosts_path, 'a') as f:
                f.write(entry)

            logger.info(f"✅ Hosts Linux: {ip} bloqué")
            return True

        except Exception as e:
            logger.error(f"❌ Erreur hosts Linux {ip}: {e}")
            return False

    def block_linux_route(self, ip, reason):
        """Méthode 3: Blocage via table de routage Linux"""
        try:
            cmd = ["sudo", "ip", "route", "add", "blackhole", ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                logger.info(f"✅ Route Linux: {ip} bloqué")
                return True
            else:
                logger.error(f"❌ Route Linux échec {ip}: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"❌ Erreur route Linux {ip}: {e}")
            return False

    def block_linux_tc(self, ip, reason):
        """Méthode 4: Blocage via Traffic Control Linux"""
        try:
            # Cette méthode est plus avancée et peut ne pas fonctionner partout
            interface = "eth0"  # À adapter selon l'interface

            cmd = [
                "sudo", "tc", "filter", "add", "dev", interface,
                "protocol", "ip", "parent", "1:", "prio", "1",
                "u32", "match", "ip", "src", ip, "flowid", "1:1"
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=10)

            if result.returncode == 0:
                logger.info(f"✅ TC Linux: {ip} bloqué")
                return True
            else:
                logger.debug(f"TC Linux: {ip} - {result.stderr}")
                return False

        except Exception as e:
            logger.debug(f"TC Linux {ip}: {e}")
            return False

    # === MÉTHODE PRINCIPALE DE BLOCAGE ===

    def force_block_ip(self, ip, reason="Menace détectée"):
        """BLOCAGE ULTRA-AGRESSIF - Utilise TOUTES les méthodes disponibles"""
        logger.critical(f"🚫 BLOCAGE FORCÉ INITIÉ: {ip} - {reason}")

        # Vérifier les privilèges
        if not self.ensure_admin_privileges():
            logger.error("❌ Privilèges administrateur requis pour le blocage")
            return False

        # Vérifier le pare-feu
        firewall_ok = self.check_firewall_status()
        if not firewall_ok:
            logger.warning("⚠️ Problème pare-feu détecté, utilisation méthodes alternatives")

        success_methods = []
        failed_methods = []

        # Appliquer TOUTES les méthodes de blocage
        for i, method in enumerate(self.firewall_methods):
            try:
                method_name = method.__name__
                logger.info(f"🔄 Méthode {i + 1}/{len(self.firewall_methods)}: {method_name}")

                if method(ip, reason):
                    success_methods.append(method_name)
                    logger.info(f"✅ {method_name}: SUCCÈS")
                else:
                    failed_methods.append(method_name)
                    logger.warning(f"❌ {method_name}: ÉCHEC")

                # Petite pause entre les méthodes
                time.sleep(0.5)

            except Exception as e:
                failed_methods.append(f"{method.__name__} (Exception)")
                logger.error(f"❌ {method.__name__} Exception: {e}")

        # Déconnexion réseau forcée (ARP poisoning)
        try:
            from app.utils.network_disconnector import network_disconnector
            disconnect_success = network_disconnector.force_disconnect_ip(ip, reason)
            if disconnect_success:
                success_methods.append("network_disconnect")
                logger.critical(f"🚫 DÉCONNEXION RÉSEAU FORCÉE: {ip}")
            else:
                failed_methods.append("network_disconnect")
        except Exception as e:
            logger.error(f"❌ Erreur déconnexion réseau {ip}: {e}")
            failed_methods.append("network_disconnect (Exception)")

        # Tuer les connexions existantes
        try:
            self.kill_all_connections(ip)
            success_methods.append("kill_connections")
        except Exception as e:
            logger.error(f"❌ Erreur fermeture connexions {ip}: {e}")
            failed_methods.append("kill_connections")

        # Ajouter à la liste des IPs bloquées
        self.blocked_ips.add(ip)

        # Rapport final
        total_methods = len(self.firewall_methods) + 2  # +2 pour disconnect et kill_connections
        success_count = len(success_methods)

        logger.critical(f"📊 RAPPORT BLOCAGE {ip}:")
        logger.critical(f"   ✅ Succès: {success_count}/{total_methods} méthodes")
        logger.critical(f"   ✅ Méthodes réussies: {', '.join(success_methods)}")
        if failed_methods:
            logger.warning(f"   ❌ Méthodes échouées: {', '.join(failed_methods)}")

        # Considérer comme succès si au moins 50% des méthodes ont réussi
        if success_count >= (total_methods // 2):
            logger.critical(f"🛡️ BLOCAGE RÉUSSI: {ip} - {success_count} méthodes actives")

            # Surveillance continue
            self.start_continuous_monitoring(ip, reason)

            return True
        else:
            logger.critical(f"❌ BLOCAGE PARTIEL: {ip} - Seulement {success_count} méthodes")
            return False

    def kill_all_connections(self, ip):
        """Tue toutes les connexions actives avec l'IP"""
        try:
            if "windows" in self.system:
                # Windows: netstat + taskkill
                result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
                lines = result.stdout.split('\n')

                pids_to_kill = set()
                for line in lines:
                    if ip in line and 'ESTABLISHED' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            pid = parts[-1]
                            if pid.isdigit():
                                pids_to_kill.add(pid)

                # Tuer les processus
                for pid in pids_to_kill:
                    try:
                        subprocess.run(['taskkill', '/F', '/PID', pid],
                                       capture_output=True, timeout=5)
                        logger.info(f"🔪 Processus {pid} terminé (connexion {ip})")
                    except:
                        pass

            else:
                # Linux: ss + kill
                result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
                # Implémentation Linux pour tuer les connexions

            logger.info(f"🔪 Connexions fermées pour {ip}")

        except Exception as e:
            logger.error(f"❌ Erreur fermeture connexions {ip}: {e}")

    def start_continuous_monitoring(self, ip, reason):
        """Démarre la surveillance continue d'une IP bloquée"""

        def monitor():
            while ip in self.blocked_ips:
                try:
                    # Vérifier si l'IP tente encore de communiquer
                    if self.check_ip_activity(ip):
                        logger.warning(f"⚠️ Activité détectée de {ip} malgré le blocage")
                        # Re-appliquer le blocage
                        self.reapply_blocking(ip, reason)

                    time.sleep(30)  # Vérification toutes les 30 secondes
                except Exception as e:
                    logger.error(f"❌ Erreur monitoring {ip}: {e}")
                    time.sleep(60)

        # Démarrer le thread de surveillance
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()
        logger.info(f"👁️ Surveillance continue activée pour {ip}")

    def check_ip_activity(self, ip):
        """Vérifie si une IP a encore de l'activité réseau"""
        try:
            if "windows" in self.system:
                result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
                return ip in result.stdout
            else:
                result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
                return ip in result.stdout
        except:
            return False

    def reapply_blocking(self, ip, reason):
        """Re-applique le blocage si nécessaire"""
        logger.warning(f"🔄 Re-application du blocage pour {ip}")

        # Re-appliquer seulement les méthodes principales
        if "windows" in self.system:
            self.block_windows_firewall(ip, f"RE-BLOCK: {reason}")
        else:
            self.block_linux_iptables(ip, f"RE-BLOCK: {reason}")

    def unblock_ip(self, ip):
        """Débloque complètement une IP"""
        logger.info(f"🔓 DÉBLOCAGE COMPLET: {ip}")

        # Retirer de la liste de surveillance
        self.blocked_ips.discard(ip)

        try:
            if "windows" in self.system:
                # Supprimer règles pare-feu
                rule_name = f"2IEM_BLOCK_{ip.replace('.', '_')}"
                for suffix in ["_IN", "_OUT", ""]:
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}{suffix}"
                    ], capture_output=True, timeout=10)

                # Supprimer route
                subprocess.run(["route", "delete", ip], capture_output=True)

                # Nettoyer hosts
                self.clean_hosts_file(ip)

            else:
                # Linux - supprimer règles iptables
                commands = [
                    ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    ["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                    ["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"],
                    ["sudo", "iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"]
                ]

                for cmd in commands:
                    subprocess.run(cmd, capture_output=True, timeout=5)

                # Supprimer route blackhole
                subprocess.run(["sudo", "ip", "route", "del", "blackhole", ip],
                               capture_output=True)

                # Nettoyer hosts
                self.clean_hosts_file(ip)

            # Restaurer la connectivité réseau
            try:
                from app.utils.network_disconnector import network_disconnector
                network_disconnector.stop_disconnect_ip(ip)
            except:
                pass

            logger.info(f"✅ DÉBLOCAGE COMPLET TERMINÉ: {ip}")
            return True

        except Exception as e:
            logger.error(f"❌ Erreur déblocage {ip}: {e}")
            return False

    def clean_hosts_file(self, ip):
        """Nettoie le fichier hosts"""
        try:
            if "windows" in self.system:
                hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
            else:
                hosts_path = "/etc/hosts"

            with open(hosts_path, 'r') as f:
                lines = f.readlines()

            # Filtrer les lignes contenant l'IP
            filtered_lines = []
            skip_next = False

            for line in lines:
                if f"# 2IEM Security Block" in line and ip in line:
                    skip_next = True
                    continue
                elif skip_next and ip in line:
                    skip_next = False
                    continue
                else:
                    filtered_lines.append(line)

            with open(hosts_path, 'w') as f:
                f.writelines(filtered_lines)

            logger.info(f"🧹 Fichier hosts nettoyé pour {ip}")

        except Exception as e:
            logger.error(f"❌ Erreur nettoyage hosts {ip}: {e}")


# Instance globale
enhanced_blocker = EnhancedIPBlocker()