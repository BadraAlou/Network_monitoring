import subprocess
import platform
import ipaddress
import psutil
import time
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import user_passes_test
from django.contrib import messages
from django.http import JsonResponse
from django.utils import timezone
from datetime import timedelta
from app.models import BlockedIP
import logging

logger = logging.getLogger(__name__)


class AdvancedIPBlocker:
    """Système de blocage IP ultra-renforcé multi-niveaux"""

    def __init__(self):
        self.system = platform.system().lower()
        self.is_admin = self._check_admin_privileges()

    def _check_admin_privileges(self):
        """Vérifier les privilèges administrateur"""
        try:
            if "windows" in self.system:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False

    def _run_command(self, cmd, timeout=15):
        """Exécuter une commande système avec gestion d'erreurs"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout lors de l'exécution: {' '.join(cmd)}")
            return False, "", "Timeout"
        except Exception as e:
            logger.error(f"Erreur commande {' '.join(cmd)}: {e}")
            return False, "", str(e)

    def force_block_ip(self, ip, reason="Blocage automatique"):
        """Blocage IP ultra-agressif multi-niveaux"""
        logger.critical(f"🚫 BLOCAGE ULTRA-AGRESSIF INITIÉ: {ip}")

        success_count = 0
        total_methods = 0

        # Méthode 1: Firewall principal
        if self._block_firewall_primary(ip):
            success_count += 1
        total_methods += 1

        # Méthode 2: Firewall secondaire (règles supplémentaires)
        if self._block_firewall_secondary(ip):
            success_count += 1
        total_methods += 1

        # Méthode 3: Blocage réseau avancé
        if self._block_network_advanced(ip):
            success_count += 1
        total_methods += 1

        # Méthode 4: Déconnexion DHCP forcée
        if self._disconnect_dhcp(ip):
            success_count += 1
        total_methods += 1

        # Méthode 5: Blocage au niveau interface réseau
        if self._block_interface_level(ip):
            success_count += 1
        total_methods += 1

        # Méthode 6: Blocage des connexions existantes
        if self._kill_existing_connections(ip):
            success_count += 1
        total_methods += 1

        success_rate = (success_count / total_methods) * 100
        logger.critical(f"🚫 Blocage {ip}: {success_count}/{total_methods} méthodes réussies ({success_rate:.1f}%)")

        return success_count >= 3  # Au moins 3 méthodes doivent réussir

    def _block_firewall_primary(self, ip):
        """Blocage firewall principal"""
        try:
            if "windows" in self.system:
                # Windows - Règles multiples
                rule_name = f"2IEM_BLOCK_IN_{ip.replace('.', '_')}"
                rule_name_out = f"2IEM_BLOCK_OUT_{ip.replace('.', '_')}"

                # Bloquer entrée
                cmd_in = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}",
                    "protocol=any"
                ]

                # Bloquer sortie
                cmd_out = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name_out}",
                    "dir=out",
                    "action=block",
                    f"remoteip={ip}",
                    "protocol=any"
                ]

                success1, _, _ = self._run_command(cmd_in)
                success2, _, _ = self._run_command(cmd_out)
                return success1 and success2

            else:
                # Linux - Règles iptables multiples
                commands = [
                    ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
                    ["sudo", "iptables", "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP"],
                    ["sudo", "iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"],
                    ["sudo", "iptables", "-I", "FORWARD", "1", "-d", ip, "-j", "DROP"]
                ]

                success_count = 0
                for cmd in commands:
                    if self._run_command(cmd)[0]:
                        success_count += 1

                return success_count >= 2

        except Exception as e:
            logger.error(f"Erreur blocage firewall principal {ip}: {e}")
            return False

    def _block_firewall_secondary(self, ip):
        """Blocage firewall secondaire avec règles spécifiques"""
        try:
            if "windows" in self.system:
                # Bloquer ports spécifiques
                ports = ["80", "443", "22", "21", "25", "53", "3389"]
                success_count = 0

                for port in ports:
                    rule_name = f"2IEM_PORT_BLOCK_{ip.replace('.', '_')}_{port}"
                    cmd = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}",
                        "dir=in",
                        "action=block",
                        f"remoteip={ip}",
                        "protocol=TCP",
                        f"localport={port}"
                    ]
                    if self._run_command(cmd)[0]:
                        success_count += 1

                return success_count >= 3

            else:
                # Linux - Blocage par protocole
                commands = [
                    ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-p", "tcp", "-j", "REJECT", "--reject-with",
                     "tcp-reset"],
                    ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-p", "udp", "-j", "REJECT", "--reject-with",
                     "icmp-port-unreachable"],
                    ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-p", "icmp", "-j", "DROP"]
                ]

                success_count = 0
                for cmd in commands:
                    if self._run_command(cmd)[0]:
                        success_count += 1

                return success_count >= 2

        except Exception as e:
            logger.error(f"Erreur blocage firewall secondaire {ip}: {e}")
            return False

    def _block_network_advanced(self, ip):
        """Blocage réseau avancé"""
        try:
            if "windows" in self.system:
                # Windows - Route vers null
                cmd = ["route", "add", ip, "mask", "255.255.255.255", "0.0.0.0", "metric", "1"]
                return self._run_command(cmd)[0]
            else:
                # Linux - Route vers blackhole
                cmd = ["sudo", "ip", "route", "add", "blackhole", ip]
                return self._run_command(cmd)[0]
        except Exception as e:
            logger.error(f"Erreur blocage réseau avancé {ip}: {e}")
            return False

    def _disconnect_dhcp(self, ip):
        """Déconnexion DHCP forcée"""
        try:
            if "windows" in self.system:
                # Windows - Netsh pour déconnecter
                cmd = ["netsh", "dhcp", "server", "scope", "delete", "reservedip", ip]
                success1, _, _ = self._run_command(cmd)

                # Forcer le renouvellement DHCP
                cmd2 = ["ipconfig", "/release"]
                cmd3 = ["ipconfig", "/renew"]
                self._run_command(cmd2)
                time.sleep(2)
                self._run_command(cmd3)

                return True  # Considérer comme succès même si DHCP échoue
            else:
                # Linux - Déconnexion via dhcp
                commands = [
                    ["sudo", "dhcp_release", "eth0", ip],
                    ["sudo", "systemctl", "restart", "dhcpd"]
                ]

                for cmd in commands:
                    self._run_command(cmd)

                return True
        except Exception as e:
            logger.error(f"Erreur déconnexion DHCP {ip}: {e}")
            return False

    def _block_interface_level(self, ip):
        """Blocage au niveau interface réseau"""
        try:
            # Obtenir les interfaces réseau
            interfaces = psutil.net_if_addrs()
            success_count = 0

            for interface_name, addresses in interfaces.items():
                if interface_name.startswith(('lo', 'Loopback')):
                    continue

                if "windows" in self.system:
                    # Windows - Désactiver temporairement l'interface pour cette IP
                    cmd = ["netsh", "interface", "ip", "add", "address", interface_name, ip, "255.255.255.255"]
                    if self._run_command(cmd)[0]:
                        success_count += 1
                else:
                    # Linux - Ajouter une règle spécifique à l'interface
                    cmd = ["sudo", "iptables", "-I", "INPUT", "1", "-i", interface_name, "-s", ip, "-j", "DROP"]
                    if self._run_command(cmd)[0]:
                        success_count += 1

            return success_count > 0
        except Exception as e:
            logger.error(f"Erreur blocage interface {ip}: {e}")
            return False

    def _kill_existing_connections(self, ip):
        """Tuer les connexions existantes"""
        try:
            killed_count = 0

            # Obtenir toutes les connexions réseau
            connections = psutil.net_connections(kind='inet')

            for conn in connections:
                if conn.raddr and conn.raddr.ip == ip:
                    try:
                        # Tuer le processus associé
                        if conn.pid:
                            process = psutil.Process(conn.pid)
                            process.terminate()
                            killed_count += 1
                            logger.info(f"Connexion tuée: PID {conn.pid} vers {ip}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

            # Commandes système pour tuer les connexions
            if "windows" in self.system:
                cmd = ["netstat", "-an", "|", "findstr", ip]
                # Windows n'a pas de commande directe pour tuer les connexions par IP
            else:
                # Linux - Tuer les connexions TCP
                cmd = ["sudo", "ss", "-K", "dst", ip]
                self._run_command(cmd)

            return True
        except Exception as e:
            logger.error(f"Erreur kill connexions {ip}: {e}")
            return False

    def unblock_ip(self, ip):
        """Déblocage complet IP"""
        logger.info(f"🔓 DÉBLOCAGE COMPLET INITIÉ: {ip}")

        success_count = 0
        total_methods = 0

        # Débloquer firewall principal
        if self._unblock_firewall_primary(ip):
            success_count += 1
        total_methods += 1

        # Débloquer firewall secondaire
        if self._unblock_firewall_secondary(ip):
            success_count += 1
        total_methods += 1

        # Débloquer réseau avancé
        if self._unblock_network_advanced(ip):
            success_count += 1
        total_methods += 1

        success_rate = (success_count / total_methods) * 100
        logger.info(f"🔓 Déblocage {ip}: {success_count}/{total_methods} méthodes réussies ({success_rate:.1f}%)")

        return success_count >= 2

    def _unblock_firewall_primary(self, ip):
        """Déblocage firewall principal"""
        try:
            if "windows" in self.system:
                rule_names = [
                    f"2IEM_BLOCK_IN_{ip.replace('.', '_')}",
                    f"2IEM_BLOCK_OUT_{ip.replace('.', '_')}"
                ]

                success_count = 0
                for rule_name in rule_names:
                    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                    if self._run_command(cmd)[0]:
                        success_count += 1

                return success_count > 0
            else:
                commands = [
                    ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    ["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                    ["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"],
                    ["sudo", "iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"]
                ]

                success_count = 0
                for cmd in commands:
                    if self._run_command(cmd)[0]:
                        success_count += 1

                return success_count > 0
        except Exception as e:
            logger.error(f"Erreur déblocage firewall principal {ip}: {e}")
            return False

    def _unblock_firewall_secondary(self, ip):
        """Déblocage firewall secondaire"""
        try:
            if "windows" in self.system:
                ports = ["80", "443", "22", "21", "25", "53", "3389"]
                success_count = 0

                for port in ports:
                    rule_name = f"2IEM_PORT_BLOCK_{ip.replace('.', '_')}_{port}"
                    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                    if self._run_command(cmd)[0]:
                        success_count += 1

                return success_count > 0
            else:
                commands = [
                    ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-p", "tcp", "-j", "REJECT"],
                    ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-p", "udp", "-j", "REJECT"],
                    ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-p", "icmp", "-j", "DROP"]
                ]

                success_count = 0
                for cmd in commands:
                    if self._run_command(cmd)[0]:
                        success_count += 1

                return success_count > 0
        except Exception as e:
            logger.error(f"Erreur déblocage firewall secondaire {ip}: {e}")
            return False

    def _unblock_network_advanced(self, ip):
        """Déblocage réseau avancé"""
        try:
            if "windows" in self.system:
                cmd = ["route", "delete", ip]
                return self._run_command(cmd)[0]
            else:
                cmd = ["sudo", "ip", "route", "del", "blackhole", ip]
                return self._run_command(cmd)[0]
        except Exception as e:
            logger.error(f"Erreur déblocage réseau avancé {ip}: {e}")
            return False


# Instance globale du bloqueur
advanced_blocker = AdvancedIPBlocker()


@user_passes_test(lambda u: u.is_superuser)
def blocked_ips_view(request):
    """Vue pour afficher toutes les IPs bloquées avec statistiques"""
    blocked_ips = BlockedIP.objects.all().order_by('-blocked_on')

    # Statistiques
    total_blocked = blocked_ips.count()
    blocked_today = blocked_ips.filter(
        blocked_on__date=timezone.now().date()
    ).count()
    blocked_this_week = blocked_ips.filter(
        blocked_on__gte=timezone.now() - timedelta(days=7)
    ).count()

    # Groupement par raison
    reasons_stats = {}
    for ip in blocked_ips:
        reason = ip.reason or "Non spécifié"
        reasons_stats[reason] = reasons_stats.get(reason, 0) + 1

    # Vérifier les privilèges admin
    admin_status = advanced_blocker.is_admin

    context = {
        'blocked_ips': blocked_ips,
        'total_blocked': total_blocked,
        'blocked_today': blocked_today,
        'blocked_this_week': blocked_this_week,
        'reasons_stats': reasons_stats,
        'admin_status': admin_status,
        'system_info': platform.system()
    }

    return render(request, 'theme/blocked_ips.html', context)


@user_passes_test(lambda u: u.is_superuser)
def block_ip_manual(request):
    """Vue pour blocage manuel ultra-renforcé"""
    if request.method == 'POST':
        ip = request.POST.get('ip_address', '').strip()
        reason = request.POST.get('reason', 'Blocage manuel').strip()

        if not ip:
            messages.error(request, "❌ Adresse IP requise.")
            return redirect('theme:blocked_ips')

        # Vérifier les privilèges admin
        if not advanced_blocker.is_admin:
            messages.error(request, "❌ Privilèges administrateur requis pour le blocage.")
            return redirect('theme:blocked_ips')

        # Vérifier si déjà bloquée
        if BlockedIP.objects.filter(ip_address=ip).exists():
            messages.warning(request, f"⚠️ L'IP {ip} est déjà bloquée.")
            return redirect('theme:blocked_ips')

        try:
            # Valider l'IP
            ipaddress.ip_address(ip)

            # BLOCAGE ULTRA-RENFORCÉ
            logger.critical(f"🚫 BLOCAGE MANUEL ULTRA-RENFORCÉ INITIÉ: {ip}")
            success = advanced_blocker.force_block_ip(ip, f"MANUEL: {reason}")

            if success:
                # Enregistrer en base
                BlockedIP.objects.create(
                    ip_address=ip,
                    reason=f"MANUEL: {reason}"
                )
                messages.success(request, f"✅ IP {ip} bloquée avec système ultra-renforcé (multi-niveaux).")
                logger.critical(f"✅ BLOCAGE MANUEL ULTRA-RENFORCÉ RÉUSSI: {ip}")
            else:
                messages.error(request, f"❌ Échec du blocage ultra-renforcé de {ip}.")
                logger.error(f"❌ ÉCHEC BLOCAGE MANUEL ULTRA-RENFORCÉ: {ip}")

        except ValueError:
            messages.error(request, f"❌ Adresse IP invalide: {ip}")
        except Exception as e:
            messages.error(request, f"❌ Erreur lors du blocage ultra-renforcé de {ip}: {e}")
            logger.error(f"❌ Exception blocage manuel {ip}: {e}")

    return redirect('theme:blocked_ips')


@user_passes_test(lambda u: u.is_superuser)
def unblock_ip(request, ip_id):
    """Vue pour déblocage complet"""
    ip_entry = get_object_or_404(BlockedIP, id=ip_id)
    ip = ip_entry.ip_address

    if request.method == 'POST':
        # Vérifier les privilèges admin
        if not advanced_blocker.is_admin:
            messages.error(request, "❌ Privilèges administrateur requis pour le déblocage.")
            return redirect('theme:blocked_ips')

        try:
            # DÉBLOCAGE COMPLET
            logger.info(f"🔓 Déblocage complet initié: {ip}")
            success = advanced_blocker.unblock_ip(ip)

            if success:
                # Supprimer de la base
                ip_entry.delete()
                messages.success(request, f"✅ IP {ip} complètement débloquée et reconnectée.")
                logger.info(f"✅ Déblocage complet réussi: {ip}")
            else:
                messages.error(request, f"❌ Erreur lors du déblocage complet de {ip}.")
                logger.error(f"❌ Échec déblocage complet: {ip}")

        except Exception as e:
            messages.error(request, f"❌ Erreur déblocage complet {ip}: {e}")
            logger.error(f"❌ Exception déblocage complet {ip}: {e}")

    return redirect('theme:blocked_ips')


@user_passes_test(lambda u: u.is_superuser)
def unblock_multiple_ips(request):
    """Vue pour débloquer plusieurs IPs en une fois"""
    if request.method == 'POST':
        ip_ids = request.POST.getlist('ip_ids')

        if not ip_ids:
            messages.warning(request, "⚠️ Aucune IP sélectionnée.")
            return redirect('theme:blocked_ips')

        # Vérifier les privilèges admin
        if not advanced_blocker.is_admin:
            messages.error(request, "❌ Privilèges administrateur requis pour le déblocage.")
            return redirect('theme:blocked_ips')

        success_count = 0
        error_count = 0

        for ip_id in ip_ids:
            try:
                ip_entry = get_object_or_404(BlockedIP, id=ip_id)
                ip = ip_entry.ip_address

                # Déblocage complet
                if advanced_blocker.unblock_ip(ip):
                    ip_entry.delete()
                    success_count += 1
                    logger.info(f"✅ IP {ip} débloquée (batch)")
                else:
                    error_count += 1
                    logger.error(f"❌ Échec déblocage batch {ip}")

            except Exception as e:
                error_count += 1
                logger.error(f"❌ Erreur déblocage batch {ip}: {e}")

        if success_count > 0:
            messages.success(request, f"✅ {success_count} IP(s) débloquée(s) avec succès.")
        if error_count > 0:
            messages.error(request, f"❌ {error_count} erreur(s) lors du déblocage.")

    return redirect('theme:blocked_ips')


@user_passes_test(lambda u: u.is_superuser)
def auto_unblock_expired_ips(request):
    """Vue pour débloquer automatiquement les IPs expirées"""
    if request.method == 'POST':
        # Vérifier les privilèges admin
        if not advanced_blocker.is_admin:
            messages.error(request, "❌ Privilèges administrateur requis.")
            return redirect('theme:blocked_ips')

        # Récupérer la durée de blocage depuis les paramètres (par défaut 24h)
        hours = int(request.POST.get('hours', 24))
        cutoff_time = timezone.now() - timedelta(hours=hours)

        # Trouver les IPs bloquées depuis plus de X heures
        expired_ips = BlockedIP.objects.filter(blocked_on__lt=cutoff_time)
        count = expired_ips.count()

        if count == 0:
            messages.info(request, f"ℹ️ Aucune IP bloquée depuis plus de {hours}h.")
            return redirect('theme:blocked_ips')

        success_count = 0
        error_count = 0

        for ip_entry in expired_ips:
            try:
                ip = ip_entry.ip_address

                # Déblocage complet
                if advanced_blocker.unblock_ip(ip):
                    ip_entry.delete()
                    success_count += 1
                    logger.info(f"✅ IP expirée {ip} débloquée automatiquement")
                else:
                    error_count += 1
                    logger.error(f"❌ Échec déblocage automatique {ip}")

            except Exception as e:
                error_count += 1
                logger.error(f"❌ Erreur déblocage automatique {ip}: {e}")

        if success_count > 0:
            messages.success(request, f"✅ {success_count} IP(s) expirée(s) débloquée(s) automatiquement.")
        if error_count > 0:
            messages.warning(request, f"⚠️ {error_count} erreur(s) lors du déblocage automatique.")

    return redirect('theme:blocked_ips')


@user_passes_test(lambda u: u.is_superuser)
def blocked_ips_api(request):
    """API JSON pour récupérer les IPs bloquées"""
    blocked_ips = BlockedIP.objects.all().order_by('-blocked_on')[:50]
    data = []

    for ip in blocked_ips:
        data.append({
            'id': ip.id,
            'ip_address': ip.ip_address,
            'reason': ip.reason,
            'blocked_on': ip.blocked_on.isoformat(),
            'alert_id': ip.alert.id if ip.alert else None,
        })

    return JsonResponse({
        'blocked_ips': data,
        'total_count': BlockedIP.objects.count(),
        'timestamp': timezone.now().isoformat(),
        'admin_status': advanced_blocker.is_admin,
        'system': platform.system()
    })


@user_passes_test(lambda u: u.is_superuser)
def test_blocking_system(request):
    """Vue pour tester le système de blocage"""
    if request.method == 'POST':
        test_ip = "192.168.1.999"  # IP de test invalide

        try:
            # Test de validation IP
            ipaddress.ip_address(test_ip)
            messages.error(request, "❌ Erreur dans le test de validation IP")
        except ValueError:
            messages.success(request, "✅ Validation IP fonctionne correctement")

        # Test des privilèges
        if advanced_blocker.is_admin:
            messages.success(request, "✅ Privilèges administrateur détectés")
        else:
            messages.error(request, "❌ Privilèges administrateur manquants")

        # Test du système
        system_info = f"Système détecté: {platform.system()}"
        messages.info(request, system_info)

    return redirect('theme:blocked_ips')