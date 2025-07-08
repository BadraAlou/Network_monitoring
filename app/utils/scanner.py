# utils/scanner.py
import subprocess
import re
import nmap
import ipaddress
from datetime import datetime
from django.utils import timezone
from app.models import Device, Log, User, Alert


def ping_device(ip_address):
    """
    Vérifie la connectivité d'un appareil via ping.
    Retourne True si l'appareil répond, sinon False.
    """
    try:
        output = subprocess.run(['ping', '-c', '1', ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
        return output.returncode == 0
    except Exception:
        return False


def run_network_scan(user_id):
    """
    Effectue un ping sur tous les appareils enregistrés et met à jour leur statut (online/offline).
    Un log est enregistré pour chaque résultat.
    """
    user = User.objects.get(id=user_id)
    devices = Device.objects.all()

    for device in devices:
        is_online = ping_device(device.ip_address)
        device.status = 'online' if is_online else 'offline'
        device.last_seen = datetime.now()
        device.save()

        Log.objects.create(
            device=device,
            event=f"Ping {'réussi' if is_online else 'échoué'} vers {device.hostname} ({device.ip_address})",
            scanned_by=user,
            scan_time=datetime.now()
        )


def extract_ports_from_rustscan(output):
    """
    Extrait les ports ouverts depuis le résultat de RustScan.
    """
    ports = []
    for line in output.splitlines():
        match = re.search(r'(\d+)/tcp', line)
        if match:
            ports.append(match.group(1))
    return ports


def scan_with_rustscan_and_nmap(ip_address, user=None):
    """
    Effectue un scan réseau intelligent combinant RustScan (rapide) et Nmap (détaillé).
    Enregistre les informations du device et les ports/services détectés.
    Génère aussi une alerte si des ports sensibles sont trouvés.
    """
    try:
        # 🔐 Vérifie la validité de l'adresse IP
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            print(f"[ERREUR] IP invalide : {ip_address}")
            return

        # 🚀 Étape 1 : RustScan
        rustscan_cmd = ['rustscan', '-a', ip_address, '--ulimit', '5000', '--timeout', '5000', '--no-color']
        rustscan_result = subprocess.run(rustscan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if rustscan_result.returncode != 0:
            print(f"Erreur RustScan: {rustscan_result.stderr}")
            return

        ports = extract_ports_from_rustscan(rustscan_result.stdout)
        ports_str = ','.join(ports) if ports else ''

        print(f"[INFO] RustScan terminé pour {ip_address} → ports : {ports_str or 'aucun'}")

        # 🛠️ Étape 2 : Scan Nmap sur les ports trouvés
        scanner = nmap.PortScanner()
        nmap_args = f'-O -sV -p {ports_str}' if ports_str else '-O -sV'
        scanner.scan(hosts=ip_address, arguments=nmap_args)

        for host in scanner.all_hosts():
            ip = scanner[host]['addresses'].get('ipv4', ip_address)
            mac = scanner[host]['addresses'].get('mac', '')
            hostname = scanner[host]['hostnames'][0]['name'] if scanner[host]['hostnames'] else ip
            os_match = scanner[host].get('osmatch')
            os_name = os_match[0]['name'] if os_match else 'Inconnu'

            # 🔍 Extraction des services TCP
            services = []
            if 'tcp' in scanner[host]:
                for port, port_data in scanner[host]['tcp'].items():
                    service_info = f"{port}/{port_data['name']} ({port_data['state']})"
                    services.append(service_info)
            services_str = "; ".join(services)

            # 💾 Mise à jour ou création de l'appareil
            device, _ = Device.objects.get_or_create(ip_address=ip)
            device.hostname = hostname
            device.mac_address = mac
            device.os = os_name
            device.status = 'online'
            device.last_seen = timezone.now()
            device.vulnerabilities = ''  # À compléter si besoin
            device.response_time = None
            device.save()

            # 📝 Enregistrement du log
            Log.objects.create(
                device=device,
                scanned_by=user,
                event=f"Scan RustScan+Nmap effectué. Ports: {services_str}",
                scan_time=timezone.now()
            )

            # 🚨 Alerte automatique sur ports sensibles
            ports_sensibles = ['22', '3389', '445']
            if any(p.split('/')[0] in ports_sensibles for p in services):
                Alert.objects.create(
                    device=device,
                    severity='high',
                    alert_type='scan',
                    source='automatique',
                    description=f"Ports sensibles détectés sur {ip} : {services_str}"
                )

            print(f"[OK] Scan de {ip} terminé et enregistré avec succès.")

    except Exception as e:
        print(f"Erreur pendant le scan de {ip_address} : {e}")
