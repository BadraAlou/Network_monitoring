import subprocess
import nmap
import netifaces
from django.utils import timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.models import Device, DeviceEvent

def get_local_subnet():
    """
    Détecte automatiquement le sous-réseau local via l'interface par défaut.
    Retourne un CIDR (ex: '192.168.1.0/24').
    """
    try:
        gw = netifaces.gateways()['default'][netifaces.AF_INET]
        iface = gw[1]
        addr = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
        ip, mask = addr['addr'], addr['netmask']
        prefix = sum(bin(int(b)).count('1') for b in mask.split('.'))
        base = '.'.join(ip.split('.')[:3])
        return f"{base}.0/{prefix}"
    except Exception:
        # Fallback basique
        return "192.168.1.0/24"

def fast_ping(ip, timeout=1000):
    """
    Ping rapide cross-platform.
    Retourne un float (ms) ou None.
    """
    count_flag = '-n' if subprocess.os.name == 'nt' else '-c'
    try:
        res = subprocess.run(
            ['ping', count_flag, '1', ip],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=timeout/1000
        )
        out = res.stdout.lower()
        # on cherche un nombre suivi de 'ms'
        for token in out.replace('=', ' ').split():
            if token.endswith('ms') and token[:-2].replace('.', '', 1).isdigit():
                return float(token[:-2])
    except Exception:
        pass
    return None

def _process_host(host, port_args="-O -T4", ping_timeout=1000):
    """
    Scan détaillé d'un hôte unique, mise à jour DB + DeviceEvent.
    """
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=host, arguments=f"{port_args} --max-retries 1 --host-timeout 5s")
        info = scanner[host] if host in scanner.all_hosts() else {}
    except Exception:
        info = {}

    device, created = Device.objects.get_or_create(ip_address=host)
    old_status = device.status

    # extract Nmap info
    mac = info.get('addresses', {}).get('mac', '')
    hostname = (info.get('hostnames') or [{}])[0].get('name') or host
    os_name = (info.get('osmatch') or [{}])[0].get('name', 'Inconnu')

    # latence
    latency = fast_ping(host, timeout=ping_timeout)

    # update device
    device.mac_address = mac
    device.hostname    = hostname
    device.os          = os_name
    device.status      = 'online'
    device.response_time = latency
    device.last_seen   = timezone.now()
    device.save()

    # event de connexion si nouveau ou statut changé
    if created or old_status != 'online':
        DeviceEvent.objects.create(
            device=device,
            event_type='connection',
            description=f"En ligne : {hostname} ({host})",
            ip_address=host,
            timestamp=timezone.now()
        )
    return host

def discover_devices_nmap(concurrency=20):
    """
    Scanne tout le réseau, met à jour Devices et génère DeviceEvent.
    1) découverte hôtes (-sn)
    2) scan détaillé concurrent
    3) bascule offline + événement disconnection
    """
    subnet = get_local_subnet()
    scanner = nmap.PortScanner()
    scanner.scan(hosts=subnet, arguments='-sn -T4 --max-retries 1 --host-timeout 5s')
    alive_hosts = [h for h in scanner.all_hosts()
                   if 'addresses' in scanner[h] and 'ipv4' in scanner[h]['addresses']]

    scanned_ips = [scanner[h]['addresses']['ipv4'] for h in alive_hosts]

    # 1) traitement concurrent des hôtes trouvés
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(_process_host, ip) for ip in scanned_ips]
        # on peut collecter exceptions ici si besoin
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as e:
                # loguer l'erreur sans interrompre le scan
                print(f"Erreur scan {e}")

    # 2) tous les devices non vus ces 2 dernières minutes => offline
    cutoff = timezone.now() - timezone.timedelta(minutes=2)
    for device in Device.objects.exclude(ip_address__in=scanned_ips):
        if device.status != 'offline':
            prev = device.status
            device.status = 'offline'
            device.response_time = None
            device.last_seen   = timezone.now()
            device.save()

            if prev == 'online':
                DeviceEvent.objects.create(
                    device=device,
                    event_type='disconnection',
                    description=f"Hors ligne : {device.hostname} ({device.ip_address})",
                    ip_address=device.ip_address,
                    timestamp=timezone.now()
                )
