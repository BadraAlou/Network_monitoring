import subprocess
import platform

def block_ip(ip, reason=None, alert_instance=None):
    system = platform.system().lower()

    try:
        if "windows" in system:
            rule_name = f"BLOCK_{ip.replace('.', '_')}"
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                f"dir=in",
                f"action=block",
                f"remoteip={ip}",
                f"description=Blocked due to: {reason or 'unknown'}"
            ], check=True)
            print(f"🛡️ IP bloquée via pare-feu Windows : {ip}")

        elif "linux" in system:
            # Vérifie si la règle existe déjà
            check = subprocess.run(
                ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if check.returncode == 0:
                print(f"⚠️ IP déjà bloquée via iptables : {ip}")
            else:
                subprocess.run(
                    ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True
                )
                print(f"🛡️ IP bloquée via iptables Linux : {ip}")

        else:
            print(f"❌ Système non supporté pour le blocage d'IP : {system}")

        # Marque éventuellement l'alerte comme bloquée
        if alert_instance:
            alert_instance.blocked = True
            alert_instance.save()

    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur lors du blocage de l'IP {ip} : {e}")
