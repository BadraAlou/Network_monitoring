# Créez ce fichier dans votre app Django
import subprocess
import platform
import socket
import requests
import json
import re
from django.conf import settings


class NetworkDetector:
    def __init__(self):
        self.system = platform.system()

    def get_wifi_name(self):
        """Récupère le nom du réseau WiFi selon l'OS"""
        try:
            if self.system == "Windows":
                return self._get_wifi_windows()
            elif self.system == "Darwin":  # macOS
                return self._get_wifi_macos()
            elif self.system == "Linux":
                return self._get_wifi_linux()
            else:
                return "Système non supporté"
        except Exception as e:
            print(f"Erreur détection WiFi: {e}")
            return "WiFi non détecté"

    def _get_wifi_windows(self):
        """Récupère le WiFi sur Windows"""
        try:
            # Méthode 1: netsh wlan
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True, text=True, encoding='utf-8'
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'SSID' in line and 'BSSID' not in line:
                        ssid = line.split(':')[-1].strip()
                        if ssid and ssid != '':
                            return ssid

            # Méthode 2: Alternative
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'profile'],
                capture_output=True, text=True, encoding='utf-8'
            )
            if result.returncode == 0:
                profiles = []
                for line in result.stdout.split('\n'):
                    if 'Profil Tous les utilisateurs' in line or 'All User Profile' in line:
                        profile = line.split(':')[-1].strip()
                        if profile:
                            profiles.append(profile)
                if profiles:
                    return profiles[0]  # Retourne le premier profil

        except Exception as e:
            print(f"Erreur Windows WiFi: {e}")

        return "WiFi-Windows"

    def _get_wifi_macos(self):
        """Récupère le WiFi sur macOS"""
        try:
            # Méthode 1: airport
            result = subprocess.run([
                '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport',
                '-I'
            ], capture_output=True, text=True)

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ' SSID:' in line:
                        return line.split(':')[-1].strip()

            # Méthode 2: networksetup
            result = subprocess.run([
                'networksetup', '-getairportnetwork', 'en0'
            ], capture_output=True, text=True)

            if result.returncode == 0 and 'Current Wi-Fi Network:' in result.stdout:
                return result.stdout.split(':')[-1].strip()

        except Exception as e:
            print(f"Erreur macOS WiFi: {e}")

        return "WiFi-Mac"

    def _get_wifi_linux(self):
        """Récupère le WiFi sur Linux"""
        try:
            # Méthode 1: iwgetid
            result = subprocess.run(['iwgetid', '-r'], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()

            # Méthode 2: nmcli
            result = subprocess.run([
                'nmcli', '-t', '-f', 'active,ssid', 'dev', 'wifi'
            ], capture_output=True, text=True)

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('yes:') or line.startswith('oui:'):
                        ssid = line.split(':')[1]
                        if ssid:
                            return ssid

            # Méthode 3: iw
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
            if result.returncode == 0:
                # Parser la sortie pour trouver l'interface active
                pass

        except Exception as e:
            print(f"Erreur Linux WiFi: {e}")

        return "WiFi-Linux"

    def get_local_ip(self):
        """Récupère l'adresse IP locale"""
        try:
            # Méthode 1: Connexion socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            try:
                # Méthode 2: hostname
                return socket.gethostbyname(socket.gethostname())
            except:
                return "127.0.0.1"

    def get_public_ip(self):
        """Récupère l'adresse IP publique"""
        try:
            # Essayer plusieurs services
            services = [
                'https://api.ipify.org?format=json',
                'https://httpbin.org/ip',
                'https://api.myip.com'
            ]

            for service in services:
                try:
                    response = requests.get(service, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        if 'ip' in data:
                            return data['ip']
                        elif 'origin' in data:
                            return data['origin']
                except:
                    continue

        except Exception as e:
            print(f"Erreur IP publique: {e}")

        return "Non disponible"

    def get_network_info(self):
        """Récupère toutes les informations réseau"""
        return {
            'wifi_name': self.get_wifi_name(),
            'local_ip': self.get_local_ip(),
            'public_ip': self.get_public_ip(),
            'hostname': socket.gethostname(),
            'system': self.system
        }
