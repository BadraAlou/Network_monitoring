from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
import subprocess
import platform
import traceback
import sys


# ========================================
# VUE DE DEBUG PRINCIPALE
# ========================================
def debug_network_view(request):
    """Vue de debug pour tester tout le système"""
    return HttpResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>🔧 Debug Network Scanner</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .test-section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
            .success { background: #d4edda; border-color: #c3e6cb; color: #155724; }
            .error { background: #f8d7da; border-color: #f5c6cb; color: #721c24; }
            .info { background: #d1ecf1; border-color: #bee5eb; color: #0c5460; }
            button { padding: 10px 20px; margin: 5px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #0056b3; }
            pre { background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }
            .loading { display: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔧 Debug Network Scanner</h1>

            <div class="test-section info">
                <h3>📋 Informations système</h3>
                <p><strong>OS:</strong> """ + platform.system() + """ """ + platform.release() + """</p>
                <p><strong>Python:</strong> """ + sys.version + """</p>
                <p><strong>Django:</strong> Actif</p>
            </div>

            <div class="test-section">
                <h3>🧪 Tests des APIs</h3>
                <button onclick="testScanAPI()">1. Tester l'API Scan</button>
                <button onclick="testConnectAPI()">2. Tester l'API Connect</button>
                <button onclick="testSystemCommands()">3. Tester les commandes système</button>
                <button onclick="testFullFlow()">4. Test complet</button>

                <div id="loading" class="loading">
                    <p>⏳ Test en cours...</p>
                </div>

                <div id="results"></div>
            </div>

            <div class="test-section">
                <h3>📊 Résultats en temps réel</h3>
                <div id="liveResults"></div>
            </div>
        </div>

        <script>
            function showLoading() {
                document.getElementById('loading').style.display = 'block';
                document.getElementById('results').innerHTML = '';
            }

            function hideLoading() {
                document.getElementById('loading').style.display = 'none';
            }

            function showResult(title, content, type = 'info') {
                const results = document.getElementById('results');
                const div = document.createElement('div');
                div.className = 'test-section ' + type;
                div.innerHTML = '<h4>' + title + '</h4><pre>' + JSON.stringify(content, null, 2) + '</pre>';
                results.appendChild(div);
            }

            async function testScanAPI() {
                showLoading();
                try {
                    console.log('🔍 Test de l\\'API Scan...');
                    const response = await fetch('/api/scan-networks/');
                    const data = await response.json();

                    if (response.ok) {
                        showResult('✅ API Scan - SUCCESS', data, 'success');
                    } else {
                        showResult('❌ API Scan - ERROR', data, 'error');
                    }
                } catch (error) {
                    showResult('❌ API Scan - EXCEPTION', {error: error.message}, 'error');
                }
                hideLoading();
            }

            async function testConnectAPI() {
                showLoading();
                try {
                    console.log('🔗 Test de l\\'API Connect...');
                    const response = await fetch('/api/connect-network/', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ssid: 'Test-Network', password: '123456'})
                    });
                    const data = await response.json();

                    if (response.ok) {
                        showResult('✅ API Connect - SUCCESS', data, 'success');
                    } else {
                        showResult('❌ API Connect - ERROR', data, 'error');
                    }
                } catch (error) {
                    showResult('❌ API Connect - EXCEPTION', {error: error.message}, 'error');
                }
                hideLoading();
            }

            async function testSystemCommands() {
                showLoading();
                try {
                    console.log('💻 Test des commandes système...');
                    const response = await fetch('/debug/system-test/');
                    const data = await response.json();

                    showResult('💻 Commandes système', data, data.success ? 'success' : 'error');
                } catch (error) {
                    showResult('❌ Commandes système - EXCEPTION', {error: error.message}, 'error');
                }
                hideLoading();
            }

            async function testFullFlow() {
                showLoading();
                document.getElementById('results').innerHTML = '<h4>🚀 Test complet en cours...</h4>';

                await testScanAPI();
                await new Promise(resolve => setTimeout(resolve, 1000));
                await testConnectAPI();
                await new Promise(resolve => setTimeout(resolve, 1000));
                await testSystemCommands();

                hideLoading();
                showResult('🎉 Test complet terminé', {message: 'Tous les tests sont terminés'}, 'success');
            }

            // Auto-refresh des résultats
            setInterval(async () => {
                try {
                    const response = await fetch('/debug/live-status/');
                    const data = await response.json();
                    document.getElementById('liveResults').innerHTML = 
                        '<strong>Status:</strong> ' + data.status + 
                        '<br><strong>Dernière activité:</strong> ' + data.timestamp;
                } catch (error) {
                    console.log('Erreur live status:', error);
                }
            }, 5000);
        </script>
    </body>
    </html>
    """)


# ========================================
# API DE SCAN AVEC DEBUG COMPLET
# ========================================
@require_http_methods(["GET"])
def debug_scan_networks_api(request):
    """API de scan avec debug complet"""
    debug_info = {
        'timestamp': str(__import__('datetime').datetime.now()),
        'system': platform.system(),
        'python_version': sys.version,
        'request_method': request.method,
        'request_path': request.path,
    }

    print("🔍 DEBUG: API scan_networks_api appelée")
    print(f"📊 DEBUG: Info système: {debug_info}")

    try:
        # Test 1: Vérifier les imports
        print("✅ DEBUG: Imports OK")

        # Test 2: Détection du système
        system = platform.system().lower()
        print(f"💻 DEBUG: Système détecté: {system}")

        # Test 3: Essayer de scanner
        networks = []
        scan_errors = []

        if system == "windows":
            try:
                print("🔍 DEBUG: Tentative scan Windows...")
                result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'],
                                        capture_output=True, text=True, timeout=10)
                print(f"📡 DEBUG: Code retour Windows: {result.returncode}")
                print(f"📡 DEBUG: Sortie Windows (100 premiers chars): {result.stdout[:100]}")

                if result.returncode == 0:
                    # Parser simple
                    lines = result.stdout.split('\n')
                    for i, line in enumerate(lines[:5]):  # Limiter pour debug
                        if 'Profil' in line or 'Profile' in line:
                            networks.append({
                                'name': f'Windows-Network-{i}',
                                'signal': 75,
                                'security': 'WPA2',
                                'channel': '6',
                                'frequency': '2.4 GHz',
                                'connected': i == 0
                            })
                else:
                    scan_errors.append(f"Windows netsh error: {result.stderr}")

            except Exception as e:
                scan_errors.append(f"Windows scan exception: {str(e)}")
                print(f"❌ DEBUG: Erreur Windows: {e}")

        elif system == "darwin":  # macOS
            try:
                print("🔍 DEBUG: Tentative scan macOS...")
                # Commande plus simple pour macOS
                result = subprocess.run(['networksetup', '-listallhardwareports'],
                                        capture_output=True, text=True, timeout=10)
                print(f"📡 DEBUG: Code retour macOS: {result.returncode}")

                networks.append({
                    'name': 'macOS-Test-Network',
                    'signal': 80,
                    'security': 'WPA2',
                    'channel': '11',
                    'frequency': '5 GHz',
                    'connected': False
                })

            except Exception as e:
                scan_errors.append(f"macOS scan exception: {str(e)}")
                print(f"❌ DEBUG: Erreur macOS: {e}")

        elif system == "linux":
            try:
                print("🔍 DEBUG: Tentative scan Linux...")
                result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=10)
                print(f"📡 DEBUG: Code retour Linux: {result.returncode}")

                networks.append({
                    'name': 'Linux-Test-Network',
                    'signal': 70,
                    'security': 'WPA3',
                    'channel': '1',
                    'frequency': '2.4 GHz',
                    'connected': False
                })

            except Exception as e:
                scan_errors.append(f"Linux scan exception: {str(e)}")
                print(f"❌ DEBUG: Erreur Linux: {e}")

        # Si aucun réseau trouvé, utiliser des données de test
        if not networks:
            print("⚠️ DEBUG: Aucun réseau réel, utilisation de données de test")
            networks = [
                {
                    'name': 'DEBUG-WiFi-1',
                    'signal': 95,
                    'security': 'WPA3',
                    'channel': '6',
                    'frequency': '2.4 GHz',
                    'connected': True
                },
                {
                    'name': 'DEBUG-WiFi-2',
                    'signal': 78,
                    'security': 'WPA2',
                    'channel': '36',
                    'frequency': '5 GHz',
                    'connected': False
                },
                {
                    'name': 'DEBUG-Public',
                    'signal': 45,
                    'security': 'Open',
                    'channel': '1',
                    'frequency': '2.4 GHz',
                    'connected': False
                }
            ]

        print(f"✅ DEBUG: {len(networks)} réseaux trouvés")

        response_data = {
            'status': 'success',
            'networks': networks,
            'count': len(networks),
            'debug_info': debug_info,
            'scan_errors': scan_errors,
            'system': system
        }

        print(f"📤 DEBUG: Réponse envoyée: {len(str(response_data))} caractères")
        return JsonResponse(response_data)

    except Exception as e:
        error_info = {
            'error': str(e),
            'traceback': traceback.format_exc(),
            'debug_info': debug_info
        }
        print(f"❌ DEBUG: Exception dans scan_networks_api: {e}")
        print(f"📋 DEBUG: Traceback: {traceback.format_exc()}")

        return JsonResponse({
            'status': 'error',
            'error_info': error_info,
            'networks': []  # Retourner au moins un tableau vide
        }, status=500)


# ========================================
# API DE CONNEXION AVEC DEBUG
# ========================================
@csrf_exempt
@require_http_methods(["POST"])
def debug_connect_network_api(request):
    """API de connexion avec debug"""
    print("🔗 DEBUG: API connect_network_api appelée")

    try:
        data = json.loads(request.body)
        ssid = data.get('ssid')
        password = data.get('password', '')

        print(f"📶 DEBUG: Connexion à {ssid}")

        # Simulation de connexion
        import time
        time.sleep(1)  # Simuler le temps de connexion

        return JsonResponse({
            'status': 'success',
            'message': f'DEBUG: Connexion simulée à {ssid}',
            'ssid': ssid,
            'connected': True,
            'debug': True
        })

    except Exception as e:
        print(f"❌ DEBUG: Erreur connect: {e}")
        return JsonResponse({
            'status': 'error',
            'error': str(e),
            'debug': True
        }, status=500)


# ========================================
# TESTS SYSTÈME
# ========================================
@require_http_methods(["GET"])
def debug_system_test(request):
    """Test des commandes système"""
    system = platform.system().lower()
    tests = {}

    if system == "windows":
        try:
            result = subprocess.run(['netsh'], capture_output=True, text=True, timeout=5)
            tests['netsh'] = {'available': True, 'returncode': result.returncode}
        except:
            tests['netsh'] = {'available': False, 'error': 'Command not found'}

        try:
            result = subprocess.run(['wmic', 'computersystem', 'get', 'name'],
                                    capture_output=True, text=True, timeout=5)
            tests['wmic'] = {'available': True, 'returncode': result.returncode}
        except:
            tests['wmic'] = {'available': False, 'error': 'Command not found'}

    elif system == "darwin":
        try:
            result = subprocess.run(['networksetup', '-help'],
                                    capture_output=True, text=True, timeout=5)
            tests['networksetup'] = {'available': True, 'returncode': result.returncode}
        except:
            tests['networksetup'] = {'available': False, 'error': 'Command not found'}

    elif system == "linux":
        try:
            result = subprocess.run(['nmcli', '--version'],
                                    capture_output=True, text=True, timeout=5)
            tests['nmcli'] = {'available': True, 'returncode': result.returncode}
        except:
            tests['nmcli'] = {'available': False, 'error': 'Command not found'}

    return JsonResponse({
        'system': system,
        'tests': tests,
        'success': any(test.get('available', False) for test in tests.values())
    })


# ========================================
# STATUS EN TEMPS RÉEL
# ========================================
@require_http_methods(["GET"])
def debug_live_status(request):
    """Status en temps réel"""
    return JsonResponse({
        'status': 'active',
        'timestamp': str(__import__('datetime').datetime.now()),
        'system': platform.system(),
        'requests_count': getattr(debug_live_status, 'count', 0)
    })


# Compteur de requêtes
if not hasattr(debug_live_status, 'count'):
    debug_live_status.count = 0
debug_live_status.count += 1
