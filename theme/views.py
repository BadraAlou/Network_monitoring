
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from django.contrib.auth.decorators import login_required, user_passes_test
import nmap, os, platform, subprocess, json, re
from django.template.loader import get_template
from xhtml2pdf import pisa
from django.http import JsonResponse, HttpResponse
from app.models import Device, Log, Alert, User, TrafficLog
from app.utils.scanner import scan_with_rustscan_and_nmap
from app.utils.detector import detect_attacks
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.utils.dateformat import DateFormat
from datetime import timedelta
from .forms import UserSettingsForm
from uuid import uuid4
from orders.models import Abonnement
from datetime import date
from django.core.mail import send_mail
from django.utils import timezone
from django.http import JsonResponse
from django.db.models import Q, Count
from uuid import uuid4
import logging
from app.utils.ia_engine import analyser_alerte

logger = logging.getLogger(__name__)


def envoyer_alerte_email(titre, description, destinataires):
    sujet = f"🚨 Alerte critique : {titre}"
    message = f"Une alerte critique a été détectée :\n\n{description}\n\nConsultez immédiatement le tableau de bord."
    send_mail(sujet, message, None, destinataires)


# Configuration de l'environnement pour Nmap (Windows)
nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
os.environ["PATH"] += os.pathsep + os.path.dirname(nmap_path)

from twilio.rest import Client
from django.conf import settings

def envoyer_sms_alerte(titre, description, numero_destinataire=None):
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)

    message_body = f"ALERTE 2IEM_Security {titre} - {description}"
    to_number = numero_destinataire or settings.ADMIN_PHONE_NUMBER

    try:
        message = client.messages.create(
            body=message_body,
            from_=settings.TWILIO_PHONE_NUMBER,
            to=to_number
        )
        print(f"✅ SMS envoyé : SID={message.sid}")
    except Exception as e:
        print(f"❌ Erreur d'envoi SMS : {e}")

# Historique d'alertes envoyer par Sms et Twilio
@login_required
def historique_alertestwem(request):
    alertes = Alert.objects.order_by('-detected_on')
    return render(request, 'theme/historique_alertestwem.html', {'alertes': alertes})


@login_required
def notification_redirect(request):
    nb_urgentes = Alert.objects.filter(severity__in=['high', 'critical'], is_resolved=False).count()

    if nb_urgentes > 0:
        return redirect('theme:alert_list')
    else:
        return render(request, 'theme/aucune_alerte.html')


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
from .network_utils import NetworkDetector


# Vue principale (accueil)
@login_required
def dashboard(request):
    # Vérification de l'abonnement actif
    abonnement = Abonnement.objects.filter(
        user=request.user,
        actif=True,
        date_expiration__gt=timezone.now()
    ).first()

    if not abonnement:
        messages.error(request, "⛔ Vous n'avez pas de licence active ou votre abonnement a expiré.")
        return redirect('theme:licence_expiree')

    reseau_uid = uuid4()
    detector = NetworkDetector()
    network_info = detector.get_network_info()
    t = threading.Thread(
        target=discover_devices_nmap,
        name="nmap-scan-thread",
        daemon=True  # pour qu'il ne bloque pas la fermeture du process
    )
    t.start()

    devices = Device.objects.all()
    total_devices = devices.count()
    total_online = devices.filter(status='online').count()
    total_offline = devices.filter(status='offline').count()
    total_alerts = Alert.objects.count()

    today = timezone.now().date()
    scan_dates, scan_counts = [], []
    for i in range(29, -1, -1):
        d = today - timedelta(days=i)
        scan_dates.append(d.strftime('%d/%m'))
        scan_counts.append(Device.objects.filter(last_seen__date=d).count())

    last_uid = Device.objects.latest('last_seen').reseau_uid
    Device.objects.filter(reseau_uid=last_uid)

    gravities = ['low', 'medium', 'high', 'critical']
    alertes_data = {g: Alert.objects.filter(severity=g).count() for g in gravities}
    last_logs = Log.objects.select_related('device').order_by('-scan_time')[:10]

    context = {
        'total_devices': total_devices,
        'total_online': total_online,
        'total_offline': total_offline,
        'total_alerts': total_alerts,
        'scan_dates': json.dumps(scan_dates),
        'scan_counts': json.dumps(scan_counts),
        'network_info': network_info,
        'alertes_data': json.dumps(alertes_data),
        'last_logs': last_logs,
        'reseau_uid': reseau_uid
    }
    return render(request, 'theme/dashboard.html', context)

from app.utils.nmap_tools import discover_devices_nmap
import threading
# Vue liste des ordinateurs (avec détection + scan automatique)
@login_required
def liste_ordinateurs(request):
    reseau_uid = uuid4()
    # discover_devices_nmap()
    detect_attacks()
    t = threading.Thread(
        target=discover_devices_nmap,
        name="nmap-scan-thread",
        daemon=True  # pour qu'il ne bloque pas la fermeture du process
    )
    t.start()

    if settings.DEBUG:
        time.sleep(3)

    last_uid = Device.objects.latest('last_seen').reseau_uid
    Device.objects.filter(reseau_uid=last_uid)

    devices = Device.objects.all()

    total_devices = devices.count()
    total_online = devices.filter(status='online').count()
    total_offline = devices.filter(status='offline').count()
    total_unknown = devices.filter(status__isnull=True).count()

    return render(request, 'theme/liste_ordinateurs.html', {
        'devices': devices,
        'total_devices': total_devices,
        'total_online': total_online,
        'total_offline': total_offline,
        'total_unknown': total_unknown,
        'reseau_uid' : reseau_uid,

        'scan_en_cours': True,
    })

# Vue détails d'un appareil
@login_required
def details_device(request, device_id):
    reseau_uid = uuid4()
    last_uid = Device.objects.latest('last_seen').reseau_uid
    Device.objects.filter(reseau_uid=last_uid)
    device = get_object_or_404(Device, id=device_id)
    alertes = Alert.objects.filter(device=device).order_by('-detected_on')[:10]
    logs = Log.objects.filter(device=device).order_by('-scan_time')[:10]

    chart_labels = [DateFormat(log.scan_time).format('H:i') for log in logs]
    chart_data = [int(log.device.response_time or 0) for log in logs]
    availability_data = [1 if log.device.status == 'online' else 0 for log in logs]

    vulnerabilities_list = []
    if device.vulnerabilities:
        vulnerabilities_list = [v.strip() for v in device.vulnerabilities.split('.') if v.strip()]

    return render(request, 'theme/details_device.html', {
        'device': device,
        'alertes': alertes,
        'logs': logs,
        'chart_labels': json.dumps(chart_labels),
        'chart_data': json.dumps(chart_data),
        'availability_labels': json.dumps(chart_labels),
        'availability_data': json.dumps(availability_data),
        'vulnerabilities_list': vulnerabilities_list,
        'reseau_uid' : reseau_uid
    })

# Vue logs de scan
@login_required
def liste_logs(request):
    reseau_uid = uuid4()
    logs = Log.objects.select_related('device', 'scanned_by').order_by('-scan_time')
    return render(request, 'theme/logs.html', {'logs': logs, 'reseau_uid': reseau_uid})


# Historique des alertes pour affichage de graphique
def historique_alertes(request):
    reseau_uid = uuid4()
    last_uid = Device.objects.latest('last_seen').reseau_uid
    Device.objects.filter(reseau_uid=last_uid)
    alertes = Alert.objects.all().order_by('-detected_on')
    gravites = ['low', 'medium', 'high', 'critical']
    gravite_counts = {
        g: Alert.objects.filter(severity=g, detected_on__gte=timezone.now() - timedelta(days=7)).count() for g in gravites
    }
    return render(request, 'theme/historique_alertes.html', {
        'alertes': alertes,
        'chart_data': json.dumps(gravite_counts),
        'reseau_uid' : reseau_uid
    })

@login_required
def alert_list(request):
    """Vue principale des alertes avec statistiques et filtres"""
    try:
        # Gestion du réseau UID
        reseau_uid = uuid4()
        try:
            last_uid = Device.objects.latest('last_seen').reseau_uid
            devices = Device.objects.filter(reseau_uid=last_uid)
        except Device.DoesNotExist:
            devices = Device.objects.none()

        # Récupération de toutes les alertes
        alerts = Alert.objects.all().order_by('-detected_on')

        # === FILTRES VIA GET ===
        severity = request.GET.get('severity')
        alert_type = request.GET.get('alert_type')
        is_resolved = request.GET.get('is_resolved')
        search = request.GET.get('search')

        if severity:
            alerts = alerts.filter(severity=severity)
        if alert_type:
            alerts = alerts.filter(alert_type=alert_type)
        if is_resolved in ['true', 'false']:
            alerts = alerts.filter(is_resolved=(is_resolved == 'true'))
        if search:
            alerts = alerts.filter(
                Q(src_ip__icontains=search) |
                Q(dest_ip__icontains=search) |
                Q(signature__icontains=search) |
                Q(description__icontains=search)
            )

        # Marquer les alertes critiques/élevées comme lues
        alerts.filter(severity__in=['high', 'critical'], is_read=False).update(is_read=True)

        # === CALCUL DES STATISTIQUES ===
        all_alerts = Alert.objects.all()
        stats = all_alerts.aggregate(
            critical_count=Count('id', filter=Q(severity='critical')),
            high_count=Count('id', filter=Q(severity='high')),
            medium_count=Count('id', filter=Q(severity='medium')),
            low_count=Count('id', filter=Q(severity='low'))
        )

        context = {
            'alerts': alerts,
            'reseau_uid': reseau_uid,
            'devices': devices,
            'critical_count': stats['critical_count'],
            'high_count': stats['high_count'],
            'medium_count': stats['medium_count'],
            'low_count': stats['low_count'],
            'total_alerts': all_alerts.count(),
            # Filtres actuels pour maintenir l'état
            'current_severity': severity,
            'current_alert_type': alert_type,
            'current_is_resolved': is_resolved,
            'current_search': search,
        }

        return render(request, 'theme/alert_list.html', context)

    except Exception as e:
        logger.error(f"Erreur dans alert_list: {e}")
        return render(request, 'theme/alert_list.html', {
            'alerts': Alert.objects.none(),
            'reseau_uid': uuid4(),
            'error': 'Erreur lors du chargement des alertes'
        })

from app.utils.ia_engine import analyser_alerte, get_attack_trend_analysis
@login_required
def alert_verdict(request, pk):
    """
        Renvoie en JSON le rapport IA et la tendance d'attaque pour l'alerte pk
        """
    alert = get_object_or_404(Alert, pk=pk)

    try:
        # 1) Analyse IA détaillée
        rapport = analyser_alerte(alert)

        # 2) Analyse de tendance
        tendance = get_attack_trend_analysis(alert)

        return JsonResponse({
            'success': True,
            'verdict': rapport,
            'trend': tendance,
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
#===================================================================================================================

@user_passes_test(lambda u: u.is_superuser)
def get_alert_verdict(request, alert_id):
    """Vue AJAX pour récupérer le verdict IA d'une alerte"""
    try:
        alert = get_object_or_404(Alert, id=alert_id)

        # Si l'analyse IA existe déjà, la retourner
        if alert.ia_analysis:
            return JsonResponse({
                'success': True,
                'verdict': alert.ia_analysis,
                'cached': True
            })

        # Sinon, générer l'analyse
        try:
            logger.info(f"Génération analyse IA pour alerte {alert_id}")
            verdict = analyser_alerte(alert)

            # Sauvegarder l'analyse
            alert.ia_analysis = verdict
            alert.save()

            logger.info(f"Analyse IA sauvegardée pour alerte {alert_id}")

            return JsonResponse({
                'success': True,
                'verdict': verdict,
                'cached': False
            })

        except Exception as e:
            logger.error(f"Erreur analyse IA pour alerte {alert_id}: {e}")
            return JsonResponse({
                'success': False,
                'error': f'Erreur lors de l\'analyse IA: {str(e)}'
            })

    except Exception as e:
        logger.error(f"Erreur get_alert_verdict: {e}")
        return JsonResponse({
            'success': False,
            'error': f'Erreur: {str(e)}'
        })


@login_required
def liste_traffic(request):
    """Vue principale du trafic réseau"""
    try:
        # Gestion du réseau UID
        reseau_uid = uuid4()
        try:
            last_uid = Device.objects.latest('last_seen').reseau_uid
            devices = Device.objects.filter(reseau_uid=last_uid)
        except Device.DoesNotExist:
            devices = Device.objects.none()

        # Statistiques du trafic
        traffic_stats = TrafficLog.objects.aggregate(
            total_packets=Count('id'),
            tcp_count=Count('id', filter=Q(protocol='TCP')),
            udp_count=Count('id', filter=Q(protocol='UDP')),
            icmp_count=Count('id', filter=Q(protocol='ICMP')),
        )

        # Top IPs sources
        top_src_ips = TrafficLog.objects.values('src_ip').annotate(
            count=Count('id')
        ).order_by('-count')[:10]

        # Top IPs destinations
        top_dst_ips = TrafficLog.objects.values('dst_ip').annotate(
            count=Count('id')
        ).order_by('-count')[:10]

        context = {
            'reseau_uid': reseau_uid,
            'devices': devices,
            'traffic_stats': traffic_stats,
            'top_src_ips': top_src_ips,
            'top_dst_ips': top_dst_ips,
        }

        return render(request, 'theme/traffic.html', context)

    except Exception as e:
        logger.error(f"Erreur dans liste_traffic: {e}")
        return render(request, 'theme/traffic.html', {
            'reseau_uid': uuid4(),
            'error': 'Erreur lors du chargement du trafic'
        })


@login_required
def get_latest_traffic(request):
    """API AJAX pour récupérer le trafic en temps réel"""
    try:
        # Filtres
        src_ip = request.GET.get('src_ip', '').strip()
        dst_ip = request.GET.get('dst_ip', '').strip()
        protocol = request.GET.get('protocol', '').strip()
        limit = int(request.GET.get('limit', 100))

        # Query de base
        traffic = TrafficLog.objects.all().order_by('-timestamp')

        # Application des filtres
        if src_ip:
            traffic = traffic.filter(src_ip__icontains=src_ip)
        if dst_ip:
            traffic = traffic.filter(dst_ip__icontains=dst_ip)
        if protocol:
            traffic = traffic.filter(protocol__icontains=protocol)

        # Limitation
        traffic = traffic[:limit]

        # Sérialisation
        logs = []
        for log in traffic:
            logs.append({
                'id': log.id,
                'timestamp': log.timestamp.strftime('%H:%M:%S.%f')[:-3],
                'src_ip': log.src_ip,
                'dst_ip': log.dst_ip,
                'protocol': log.protocol,
                'src_port': log.src_port or '-',
                'dst_port': log.dst_port or '-',
                'length': log.length,
                'info': log.info or '-',
                'has_alert': bool(log.alert_linked),
                'alert_severity': log.alert_linked.severity if log.alert_linked else None
            })

        return JsonResponse({
            'success': True,
            'logs': logs,
            'count': len(logs),
            'timestamp': timezone.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Erreur get_latest_traffic: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        })


from app.models import DeviceEvent

def log_device_event(device=None, event_type='', description='', ip_address=None):
    """
    Crée un DeviceEvent compatible avec votre API recent_events_api.
    """
    DeviceEvent.objects.create(
        device=device,                 # ou None si pas de FK
        event_type=event_type,         # 'connection', 'disconnection', 'scan', 'alert', etc.
        description=description,
        ip_address=ip_address or getattr(device, 'ip_address', None),
        timestamp=timezone.now()
    )
@login_required
def lancer_ping(request):
    ip = request.GET.get('ip')
    if not ip:
        messages.error(request, "Adresse IP non spécifiée.")
        return redirect('liste_ordinateurs')

    device = get_object_or_404(Device, ip_address=ip)
    system = platform.system()
    command = ['ping', '-n', '1', ip] if system == "Windows" else ['ping', '-c', '1', ip]

    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        output = result.stdout

        if result.returncode == 0:
            device.status = 'online'
            if system == "Windows":
                match = re.search(r'temps[=<]?\s*=?\s*(\d+)', output, re.IGNORECASE)
            else:
                match = re.search(r'time[=<]?\s*=?\s*(\d+\.?\d*)', output)

            device.response_time = float(match.group(1)) if match else None
            messages.success(request, f"✅ {device.hostname} ({ip}) est en ligne.")
        else:
            device.status = 'offline'
            device.response_time = None
            messages.error(request, f"❌ {device.hostname} ({ip}) est hors ligne.")
            Alert.objects.create(
                device=device,
                severity='medium',
                alert_type='scan',
                description=f"{device.hostname} ne répond pas au ping."
            )

        device.last_seen = timezone.now()
        device.save()

        Log.objects.create(
            device=device,
            scanned_by=request.user,
            event=output,
            scan_time=timezone.now()
        )

    except Exception as e:
        messages.error(request, f"Erreur pendant le ping : {str(e)}")

    return redirect('liste_ordinateurs')


from django.contrib import messages



from uuid import uuid4
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from django.utils import timezone
from django.contrib.auth.decorators import login_required

import nmap, subprocess, re

from app.models import Device, Log, DeviceEvent


@login_required
def lancer_scan_complet(request, ip):
    device = get_object_or_404(Device, ip_address=ip)

    # 1) Connexion détectée
    try:
        print("🔔 [DEBUG] Création event connection pour", ip)
        ev1 = DeviceEvent.objects.create(
            device=device,
            event_type='connection',
            description=f"Connexion détectée vers {ip}",
            ip_address=ip,
            timestamp=timezone.now()
        )
        print("✅ [DEBUG] Event connection créé :", ev1.id)
    except Exception as e:
        print("❌ [DEBUG] Erreur création connection event :", e)
        messages.error(request, f"Impossible de créer l’événement de connexion : {e}")

    # 2) Scan Nmap
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=ip, arguments="-T4 -sV -O -R --top-ports 100")
        host_data = scanner[ip] if ip in scanner.all_hosts() else None

        if host_data:
            services = [
                f"{p}/{d['name']}({d['state']})"
                for p, d in host_data.get('tcp', {}).items()
            ]
            services_str = "; ".join(services) or "Aucun"

            # mise à jour Device
            device.status    = 'online'
            device.last_seen = timezone.now()
            device.save()

            # 3) Scan event
            try:
                print("🔔 [DEBUG] Création event scan pour", ip, "->", services_str)
                ev2 = DeviceEvent.objects.create(
                    device=device,
                    event_type='scan',
                    description=f"Scan réseau effectué : {services_str}",
                    ip_address=ip,
                    timestamp=timezone.now()
                )
                print("✅ [DEBUG] Event scan créé :", ev2.id)
            except Exception as e:
                print("❌ [DEBUG] Erreur création scan event :", e)
                messages.error(request, f"Impossible de créer l’événement de scan : {e}")

            messages.success(request, f"Scan terminé pour {ip}")

        else:
            # 4) Disconnection event
            device.status    = 'offline'
            device.last_seen = timezone.now()
            device.save()
            try:
                print("🔔 [DEBUG] Création event disconnection pour", ip)
                ev3 = DeviceEvent.objects.create(
                    device=device,
                    event_type='disconnection',
                    description=f"Nmap n’a pas pu scanner {ip}",
                    ip_address=ip,
                    timestamp=timezone.now()
                )
                print("✅ [DEBUG] Event disconnection créé :", ev3.id)
            except Exception as e:
                print("❌ [DEBUG] Erreur création disconnection event :", e)
                messages.error(request, f"Impossible de créer l’événement de disconnection : {e}")

            messages.warning(request, f"Aucun hôte détecté à {ip}")

    except Exception as scan_err:
        print("❌ [DEBUG] Erreur globale du scan :", scan_err)
        messages.error(request, f"Erreur durant le scan : {scan_err}")

    return redirect('liste_ordinateurs')


@login_required
def details_device(request, device_id):
    device = get_object_or_404(Device, id=device_id)

    logs = Log.objects.filter(device=device).order_by('-scan_time')[:10]
    alertes = Alert.objects.filter(device=device).order_by('-detected_on')[:5]

    context = {
        'device': device,
        'logs': logs,
        'alertes': alertes,
    }
    return render(request, 'theme/details_device.html', context)



#Fonction pour l'exportation des alertes
def exporter_alertes_pdf(request):
    gravite = request.GET.get('gravite')
    if gravite in ['low', 'medium', 'high', 'critical']:
        alertes = Alert.objects.select_related('device').filter(severity=gravite).order_by('-detected_on')
    else:
        alertes = Alert.objects.select_related('device').order_by('-detected_on')
    template = get_template('theme/pdf_alertes.html')
    html = template.render({'alertes': alertes})
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="alertes.pdf"'
    pisa_status = pisa.CreatePDF(html, dest=response)
    if pisa_status.err:
        return HttpResponse('Erreur PDF', status=500)
    return response


@login_required
def user_settings(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        settings_form = UserSettingsForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid() and settings_form.is_valid():
            form.save()
            settings_form.save()
            update_session_auth_hash(request, request.user)
            messages.success(request, "Modifications enregistrées.")
            return redirect('parametres')
        else:
            messages.error(request, "Erreur dans le formulaire.")
    else:
        form = PasswordChangeForm(request.user)
        settings_form = UserSettingsForm(instance=request.user)
    return render(request, 'theme/parametres.html', {
        'form': form,
        'settings_form': settings_form
    })

#=========================================================================================================

from app.models import User
from django.db.models import Q, Count, Case, When, IntegerField
import logging

logger = logging.getLogger(__name__)


def is_admin(user):
    """Vérifie si l'utilisateur est administrateur"""
    return user.is_staff or user.is_superuser or getattr(user, 'role', '') == 'admin'


@login_required
@user_passes_test(is_admin)
def liste_utilisateurs(request):
    """
    Vue complète pour la liste des utilisateurs avec statistiques et filtres
    """
    try:
        # === RÉCUPÉRATION DES UTILISATEURS ===
        utilisateurs = User.objects.select_related().prefetch_related()

        # === FILTRES VIA GET ===
        search = request.GET.get('search', '').strip()
        role_filter = request.GET.get('role', '').strip()
        status_filter = request.GET.get('status', '').strip()

        # Filtre de recherche (nom, email, username)
        if search:
            utilisateurs = utilisateurs.filter(
                Q(username__icontains=search) |
                Q(email__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search)
            )

        # Filtre par rôle
        if role_filter:
            if role_filter == 'admin':
                utilisateurs = utilisateurs.filter(
                    Q(is_staff=True) | Q(is_superuser=True)
                )
            elif role_filter == 'agent':
                # Si vous avez un champ 'role' dans votre modèle User
                if hasattr(User, 'role'):
                    utilisateurs = utilisateurs.filter(role='agent')
                else:
                    # Sinon, filtrer par groupes ou permissions
                    utilisateurs = utilisateurs.filter(groups__name__icontains='agent')
            elif role_filter == 'user':
                utilisateurs = utilisateurs.filter(
                    is_staff=False,
                    is_superuser=False
                )

        # Filtre par statut
        if status_filter:
            if status_filter == 'active':
                utilisateurs = utilisateurs.filter(is_active=True)
            elif status_filter == 'inactive':
                utilisateurs = utilisateurs.filter(is_active=False)

        # === CALCUL DES STATISTIQUES ===
        all_users = User.objects.all()

        # Comptage des rôles
        admin_count = all_users.filter(
            Q(is_staff=True) | Q(is_superuser=True)
        ).count()

        # Si vous avez un champ 'role'
        if hasattr(User, 'role'):
            agent_count = all_users.filter(role='agent').count()
        else:
            # Sinon estimation basée sur les groupes
            agent_count = all_users.filter(groups__name__icontains='agent').distinct().count()

        # Utilisateurs actifs/inactifs
        active_count = all_users.filter(is_active=True).count()
        inactive_count = all_users.filter(is_active=False).count()

        # Utilisateurs connectés récemment (dernières 24h)
        recent_login_threshold = timezone.now() - timedelta(days=1)
        recent_active_count = all_users.filter(
            last_login__gte=recent_login_threshold
        ).count()

        # === ENRICHISSEMENT DES DONNÉES UTILISATEUR ===
        enriched_users = []
        for user in utilisateurs:
            # Détermination du rôle
            if user.is_superuser:
                user_role = 'superadmin'
            elif user.is_staff:
                user_role = 'admin'
            elif hasattr(user, 'role') and user.role:
                user_role = user.role
            elif user.groups.filter(name__icontains='agent').exists():
                user_role = 'agent'
            else:
                user_role = 'user'

            # Ajout des informations enrichies
            user.computed_role = user_role
            user.full_name = f"{user.first_name} {user.last_name}".strip() or "Non renseigné"
            user.is_recently_active = (
                    user.last_login and
                    user.last_login >= recent_login_threshold
            ) if user.last_login else False

            enriched_users.append(user)

        # === ORDRE ET PAGINATION ===
        # Tri par défaut : admins d'abord, puis par date d'inscription
        utilisateurs = sorted(enriched_users, key=lambda u: (
            0 if u.computed_role in ['superadmin', 'admin'] else 1,
            -u.date_joined.timestamp()
        ))

        # === CONTEXTE POUR LE TEMPLATE ===
        context = {
            'utilisateurs': utilisateurs,
            'total_users': all_users.count(),
            'admin_count': admin_count,
            'agent_count': agent_count,
            'active_count': active_count,
            'inactive_count': inactive_count,
            'recent_active_count': recent_active_count,

            # Filtres actuels pour maintenir l'état
            'current_search': search,
            'current_role': role_filter,
            'current_status': status_filter,

            # Statistiques supplémentaires
            'users_this_month': all_users.filter(
                date_joined__gte=timezone.now() - timedelta(days=30)
            ).count(),
            'users_this_week': all_users.filter(
                date_joined__gte=timezone.now() - timedelta(days=7)
            ).count(),
        }

        logger.info(f"Liste utilisateurs chargée: {len(utilisateurs)} utilisateurs affichés")
        return render(request, 'theme/liste_utilisateurs.html', context)

    except Exception as e:
        logger.error(f"Erreur dans liste_utilisateurs: {e}")
        return render(request, 'theme/liste_utilisateurs.html', {
            'utilisateurs': [],
            'error': 'Erreur lors du chargement des utilisateurs',
            'admin_count': 0,
            'agent_count': 0,
            'active_count': 0,
            'inactive_count': 0,
        })


# === VUES AJAX POUR LES ACTIONS RAPIDES ===
@login_required
@user_passes_test(is_admin)
def toggle_user_status(request, user_id):
    """Active/désactive un utilisateur via AJAX"""
    if request.method == 'POST':
        try:
            user = User.objects.get(id=user_id)
            user.is_active = not user.is_active
            user.save()

            return JsonResponse({
                'success': True,
                'new_status': user.is_active,
                'message': f"Utilisateur {'activé' if user.is_active else 'désactivé'}"
            })
        except User.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Utilisateur introuvable'
            })

    return JsonResponse({'success': False, 'error': 'Méthode non autorisée'})


@login_required
@user_passes_test(is_admin)
def export_users(request):
    """Exporte la liste des utilisateurs en CSV"""
    import csv
    from django.http import HttpResponse

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="utilisateurs_2iem_security.csv"'

    writer = csv.writer(response)
    writer.writerow([
        'Username', 'Email', 'Prénom', 'Nom', 'Rôle',
        'Actif', 'Date inscription', 'Dernière connexion'
    ])

    for user in User.objects.all():
        writer.writerow([
            user.username,
            user.email,
            user.first_name,
            user.last_name,
            'Admin' if user.is_staff else 'Utilisateur',
            'Oui' if user.is_active else 'Non',
            user.date_joined.strftime('%d/%m/%Y %H:%M'),
            user.last_login.strftime('%d/%m/%Y %H:%M') if user.last_login else 'Jamais'
        ])

    return response
#==========================================================================================================
from app.models import HoneypotLog

@login_required
def honeypots_view(request):
    """Vue principale des honeypots avec statistiques et filtres"""
    try:
        # Récupération de tous les logs
        logs = HoneypotLog.objects.all().order_by('-detected_on')

        # === FILTRES VIA GET ===
        service = request.GET.get('service')
        ip_search = request.GET.get('ip_search')
        port = request.GET.get('port')
        period = request.GET.get('period')

        if service:
            logs = logs.filter(service__icontains=service)
        if ip_search:
            logs = logs.filter(ip_address__icontains=ip_search)
        if port:
            logs = logs.filter(port=port)
        if period:
            now = timezone.now()
            if period == '1h':
                logs = logs.filter(detected_on__gte=now - timedelta(hours=1))
            elif period == '24h':
                logs = logs.filter(detected_on__gte=now - timedelta(days=1))
            elif period == '7d':
                logs = logs.filter(detected_on__gte=now - timedelta(days=7))
            elif period == '30d':
                logs = logs.filter(detected_on__gte=now - timedelta(days=30))

        # === CALCUL DES STATISTIQUES ===
        all_logs = HoneypotLog.objects.all()
        stats = all_logs.aggregate(
            ssh_count=Count('id', filter=Q(service__icontains='SSH')),
            ftp_count=Count('id', filter=Q(service__icontains='FTP')),
            http_count=Count('id', filter=Q(service__icontains='HTTP')),
            other_count=Count('id', filter=~Q(service__icontains='SSH') &
                                           ~Q(service__icontains='FTP') &
                                           ~Q(service__icontains='HTTP'))
        )

        context = {
            'logs': logs,
            'ssh_count': stats['ssh_count'],
            'ftp_count': stats['ftp_count'],
            'http_count': stats['http_count'],
            'other_count': stats['other_count'],
            'total_attempts': all_logs.count(),
            # Filtres actuels
            'current_service': service,
            'current_ip_search': ip_search,
            'current_port': port,
            'current_period': period,
        }

        return render(request, 'theme/honeypot_logs.html', context)

    except Exception as e:
        logger.error(f"Erreur dans honeypots_view: {e}")
        return render(request, 'theme/honeypot_logs.html', {
            'logs': HoneypotLog.objects.none(),
            'error': 'Erreur lors du chargement des honeypots'
        })

#==================================Versions====================================================================
from orders.models import Abonnement

@login_required
def dashboard_redirect(request):
    t = threading.Thread(
        target=discover_devices_nmap,
        name="nmap-scan-thread",
        daemon=True  # pour qu'il ne bloque pas la fermeture du process
    )
    t.start()
    try:
        abonnement = Abonnement.objects.get(user=request.user)

        # Vérifie si l’abonneement est expiré
        if abonnement.date_fin and abonnement.date_fin.date() < date.today():
            return redirect('theme:choisir_version')  # vers la page de sélection

        version_slug = abonnement.version.nom

        if version_slug == 'aegis_sec':
            return redirect('theme:dashboard_aegis')
        elif version_slug == 'dome':
            return redirect('theme:dashboard_dome')
        elif version_slug == 'black_vault':
            return redirect('theme:dashboard_black_vault')
        else:
            return render(request, 'errors/no_version.html')  # version inconnue

    except Abonnement.DoesNotExist:
        # Aucun abonnement trouvé
        return redirect('theme:choisir_version')

@login_required
def licence_expiree(request):
    return render(request, 'dashboards/licence_expiree.html', {
        'page_title': 'Licence Inactive',
        'message': "Votre licence est expirée, désactivée ou n’existe pas. Veuillez acheter une licence ou réactiver votre abonnement."
    })

from django.utils.crypto import get_random_string
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.decorators import login_required
from app.models import Version
from pages.views import envoyer_email_licence

@login_required
def choisir_version(request):
    if request.method == 'POST':
        version_nom = request.POST.get('version')
        try:
            version = Version.objects.get(nom=version_nom)

            # Supprimer les anciens abonnements
            Abonnement.objects.filter(user=request.user).delete()

            # Créer un nouvel abonnement (la licence sera générée automatiquement dans save())
            abonnement = Abonnement.objects.create(
                user=request.user,
                version=version,
                date_fin=timezone.now() + timedelta(days=90),
                actif=True,
                est_paye=True  # simulate un paiement réussi
            )
            abonnement.save()
            envoyer_email_licence(user, abonnement)

            # Rediriger selon la version choisie
            if version.nom == 'aegis_sec':
                return redirect('theme:dashboard_aegis')
            elif version.nom == 'dome':
                return redirect('theme:dashboard_dome')
            elif version.nom == 'black_vault':
                return redirect('theme:dashboard_black_vault')
            else:
                return redirect('theme:dashboard_access')

        except Version.DoesNotExist:
            return render(request, 'dashboards/choisir_version.html', {
                'versions': Version.objects.all(),
                'error': "La version choisie est invalide."
            })

    versions = Version.objects.all()
    return render(request, 'dashboards/choisir_version.html', {'versions': versions})

from django.http import FileResponse, Http404
import os

@login_required
def telecharger_dependances(request):
    abonnement = getattr(request.user, 'abonnement', None)

    if not abonnement or not abonnement.est_valide():
        return HttpResponseForbidden("Votre licence est invalide ou expirée.")

    # Chemin vers le fichier ZIP des dépendances
    chemin_fichier = os.path.join(settings.MEDIA_ROOT, 'packages', 'dependances_2iem_security.zip')

    if os.path.exists(chemin_fichier):
        return FileResponse(open(chemin_fichier, 'rb'), as_attachment=True, filename='dependances_2iem_security.zip')
    else:
        raise Http404("Fichier non trouvé.")











from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import socket
import subprocess
import platform


def network_info_api(request):
    """API pour récupérer les informations réseau côté serveur"""
    if request.method == 'GET':
        try:
            network_data = {
                'network_name': get_network_name(),
                'server_ip': get_server_ip(),
                'hostname': socket.gethostname(),
                'platform': platform.system()
            }
            return JsonResponse(network_data)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)


def get_network_name():
    """Récupère le nom du réseau WiFi (Windows/Linux/Mac)"""
    try:
        system = platform.system()

        if system == "Windows":
            # Windows - utilise netsh
            result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Profil Tous les utilisateurs' in line or 'All User Profile' in line:
                        return line.split(':')[-1].strip()

        elif system == "Darwin":  # macOS
            result = subprocess.run(
                ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'],
                capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'SSID' in line:
                        return line.split(':')[-1].strip()

        elif system == "Linux":
            # Linux - essaie plusieurs méthodes
            try:
                result = subprocess.run(['iwgetid', '-r'], capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            except:
                pass

            try:
                result = subprocess.run(['nmcli', '-t', '-f', 'active,ssid', 'dev', 'wifi'],
                                        capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.startswith('yes:'):
                            return line.split(':')[1]
            except:
                pass

        # Si aucune méthode ne fonctionne, retourner un nom basé sur l'IP
        hostname = socket.gethostname()
        return f"NETWORK-{hostname.upper()}"

    except Exception as e:
        return "RÉSEAU-LOCAL"


def get_server_ip():
    """Récupère l'adresse IP du serveur"""
    try:
        # Connexion temporaire pour récupérer l'IP locale
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


@require_http_methods(["GET"])
def network_info_api(request):
    """API pour récupérer les informations réseau en temps réel"""
    try:
        detector = NetworkDetector()
        network_data = detector.get_network_info()

        # Ajouter des informations supplémentaires
        network_data.update({
            'timestamp': timezone.now().isoformat(),
            'status': 'success'
        })

        return JsonResponse(network_data)

    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'error': str(e),
            'wifi_name': 'Erreur de détection',
            'local_ip': 'Non disponible',
            'public_ip': 'Non disponible'
        }, status=500)


@require_http_methods(["POST"])
def refresh_network_api(request):
    """API pour forcer la mise à jour des informations réseau"""
    try:
        detector = NetworkDetector()
        network_data = detector.get_network_info()

        return JsonResponse({
            'status': 'refreshed',
            'data': network_data,
            'timestamp': timezone.now().isoformat()
        })

    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'error': str(e)
        }, status=500)

from app.utils.geolocalisation import geolocate_ip

def geolocalisation(request):
    attaques = []

    for alert in Alert.objects.exclude(src_ip__isnull=True).exclude(src_ip=''):
        coords = geolocate_ip(alert.src_ip)
        print(alert.src_ip, coords)  # Ajoute ce log

        if coords:
            attaques.append({
                "ip": alert.src_ip,
                "lat": coords[0],
                "lng": coords[1]
            })

    print("attaques:", attaques)  # Confirme ici aussi

    return render(request, 'theme/localisation.html', {
        "attaques_json": json.dumps(attaques)
    })







from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.contrib import messages
import subprocess
import platform
import json
import time
import random

# ========================================
# 2. API POUR SCANNER LES RÉSEAUX WIFI
# ========================================
def scan_wifi_networks():
    """Scanner les réseaux WiFi disponibles"""
    try:
        system = platform.system().lower()
        networks = []

        if system == "windows":
            networks = scan_windows_wifi()
        elif system == "darwin":  # macOS
            networks = scan_macos_wifi()
        elif system == "linux":
            networks = scan_linux_wifi()

        # Si aucun réseau trouvé, utiliser des données de test
        if not networks:
            networks = get_test_networks()

        return networks

    except Exception as e:
        print(f"Erreur lors du scan: {e}")
        return get_test_networks()


def scan_windows_wifi():
    """Scanner WiFi sur Windows"""
    try:
        result = subprocess.run([
            'netsh', 'wlan', 'show', 'profiles'
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=10)

        networks = []
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Profil Tous les utilisateurs' in line or 'All User Profile' in line:
                    profile_name = line.split(':')[-1].strip()
                    if profile_name:
                        networks.append({
                            'name': profile_name,
                            'signal': random.randint(40, 95),
                            'security': random.choice(['WPA2', 'WPA3']),
                            'channel': random.randint(1, 11),
                            'frequency': random.choice(['2.4 GHz', '5 GHz']),
                            'connected': False
                        })
        return networks[:8]  # Limiter à 8 réseaux
    except:
        return []


def scan_macos_wifi():
    """Scanner WiFi sur macOS"""
    try:
        result = subprocess.run([
            '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport',
            '-s'
        ], capture_output=True, text=True, timeout=10)

        networks = []
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')[1:]  # Ignorer l'en-tête
            for line in lines[:8]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        networks.append({
                            'name': parts[0],
                            'signal': abs(int(parts[2])) if parts[2].lstrip('-').isdigit() else random.randint(40, 90),
                            'security': "WPA2" if "WPA2" in line else "WPA" if "WPA" in line else "Open",
                            'channel': random.randint(1, 11),
                            'frequency': random.choice(['2.4 GHz', '5 GHz']),
                            'connected': False
                        })
        return networks
    except:
        return []


def scan_linux_wifi():
    """Scanner WiFi sur Linux"""
    try:
        result = subprocess.run([
            'nmcli', '-t', '-f', 'SSID,SIGNAL,SECURITY', 'dev', 'wifi'
        ], capture_output=True, text=True, timeout=10)

        networks = []
        if result.returncode == 0:
            for line in result.stdout.split('\n')[:8]:
                if line.strip():
                    parts = line.split(':')
                    if len(parts) >= 2 and parts[0]:
                        networks.append({
                            'name': parts[0],
                            'signal': int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else random.randint(40,
                                                                                                                 90),
                            'security': parts[2] if len(parts) > 2 and parts[2] != '--' else "Open",
                            'channel': random.randint(1, 11),
                            'frequency': random.choice(['2.4 GHz', '5 GHz']),
                            'connected': False
                        })
        return networks
    except:
        return []


def get_test_networks():
    """Réseaux de test si le scan échoue"""
    return [
        {
            'name': 'MonWiFi-Maison',
            'signal': 95,
            'security': 'WPA3',
            'channel': 6,
            'frequency': '2.4 GHz',
            'connected': True
        },
        {
            'name': 'Voisin-WiFi',
            'signal': 78,
            'security': 'WPA2',
            'channel': 11,
            'frequency': '2.4 GHz',
            'connected': False
        },
        {
            'name': 'FreeWiFi',
            'signal': 65,
            'security': 'Open',
            'channel': 1,
            'frequency': '2.4 GHz',
            'connected': False
        },
        {
            'name': 'Bureau-5G',
            'signal': 82,
            'security': 'WPA2',
            'channel': 36,
            'frequency': '5 GHz',
            'connected': False
        },
        {
            'name': 'Hotspot-Public',
            'signal': 45,
            'security': 'Open',
            'channel': 3,
            'frequency': '2.4 GHz',
            'connected': False
        }
    ]


def simulate_wifi_connection(ssid, password):
    """Simuler la connexion WiFi (remplacez par votre vraie logique)"""
    # Simulation : 85% de chance de succès
    time.sleep(1)  # Simuler le temps de connexion
    return random.random() < 0.85
