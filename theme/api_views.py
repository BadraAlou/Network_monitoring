from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
import json
import random
from datetime import datetime, timedelta
from django.views.decorators.http import require_GET
from django.db.models import Count
from django.utils import timezone


from app.models import DeviceEvent

@login_required
@require_http_methods(["GET"])
def network_info_api(request):
    """API pour récupérer les informations réseau en temps réel"""
    try:
        # Simuler la récupération d'informations réseau
        # Remplacez par votre logique réelle
        network_data = {
            'wifi_name': 'FAMILLE-SAGHO',
            'local_ip': '192.168.1.105',
            'public_ip': '78.192.45.123',
            'hostname': 'PC-UTILISATEUR',
            'system': 'Windows 11',
            'timestamp': datetime.now().isoformat()
        }

        return JsonResponse({
            'status': 'success',
            'data': network_data
        })

    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)


from django.http import JsonResponse
from django.views.decorators.http import require_GET
from django.db.models import Count
from django.utils.timezone import now
from app.models import Alert  # adapte selon ton app

@require_GET
def alerts_api(request):
    """API pour récupérer les alertes actives depuis la BDD"""
    try:
        # 1. Récupérer les alertes non résolues, les plus récentes en premier
        qs = Alert.objects.filter(is_resolved=False).order_by('-detected_on')

        # 2. Construire la liste des alertes
        alerts = []
        for a in qs:
            alerts.append({
                'id': a.id,
                'title': a.titre,
                'description': a.description or a.signature,
                'severity': a.severity,
                'timestamp': a.detected_on.strftime('%H:%M'),
                'type': a.alert_type,
            })

        # 3. Distribution par sévérité (low, medium, high, critical)
        dist_qs = (
            qs
            .values('severity')
            .annotate(count=Count('severity'))
        )
        # initialisation à zéro
        distribution = {lvl: 0 for lvl, _ in Alert.SEVERITY_CHOICES}
        for entry in dist_qs:
            distribution[entry['severity']] = entry['count']

        # 4. Réponse JSON
        return JsonResponse({
            'status':  'success',
            'alerts':  alerts,
            'distribution': distribution,
            'total':   qs.count(),
        })

    except Exception as e:
        return JsonResponse({
            'status':  'error',
            'message': str(e),
        }, status=500)

@login_required
@require_GET
def recent_events_api(request):
    """
    API pour :
      - récupérer les derniers 50 événements des dernières 24 h
      - fournir la distribution par type
      - renvoyer timestamp formaté et ISO
      - inclure un lien de détail vers chaque device
    """
    try:
        # 1. Période d’intérêt : dernières 24 h
        since = timezone.now() - timedelta(hours=24)

        # 2. Sélectionner tous les événements récents
        base_qs = DeviceEvent.objects.filter(timestamp__gte=since)

        # 3. Nombre total dans ces 24 h
        total_events = base_qs.count()

        # 4. Les 50 plus récents
        recent_qs = base_qs.order_by('-timestamp')[:50]

        # 5. Sérialisation
        events = []
        for ev in recent_qs:
            events.append({
                'id':           ev.id,
                'device_name':  ev.device.hostname if ev.device else None,
                'description':  ev.description,
                'type':         ev.event_type,
                'timestamp':    ev.timestamp.strftime('%d/%m/%Y %H:%M'),
                'timestamp_iso': ev.timestamp.isoformat(),
                'ip_address':   ev.ip_address,
                'device_url':   (
                    request.build_absolute_uri(f"/devices/{ev.device_id}/")
                    if ev.device_id else None
                )
            })

        # 6. Distribution par type sur 24 h
        dist_qs = (base_qs
                   .values('event_type')
                   .annotate(count=Count('event_type')))
        distribution = {t[0]: 0 for t in DeviceEvent.EVENT_TYPE_CHOICES}
        for entry in dist_qs:
            distribution[entry['event_type']] = entry['count']

        # 7. Réponse JSON
        return JsonResponse({
            'status':       'success',
            'since':        since.isoformat(),
            'limit':        50,
            'total':        total_events,
            'events':       events,
            'distribution': distribution,
        })

    except Exception as e:
        return JsonResponse({
            'status':  'error',
            'message': str(e),
        }, status=500)