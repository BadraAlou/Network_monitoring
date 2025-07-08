from app.models import Alert

def critical_alert_count(request):
    count = Alert.objects.filter(
        severity__in=['high', 'critical'],
        is_resolved=False,
        is_read=False
    ).count()
    return {'critical_alert_count': count}