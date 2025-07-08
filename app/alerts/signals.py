from django.db.models.signals import post_save
from django.dispatch import receiver
from app.models import Alert
from theme.views import envoyer_alerte_email, envoyer_sms_alerte

@receiver(post_save, sender=Alert)
def alerte_importante_detectee(sender, instance, created, **kwargs):
    """
        Déclenche une alerte par email + SMS dans deux cas :
        - Si l'alerte est de type 'DoS' ET de sévérité 'high'
        - Si l'alerte est de sévérité 'critical' (peu importe le type)
    """
    if not created:
        return

    alerte_importante = (
        (instance.severity == 'high' and instance.alert_type.lower() == 'dos') or
        (instance.severity == 'critical')
    )

    if alerte_importante:
        email_envoye = envoyer_alerte_email(instance.titre, instance.description, ['saghoousmane51@gmail.com'])
        sms_envoye = envoyer_sms_alerte(instance.titre, instance.description, '+22375909218')

        instance.is_email_sent = bool(email_envoye)
        instance.is_sms_sent = bool(sms_envoye)
        instance.save(update_fields=['is_email_sent', 'is_sms_sent'])
