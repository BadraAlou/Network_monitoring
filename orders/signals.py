from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils.timezone import now, timedelta
from django.conf import settings
from django.contrib.auth import get_user_model
from app.models import Version
from .models import Abonnement

User = get_user_model()

@receiver(post_save, sender=User)
def creer_abonnement_apres_inscription(sender, instance, created, **kwargs):
    if created:
        if not hasattr(instance, 'abonnement'):
            try:
                version_essai = Version.objects.get(nom='dome')
                Abonnement.objects.create(
                    user=instance,
                    version=version_essai,
                    date_debut=now().date(),
                    date_expiration=now().date() + timedelta(days=30),
                    est_paye=False,
                    actif=True
                )
            except Version.DoesNotExist:
                print("❌ La version Dôme n’existe pas encore en base.")
