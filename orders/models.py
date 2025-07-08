
from django.db import models
from django.conf import settings
from django.utils.timezone import now, timedelta
from app.models import Version
import uuid
from django.utils import timezone

def default_date_expiration():
    return now().date() + timedelta(days=30)

class Abonnement(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    version = models.ForeignKey(Version, on_delete=models.SET_NULL, null=True)
    date_debut = models.DateField(default=now)
    date_expiration = models.DateField(default=default_date_expiration)
    est_paye = models.BooleanField(default=False)
    actif = models.BooleanField(default=False)
    date_fin = models.DateTimeField(null=True, blank=True)
    transaction_id = models.CharField(max_length=100, unique=True)
    licence = models.CharField(max_length=100, unique=True,editable=False, blank=True, null=True,)

    def generate_licence_key(self):
        prefix = {
            'dome': 'DOME',
            'aegis_sec': 'AEGIS',
            'black_vault': 'VAULT'
        }.get(self.version.nom.lower(), 'GEN')

        random_part = uuid.uuid4().hex[:12].upper()  # 12 caractères aléatoires
        return f"{prefix}-{random_part}"

    def save(self, *args, **kwargs):
        if not self.licence and self.version:
            self.licence = self.generate_licence_key()

        if not self.transaction_id:
            self.transaction_id = str(uuid.uuid4())

        super().save(*args, **kwargs)

    # def generate_licence(self):
    #     self.licence = str(uuid.uuid4()).replace('-', '').upper()[:16]  # 16 caractères aléatoires
    #     self.save()

    def est_valide(self):
        return self.actif and self.date_expiration >= now().date()

    def __str__(self):
        return f"{self.user.username} - {self.version.nom} - {'Payé' if self.est_paye else 'Essai'}"


class Paiement(models.Model):
    STATUT_CHOICES = [
        ('en_attente', 'En attente'),
        ('paye', 'Payé'),
        ('annule', 'Annulé'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    nom_complet = models.CharField(max_length=255)
    entreprise = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField()
    telephone = models.CharField(max_length=50)
    version_slug = models.CharField(max_length=50)
    montant = models.IntegerField()  # en centimes XOF
    stripe_session_id = models.CharField(max_length=255, blank=True, null=True)
    statut = models.CharField(max_length=20, choices=STATUT_CHOICES, default='en_attente')
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username} - {self.version_slug} - {self.statut}"

class MessageContact(models.Model):
    SUJETS_CHOIX = [
        ('information', 'Demande d’information'),
        ('devis', 'Demande de devis'),
        ('support', 'Support technique'),
        ('licence', 'Problème de licence'),
        ('partenariat', 'Partenariat'),
        ('autre', 'Autre'),
    ]

    nom = models.CharField(max_length=100)
    email = models.EmailField()
    entreprise = models.CharField(max_length=100, blank=True, null=True)
    telephone = models.CharField(max_length=30, blank=True, null=True)
    sujet = models.CharField(max_length=50, choices=SUJETS_CHOIX)
    message = models.TextField()
    date_reception = models.DateTimeField(auto_now_add=True)
    traite = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.nom} – {self.sujet} – {'Traité' if self.traite else 'Non traité'}"
