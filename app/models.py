from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
import uuid


class Version(models.Model):
    NOM_CHOICES = [
        ('black_vault', 'Black Vault (Premium)'),
        ('dome', 'Dôme (Standard)'),
        ('aegis_sec', 'Aegis Sec (Moyen)'),
    ]

    nom = models.CharField(max_length=20, choices=NOM_CHOICES, unique=True)
    description = models.TextField()
    prix = models.DecimalField(max_digits=10, decimal_places=2)
    fonctionnalités = models.TextField(help_text="Liste des fonctionnalités ou avantages de cette version")

    def __str__(self):
        return self.get_nom_display()


class User(AbstractUser):
    role = models.CharField(max_length=20, choices=[
        ('admin', 'Administrateur'),
        ('technicien', 'Technicien'),
        ('utilisateur', 'Utilisateur'),
    ], default='utilisateur')
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    version = models.ForeignKey(Version, null=True, blank=True, on_delete=models.SET_NULL)
    email = models.EmailField(unique=True)

    def __str__(self):
        return f"{self.username} ({self.role})"


class Device(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    hostname = models.CharField(max_length=255)
    mac_address = models.CharField(max_length=17, blank=True, null=True)
    os = models.CharField(max_length=100, blank=True, null=True)
    status = models.CharField(max_length=50, default='inconnu')
    last_seen = models.DateTimeField(auto_now=True)
    response_time = models.IntegerField(blank=True, null=True)
    vulnerabilities = models.TextField(blank=True, null=True)
    reseau_uid = models.UUIDField(default=uuid.uuid4, editable=False)

    def __str__(self):
        return f"{self.hostname} ({self.ip_address})"


class Alert(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Faible'),
        ('medium', 'Moyenne'),
        ('high', 'Élevée'),
        ('critical', 'Critique'),
    ]

    ALERT_TYPE_CHOICES = [
        ('scan', 'Scan'),
        ('attaque', 'Attaque'),
        ('autre', 'Autre'),
    ]

    SOURCE_CHOICES = [
        ('automatique', 'Automatique'),
        ('manuelle', 'Manuelle'),
    ]

    device = models.ForeignKey('Device', on_delete=models.SET_NULL, null=True, blank=True)
    src_ip = models.GenericIPAddressField(null=True, blank=True)
    dest_ip = models.GenericIPAddressField(null=True, blank=True)
    protocol = models.CharField(max_length=20, blank=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    signature = models.CharField(max_length=255)
    category = models.CharField(max_length=255, blank=True)
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPE_CHOICES, default='autre')
    description = models.TextField(blank=True)
    detected_on = models.DateTimeField(default=timezone.now)
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES, default='automatique')
    is_resolved = models.BooleanField(default=False)
    titre = models.CharField(max_length=255, default="Alerte de sécurité")
    is_email_sent = models.BooleanField(default=False)
    is_sms_sent = models.BooleanField(default=False)
    is_read = models.BooleanField(default=False)
    ia_analysis = models.TextField(blank=True, null=True,
                                   help_text="Explication intelligente de l'alerte et recommandation IA")
    reseau_uid = models.UUIDField(default=uuid.uuid4, editable=False)

    def __str__(self):
        return f"{self.titre} {self.source.upper()} {self.severity.upper()} - {self.signature}"


class Log(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    event = models.TextField()
    scanned_by = models.ForeignKey(User, on_delete=models.CASCADE)
    scan_time = models.DateTimeField(auto_now_add=True)
    reseau_uid = models.UUIDField(default=uuid.uuid4, editable=False)

    def __str__(self):
        return f"{self.device.hostname} - {self.scan_time}"


class TrafficLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    protocol = models.CharField(max_length=20)
    src_port = models.IntegerField(null=True, blank=True)
    dst_port = models.IntegerField(null=True, blank=True)
    length = models.IntegerField()
    info = models.TextField(blank=True, null=True)
    alert_linked = models.ForeignKey(Alert, null=True, blank=True, on_delete=models.SET_NULL)
    reseau_uid = models.UUIDField(default=uuid.uuid4, editable=False)

    def __str__(self):
        return f"{self.timestamp} - {self.src_ip} → {self.dst_ip} ({self.protocol})"


class Notification(models.Model):
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    reseau_uid = models.UUIDField(default=uuid.uuid4, editable=False)

    def __str__(self):
        return self.message

class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField()
    reason = models.CharField(max_length=255)
    blocked_on = models.DateTimeField(auto_now_add=True)
    alert = models.ForeignKey(Alert, on_delete=models.SET_NULL, null=True, blank=True)
    reseau_uid = models.UUIDField(default=uuid.uuid4, editable=False)

    def __str__(self):
        return self.ip_address

class HoneypotLog(models.Model):
    ip_address = models.GenericIPAddressField()
    port = models.IntegerField()
    service = models.CharField(max_length=100)
    message_sent = models.TextField()
    detected_on = models.DateTimeField(auto_now_add=True)
    reseau_uid = models.UUIDField(default=uuid.uuid4, editable=False)

    def __str__(self):
        return f"{self.service} | {self.ip_address} @ {self.detected_on}"


class DeviceEvent(models.Model):
    EVENT_TYPE_CHOICES = [
        ('connection',   'Connexion'),
        ('disconnection','Déconnexion'),
        ('scan',         'Scan'),
        ('alert',        'Alerte'),

    ]

    id          = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device      = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='events')
    event_type  = models.CharField(max_length=20, choices=EVENT_TYPE_CHOICES)
    description = models.TextField()
    ip_address  = models.GenericIPAddressField()
    timestamp   = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.get_event_type_display()}] {self.device.hostname} @ {self.timestamp:%Y-%m-%d %H:%M}"
