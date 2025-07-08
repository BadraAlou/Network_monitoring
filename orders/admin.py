
from django.contrib import admin
from .models import Abonnement , Paiement, MessageContact
from app.models import Version


@admin.register(Abonnement)
class AbonnementAdmin(admin.ModelAdmin):
    list_display = ('user', 'version', 'date_debut', 'date_fin', 'actif', 'licence')
    list_filter = ('version', 'actif', 'date_fin')
    search_fields = ('user__username', 'licence')
    readonly_fields = ('licence', 'date_debut')

@admin.register(Version)
class VersionAdmin(admin.ModelAdmin):
    list_display = ('nom', 'prix')

@admin.register(Paiement)
class PaiementAdmin(admin.ModelAdmin):
    list_display = ('nom_complet', 'entreprise', 'telephone', 'version_slug')


@admin.register(MessageContact)
class MessageContactAdmin(admin.ModelAdmin):
    list_display = ('nom','email', 'entreprise', 'telephone', 'sujet', 'date_reception', 'traite')