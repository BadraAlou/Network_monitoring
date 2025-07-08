from django.shortcuts import render, redirect
from django.views.decorators.http import require_http_methods
from django.conf import settings
from django.core.mail import send_mail
import uuid
import requests
from django.conf import settings
from django.contrib.auth.decorators import login_required
from datetime import timedelta, date

from django.utils import timezone
from django.contrib import messages

from orders.models import Abonnement
from app.models import Version
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.utils.timezone import now

from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model


from django.contrib.auth import get_user_model

from datetime import timedelta
from django.utils import timezone
from django.contrib.auth import login, logout
from django.contrib.auth.views import LoginView
from django.urls import reverse_lazy
from .forms import CustomUserCreationForm

User = get_user_model()
from django.utils.crypto import get_random_string
from django.db import IntegrityError

import threading
import time


def envoyer_email_licence(user, abonnement):
    sujet = f"Votre licence 2IEM Security – {abonnement.version.get_nom_display()}"
    message = f"""
Bonjour {user.username},

Merci d’avoir choisi 2IEM Security !

Voici votre clé de licence pour la version {abonnement.version.get_nom_display()} :

     {abonnement.licence}

Date de début : {abonnement.date_debut.strftime('%d/%m/%Y')}
Date d’expiration : {abonnement.date_expiration.strftime('%d/%m/%Y')}

Gardez cette clé précieusement. Si vous ne l’avez pas encore activée 
vous pouvez l’activer à tout moment via le lien suivant :
http://127.0.0.1:8000/activer-licence/

Cordialement,  
L’équipe 2IEM Security.
    """

    send_mail(
        sujet,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )


def envoyer_licence_apres_3_minutes(email):
    def attente_et_envoi():
        try:
            user = User.objects.get(email=email)
            abonnement = Abonnement.objects.get(user=user, actif=True)

            if abonnement.licence:
                time.sleep(180)  # 3 minutes
                envoyer_email_licence(user, abonnement)
        except Exception as e:
            print(f"[ERREUR ENVOI LICENCE] {e}")

    threading.Thread(target=attente_et_envoi).start()
def home(request):
    return render(request, 'pages/home.html')

def fonctionnalites(request):
    return render(request, 'pages/fonctionnalites.html')


def versions(request):
    # Cartes Mobiles
    mobile_features = [
        'Protection DoS/DDoS',
        'Blocage automatique IP',
        'Alertes PDF/Email/SMS',
        'Tableau de bord avancé',
        'Support 24h/24',
        'API complète',
    ]
    dome_features = [
        ('Protection DoS/DDoS', True),
        ('Blocage automatique IP', False),
        ('Alertes PDF/Email/SMS', True),
        ('Tableau de bord standard', True),
        ('Support email', True),
        ('API limitée', False),
    ]
    vault_features = [
        ('Protection DoS/DDoS', False),
        ('Blocage automatique IP', False),
        ('Alertes PDF/Email/SMS', True),
        ('Tableau de bord basique', True),
        ('Support email', True),
        ('Pas d’API', False),
    ]

    # Tableau Desktop
    compare_rows = [
        ('Protection DoS/DDoS',            True,   True,    False),
        ("Blocage automatique d'IP",       True,   False,   False),
        ('Alertes PDF des incidents',      True,   True,    True),
        ('Notifications Email',            True,   True,    True),
        ('Alertes SMS',                    True,   True,    True),
        ('Tableau de bord',                'Avancé','Standard','Basique'),
        ('Support technique',              '7j/7', 'Email',  'Email'),
        ("API d'intégration",              True,   True,    False),
        ('Surveillance en temps réel',     '24/24', 'Limitée','Basique'),
    ]

    # FAQ
    faqs = [
        ("Quelle version choisir pour débuter ?",
         "Nous recommandons  Dome pour commencer : toutes les fonctionnalités essentielles à prix doux."),
        ("Puis-je changer de version après l'achat ?",
         "Oui : passez à une version supérieure à tout moment via votre espace client."),
        ("Le support est-il inclus ?",
         "Aegis Sec et Dôme bénéficient d’un support email. Black Vault ajoute un support téléphonique 24h/24."),
        ("Comment activer ma licence ?",
         "Après achat, vous recevez votre clé par email. Activez-la dans votre tableau de bord sécurisé."),
    ]

    return render(request, 'pages/versions.html', {
        'mobile_features': mobile_features,
        'dome_features': dome_features,
        'vault_features': vault_features,
        'compare_rows': compare_rows,
        'faqs': faqs,
    })

@require_http_methods(["GET", "POST"])
def acheter(request):
    versions = [
        {'slug': 'black-vault', 'name': 'Black Vault', 'desc': 'Protection de base', 'price': 250000, 'accent': 'blue', 'popular': False},
        {'slug': 'dome', 'name': 'Dôme', 'desc': 'Protection équilibrée', 'price': 200000, 'accent': 'orange', 'popular': True},
        {'slug': 'aegis-sec', 'name': 'Aegis Sec', 'desc': 'Protection complète', 'price': 150000, 'accent': 'gray', 'popular': False},
    ]

    payment_methods = [
        {'method': 'orange-money', 'title': 'Orange Money', 'subtitle': 'Paiement mobile sécurisé', 'accent': 'orange'},
        {'method': 'virement', 'title': 'Virement bancaire', 'subtitle': 'Par banque', 'accent': 'blue'},
    ]

    if request.method == 'POST':
        version_slug = request.POST.get('version')
        nom = request.POST.get('nom')
        email = request.POST.get('email')
        telephone = request.POST.get('telephone')
        entreprise = request.POST.get('entreprise', '')
        payment_method = request.POST.get('payment')

        version_info = next((v for v in versions if v['slug'] == version_slug), None)
        if not version_info:
            return render(request, 'pages/acheter.html', {
                'versions': versions,
                'payment_methods': payment_methods,
                'erreur': "Version invalide sélectionnée."
            })


        version_obj = Version.objects.get(nom__icontains=version_slug.replace("-", "_"))
        Abonnement.objects.create(
            user=request.user,
            version=version_obj,
            date_debut=timezone.now(),
            date_fin=timezone.now() + timezone.timedelta(days=90),  # Abonnement trimestriel
            actif=True,
            transaction_id=str(uuid.uuid4())
        )

        # Période d'abonnement de 3 mois
        date_debut = timezone.now()
        date_fin = date_debut + timedelta(days=90)

        # Récupérer ou créer l’abonnement
        abonnement, created = Abonnement.objects.update_or_create(
            user=request.user,
            defaults={
                'version': version_obj,
                'date_debut': date_debut,
                'date_fin': date_fin,
                'actif': True
            }
        )

        messages.success(request, "Paiement fictif effectué avec succès. Abonnement activé !")
        return redirect('theme:dashboard_access')  # Redirige vers ta page dashboard


    return render(request, 'pages/acheter.html', {
        'versions': versions,
        'payment_methods': payment_methods,
    })

from orders.models import MessageContact

@require_http_methods(["GET", "POST"])
def contact_view(request):
    if request.method == 'POST':
        nom = request.POST.get('nom')
        entreprise = request.POST.get('entreprise', '')
        email = request.POST.get('email')
        telephone = request.POST.get('telephone', '')
        sujet = request.POST.get('sujet')
        message = request.POST.get('message')

        if nom and email and sujet and message:
            # 1. Enregistrer dans la base de données
            MessageContact.objects.create(
                nom=nom,
                entreprise=entreprise,
                email=email,
                telephone=telephone,
                sujet=sujet,
                message=message
            )

            # 2. Envoyer le message à l'équipe 2IEM
            sujet_email = f"2IEM Security – Contact {sujet}"
            corps_message = f"""
            Nouveau message de contact :

            Nom complet : {nom}
            Entreprise : {entreprise or 'Non renseignée'}
            Email : {email}
            Téléphone : {telephone or 'Non renseigné'}
            Sujet : {sujet}

            Message :
            {message}
            """

            send_mail(
                subject=sujet_email,
                message=corps_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=['contact@2iemsecurity.com', 'support@2iemsecurity.com'],
                fail_silently=False,
            )

            # 3. (Optionnel) Envoyer une réponse automatique de confirmation à l'utilisateur
            confirmation = f"""
            Bonjour {nom},

            Nous avons bien reçu votre message concernant "{sujet}".
            Notre équipe vous répondra dans les plus brefs délais.

            Voici un résumé de votre demande :
            — Message : {message}

            Merci de votre confiance,
            — L’équipe 2IEM Security
            """
            send_mail(
                subject="Votre message a bien été reçu – 2IEM Security",
                message=confirmation,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )

            if sujet.strip().lower() == 'licence':
                envoyer_licence_apres_3_minutes(email)

            return render(request, 'pages/contact.html', {'success': True})

    return render(request, 'pages/contact.html')


def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)

            try:
                version_essai = Version.objects.get(nom='dome')  # Version moyenne offerte

                # Supprimer un abonnement existant pour cet utilisateur (évite les doublons)
                Abonnement.objects.filter(user=user).delete()

                # Créer un nouvel abonnement
                abonnement = Abonnement.objects.create(
                    user=user,
                    version=version_essai,
                    date_fin=timezone.now() + timedelta(days=30),
                    actif=True
                )
                abonnement.save()  # La licence est générée dans save()
                envoyer_email_licence(user, abonnement)

            except Version.DoesNotExist:
                print("❌ La version d'essai 'dome' n'existe pas !")
            except IntegrityError as e:
                print(f"❌ Erreur d'intégrité : {e}")

            return redirect('theme:network_selection')
    else:
        form = CustomUserCreationForm()

    return render(request, 'pages/register.html', {'form': form})


class CustomLoginView(LoginView):
    template_name = 'pages/login.html'
    redirect_authenticated_user = True

    def get_success_url(self):
        return reverse_lazy('theme:network_selection')


def logout_view(request):
    logout(request)
    return redirect('pages:home')

User = get_user_model()
def activer_licence(request):
    success = False
    error = None
    activated_product = None
    tips = [
        {"title": "Email de confirmation", "text": "Vérifiez votre boîte mail utilisée lors de l'achat.", "icon": "M5 13l4 4L19 7", "color": "indigo"},
        {"title": "Support technique", "text": "Contactez-nous si vous avez perdu votre clé.", "icon": "M6 18L18 6M6 6l12 12", "color": "red"}
    ]

    if request.method == 'POST':
        licence_key = request.POST.get('license_key')
        email = request.POST.get('email')

        try:
            abonnement = Abonnement.objects.select_related('user', 'version').get(licence=licence_key)

            if abonnement.user.email != email:
                error = "L’adresse email ne correspond pas à cette licence."
            elif not abonnement.actif:
                abonnement.actif = True
                abonnement.date_expiration = now().date() + timedelta(days=90)
                abonnement.save()
                success = True
                activated_product = abonnement.version.get_nom_display()
            else:
                success = True
                activated_product = abonnement.version.get_nom_display()

        except Abonnement.DoesNotExist:
            error = "Clé de licence invalide. Veuillez réessayer."

    return render(request, 'pages/activation.html', {
        'success': success,
        'error': error,
        'activated_product': activated_product,
        'tips': tips
    })

