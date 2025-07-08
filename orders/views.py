from django.shortcuts import render, redirect, get_object_or_404
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.utils.timezone import now, timedelta
from app.models import Version
import stripe
from django.contrib import messages
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse

from django.utils import timezone
from datetime import timedelta
from orders.models import Paiement
from app.models import Version
from orders.models import Abonnement
from django.utils import timezone
from datetime import date
from django.http import HttpResponse


stripe.api_key = settings.STRIPE_SECRET_KEY

@login_required
@csrf_exempt
def stripe_checkout_view(request):
    if request.method == 'POST':
        version_slug = request.POST.get('version')
        nom = request.POST.get('nom')
        entreprise = request.POST.get('entreprise')
        email = request.POST.get('email')
        telephone = request.POST.get('telephone')

        # Exemple de tarif par version
        prix_versions = {
            'dome': 200000,
            'aegis_sec': 150000,
            'black_vault': 250000,
        }
        montant = prix_versions.get(version_slug) * 1  # en centimes XOF

        paiement = Paiement.objects.create(
            user=request.user,
            nom_complet=nom,
            entreprise=entreprise,
            email=email,
            telephone=telephone,
            version_slug=version_slug,
            montant=montant
        )

        success_url = request.build_absolute_uri(reverse('orders:paiement_success'))
        cancel_url = request.build_absolute_uri(reverse('orders:paiement_cancel'))

        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            customer_email=email,
            line_items=[{
                'price_data': {
                    'currency': 'xof',
                    'product_data': {
                        'name': f"Licence 2IEM Security - {version_slug.upper()}",
                    },
                    'unit_amount': montant,
                },
                'quantity': 1,
            }],
            mode='payment',

            success_url=success_url,
            cancel_url=cancel_url,
        )

        paiement.stripe_session_id = session.id
        paiement.save()

        return redirect(session.url, code=303)
    else:
        return render(request, 'paiement/checkout_error.html')


@login_required
def paiement_success(request):
    # Récupérer le dernier paiement de l'utilisateur
    paiement = Paiement.objects.filter(user=request.user).order_by('-created_at').first()

    if paiement:
        version_nom = paiement.version_slug
        try:
            version = Version.objects.get(nom=version_nom)

            # Supprimer anciens abonnements
            Abonnement.objects.filter(user=request.user).delete()

            # Créer un abonnement payé
            abonnement = Abonnement.objects.create(
                user=request.user,
                version=version,
                date_fin=timezone.now() + timedelta(days=90),
                est_paye=True,
                actif=True
            )

            # Rediriger selon la version achetée
            if version.nom == 'aegis_sec':
                return redirect('theme:dashboard')
            elif version.nom == 'dome':
                return redirect('theme:dashboard')
            elif version.nom == 'black_vault':
                return redirect('theme:dashboard')
        except Version.DoesNotExist:
            pass

    return redirect('theme:dashboard')  # Fallback


def paiement_cancel(request):
    return render(request, 'pages/checkout_error.html')



@csrf_exempt
def stripe_webhook(request):
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
    endpoint_secret = settings.STRIPE_WEBHOOK_SECRET

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except ValueError:
        return HttpResponse(status=400)
    except stripe.error.SignatureVerificationError:
        return HttpResponse(status=400)

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        paiement = Paiement.objects.filter(stripe_session_id=session.get("id")).first()
        if paiement:
            paiement.statut = 'paye'
            paiement.save()

            # Création/activation de l’abonnement
            version = Version.objects.get(nom=paiement.version_slug)
            Abonnement.objects.update_or_create(
                user=paiement.user,
                defaults={
                    'version': version,
                    'date_fin': now() + timedelta(days=90),
                    'actif': True,
                }
            )

    return HttpResponse(status=200)






def create_order(request):
    # formulaire, création d’Order, génération de LicenseKey, redirection vers confirm
    return render(request, 'orders/create.html', {...})

def confirm_order(request, pk):
    order = get_object_or_404(Order, pk=pk)
    # afficher page de confirmation / facture
    return render(request, 'orders/confirm.html', {'order': order})


