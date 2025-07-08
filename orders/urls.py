from django.urls import path
from . import views

app_name = 'orders'

urlpatterns = [

    path('create/', views.create_order, name='create'),
    path('confirm/<int:pk>/', views.confirm_order, name='confirm'),

    path('stripe/webhook/', views.stripe_webhook, name='stripe_webhook'),

    path('payer/', views.stripe_checkout_view, name='stripe_checkout'),
    path('paiement/success/', views.paiement_success, name='paiement_success'),
    path('paiement/annule/', views.paiement_cancel, name='paiement_cancel'),
]
