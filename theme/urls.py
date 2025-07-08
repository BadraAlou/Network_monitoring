from django.urls import path
from . import views
from . import wifi_api_views
from . import debug_views
from . import api_views
from . import block_unblock_views


app_name = "theme"

urlpatterns = [
    # Tableau de bord
    # path('accueil/', views.Index, name='index'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('licence/', views.licence_expiree, name='licence_expiree'),
    path('dashboard/access/', views.dashboard_redirect, name='dashboard_access'),
    path('choisir-version/', views.choisir_version, name='choisir_version'),
    path('notification/', views.notification_redirect, name='notification_redirect'),

    path('telecharger-dependances/', views.telecharger_dependances, name='telecharger_dependances'),


    # Ordinateurs
    path('ordinateurs/', views.liste_ordinateurs, name='liste_ordinateurs'),
    path('ordinateurs/<int:device_id>/', views.details_device, name='details_device'),
    path('scan_complet/<str:ip>/', views.lancer_scan_complet, name='lancer_scan_complet'),
    path('scan/', views.lancer_ping, name='lancer_ping'),

    # Logs
    path('logs/', views.liste_logs, name='liste_logs'),
    path('honeypot/', views.honeypots_view, name='honeypot'),
    path('twem/', views.historique_alertestwem, name='historique_alertestwem'),


    # Alertes
    path('alertes/', views.alert_list, name='alert_list'),
    path('alert/<int:pk>/verdict/', views.alert_verdict, name='alert_verdict'),
    path('historique-alertes/', views.historique_alertes, name='historique_alertes'),
    path('export-alertes/', views.exporter_alertes_pdf, name='exporter_alertes_pdf'),

    # Trafic réseau
    path('traffic/', views.liste_traffic, name='liste_traffic'),
    path('ajax/traffic/', views.get_latest_traffic, name='get_latest_traffic'),

    path('alert/<int:alert_id>/verdict/', views.get_alert_verdict, name='alert_verdict'),


    # Paramètres utilisateurs & admin
    path('parametres/', views.user_settings, name='parametres'),
    path('utilisateurs/', views.liste_utilisateurs, name='liste_utilisateurs'),

    #================================================================================

    # === GESTION DES IPS BLOQUÉES ===
    path('security/blocked-ips/', block_unblock_views.blocked_ips_view, name='blocked_ips'),
    path('security/unblock-ip/<int:ip_id>/', block_unblock_views.unblock_ip, name='unblock_ip'),
    path('security/unblock-multiple/', block_unblock_views.unblock_multiple_ips, name='unblock_multiple_ips'),
    path('security/auto-unblock/', block_unblock_views.auto_unblock_expired_ips, name='auto_unblock_expired'),
    path('security/block-ip-manual/', block_unblock_views.block_ip_manual, name='block_ip_manual'),

    # API pour dashboard temps réel
    path('api/blocked-ips/', block_unblock_views.blocked_ips_api, name='blocked_ips_api'),

    # path('blocked-ips/', views.blocked_ips_view, name='blocked_ips'),
    # path('ips-bloquees/debloquer/<int:ip_id>/', views.unblock_ip, name='unblock_ip'),


    #=====================================================================================

    path('networks/', wifi_api_views.network_selection_view, name='network_selection'),

    path('api/network-info/', api_views.network_info_api, name='network_info_api'),
    path('api/alerts/', api_views.alerts_api, name='alerts_api'),
    path('api/recent-events/', api_views.recent_events_api, name='recent_events_api'),
    path('geolocalisation/', views.geolocalisation, name='geolocalisation'),


    # # ... vos autres URLs
    # path('api/network-info/', views.network_info_api, name='network_info_api'),
    # path('api/refresh-network/', views.refresh_network_api, name='refresh_network_api'),
    #
    # path('networks/', views.network_selection_view, name='networks'),
    # path('api/scan-networks/', views.scan_networks_api, name='scan_api'),
    # path('api/connect-network/', views.connect_network_api, name='connect_api'),
    #
    # #=======================================================================================

    #
    # # Page de debug principale
    # path('debug/', debug_views.debug_network_view, name='debug_network'),
    # # APIs de debug
    # path('api/scan-networks/', debug_views.debug_scan_networks_api, name='debug_scan_networks_api'),
    # path('api/connect-network/', debug_views.debug_connect_network_api, name='debug_connect_network_api'),
    #
    # # Tests système
    # path('debug/system-test/', debug_views.debug_system_test, name='debug_system_test'),
    # path('debug/live-status/', debug_views.debug_live_status, name='debug_live_status'),

]
