
from django.contrib import admin
from django.urls import path , include
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    # pour le rechargement en développement
    path("__reload__/", include("django_browser_reload.urls")),

    # l’interface d’administration
    path("admin/", admin.site.urls),

    # toutes les theme statiques (home, acheter, activer, contact…)
    path("", include(("pages.urls", "pages"), namespace="pages")),

    # toutes les vues « système » (dashboard, API, etc.)
    path("systeme/", include(("theme.urls", "theme"), namespace="theme")),

    # toutes les commandee et à la génération de licences.
    path("orders/", include(("orders.urls", "orders"), namespace="orders")),

]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
