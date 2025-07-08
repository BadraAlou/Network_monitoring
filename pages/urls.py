
from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LoginView, LogoutView

app_name = "pages"

urlpatterns = [
    path("", views.home, name='home'),
    path('fonctionnalites/', views.fonctionnalites, name='fonctionnalites'),
    path('versions/', views.versions, name='versions'),
    path('acheter/', views.acheter, name='acheter'),
    path('activer-licence/', views.activer_licence, name='activer_licence'),
    path('contact/', views.contact_view, name='contact'),

    path('register/', views.register, name='register'),
    path('login/', views.CustomLoginView.as_view(), name='login'),
    path('logout/', views.logout_view, name='logout'),


]