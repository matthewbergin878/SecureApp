from django.urls import path

from . import views

urlpatterns = [
    path('ssrf/', views.ssrf, name='ssrf'),
    path('internal/', views.internal, name='internal'),
]