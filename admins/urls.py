# users/urls.py

from django.urls import path
from . import views

urlpatterns = [
    path("login/",views.admin_login, name='admin_login'),
     #path("hello/", views.index, name="index"),
    # Add other URL patterns as needed
]
