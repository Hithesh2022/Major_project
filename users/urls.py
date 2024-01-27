from django.urls import path

from . import views

urlpatterns = [
    path("hello/", views.index, name="index"),
    path("register/", views.user_register, name="user_register"),
    path("login/", views.user_login, name="user_login"),
]