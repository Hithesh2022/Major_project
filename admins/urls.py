# users/urls.py

from django.urls import path,re_path
from . import views

from django.conf import settings
from django.conf.urls.static import static

from django.urls import path
urlpatterns = [
    path("login/",views.admin_login, name='admin_login'),
    path("upload/",views.upload_file, name='admin_upload'),
    
     #path("hello/", views.index, name="index"),
    # Add other URL patterns as needed
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)