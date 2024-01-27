from django.contrib import admin
from .models import CustomUser

class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'phone', 'address')
    search_fields = ('username', 'email', 'phone', 'address')
    readonly_fields = ('date_joined', 'last_login')

    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()

# Use site.register instead of admin.site.register
admin.site.register(CustomUser, CustomUserAdmin)
