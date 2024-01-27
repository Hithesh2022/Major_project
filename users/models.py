from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from django.apps import AppConfig

class CustomUser(AbstractUser):
    phone = models.CharField(max_length=15, blank=True)
    address = models.CharField(max_length=255, blank=True)
    first_name = None
    last_name = None
    def clean(self):
        super().clean()
        password = self.password
        # Add your custom password validation logic here
        if len(password) < 6:
            raise ValidationError(_("Password must be at least 6 characters long."))

    # Provide unique related_name for groups and user_permissions
    groups = models.ManyToManyField(
        "auth.Group",
        related_name="custom_user_groups",
        blank=True,
        help_text="The groups this user belongs to. A user will get all permissions granted to each of their groups.",
    )
    user_permissions = models.ManyToManyField(
        "auth.Permission",
        related_name="custom_user_permissions",
        blank=True,
        help_text="Specific permissions for this user.",
        verbose_name="user permissions",
    )

class CustomUserConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'
    verbose_name = 'Users'
