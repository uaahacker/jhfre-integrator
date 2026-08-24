from django.db import models
import os
from os.path import join
from django.conf import settings
from django.templatetags.static import static
from django.contrib.auth.models import User



    
    

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    avatar = models.ImageField(
        upload_to="avatars/", 
        blank=True, 
        null=True, 
    )
    address = models.CharField(max_length=255, blank=True, null=True)
    designation = models.CharField(max_length=100, blank=True, null=True)
    company = models.CharField(max_length=255, blank=True, null=True)
    contact_phone = models.CharField(max_length=20, blank=True, null=True)
    company_site = models.URLField(blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    communication = models.CharField(max_length=50, blank=True, null=True)
    allow_changes = models.BooleanField(default=True)

    @property
    def avatar_url(self):
        if self.avatar and self.avatar.name:
            avatar_path = os.path.join(settings.MEDIA_ROOT, self.avatar.name)
            if os.path.exists(avatar_path):
                return f"{settings.MEDIA_URL}{self.avatar.name}"
        return static('assets/media/svg/avatars/blank.svg')

    def __str__(self):
        return self.user.username