from django.contrib import admin
from django import forms
from .models import UserProfile
from core.image_upload_validation import validate_branding_image


class UserProfileAdminForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = '__all__'

    def clean_avatar(self):
        return validate_branding_image(self.cleaned_data.get('avatar'))


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    form = UserProfileAdminForm
