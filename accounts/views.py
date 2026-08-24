# ============================================================================
#                      DJANGO CORE IMPORTS
# ============================================================================
from django.shortcuts import render, get_object_or_404, redirect # For handling shortcuts for views
from django.contrib.auth.views import redirect_to_login # For redirecting unauthorized users to the login page
from django.urls import reverse # For handling url reversals
from django.http import JsonResponse # For creating HTTP responses (including JSON)
from django.views import View # Base class for generic views
from django.contrib.auth import authenticate # For handling authentication related tasks
from django.conf import settings # To access the application settings
from django.contrib.auth.decorators import login_required # For views that need authentication

# ============================================================================
#                  GENERAL UTILITIES
# ============================================================================
import logging # To log errors
import uuid as uuid_lib  # To generate UUIDs for unique identifiers
import json # To handle JSON data


# ============================================================================
#                     AUTHENTICATION AND MODELS
# ============================================================================
from django.contrib.auth.models import User  # User model
from .models import UserProfile  # Import UserProfile model
from django.contrib.auth.mixins import LoginRequiredMixin  # For view access checks
from django.contrib.auth.hashers import make_password  # Hash the password

# ============================================================================
#                    REST API IMPORTS
# ============================================================================
# REST API imports
from rest_framework.decorators import api_view  # For API view decorators
from rest_framework.response import Response # To create responses for REST API calls

import requests #used to make HTTP requests


logger = logging.getLogger(__name__)  # Logger object



class UserProfileView(LoginRequiredMixin, View):
    """
    View to render the user profile page.

    Retrieves the logged-in user's profile and passes both
    user and profile information to the template.
    """
    def get(self, request):
        loggedin_user = get_object_or_404(User, id=request.user.id)
        loggedin_user_profile = get_object_or_404(UserProfile, user=request.user)
        
        context = {
            'user': loggedin_user,
            'profile': loggedin_user_profile
        }
        return render(request, "pages/user-profile/profile.html",context)
    
    
class UserProfileSettingView(LoginRequiredMixin,View):
    """
    View to render the user profile settings page.
    
    Retrieves the logged-in user information and sends it to the
    template to display the User Profile Setting Page.
    """
    def get(self, request):
        loggedin_user = get_object_or_404(User, id=request.user.id)
       
        context = {
            'user': loggedin_user,
        }
        return render(request, "pages/user-profile/user-profile-setting.html",context)

class UserProfileUpdateView(LoginRequiredMixin, View):
    """
    View to handle updates to the user profile information
    """
    def post(self, request):
        user = request.user
        profile = user.profile

        try:
            # Update user fields
            user.first_name = request.POST.get("first_name", user.first_name)
            user.last_name = request.POST.get("last_name", user.last_name)
            user.save()

            # Update profile fields
            profile.address = request.POST.get("address", profile.address)
            profile.contact_phone = request.POST.get("contact_phone", profile.contact_phone)
            profile.designation = request.POST.get("designation", profile.designation)
            profile.company = request.POST.get("company", profile.company)

            # Handle avatar upload or removal
            if "avatar" in request.FILES:
                profile.avatar = request.FILES["avatar"]
            elif request.POST.get("avatar_remove") == "true":
                profile.avatar.delete(save=False)  # Remove file from storage
                profile.avatar = "avatars/blank.png"

            profile.save()

            return JsonResponse({"status": "success", "message": "Profile updated successfully."})
        except Exception:
            logger.warning('Profile update failed.')
            return JsonResponse({"status": "error", "message": "Profile update failed."}, status=500)
