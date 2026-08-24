from django.urls import path
from . import views
from .views import *

urlpatterns = [
    
    # Users add
    
    path('profile/', UserProfileView.as_view(), name='user_profile'),
    path('profile/setting/', UserProfileSettingView.as_view(), name='user_profile_setting'),
    path("profile/update/", UserProfileUpdateView.as_view(), name="user_profile_update"),
    
    
 

]
