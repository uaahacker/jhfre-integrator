from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.saml_login, name='saml_login'),
    path('acs/', views.saml_acs, name='saml_acs'),
    path('logout/', views.saml_logout, name='saml_logout'),
    path('metadata/', views.saml_metadata, name='saml_metadata'),
    
]
