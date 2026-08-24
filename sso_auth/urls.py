from django.urls import path
from . import views

app_name = 'sso'

urlpatterns = [
    # Management URLs
    path('management/', views.SSOManagementView.as_view(), name='management'),
    path('create/', views.create_sso_provider, name='create_provider'),
    path('edit/<int:provider_id>/', views.edit_sso_provider, name='edit_provider'),
    path('delete/<int:provider_id>/', views.delete_sso_provider, name='delete_provider'),
    path('test/<int:provider_id>/', views.test_sso_provider, name='test_provider'),
    
    # API endpoints
    path('api/provider/<int:provider_id>/', views.get_provider_details, name='provider_details'),
    path('api/provider/<int:provider_id>/logs/', views.get_audit_logs, name='provider_logs'),
    
    # SAML URLs
    path('saml/login/', views.saml_login, name='saml_login'),
    path('saml/login/<str:provider_name>/', views.saml_login, name='saml_login_named'),
    path('saml/acs/', views.saml_acs, name='saml_acs'),
    path('saml/acs/<str:provider_name>/', views.saml_acs, name='saml_acs_named'),
    path('saml/logout/', views.saml_logout, name='saml_logout'),
    path('saml/logout/<str:provider_name>/', views.saml_logout, name='saml_logout_named'),
    path('saml/metadata/', views.saml_metadata, name='saml_metadata'),
    path('saml/metadata/<str:provider_name>/', views.saml_metadata, name='saml_metadata_named'),
    
    # OIDC URLs
    path('oidc/login/', views.oidc_login, name='oidc_login'),
    path('oidc/login/<str:provider_name>/', views.oidc_login, name='oidc_login_named'),
    path('oidc/callback/<str:provider_name>/', views.oidc_callback, name='oidc_callback'),
    
    # Dynamic SSO URLs
    path('login/', views.dynamic_sso_login, name='dynamic_sso_login'),
    path('api/providers/', views.get_sso_providers_json, name='sso_providers_api'),
]
