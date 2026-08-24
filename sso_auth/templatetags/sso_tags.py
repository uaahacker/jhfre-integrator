from django import template
from django.urls import reverse
from sso_auth.models import SSOProvider

register = template.Library()

@register.simple_tag
def get_sso_login_url(next_url=None):
    """
    Get the appropriate SSO login URL for the single active provider.
    Returns the URL with optional next parameter.
    """
    # Get the single active provider
    provider = SSOProvider.objects.filter(enabled=True).first()
    
    if not provider:
        return None
    
    if provider.protocol == 'oidc':
        url_name = 'sso:oidc_login_named'
    elif provider.protocol == 'saml':
        url_name = 'sso:saml_login_named'
    else:
        return None
    
    base_url = reverse(url_name, kwargs={'provider_name': provider.name})
    
    if next_url:
        return f"{base_url}?next={next_url}"
    return base_url

@register.simple_tag
def get_active_sso_provider():
    """
    Get the single active SSO provider.
    """
    return SSOProvider.objects.filter(enabled=True).first()

@register.simple_tag
def has_active_sso_provider():
    """
    Check if there is an active SSO provider.
    """
    return SSOProvider.objects.filter(enabled=True).exists()
