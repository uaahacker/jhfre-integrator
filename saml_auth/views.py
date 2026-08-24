from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth import login, logout
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.utils.http import url_has_allowed_host_and_scheme
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from core.saml.settings import SAML_SETTINGS

from onelogin.saml2.auth import OneLogin_Saml2_Auth
# from core.saml.utils import get_saml_settings
from django.contrib.auth import get_user_model
# Import our dynamic function
from .utils import get_saml_settings

from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
import logging

logger = logging.getLogger(__name__)


###############################
# Utility function to prepare Django request for SAML
###############################
def prepare_django_request(request):
    return {
        'https': 'on' if request.is_secure() else 'off',
        'http_host': request.get_host(),
        'script_name': request.path,
        'server_port': request.META['SERVER_PORT'],
        'get_data': request.GET.copy(),
        'post_data': request.POST.copy()
    }
    
###############################
# SAML Metadata
###############################
@csrf_exempt
def saml_metadata(request):
    saml_settings_dict = get_saml_settings()
    if not saml_settings_dict:
        return HttpResponse("SAML is disabled or not configured.", status=404)

    try:
        saml_settings = OneLogin_Saml2_Settings(settings=saml_settings_dict)
    except Exception:
        logger.warning('Legacy SAML metadata loading failed.')
        return HttpResponse('SAML metadata is unavailable.', status=500)
    
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)

    if len(errors) == 0:
        return HttpResponse(metadata, content_type='text/xml')
    else:
        logger.warning('Legacy SAML metadata validation failed.')
        return HttpResponse('SAML metadata is unavailable.', status=500)


###############################
# SAML Login
###############################
@csrf_exempt
def saml_login(request):
    saml_settings_dict = get_saml_settings()
    
    # If no config or disabled, fallback to normal (default) login URL
    if not saml_settings_dict:
        return redirect('login')
    
    req = prepare_django_request(request)
    auth = OneLogin_Saml2_Auth(req, old_settings=saml_settings_dict)

    next_url = request.GET.get('next')
    if not next_url or not url_has_allowed_host_and_scheme(
        url=next_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure()
    ):
        next_url = reverse('home')
        
    full_return_url = request.build_absolute_uri(next_url)

    login_url = auth.login(return_to=full_return_url)
    return redirect(login_url)



###############################
# SAML ACS
###############################
@csrf_exempt
def saml_acs(request):
    req = prepare_django_request(request)
    saml_settings_dict = get_saml_settings()
    auth = OneLogin_Saml2_Auth(req, old_settings=saml_settings_dict)
    auth.process_response()
    errors = auth.get_errors()
    if len(errors) == 0 and auth.is_authenticated():
        user = authenticate_saml_user(auth)
        if user:
            user.backend = 'django.contrib.auth.backends.ModelBackend'
            login(request, user)

            relay_state = request.POST.get('RelayState')
            if relay_state and url_has_allowed_host_and_scheme(relay_state, allowed_hosts={request.get_host()}):
                return redirect(relay_state)

            next_url = request.GET.get('next')
            if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
                 return redirect(next_url)
            return redirect(reverse('home'))
        else:
            logger.warning('Legacy SAML user authentication failed.')
            return HttpResponse("User authentication failed.", status=401)
    else:
        logger.warning('Legacy SAML response validation failed.')
        return HttpResponse('SAML authentication failed.', status=500)




###############################
# SAML Logout
###############################
@csrf_exempt
def saml_logout(request):
    req = prepare_django_request(request)
    saml_settings_dict = get_saml_settings()
    auth = OneLogin_Saml2_Auth(req, old_settings=saml_settings_dict)
    if 'SAMLResponse' in req['get_data']:
       # Process the logout response from the IdP
        auth.process_slo()
        errors = auth.get_errors()
        if len(errors) == 0:
             logout(request)
             logger.info('Legacy SAML logout completed.')
             return redirect('login')
        else:
             logger.warning('Legacy SAML logout response validation failed.')
             return HttpResponse('SAML logout failed.', status=500)

    # Otherwise, initiate the logout request
    name_id = request.session.get('_saml_nameid')

    if not name_id:
        logout(request)
        return redirect('login')  # Or where you want to redirect the user

    return_to = request.build_absolute_uri(reverse('login'))
    logout_url = auth.logout(
        name_id=name_id,  # Use the stored name_id
        name_id_format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        return_to=return_to
    )
    return redirect(logout_url)

###############################
# Helper function to authenticate the user
###############################
@csrf_exempt
def authenticate_saml_user(auth):
    user_data = auth.get_attributes()
    logger.warning('Legacy SAML authentication path invoked.')

    # Typically, Keycloak sends email in "urn:oid:1.2.840.113549.1.9.1" or "email"
    email = user_data.get('urn:oid:1.2.840.113549.1.9.1', [None])[0]
    if not email:
        # Fallback if Keycloak uses different attribute keys
        email = user_data.get('email', [None])[0]

    first_name = user_data.get('urn:oid:2.5.4.42', [None])[0]  # or user_data.get('givenName', [None])[0]
    last_name = user_data.get('urn:oid:2.5.4.4', [None])[0]    # or user_data.get('sn', [None])[0]

    if email:
        User = get_user_model()
        user, created = User.objects.get_or_create(
            username=email,
            defaults={
                'email': email,
                'first_name': first_name or '',
                'last_name': last_name or ''
            }
        )
        # Store the name ID in the session
       
        return user
    else:
        logger.warning('Legacy SAML response did not contain a usable email attribute.')
        return None

