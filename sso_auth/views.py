import uuid
import secrets
import time
from functools import wraps
from urllib.parse import urlsplit
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout
from django.contrib.auth.views import redirect_to_login
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET
from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.contrib import messages
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.template import loader
from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin

# SAML imports
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

# Local imports
from .models import SAML_BINDING_HTTP_POST, SAML_BINDING_HTTP_REDIRECT, SSOProvider, SSOAuditLog, SSOUserProfile
from .utils import OIDCValidationError, SSOUtils, OIDCClient, get_client_ip
from .forms import SSOProviderForm
from .saml_replay import register_validated_assertion
from .saml_post_binding import SAMLPostBindingError, build_post_authn_request
from .saml_metadata_parser import SAMLMetadataError, parse_idp_metadata_xml

import logging
logger = logging.getLogger(__name__)

OIDC_STATE_LIFETIME_SECONDS = 600
OIDC_STATE_CLOCK_SKEW_SECONDS = 60
SAML_REQUEST_STATE_LIFETIME_SECONDS = 600
SAML_REQUEST_STATE_CLOCK_SKEW_SECONDS = 60


def _sanitize_saml_validation_category(errors=None, reason=None):
    """Map toolkit validation output to a fixed, non-sensitive log category."""
    text = ' '.join(str(value).lower() for value in (errors or []))
    if reason:
        text = f'{text} {str(reason).lower()}'

    category_markers = (
        ('schema', 'SAML_SCHEMA_VALIDATION_FAILED'),
        ('not match the saml-schema', 'SAML_SCHEMA_VALIDATION_FAILED'),
        ('assertion of the response is not signed', 'SAML_ASSERTION_SIGNATURE_MISSING'),
        ('message of the response is not signed', 'SAML_RESPONSE_SIGNATURE_MISSING'),
        ('not signed', 'SAML_RESPONSE_SIGNATURE_MISSING'),
        ('no signature found', 'SAML_RESPONSE_SIGNATURE_MISSING'),
        ('signature validation failed', 'SAML_SIGNATURE_INVALID'),
        ('certificate', 'SAML_CERTIFICATE_MISMATCH'),
        ('issuer', 'SAML_ISSUER_INVALID'),
        ('audience', 'SAML_AUDIENCE_INVALID'),
        ('destination', 'SAML_DESTINATION_INVALID'),
        ('inresponseto', 'SAML_INRESPONSETO_INVALID'),
        ('expired', 'SAML_ASSERTION_EXPIRED'),
        ('session_expired', 'SAML_ASSERTION_EXPIRED'),
    )
    for marker, category in category_markers:
        if marker in text:
            return category
    return 'SAML_TOOLKIT_ERROR'


def _extract_safe_request_metadata(request):
    """Extract safe request metadata for SAML failure diagnostics."""
    return {
        'scheme': request.scheme,
        'secure': request.is_secure(),
        'host': request.get_host(),
        'forwarded_proto': request.META.get('HTTP_X_FORWARDED_PROTO'),
        'forwarded_host': request.META.get('HTTP_X_FORWARDED_HOST'),
        'forwarded_port': request.META.get('HTTP_X_FORWARDED_PORT'),
        'path': request.path,
        'method': request.method,
    }


def _log_saml_failure(provider, stage, category, errors=None, reason=None, request=None, exc=None):
    """
    Log detailed SAML diagnostics including toolkit errors and request metadata.
    Does not log: SAMLResponse, assertions, credentials, cookies, certificates, private keys, RelayState.
    """
    log_parts = []
    if provider is not None:
        log_parts.append(f'provider_id={provider.pk}')
    log_parts.append(f'stage={stage}')
    log_parts.append(f'category={category}')
    if errors:
        safe_errors = [str(err).lower() for err in errors]
        log_parts.append(f'errors={safe_errors}')
    if reason:
        safe_reason = str(reason).lower()
        log_parts.append(f'reason="{safe_reason}"')
    if request:
        metadata = _extract_safe_request_metadata(request)
        for key, value in metadata.items():
            if value is not None:
                log_parts.append(f'{key}={value}')
    if exc:
        exc_class = exc.__class__.__name__
        exc_msg = str(exc)
        log_parts.append(f'exception={exc_class}')
        if exc_msg and exc_msg not in ('SAML response validation failed.', 'SAML assertion replay detected.', 'SAML persistent NameID policy validation failed.', 'SAML identity policy is disabled.'):
            log_parts.append(f'exception_msg="{exc_msg}"')
    log_message = 'SAML ACS validation failed ' + ' '.join(log_parts)
    logger.warning(log_message)


def superuser_json_required(view_func):
    """Apply the provider-management JSON authorization contract."""
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication required.'}, status=401)
        if not request.user.is_superuser:
            return JsonResponse({'detail': 'Administrative access required.'}, status=403)
        return view_func(request, *args, **kwargs)
    return wrapped_view


def superuser_required(view_func):
    """Restrict a browser view to Django superusers.

    Mirrors SuperuserRequiredMixin/AccessMixin's fail-closed behavior: an
    anonymous user is sent to login, but an already-authenticated user who
    fails the test gets 403 instead of being bounced back through login --
    bouncing them through login (as django.contrib.auth.decorators.user_passes_test
    does unconditionally) sends them right back to this same denial, looping forever.
    """
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect_to_login(request.get_full_path(), login_url=settings.LOGIN_URL)
        if not request.user.is_superuser:
            raise PermissionDenied
        return view_func(request, *args, **kwargs)
    return wrapped_view


def build_absolute_uri_with_https(request, path):
    """
    Build absolute URI with HTTPS for SSO callbacks in production.
    """
    uri = request.build_absolute_uri(path)
    
    # Force HTTPS in production or when SSO_FORCE_HTTPS is set
    if getattr(settings, 'SSO_FORCE_HTTPS', False) or not settings.DEBUG:
        uri = uri.replace('http://', 'https://', 1)
    
    return uri


class SSOManagementView(LoginRequiredMixin, UserPassesTestMixin, TemplateView):
    """
    Main SSO configuration management view.
    """
    template_name = 'sso_auth/management.html'
    login_url = '/login/'

    def test_func(self):
        return self.request.user.is_superuser

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['sso_providers'] = SSOProvider.objects.all().order_by('protocol', 'name')
        context['title'] = 'SSO Configuration Management'
        return context


def _metadata_prefilled_post_data(post_data, parsed):
    """Return a mutable copy of submitted POST data pre-filled from parsed IdP metadata.

    Nothing here touches the database; it only changes what the (unsaved) form will
    display so an operator can review before submitting normally.
    """
    data = post_data.copy()
    data['saml_idp_entity_id'] = parsed['entity_id']

    endpoints_by_binding = {}
    for endpoint in parsed['sso_endpoints']:
        if endpoint['binding'] == SAML_BINDING_HTTP_REDIRECT:
            endpoints_by_binding.setdefault('http_redirect', endpoint['url'])
        elif endpoint['binding'] == SAML_BINDING_HTTP_POST:
            endpoints_by_binding.setdefault('http_post', endpoint['url'])

    # Prefer Redirect when both are advertised: it preserves current default behavior.
    # An operator who wants POST can still switch the binding field and paste the
    # discovered POST URL shown in the confirmation message.
    for binding in ('http_redirect', 'http_post'):
        if binding in endpoints_by_binding:
            data['saml_idp_sso_binding'] = binding
            data['saml_idp_sso_url'] = endpoints_by_binding[binding]
            break

    if parsed['slo_endpoints']:
        data['saml_idp_slo_url'] = parsed['slo_endpoints'][0]['url']

    if parsed['certs']:
        data['saml_idp_x509cert'] = parsed['certs'][0]
        data['saml_idp_x509cert_additional'] = '\n\n'.join(parsed['certs'][1:])

    return data


def _handle_metadata_parse_request(request, *, instance, title, action):
    """Handle the "Parse Metadata" submit action shared by create/edit provider views.

    Returns a rendered HttpResponse when the request asked to parse metadata (whether
    parsing succeeded or failed), or None when the caller should continue its normal
    save/validate flow.
    """
    if 'parse_metadata' not in request.POST:
        return None

    try:
        parsed = parse_idp_metadata_xml(request.POST.get('metadata_xml', ''))
    except SAMLMetadataError as exc:
        form = SSOProviderForm(request.POST, instance=instance)
        form.add_error('metadata_xml', str(exc))
    else:
        form = SSOProviderForm(_metadata_prefilled_post_data(request.POST, parsed), instance=instance)
        endpoint_summary = ', '.join(
            f"{endpoint['binding'].rsplit(':', 1)[-1]}" for endpoint in parsed['sso_endpoints']
        )
        messages.info(
            request,
            f'Parsed metadata for entity ID "{parsed["entity_id"]}". Discovered SSO '
            f'binding(s): {endpoint_summary or "none"}; '
            f'{len(parsed["certs"])} signing certificate(s). Review the fields below, '
            'then submit to save the provider.',
        )

    return render(request, 'sso_auth/provider_form.html', {
        'form': form,
        'provider': instance,
        'title': title,
        'action': action,
    })


@superuser_required
def create_sso_provider(request):
    """Create a new SSO provider."""
    if request.method == 'POST':
        parse_response = _handle_metadata_parse_request(
            request, instance=None, title='Create SSO Provider', action='Create',
        )
        if parse_response is not None:
            return parse_response

        form = SSOProviderForm(request.POST)
        if form.is_valid():
            provider = form.save()

            # Log the configuration change
            SSOUtils.log_sso_event(
                provider=provider,
                event_type='config_change',
                user_identifier=request.user.username,
                details={'action': 'created'},
                request=request
            )

            messages.success(request, f'SSO Provider "{provider.name}" created successfully.')
            return redirect('sso:management')
    else:
        form = SSOProviderForm()

    return render(request, 'sso_auth/provider_form.html', {
        'form': form,
        'title': 'Create SSO Provider',
        'action': 'Create'
    })


@superuser_required
def edit_sso_provider(request, provider_id):
    """Edit an existing SSO provider."""
    provider = get_object_or_404(SSOProvider, id=provider_id)

    if request.method == 'POST':
        parse_response = _handle_metadata_parse_request(
            request, instance=provider, title=f'Edit {provider.name}', action='Update',
        )
        if parse_response is not None:
            return parse_response

        form = SSOProviderForm(request.POST, instance=provider)
        if form.is_valid():
            form.save()

            # Log the configuration change
            SSOUtils.log_sso_event(
                provider=provider,
                event_type='config_change',
                user_identifier=request.user.username,
                details={'action': 'updated'},
                request=request
            )

            messages.success(request, f'SSO Provider "{provider.name}" updated successfully.')
            return redirect('sso:management')
    else:
        form = SSOProviderForm(instance=provider)

    return render(request, 'sso_auth/provider_form.html', {
        'form': form,
        'provider': provider,
        'title': f'Edit {provider.name}',
        'action': 'Update'
    })


@superuser_required
@require_POST
def test_sso_provider(request, provider_id):
    """Test SSO provider connection."""
    provider = get_object_or_404(SSOProvider, id=provider_id)
    
    try:
        results = provider.test_connection()
        
        # Log the test
        SSOUtils.log_sso_event(
            provider=provider,
            event_type='test_connection',
            user_identifier=request.user.username,
            details={
                'success': bool(results.get('success')),
                'failure_category': results.get('failure_category'),
            },
            request=request
        )
        
        if results['success']:
            messages.success(request, f'Connection test for "{provider.name}" passed.')
        else:
            messages.error(request, f'Connection test for "{provider.name}" failed.')
            
    except Exception:
        messages.error(request, 'SSO connection test failed.')
        logger.warning('SSO provider test failed for provider_id=%s', provider.id)
    
    return redirect('sso:management')


@superuser_required
@require_POST
def delete_sso_provider(request, provider_id):
    """Delete an SSO provider."""
    provider = get_object_or_404(SSOProvider, id=provider_id)
    provider_name = provider.name
    provider.delete()
    
    messages.success(request, f'SSO Provider "{provider_name}" deleted successfully.')
    return redirect('sso:management')


# SAML Views
def prepare_django_request(request):
    """Prepare Django request for SAML processing."""
    scheme = 'https' if request.is_secure() else 'http'
    host = request.get_host()
    parsed_host = urlsplit(f'{scheme}://{host}')
    server_port = parsed_host.port or (443 if request.is_secure() else 80)
    return {
        'https': 'on' if request.is_secure() else 'off',
        'http_host': host,
        'script_name': request.path,
        'server_port': str(server_port),
        'get_data': request.GET.copy(),
        'post_data': request.POST.copy()
    }


@csrf_exempt
def saml_login(request, provider_name=None):
    """Initiate SAML login."""
    # Get provider
    if provider_name:
        provider = get_object_or_404(
            SSOProvider, 
            name=provider_name, 
            protocol='saml', 
            enabled=True,
            status='active',
        )
    else:
        provider = SSOProvider.get_active_provider('saml')
        if not provider:
            messages.error(request, 'No active SAML provider found.')
            return redirect('login')
    
    try:
        saml_settings = provider.get_saml_settings()
        next_url = request.GET.get('next', reverse('home'))
        if not url_has_allowed_host_and_scheme(
            url=next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()
        ):
            next_url = reverse('home')
        return_to = request.build_absolute_uri(next_url)

        if provider.saml_idp_sso_binding == 'http_post':
            post_request = build_post_authn_request(provider, saml_settings, return_to)
            request_id = post_request['request_id']
            response = render(request, 'sso_auth/saml_post_binding.html', {
                'sso_url': post_request['sso_url'],
                'saml_request': post_request['saml_request'],
                'relay_state': post_request['relay_state'],
            })
        else:
            auth = OneLogin_Saml2_Auth(prepare_django_request(request), old_settings=saml_settings)
            login_url = auth.login(return_to=return_to)
            request_id = auth.get_last_request_id()
            response = redirect(login_url)

        if not isinstance(request_id, str) or not request_id:
            raise ValueError('SAML AuthnRequest ID was not generated.')
        request.session['saml_authn_request_id'] = request_id
        request.session['saml_authn_provider_id'] = provider.pk
        request.session['saml_authn_started_at'] = time.time()
        request.session['saml_authn_next'] = next_url
        SSOUtils.log_sso_event(
            provider=provider, event_type='login_attempt', request=request
        )
        return response
    except Exception:
        logger.warning('SAML login initiation failed for provider_id=%s', provider.pk)
        messages.error(request, 'SAML authentication failed.')
        return redirect('login')


@csrf_exempt
def saml_acs(request, provider_name=None):
    """Handle SAML Assertion Consumer Service."""
    request_id = request.session.pop('saml_authn_request_id', None)
    session_provider_id = request.session.pop('saml_authn_provider_id', None)
    started_at = request.session.pop('saml_authn_started_at', None)
    next_url = request.session.pop('saml_authn_next', reverse('home'))
    provider = None
    stage = 'request_correlation'
    category = 'SAML_REQUEST_STATE_INVALID'
    try:
        if not isinstance(request_id, str) or not request_id or not isinstance(session_provider_id, int):
            raise ValueError('SAML request state is incomplete.')
        try:
            state_age = time.time() - float(started_at)
        except (TypeError, ValueError):
            raise ValueError('SAML request state timestamp is invalid.')
        if state_age < -SAML_REQUEST_STATE_CLOCK_SKEW_SECONDS or state_age > SAML_REQUEST_STATE_LIFETIME_SECONDS:
            raise ValueError('SAML request state has expired.')
        stage = 'provider_lookup'
        provider = SSOProvider.objects.get(
            pk=session_provider_id, protocol='saml', enabled=True, status='active'
        )
        if provider_name is not None and not secrets.compare_digest(provider_name, provider.name):
            raise ValueError('SAML callback provider does not match the request state.')
        stage = 'provider_settings'
        saml_settings = provider.get_saml_settings()
        stage = 'auth_construction'
        auth = OneLogin_Saml2_Auth(prepare_django_request(request), old_settings=saml_settings)
        stage = 'process_response'
        auth.process_response(request_id=request_id)
        stage = 'toolkit_errors'
        errors = auth.get_errors()
        try:
            reason = auth.get_last_error_reason()
        except AttributeError:
            reason = None
        if errors:
            category = _sanitize_saml_validation_category(errors, reason)
            _log_saml_failure(provider, stage, category, errors, reason, request)
            raise ValueError('SAML response validation failed.')
        stage = 'authentication_result'
        if not auth.is_authenticated():
            category = 'SAML_RESPONSE_INVALID'
            raise ValueError('SAML response validation failed.')
        stage = 'assertion_replay'
        if not register_validated_assertion(provider, auth.get_last_assertion_id()):
            category = 'SAML_ASSERTION_REPLAY'
            raise ValueError('SAML assertion replay detected.')
        stage = 'identity_policy'
        sso_id_field = SSOUserProfile._meta.get_field('sso_id')
        if provider.saml_identity_policy == 'persistent_nameid':
            nameid = auth.get_nameid()
            nameid_format = auth.get_nameid_format()
            persistent_format = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
            if (
                not isinstance(nameid, str) or not nameid.strip()
                or len(nameid) > sso_id_field.max_length
                or nameid_format != persistent_format
            ):
                category = 'SAML_NAMEID_INVALID'
                raise ValueError('SAML persistent NameID policy validation failed.')
            external_subject = nameid
        elif provider.saml_identity_policy == 'configured_immutable_attribute':
            attribute_values = auth.get_attributes().get(provider.saml_immutable_attribute_name)
            if isinstance(attribute_values, (list, tuple)):
                attribute_value = attribute_values[0] if attribute_values else None
            else:
                attribute_value = attribute_values
            if (
                not isinstance(attribute_value, str) or not attribute_value.strip()
                or len(attribute_value) > sso_id_field.max_length
            ):
                category = 'SAML_IDENTITY_ATTRIBUTE_INVALID'
                raise ValueError('SAML configured immutable attribute policy validation failed.')
            external_subject = attribute_value
        else:
            category = 'SAML_IDENTITY_POLICY_REJECTED'
            raise ValueError('SAML identity policy is disabled.')
        stage = 'provisioning'
        user = SSOUtils.create_or_update_user(
            provider, auth.get_attributes(), sso_id=external_subject,
            raw_attributes=auth.get_attributes(), require_verified_email=False,
        )
        if user is None:
            category = 'SAML_PROVISIONING_DENIED'
            raise ValueError('SAML registration was denied.')
        SSOUtils.log_sso_event(
            provider=provider, event_type='login_success', user_identifier=user.username,
            request=request,
        )
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(request, user)
        return redirect(next_url)
    except Exception as exc:
        if stage == 'request_correlation':
            category = 'SAML_REQUEST_STATE_INVALID'
        elif stage == 'provider_lookup':
            category = 'SAML_PROVIDER_LOOKUP_FAILED'
        elif stage == 'provider_settings':
            category = 'SAML_PROVIDER_SETTINGS_FAILED'
        elif stage == 'auth_construction':
            category = 'SAML_AUTH_CONSTRUCTION_FAILED'
        elif stage == 'process_response':
            category = 'SAML_RESPONSE_INVALID'
        elif stage == 'toolkit_errors' and category == 'SAML_REQUEST_STATE_INVALID':
            category = 'SAML_TOOLKIT_ERROR'
        if provider is not None:
            SSOUtils.log_sso_event(
                provider=provider, event_type='login_failure',
                details={'reason': 'saml_validation_failed'}, request=request,
            )
        _log_saml_failure(provider, stage, category, exc=exc, request=request)
    messages.error(request, 'SAML authentication failed.')
    return redirect('login')


@csrf_exempt
def saml_logout(request, provider_name=None):
    """Handle SAML logout."""
    # Get provider
    provider_name = provider_name or request.session.get('_saml_provider')
    if provider_name:
        provider = SSOProvider.objects.filter(
            name=provider_name, 
            protocol='saml', 
            enabled=True,
            status='active',
        ).first()
    else:
        provider = SSOProvider.get_active_provider('saml')
    
    if not provider:
        logout(request)
        return redirect('login')
    
    req = prepare_django_request(request)
    saml_settings = provider.get_saml_settings()
    auth = OneLogin_Saml2_Auth(req, old_settings=saml_settings)
    
    # Check if this is a logout response from IdP
    if 'SAMLResponse' in req['get_data']:
        auth.process_slo()
        errors = auth.get_errors()
        if len(errors) == 0:
            # Log logout
            SSOUtils.log_sso_event(
                provider=provider,
                event_type='logout',
                user_identifier=request.user.username if request.user.is_authenticated else None,
                request=request
            )
            logout(request)
            return redirect('login')
        else:
            messages.error(request, 'SAML logout failed.')
            return redirect('login')
    
    # Initiate logout request
    nameid = request.session.get('_saml_nameid')
    if not nameid:
        logout(request)
        return redirect('login')
    
    return_to = request.build_absolute_uri(reverse('login'))
    logout_url = auth.logout(
        name_id=nameid,
        name_id_format=provider.saml_name_id_format,
        return_to=return_to
    )
    
    return redirect(logout_url)


@csrf_exempt
def saml_metadata(request, provider_name=None):
    """Generate SAML metadata."""
    # Get provider
    if provider_name:
        provider = get_object_or_404(
            SSOProvider, 
            name=provider_name, 
            protocol='saml', 
            enabled=True,
            status='active',
        )
    else:
        provider = SSOProvider.get_active_provider('saml')
        if not provider:
            return HttpResponse("No active SAML provider found", status=404)
    
    try:
        saml_settings = provider.get_saml_settings()
        saml_settings_obj = OneLogin_Saml2_Settings(settings=saml_settings)
        metadata = saml_settings_obj.get_sp_metadata()
        errors = saml_settings_obj.validate_metadata(metadata)
        
        if len(errors) == 0:
            return HttpResponse(metadata, content_type='text/xml')
        else:
            logger.warning('SAML metadata validation failed for provider_id=%s', provider.id)
            return HttpResponse('SAML metadata is unavailable.', status=500)
    except Exception:
        logger.warning('Failed to generate SAML metadata for provider_id=%s', provider.id)
        return HttpResponse('SAML metadata is unavailable.', status=500)


# OIDC Views
@require_GET
def oidc_login(request, provider_name=None):
    """Initiate OIDC login."""
    # Get provider
    if provider_name:
        provider = get_object_or_404(
            SSOProvider, 
            name=provider_name, 
            protocol='oidc', 
            enabled=True,
            status='active',
        )
    else:
        provider = SSOProvider.get_active_provider('oidc')
        if not provider:
            messages.error(request, 'No active OIDC provider found.')
            return redirect('login')
    
    try:
        # Log login attempt
        SSOUtils.log_sso_event(
            provider=provider,
            event_type='login_attempt',
            request=request
        )
        
        # Create OIDC client
        oidc_client = OIDCClient(provider)
        
        # Generate state and nonce
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        
        # Store in session
        request.session['oidc_state'] = state
        request.session['oidc_nonce'] = nonce
        request.session['oidc_provider'] = provider.name
        request.session['oidc_next'] = request.GET.get('next', reverse('home'))
        request.session['oidc_started_at'] = time.time()
        
        # Generate authorization URL with HTTPS redirect URI
        redirect_uri = build_absolute_uri_with_https(request, reverse('sso:oidc_callback', args=[provider.name]))
        auth_url = oidc_client.get_authorization_url(redirect_uri, state, nonce)
        
        return redirect(auth_url)
        
    except Exception:
        logger.warning('OIDC login failed for provider_id=%s', provider.id)
        messages.error(request, 'OIDC login failed.')
        return redirect('login')


@require_GET
def oidc_callback(request, provider_name):
    """Handle OIDC callback."""
    provider = None
    try:
        # Consume every one-time transaction value before validating the callback.
        received_state = request.GET.get('state')
        session_state = request.session.pop('oidc_state', None)
        session_nonce = request.session.pop('oidc_nonce', None)
        session_provider = request.session.pop('oidc_provider', None)
        next_url = request.session.pop('oidc_next', reverse('home'))
        started_at = request.session.pop('oidc_started_at', None)

        if not all(isinstance(value, str) and value for value in (
            received_state, session_state, session_nonce, session_provider,
        )):
            raise OIDCValidationError('OIDC callback transaction is incomplete.')
        if not secrets.compare_digest(provider_name, session_provider):
            raise OIDCValidationError('OIDC callback provider does not match the login transaction.')
        try:
            state_age = time.time() - float(started_at)
        except (TypeError, ValueError):
            raise OIDCValidationError('OIDC callback transaction timestamp is invalid.')
        if state_age < -OIDC_STATE_CLOCK_SKEW_SECONDS or state_age > OIDC_STATE_LIFETIME_SECONDS:
            raise OIDCValidationError('OIDC callback transaction has expired.')
        if not secrets.compare_digest(received_state, session_state):
            raise OIDCValidationError('OIDC callback state does not match.')

        provider = get_object_or_404(
            SSOProvider,
            name=session_provider,
            protocol='oidc',
            enabled=True,
            status='active',
        )
        
        # Get authorization code
        code = request.GET.get('code')
        if not code:
            error = request.GET.get('error', 'No authorization code received')
            raise ValueError(f"Authorization failed: {error}")
        
        # Create OIDC client and exchange code for token
        oidc_client = OIDCClient(provider)
        redirect_uri = build_absolute_uri_with_https(request, reverse('sso:oidc_callback', args=[provider.name]))
        token_data = oidc_client.exchange_code_for_token(code, redirect_uri)

        id_token_claims = oidc_client.validate_id_token(
            token_data.get('id_token'), session_nonce
        )
        
        # Get user info
        access_token = token_data.get('access_token')
        if not access_token:
            raise ValueError("No access token received")
        
        user_info = oidc_client.get_user_info(access_token)
        userinfo_subject = user_info.get('sub')
        if not isinstance(userinfo_subject, str) or not secrets.compare_digest(
            userinfo_subject, str(id_token_claims['sub'])
        ):
            raise OIDCValidationError('OIDC UserInfo subject does not match the ID token.')
        
        # Only the already validated ID-token subject establishes identity. Email
        # metadata is usable for registration only when the validated token binds
        # that exact email and marks it verified.
        token_email = id_token_claims.get('email')
        userinfo_email = user_info.get(provider.attr_email)
        email_verified = (
            id_token_claims.get('email_verified') is True
            and isinstance(token_email, str)
            and isinstance(userinfo_email, str)
            and secrets.compare_digest(token_email, userinfo_email)
        )
        user = SSOUtils.create_or_update_user(
            provider,
            user_info,
            sso_id=id_token_claims['sub'],
            raw_attributes=user_info,
            email_verified=email_verified,
            require_verified_email=True,
        )
        
        if user:
            # Log successful login
            SSOUtils.log_sso_event(
                provider=provider,
                event_type='login_success',
                user_identifier=user.username,
                request=request
            )
            
            # Login user
            user.backend = 'django.contrib.auth.backends.ModelBackend'
            login(request, user)
            
            # Store additional user attributes for form prepopulation
            request.session['_oidc_user_attributes'] = {
                'email': user_info.get(provider.attr_email, ''),
                'username': user_info.get(provider.attr_username, ''),
                'first_name': user_info.get(provider.attr_first_name, ''),
                'last_name': user_info.get(provider.attr_last_name, ''),
                'full_name': f"{user_info.get(provider.attr_first_name, '')} {user_info.get(provider.attr_last_name, '')}".strip()
            }
            request.session['_oidc_provider'] = provider.name
            
            # Redirect
            if url_has_allowed_host_and_scheme(
                next_url, 
                allowed_hosts={request.get_host()}
            ):
                return redirect(next_url)
            
            return redirect('home')
        else:
            # Log failed login
            SSOUtils.log_sso_event(
                provider=provider,
                event_type='login_failure',
                details={'reason': 'registration_denied'},
                request=request
            )
            messages.error(request, "Failed to create or authenticate user.")
            return redirect('login')
            
    except Exception:
        if provider is not None:
            SSOUtils.log_sso_event(
                provider=provider,
                event_type='login_failure',
                details={'reason': 'callback_failure'},
                request=request
            )
            logger.warning('OIDC callback failed for provider_id=%s', provider.id)
        else:
            logger.warning('OIDC callback failed before provider resolution.')
        messages.error(request, 'OIDC authentication failed.')
        return redirect('login')


# API endpoints for AJAX calls
@superuser_json_required
def get_provider_details(request, provider_id):
    """Get provider details as JSON."""
    provider = get_object_or_404(SSOProvider, id=provider_id)
    test_results = provider.test_results if isinstance(provider.test_results, dict) else {}
    data = {
        'id': provider.id,
        'name': provider.name,
        'protocol': provider.protocol,
        'status': provider.status,
        'enabled': provider.enabled,
        'saml_identity_policy': provider.saml_identity_policy,
        'oidc_client_secret_configured': bool(provider.oidc_client_secret),
        'saml_sp_private_key_configured': bool(provider.saml_sp_private_key),
        'test_results': {'success': bool(test_results.get('success'))},
        'last_tested': provider.last_tested.isoformat() if provider.last_tested else None,
    }
    
    return JsonResponse(data)


@superuser_json_required
def get_audit_logs(request, provider_id):
    """Get audit logs for a provider."""
    provider = get_object_or_404(SSOProvider, id=provider_id)
    
    logs = SSOAuditLog.objects.filter(provider=provider).order_by('-timestamp')[:50]
    
    data = {
        'logs': [
            {
                'id': log.id,
                'event_type': log.get_event_type_display(),
                'user_identifier': log.user_identifier,
                'ip_address': log.ip_address,
                'timestamp': log.timestamp.isoformat(),
            }
            for log in logs
        ]
    }
    
    return JsonResponse(data)


def dynamic_sso_login(request):
    """
    Dynamic SSO login view that redirects to the single active SSO provider.
    """
    # Get the next URL from the request
    next_url = request.GET.get('next', '/')
    
    # Get the single active provider
    provider = SSOProvider.objects.filter(enabled=True, status='active').first()
    
    if not provider:
        messages.error(request, "No SSO provider is active. Please contact your administrator.")
        return redirect('login')  # Fallback to regular login
    
    if provider.protocol == 'oidc':
        # Redirect to OIDC login
        oidc_url = reverse('sso:oidc_login_named', kwargs={'provider_name': provider.name})
        return redirect(f"{oidc_url}?next={next_url}")
    elif provider.protocol == 'saml':
        # Redirect to SAML login
        saml_url = reverse('sso:saml_login_named', kwargs={'provider_name': provider.name})
        return redirect(f"{saml_url}?next={next_url}")
    else:
        messages.error(request, f"Unsupported SSO protocol: {provider.protocol}")
        return redirect('login')


def get_sso_providers_json(request):
    """
    API endpoint to get enabled SSO providers for frontend JavaScript.
    """
    providers = SSOProvider.objects.filter(enabled=True, status='active').values(
        'id', 'name', 'protocol', 'display_name'
    ).order_by('protocol', 'name')
    
    return JsonResponse({
        'providers': list(providers),
        'count': len(providers)
    })
