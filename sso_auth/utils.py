import requests
import logging
import hmac
import ipaddress
import time
from urllib.parse import urlencode, urlsplit

import jwt
from jwt import PyJWKSet
from django.contrib.auth import get_user_model
from django.conf import settings
from django.db import IntegrityError, transaction
from .models import SSOProvider, SSOAuditLog, SSOUserProfile

logger = logging.getLogger(__name__)
User = get_user_model()


class OIDCValidationError(ValueError):
    """Raised when an OIDC protocol or trusted-configuration check fails."""


OIDC_HTTP_TIMEOUT_SECONDS = 10
OIDC_CLOCK_SKEW_SECONDS = 60
SAFE_ID_TOKEN_ALGORITHMS = frozenset({
    'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512',
})
_LOCAL_DEVELOPMENT_HOSTS = {'localhost', '127.0.0.1', '::1', 'testserver'}


def _is_private_or_local_host(hostname):
    if not hostname:
        return True
    normalized_host = hostname.lower().strip('[]')
    if normalized_host in _LOCAL_DEVELOPMENT_HOSTS:
        return True
    try:
        address = ipaddress.ip_address(normalized_host)
    except ValueError:
        return False
    return any((
        address.is_private,
        address.is_loopback,
        address.is_link_local,
        address.is_multicast,
        address.is_reserved,
        address.is_unspecified,
    ))


def _url_origin(url):
    parsed = urlsplit(url)
    host = parsed.hostname.lower() if parsed.hostname else ''
    port = parsed.port
    default_port = 443 if parsed.scheme == 'https' else 80
    return parsed.scheme.lower(), host, port or default_port


def validate_oidc_url(url, *, expected_origin=None):
    """Validate a trusted OIDC URL before any HTTP request is made."""
    if not isinstance(url, str) or not url:
        raise OIDCValidationError('OIDC URL is missing.')

    try:
        parsed = urlsplit(url)
        origin = _url_origin(url)
    except ValueError as exc:
        raise OIDCValidationError('OIDC URL is invalid.') from exc

    if parsed.username or parsed.password or not parsed.hostname:
        raise OIDCValidationError('OIDC URL contains unsafe authority data.')

    is_local = _is_private_or_local_host(parsed.hostname)
    if parsed.scheme != 'https':
        if not (settings.DEBUG and is_local and parsed.scheme == 'http'):
            raise OIDCValidationError('OIDC URL must use HTTPS.')
    elif is_local and not settings.DEBUG:
        raise OIDCValidationError('OIDC URL cannot target a private or local host.')

    if expected_origin is not None and origin != expected_origin:
        raise OIDCValidationError('OIDC URL origin is not trusted for this provider.')
    return origin


def _fetch_trusted_json(url):
    validate_oidc_url(url)
    try:
        response = requests.get(
            url,
            timeout=OIDC_HTTP_TIMEOUT_SECONDS,
            verify=True,
            allow_redirects=False,
        )
        if response.is_redirect:
            raise OIDCValidationError('OIDC redirects are not permitted.')
        response.raise_for_status()
        payload = response.json()
    except OIDCValidationError:
        raise
    except (requests.RequestException, ValueError) as exc:
        raise OIDCValidationError('OIDC metadata retrieval failed.') from exc

    if not isinstance(payload, dict):
        raise OIDCValidationError('OIDC metadata is not a JSON object.')
    return payload


def load_trusted_oidc_discovery(discovery_url, expected_issuer=None):
    """Retrieve and validate discovery metadata under the local trust policy."""
    validate_oidc_url(discovery_url)
    if expected_issuer:
        validate_oidc_url(expected_issuer)

    discovery = _fetch_trusted_json(discovery_url)
    issuer = discovery.get('issuer')
    issuer_origin = validate_oidc_url(issuer)
    if expected_issuer and issuer != expected_issuer:
        raise OIDCValidationError('OIDC discovery issuer does not match the configured issuer.')

    for field in ('authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'):
        validate_oidc_url(discovery.get(field), expected_origin=issuer_origin)
    return discovery


class SSOUtils:
    """Utility class for SSO operations."""
    
    @staticmethod
    def get_saml_settings(provider_name=None):
        """
        Get SAML settings for the specified provider or the active one.
        """
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
            return None
        
        return provider.get_saml_settings()

    @staticmethod
    def get_oidc_settings(provider_name=None):
        """
        Get OIDC settings for the specified provider or the active one.
        """
        if provider_name:
            provider = SSOProvider.objects.filter(
                name=provider_name, 
                protocol='oidc', 
                enabled=True,
                status='active',
            ).first()
        else:
            provider = SSOProvider.get_active_provider('oidc')
        
        if not provider:
            return None
        
        return provider.get_oidc_settings()

    @staticmethod
    def discover_oidc_config(discovery_url):
        """
        Fetch OIDC configuration from discovery endpoint.
        """
        try:
            return load_trusted_oidc_discovery(discovery_url)
        except OIDCValidationError:
            logger.warning('OIDC discovery configuration could not be trusted.')
            return None

    @staticmethod
    def create_or_update_user(
        provider, user_data, sso_id=None, raw_attributes=None, email_verified=False,
        require_verified_email=True,
    ):
        """Resolve a trusted provider+subject mapping or safely register a new user."""
        if not provider.enabled or provider.status != 'active':
            logger.warning('SSO provisioning denied for inactive provider_id=%s', provider.pk)
            return None
        if not isinstance(sso_id, str) or not sso_id.strip():
            logger.warning('SSO provisioning denied for missing external subject, provider_id=%s', provider.pk)
            return None

        profile = SSOUserProfile.objects.select_related('user').filter(
            provider=provider, sso_id=sso_id,
        ).first()
        mapped_attributes = SSOUtils._map_sso_attributes(provider, user_data, raw_attributes)
        first_name = SSOUtils._claim_value(user_data.get(provider.attr_first_name))
        last_name = SSOUtils._claim_value(user_data.get(provider.attr_last_name))
        if profile:
            user = profile.user
            changed = False
            if user.first_name != first_name:
                user.first_name = first_name
                changed = True
            if user.last_name != last_name:
                user.last_name = last_name
                changed = True
            if changed:
                user.save(update_fields=['first_name', 'last_name'])
            profile.update_attributes(raw_attrs=raw_attributes or {}, mapped_attrs=mapped_attributes)
            logger.info('SSO identity mapping found for provider_id=%s', provider.pk)
            return user

        if not provider.allow_registration:
            logger.warning('SSO registration denied by provider policy, provider_id=%s', provider.pk)
            return None

        email = SSOUtils._claim_value(user_data.get(provider.attr_email))
        username = SSOUtils._claim_value(user_data.get(provider.attr_username)) or email
        if not email or not username or (require_verified_email and not email_verified):
            logger.warning('SSO registration denied for insufficient verified metadata, provider_id=%s', provider.pk)
            return None
        if User.objects.filter(email=email).exists() or User.objects.filter(username=username).exists():
            logger.warning('SSO identity collision denied for provider_id=%s', provider.pk)
            return None

        try:
            with transaction.atomic():
                # Re-check inside the transaction before creating either record.
                if SSOUserProfile.objects.filter(provider=provider, sso_id=sso_id).exists():
                    return None
                if User.objects.filter(email=email).exists() or User.objects.filter(username=username).exists():
                    return None
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    is_staff=False,
                    is_superuser=False,
                )
                SSOUserProfile.objects.create(
                    user=user,
                    provider=provider,
                    sso_id=sso_id,
                    raw_attributes=raw_attributes or {},
                    mapped_attributes=mapped_attributes,
                    sso_login_count=1,
                )
        except IntegrityError:
            logger.warning('SSO registration failed safely for provider_id=%s', provider.pk)
            return None

        logger.info('SSO registration created for provider_id=%s', provider.pk)
        return user

    @staticmethod
    def _claim_value(value):
        """Normalize scalar or SAML-style single-value claims without treating claims as identity."""
        if isinstance(value, (list, tuple)):
            value = value[0] if value else ''
        return value if isinstance(value, str) else ''

    @staticmethod
    def _map_sso_attributes(provider, user_data, raw_attributes=None):
        """
        Map SSO attributes to standardized format for easy access.
        """
        mapped = {}
        
        # Standard attributes from provider mapping
        if provider.attr_email and user_data.get(provider.attr_email):
            mapped['email'] = user_data.get(provider.attr_email)
        
        if provider.attr_first_name and user_data.get(provider.attr_first_name):
            mapped['first_name'] = user_data.get(provider.attr_first_name)
        
        if provider.attr_last_name and user_data.get(provider.attr_last_name):
            mapped['last_name'] = user_data.get(provider.attr_last_name)
        
        if provider.attr_username and user_data.get(provider.attr_username):
            mapped['username'] = user_data.get(provider.attr_username)
        
        # Common extended attributes (try multiple field names)
        common_mappings = {
            'department': ['department', 'dept', 'ou', 'organizationalUnit'],
            'job_title': ['title', 'job_title', 'jobTitle', 'position'],
            'phone': ['phone', 'phoneNumber', 'telephone', 'mobile'],
            'organization': ['organization', 'company', 'org', 'o'],
            'manager': ['manager', 'supervisor', 'reportingManager'],
            'employee_id': ['employeeId', 'employee_id', 'empId', 'id'],
            'groups': ['groups', 'roles', 'memberOf', 'group_membership'],
            'office_location': ['office', 'location', 'physicalDeliveryOfficeName'],
            'country': ['country', 'c', 'countryCode'],
            'state': ['state', 'st', 'stateOrProvince'],
            'city': ['city', 'l', 'locality'],
            'postal_code': ['postalCode', 'zip', 'zipCode'],
            'address': ['address', 'streetAddress', 'street'],
        }
        
        all_data = {**(raw_attributes or {}), **user_data}
        
        for mapped_key, possible_keys in common_mappings.items():
            for key in possible_keys:
                if key in all_data and all_data[key]:
                    mapped[mapped_key] = all_data[key]
                    break
        
        return mapped

    @staticmethod
    def log_sso_event(provider, event_type, user_identifier=None, ip_address=None, 
                     user_agent=None, details=None, request=None):
        """Store only the minimum security-relevant metadata for an SSO event."""
        if request:
            ip_address = ip_address or get_client_ip(request)

        SSOAuditLog.objects.create(
            provider=provider,
            event_type=event_type,
            user_identifier=user_identifier,
            ip_address=ip_address,
            # Full user-agent strings are not required by the management audit UI
            # and may contain caller-supplied identifying data.
            user_agent=None,
            details=SSOUtils._minimal_audit_details(event_type, details),
        )

    @staticmethod
    def _minimal_audit_details(event_type, details):
        """Allowlist small audit categories; never retain protocol payloads or exceptions."""
        details = details if isinstance(details, dict) else {}
        if event_type == 'config_change':
            action = details.get('action')
            return {'action': action} if action in {'created', 'updated'} else {}
        if event_type == 'test_connection':
            result = details.get('results') if isinstance(details.get('results'), dict) else details
            safe = {'success': bool(result.get('success'))}
            category = result.get('failure_category')
            if category in {
                'discovery_http_error', 'discovery_connection_failed',
                'configuration_incomplete', 'configuration_test_failed',
            }:
                safe['failure_category'] = category
            return safe
        if event_type == 'login_failure':
            reason = details.get('reason')
            if reason in {
                'saml_validation_failed', 'registration_denied', 'callback_failure',
            }:
                return {'reason': reason}
        return {}

    @staticmethod
    def get_sso_user_data(request):
        """
        Extract user data from the current request for form prepopulation.
        Works for both SSO and regular users - returns available user attributes.
        """
        if not request.user.is_authenticated:
            return {}
        
        user_data = {}
        
        # Get basic user information (available for all users)
        if hasattr(request.user, 'email') and request.user.email:
            user_data['email'] = request.user.email
        
        if hasattr(request.user, 'username') and request.user.username:
            user_data['username'] = request.user.username
        
        if hasattr(request.user, 'first_name') and request.user.first_name:
            user_data['first_name'] = request.user.first_name
        
        if hasattr(request.user, 'last_name') and request.user.last_name:
            user_data['last_name'] = request.user.last_name
        
        # Get full name
        if user_data.get('first_name') or user_data.get('last_name'):
            full_name_parts = []
            if user_data.get('first_name'):
                full_name_parts.append(user_data['first_name'])
            if user_data.get('last_name'):
                full_name_parts.append(user_data['last_name'])
            user_data['full_name'] = ' '.join(full_name_parts)
        
        # Try to get enhanced SSO data from user's SSO profile (if they're an SSO user)
        try:
            sso_profile = request.user.sso_profile
            if sso_profile:
                # Add all mapped attributes from SSO
                user_data.update(sso_profile.mapped_attributes)
                
                # Add provider info
                user_data['sso_provider'] = sso_profile.provider.protocol
                user_data['sso_provider_name'] = sso_profile.provider.name
                user_data['sso_login_count'] = sso_profile.sso_login_count
                user_data['last_sso_login'] = sso_profile.last_login_from_sso.isoformat() if sso_profile.last_login_from_sso else None
                user_data['is_sso_user'] = True
                
                # Add convenient property access
                if sso_profile.department:
                    user_data['department'] = sso_profile.department
                if sso_profile.job_title:
                    user_data['job_title'] = sso_profile.job_title
                if sso_profile.phone:
                    user_data['phone'] = sso_profile.phone
                if sso_profile.organization:
                    user_data['organization'] = sso_profile.organization
                if sso_profile.manager:
                    user_data['manager'] = sso_profile.manager
                if sso_profile.groups:
                    user_data['groups'] = sso_profile.groups
                
        except (SSOUserProfile.DoesNotExist, AttributeError):
            # User is not an SSO user or SSO profile doesn't exist
            user_data['is_sso_user'] = False
            
            # Fallback to session data for backward compatibility (for active SSO sessions)
            if hasattr(request, 'session'):
                # SAML attributes
                if '_saml_provider' in request.session:
                    provider_name = request.session.get('_saml_provider')
                    saml_attributes = request.session.get('_saml_user_attributes', {})
                    if saml_attributes:
                        user_data.update(saml_attributes)
                        user_data['sso_provider'] = 'saml'
                        user_data['sso_provider_name'] = provider_name
                        user_data['is_sso_user'] = True
                
                # OIDC attributes
                elif '_oidc_provider' in request.session:
                    provider_name = request.session.get('_oidc_provider')
                    oidc_attributes = request.session.get('_oidc_user_attributes', {})
                    if oidc_attributes:
                        user_data.update(oidc_attributes)
                        user_data['sso_provider'] = 'oidc'
                        user_data['sso_provider_name'] = provider_name
                        user_data['is_sso_user'] = True
        
        # Get additional data from UserProfile if available (for all users)
        try:
            if hasattr(request.user, 'userprofile'):
                profile = request.user.userprofile
                if profile.contact_phone:
                    user_data['phone'] = user_data.get('phone') or profile.contact_phone
                if profile.company:
                    user_data['organization'] = user_data.get('organization') or profile.company
                if profile.designation:
                    user_data['job_title'] = user_data.get('job_title') or profile.designation
                if profile.address:
                    user_data['address'] = user_data.get('address') or profile.address
        except AttributeError:
            # UserProfile doesn't exist, skip
            pass
        
        return user_data
    
    @staticmethod
    def get_user_sso_attributes(user):
        """
        Get all SSO attributes for a specific user.
        """
        try:
            sso_profile = user.sso_profile
            return {
                'provider': sso_profile.provider.name,
                'protocol': sso_profile.provider.protocol,
                'mapped_attributes': sso_profile.mapped_attributes,
                'raw_attributes': sso_profile.raw_attributes,
                'login_count': sso_profile.sso_login_count,
                'last_login': sso_profile.last_login_from_sso,
            }
        except SSOUserProfile.DoesNotExist:
            return {}


class OIDCClient:
    """OIDC client for handling OpenID Connect authentication."""
    
    def __init__(self, provider):
        self.provider = provider
        self.settings = provider.get_oidc_settings()
        self.discovery_data = None
        self.expected_issuer = self.settings['issuer'] or None

        if self.settings['discovery_url']:
            self.discovery_data = load_trusted_oidc_discovery(
                self.settings['discovery_url'], self.expected_issuer
            )
            self.issuer = self.discovery_data['issuer']
            self.jwks_uri = self.discovery_data['jwks_uri']
            advertised_algorithms = self.discovery_data.get('id_token_signing_alg_values_supported')
            if advertised_algorithms is None:
                self.allowed_id_token_algorithms = SAFE_ID_TOKEN_ALGORITHMS
            elif isinstance(advertised_algorithms, list):
                self.allowed_id_token_algorithms = frozenset(advertised_algorithms) & SAFE_ID_TOKEN_ALGORITHMS
            else:
                raise OIDCValidationError('OIDC signing algorithm metadata is invalid.')
        else:
            if not self.expected_issuer or not self.settings['jwks_uri']:
                raise OIDCValidationError('OIDC issuer and JWKS URI are required without discovery.')
            issuer_origin = validate_oidc_url(self.expected_issuer)
            for field in ('authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'):
                validate_oidc_url(self.settings.get(field), expected_origin=issuer_origin)
            self.issuer = self.expected_issuer
            self.jwks_uri = self.settings['jwks_uri']
            self.allowed_id_token_algorithms = SAFE_ID_TOKEN_ALGORITHMS

        if not self.allowed_id_token_algorithms:
            raise OIDCValidationError('OIDC provider has no supported ID-token signing algorithm.')

    def get_authorization_url(self, redirect_uri, state=None, nonce=None):
        """
        Generate OIDC authorization URL.
        """
        auth_endpoint = self._endpoint('authorization_endpoint')
        
        if not auth_endpoint:
            raise ValueError("Authorization endpoint not available")

        params = {
            'response_type': 'code',
            'client_id': self.settings['client_id'],
            'redirect_uri': redirect_uri,
            'scope': ' '.join(self.settings['scopes']),
        }
        
        if state:
            params['state'] = state
        if nonce:
            params['nonce'] = nonce

        return f"{auth_endpoint}?{urlencode(params)}"

    def exchange_code_for_token(self, code, redirect_uri):
        """
        Exchange authorization code for access token.
        """
        token_endpoint = self._endpoint('token_endpoint')
        
        if not token_endpoint:
            raise ValueError("Token endpoint not available")

        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': self.settings['client_id'],
            'client_secret': self.settings['client_secret'],
        }

        try:
            response = requests.post(
                token_endpoint,
                data=data,
                timeout=OIDC_HTTP_TIMEOUT_SECONDS,
                verify=True,
                allow_redirects=False,
            )
            if response.is_redirect:
                raise OIDCValidationError('OIDC token redirects are not permitted.')
            response.raise_for_status()
            token_data = response.json()
        except OIDCValidationError:
            raise
        except (requests.RequestException, ValueError) as exc:
            raise OIDCValidationError('OIDC token exchange failed.') from exc
        if not isinstance(token_data, dict):
            raise OIDCValidationError('OIDC token response is invalid.')
        return token_data

    def get_user_info(self, access_token):
        """
        Get user information using access token.
        """
        userinfo_endpoint = self._endpoint('userinfo_endpoint')
        
        if not userinfo_endpoint:
            raise ValueError("UserInfo endpoint not available")

        headers = {'Authorization': f'Bearer {access_token}'}
        try:
            response = requests.get(
                userinfo_endpoint,
                headers=headers,
                timeout=OIDC_HTTP_TIMEOUT_SECONDS,
                verify=True,
                allow_redirects=False,
            )
            if response.is_redirect:
                raise OIDCValidationError('OIDC UserInfo redirects are not permitted.')
            response.raise_for_status()
            user_info = response.json()
        except OIDCValidationError:
            raise
        except (requests.RequestException, ValueError) as exc:
            raise OIDCValidationError('OIDC UserInfo retrieval failed.') from exc
        if not isinstance(user_info, dict):
            raise OIDCValidationError('OIDC UserInfo response is invalid.')
        return user_info

    def _endpoint(self, field):
        endpoint = self.discovery_data.get(field) if self.discovery_data else self.settings[field]
        if not endpoint:
            raise OIDCValidationError('OIDC endpoint is unavailable.')
        return endpoint

    def validate_id_token(self, id_token, expected_nonce):
        """Verify the ID token signature and mandatory OIDC claims before login."""
        if not isinstance(id_token, str) or not id_token:
            raise OIDCValidationError('OIDC ID token is missing.')
        if not isinstance(expected_nonce, str) or not expected_nonce:
            raise OIDCValidationError('OIDC nonce is missing.')

        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise OIDCValidationError('OIDC ID token header is invalid.') from exc

        algorithm = header.get('alg')
        key_id = header.get('kid')
        if algorithm == 'none' or algorithm not in self.allowed_id_token_algorithms:
            raise OIDCValidationError('OIDC ID token algorithm is not allowed.')
        if not isinstance(key_id, str) or not key_id:
            raise OIDCValidationError('OIDC ID token signing key is missing.')

        jwks = _fetch_trusted_json(self.jwks_uri)
        try:
            key_set = PyJWKSet.from_dict(jwks)
            signing_key = next(key for key in key_set.keys if key.key_id == key_id)
        except (jwt.PyJWTError, StopIteration, ValueError, KeyError) as exc:
            raise OIDCValidationError('OIDC signing key is unavailable.') from exc

        if signing_key.algorithm_name and signing_key.algorithm_name != algorithm:
            raise OIDCValidationError('OIDC signing key algorithm does not match the token.')
        if signing_key.public_key_use and signing_key.public_key_use != 'sig':
            raise OIDCValidationError('OIDC signing key cannot verify ID tokens.')

        try:
            claims = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=[algorithm],
                audience=self.settings['client_id'],
                issuer=self.issuer,
                leeway=OIDC_CLOCK_SKEW_SECONDS,
                options={
                    'require': ['exp', 'iat', 'iss', 'aud', 'sub', 'nonce'],
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iat': True,
                    'verify_nbf': True,
                    'verify_aud': True,
                    'verify_iss': True,
                },
            )
        except jwt.PyJWTError as exc:
            raise OIDCValidationError('OIDC ID token validation failed.') from exc

        audiences = claims.get('aud')
        authorized_party = claims.get('azp')
        if isinstance(audiences, list) and len(audiences) > 1:
            if authorized_party != self.settings['client_id']:
                raise OIDCValidationError('OIDC authorized party is invalid.')
        elif authorized_party is not None and authorized_party != self.settings['client_id']:
            raise OIDCValidationError('OIDC authorized party is invalid.')

        if not hmac.compare_digest(str(claims['nonce']), expected_nonce):
            raise OIDCValidationError('OIDC nonce does not match.')
        return claims


def get_client_ip(request):
    """Get client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_available_sso_providers():
    """Get all available SSO providers for the login page."""
    return SSOProvider.get_available_providers()
