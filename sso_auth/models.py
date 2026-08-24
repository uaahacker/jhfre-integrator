from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone

from .secret_encryption import decrypt_sso_secret, encrypt_sso_secret


SAML_BINDING_HTTP_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
SAML_BINDING_HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'

SAML_SSO_BINDING_URNS = {
    'http_redirect': SAML_BINDING_HTTP_REDIRECT,
    'http_post': SAML_BINDING_HTTP_POST,
}


def parse_pem_certificate_list(text):
    """Split pasted PEM text into individual certificate strings."""
    if not text:
        return []
    certs = []
    for block in text.split('-----END CERTIFICATE-----'):
        block = block.strip()
        if not block:
            continue
        certs.append(block + '\n-----END CERTIFICATE-----')
    return certs


class SSOProvider(models.Model):
    """
    Unified SSO Provider model supporting both SAML and OIDC protocols.
    """
    PROTOCOL_CHOICES = [
        ('saml', 'SAML 2.0'),
        ('oidc', 'OpenID Connect'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('testing', 'Testing'),
    ]
    SAML_IDENTITY_POLICY_CHOICES = [
        ('disabled', 'Disabled — do not allow SAML account identity'),
        ('persistent_nameid', 'Persistent NameID — require SAML persistent NameID format'),
        ('configured_immutable_attribute', 'Configured immutable attribute — require a named, non-empty assertion attribute'),
    ]
    SAML_IDP_SSO_BINDING_CHOICES = [
        ('http_redirect', 'HTTP-Redirect'),
        ('http_post', 'HTTP-POST'),
    ]

    # Basic Provider Information
    name = models.CharField(max_length=100, unique=True, help_text="Friendly name for the SSO provider")
    protocol = models.CharField(max_length=10, choices=PROTOCOL_CHOICES, help_text="SSO Protocol type")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='inactive', help_text="Provider status")
    description = models.TextField(blank=True, null=True, help_text="Optional description")
    
    # Common Settings
    enabled = models.BooleanField(default=False, help_text="Enable/disable this provider for authentication")
    allow_registration = models.BooleanField(default=True, help_text="Allow automatic user registration")
    debug_mode = models.BooleanField(default=False, help_text="Enable debug logging")
    
    # SAML Specific Settings
    # IdP Settings
    saml_idp_entity_id = models.URLField("SAML IdP Entity ID", max_length=500, blank=True, null=True)
    saml_idp_sso_url = models.URLField("SAML IdP Single Sign-On URL", max_length=500, blank=True, null=True)
    saml_idp_sso_binding = models.CharField(
        "SAML IdP SSO Binding",
        max_length=16,
        choices=SAML_IDP_SSO_BINDING_CHOICES,
        default='http_redirect',
        help_text='SingleSignOnService binding the AuthnRequest is sent with.',
    )
    saml_idp_slo_url = models.URLField("SAML IdP Single Logout URL", max_length=500, blank=True, null=True)
    saml_idp_x509cert = models.TextField("SAML IdP x509 Certificate", blank=True, null=True)
    saml_idp_x509cert_additional = models.TextField(
        "SAML IdP Additional x509 Certificates",
        blank=True,
        null=True,
        help_text='Optional rollover signing certificate(s). Paste one or more PEM certificates.',
    )

    # SP Settings
    saml_sp_entity_id = models.URLField("SAML SP Entity ID", max_length=500, blank=True, null=True)
    saml_sp_acs_url = models.URLField("SAML SP ACS URL", max_length=500, blank=True, null=True)
    saml_sp_slo_url = models.URLField("SAML SP SLO URL", max_length=500, blank=True, null=True)
    saml_sp_x509cert = models.TextField("SAML SP x509 Certificate", blank=True, null=True)
    saml_sp_private_key = models.TextField("SAML SP Private Key", blank=True, null=True)
    
    # SAML Security Settings
    saml_name_id_format = models.CharField(
        "SAML NameID Format",
        max_length=255,
        default='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        blank=True
    )
    saml_identity_policy = models.CharField(
        'SAML Identity Policy',
        max_length=32,
        choices=SAML_IDENTITY_POLICY_CHOICES,
        default='disabled',
        help_text='Controls which received SAML identity may be trusted; separate from the SP-requested NameID format.',
    )
    saml_immutable_attribute_name = models.CharField(
        "SAML Immutable Attribute Name",
        max_length=255,
        blank=True,
        help_text=(
            'Required when SAML Identity Policy is "Configured immutable attribute". '
            'Exact assertion attribute name the IdP issues as a stable, unique subject '
            'identifier (for example an object GUID or employee ID). Never use email, '
            'username, or display name here.'
        ),
    )
    saml_want_messages_signed = models.BooleanField(default=True)
    saml_want_assertions_signed = models.BooleanField(default=False)
    saml_authn_requests_signed = models.BooleanField(default=True)
    saml_logout_requests_signed = models.BooleanField(default=True)
    saml_logout_responses_signed = models.BooleanField(default=True)
    saml_signature_algorithm = models.CharField(
        max_length=255,
        default='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
    )
    saml_digest_algorithm = models.CharField(
        max_length=255,
        default='http://www.w3.org/2001/04/xmlenc#sha256'
    )
    saml_strict_mode = models.BooleanField(default=True)
    
    # OIDC Specific Settings
    oidc_client_id = models.CharField("OIDC Client ID", max_length=255, blank=True, null=True)
    oidc_client_secret = models.TextField("OIDC Client Secret", blank=True, null=True)
    oidc_discovery_url = models.URLField("OIDC Discovery URL", max_length=500, blank=True, null=True)
    oidc_authorization_endpoint = models.URLField("OIDC Authorization Endpoint", max_length=500, blank=True, null=True)
    oidc_token_endpoint = models.URLField("OIDC Token Endpoint", max_length=500, blank=True, null=True)
    oidc_userinfo_endpoint = models.URLField("OIDC UserInfo Endpoint", max_length=500, blank=True, null=True)
    oidc_jwks_uri = models.URLField("OIDC JWKS URI", max_length=500, blank=True, null=True)
    oidc_issuer = models.URLField("OIDC Issuer", max_length=500, blank=True, null=True)
    oidc_scopes = models.CharField("OIDC Scopes", max_length=255, default="openid email profile", blank=True)
    
    # Attribute Mapping
    attr_email = models.CharField("Email Attribute", max_length=100, default="email")
    attr_first_name = models.CharField("First Name Attribute", max_length=100, default="first_name")
    attr_last_name = models.CharField("Last Name Attribute", max_length=100, default="last_name")
    attr_username = models.CharField("Username Attribute", max_length=100, default="email")
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_tested = models.DateTimeField(blank=True, null=True)
    test_results = models.JSONField(default=dict, blank=True, help_text="Test results and logs")
    
    class Meta:
        ordering = ['name']
        verbose_name = "SSO Provider"
        verbose_name_plural = "SSO Providers"

    def __str__(self):
        return f"{self.name} ({self.get_protocol_display()})"

    def clean(self):
        """Validate that required fields are provided based on protocol."""
        super().clean()
        
        if self.protocol == 'saml':
            if self.enabled and not all([
                self.saml_idp_entity_id,
                self.saml_idp_sso_url,
                self.saml_sp_entity_id,
                self.saml_sp_acs_url
            ]):
                raise ValidationError(
                    "For SAML providers, IdP Entity ID, IdP SSO URL, SP Entity ID, and SP ACS URL are required."
                )
        elif self.protocol == 'oidc':
            if self.enabled and not all([
                self.oidc_client_id,
                self.oidc_client_secret,
                self.oidc_discovery_url or (
                    self.oidc_authorization_endpoint and 
                    self.oidc_token_endpoint and 
                    self.oidc_userinfo_endpoint
                )
            ]):
                raise ValidationError(
                    "For OIDC providers, Client ID, Client Secret, and either Discovery URL or manual endpoints are required."
                )

    def _get_saml_idp_settings(self):
        """Build the python3-saml `idp` settings block, including binding and rollover certs."""
        idp_settings = {
            'entityId': self.saml_idp_entity_id,
            'singleSignOnService': {
                'url': self.saml_idp_sso_url,
                'binding': SAML_SSO_BINDING_URNS.get(self.saml_idp_sso_binding, SAML_BINDING_HTTP_REDIRECT),
            },
            'singleLogoutService': {
                'url': self.saml_idp_slo_url or '',
                'binding': SAML_BINDING_HTTP_REDIRECT,
            },
            'x509cert': self.saml_idp_x509cert or '',
        }
        additional_certs = parse_pem_certificate_list(self.saml_idp_x509cert_additional)
        if additional_certs:
            signing_certs = additional_certs
            if self.saml_idp_x509cert:
                signing_certs = [self.saml_idp_x509cert] + additional_certs
            idp_settings['x509certMulti'] = {'signing': signing_certs}
        return idp_settings

    def get_saml_settings(self):
        """
        Returns SAML settings dictionary compatible with OneLogin_Saml2_Auth.
        """
        if self.protocol != 'saml':
            raise ValueError("This provider is not configured for SAML")
        if self.enabled and self.status == 'active':
            if not self.saml_strict_mode:
                raise ValueError('Active SAML providers require strict validation.')
            if not self.saml_want_assertions_signed:
                raise ValueError('Active SAML providers require signed assertions.')
            if not self.saml_idp_x509cert:
                raise ValueError('Active SAML providers require an IdP signing certificate.')
            
        return {
            'strict': self.saml_strict_mode,
            'debug': self.debug_mode,
            'sp': {
                'entityId': self.saml_sp_entity_id,
                'assertionConsumerService': {
                    'url': self.saml_sp_acs_url,
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                },
                'singleLogoutService': {
                    'url': self.saml_sp_slo_url or '',
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                },
                'NameIDFormat': self.saml_name_id_format,
                'x509cert': self.saml_sp_x509cert or '',
                'privateKey': (
                    decrypt_sso_secret(self.saml_sp_private_key)
                    if self.saml_sp_private_key else ''
                ),
            },
            'idp': self._get_saml_idp_settings(),
            'security': {
                'authnRequestsSigned': self.saml_authn_requests_signed,
                'logoutRequestSigned': self.saml_logout_requests_signed,
                'logoutResponseSigned': self.saml_logout_responses_signed,
                'wantMessagesSigned': self.saml_want_messages_signed,
                'wantAssertionsSigned': self.saml_want_assertions_signed,
                'wantNameId': True,
                'signatureAlgorithm': self.saml_signature_algorithm,
                'digestAlgorithm': self.saml_digest_algorithm,
                'debug': self.debug_mode,
            },
        }

    def get_oidc_settings(self):
        """
        Returns OIDC settings dictionary.
        """
        if self.protocol != 'oidc':
            raise ValueError("This provider is not configured for OIDC")
            
        return {
            'client_id': self.oidc_client_id,
            'client_secret': (
                decrypt_sso_secret(self.oidc_client_secret)
                if self.oidc_client_secret else ''
            ),
            'discovery_url': self.oidc_discovery_url,
            'authorization_endpoint': self.oidc_authorization_endpoint,
            'token_endpoint': self.oidc_token_endpoint,
            'userinfo_endpoint': self.oidc_userinfo_endpoint,
            'jwks_uri': self.oidc_jwks_uri,
            'issuer': self.oidc_issuer,
            'scopes': self.oidc_scopes.split(),
        }

    def test_connection(self):
        """
        Test the SSO provider connection and update test results.
        """
        test_results = {
            'timestamp': timezone.now().isoformat(),
            'success': False,
            'errors': [],
            'warnings': [],
        }
        
        try:
            if self.protocol == 'saml':
                # Test SAML configuration
                settings = self.get_saml_settings()
                
                # Basic validation
                if not settings['idp']['entityId']:
                    test_results['errors'].append("Missing IdP Entity ID")
                if not settings['idp']['singleSignOnService']['url']:
                    test_results['errors'].append("Missing IdP SSO URL")
                if not settings['sp']['entityId']:
                    test_results['errors'].append("Missing SP Entity ID")
                if not settings['sp']['assertionConsumerService']['url']:
                    test_results['errors'].append("Missing SP ACS URL")
                    
                # Certificate validation
                if not settings['idp']['x509cert']:
                    test_results['warnings'].append("No IdP certificate configured")
                    
                if not test_results['errors']:
                    test_results['success'] = True
                    test_results['message'] = "SAML configuration is valid"
                    
            elif self.protocol == 'oidc':
                # Test OIDC configuration
                import requests
                
                settings = self.get_oidc_settings()
                
                if settings['discovery_url']:
                    # Test discovery endpoint
                    try:
                        response = requests.get(settings['discovery_url'], timeout=10)
                        if response.status_code == 200:
                            # Confirm that the endpoint returns JSON, but never retain the
                            # discovery document: it can contain provider-specific metadata
                            # that is not needed after this connection check.
                            response.json()
                            test_results['discovery'] = {
                                'reachable': True,
                                'status_code': response.status_code,
                            }
                            test_results['success'] = True
                            test_results['message'] = "OIDC discovery endpoint is accessible"
                        else:
                            test_results['failure_category'] = 'discovery_http_error'
                            test_results['errors'].append("Discovery endpoint was unavailable")
                    except requests.RequestException:
                        test_results['failure_category'] = 'discovery_connection_failed'
                        test_results['errors'].append('Failed to connect to discovery endpoint')
                else:
                    # Validate manual endpoints
                    if not settings['authorization_endpoint']:
                        test_results['errors'].append("Missing authorization endpoint")
                    if not settings['token_endpoint']:
                        test_results['errors'].append("Missing token endpoint")
                    if not settings['userinfo_endpoint']:
                        test_results['errors'].append("Missing userinfo endpoint")
                        
                    if not test_results['errors']:
                        test_results['success'] = True
                        test_results['message'] = "OIDC configuration is valid"
                    else:
                        test_results['failure_category'] = 'configuration_incomplete'
                        
        except Exception:
            test_results['failure_category'] = 'configuration_test_failed'
            test_results['errors'].append('Configuration test failed')
        
        # Update test results
        self.test_results = test_results
        self.last_tested = timezone.now()
        self.save(update_fields=['test_results', 'last_tested'])
        
        return test_results

    def save(self, *args, **kwargs):
        """
        Encrypt secret fields for storage and ensure only one provider is enabled.
        """
        for field_name in ('oidc_client_secret', 'saml_sp_private_key'):
            value = getattr(self, field_name)
            if value not in (None, ''):
                setattr(self, field_name, encrypt_sso_secret(value))
        if self.enabled:
            # Disable all other providers when enabling this one
            SSOProvider.objects.exclude(pk=self.pk).update(enabled=False)
        
        super().save(*args, **kwargs)

    @classmethod
    def get_active_provider(cls, protocol=None):
        """Get the active SSO provider for a specific protocol."""
        queryset = cls.objects.filter(enabled=True, status='active')
        if protocol:
            queryset = queryset.filter(protocol=protocol)
        return queryset.first()

    @classmethod
    def get_available_providers(cls):
        """Get all available (enabled) SSO providers."""
        return cls.objects.filter(enabled=True, status='active').order_by('protocol', 'name')


class SSOAuditLog(models.Model):
    """
    Audit log for SSO authentication events.
    """
    EVENT_TYPES = [
        ('login_attempt', 'Login Attempt'),
        ('login_success', 'Login Success'),
        ('login_failure', 'Login Failure'),
        ('logout', 'Logout'),
        ('test_connection', 'Test Connection'),
        ('config_change', 'Configuration Change'),
    ]
    
    provider = models.ForeignKey(SSOProvider, on_delete=models.CASCADE, related_name='audit_logs')
    event_type = models.CharField(max_length=20, choices=EVENT_TYPES)
    user_identifier = models.CharField(max_length=255, blank=True, null=True, help_text="Username or email")
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    details = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = "SSO Audit Log"
        verbose_name_plural = "SSO Audit Logs"

    def __str__(self):
        return f"{self.provider.name} - {self.get_event_type_display()} - {self.timestamp}"


class SAMLReplayRecord(models.Model):
    """Minimal security metadata used to reject replayed validated SAML assertions."""
    provider = models.ForeignKey(SSOProvider, on_delete=models.CASCADE, related_name='saml_replay_records')
    assertion_id_hash = models.CharField(max_length=64)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['provider', 'assertion_id_hash'],
                name='sso_auth_replay_provider_assertion_uniq',
            ),
        ]


class SSOUserProfile(models.Model):
    """
    Extended SSO user profile to store all SSO attributes and sync data.
    This stores additional SSO data beyond what's in the standard User model.
    """
    user = models.OneToOneField(
        'auth.User', 
        on_delete=models.CASCADE, 
        related_name='sso_profile',
        help_text="Associated Django user"
    )
    provider = models.ForeignKey(
        SSOProvider, 
        on_delete=models.CASCADE, 
        related_name='user_profiles',
        help_text="SSO provider used to authenticate this user"
    )
    
    # SSO Identifiers
    sso_id = models.CharField(
        max_length=255, 
        help_text="SSO unique identifier (NameID for SAML, sub for OIDC)"
    )
    
    # SSO Attributes Storage
    raw_attributes = models.JSONField(
        default=dict, 
        help_text="All raw SSO attributes received from provider"
    )
    mapped_attributes = models.JSONField(
        default=dict, 
        help_text="Processed/mapped attributes for easy access"
    )
    
    # Login Tracking
    last_login_from_sso = models.DateTimeField(
        auto_now=True, 
        help_text="Last time user logged in via SSO"
    )
    sso_login_count = models.PositiveIntegerField(
        default=0, 
        help_text="Number of SSO logins"
    )
    is_sso_user = models.BooleanField(
        default=True, 
        help_text="Whether this user came from SSO"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "SSO User Profile"
        verbose_name_plural = "SSO User Profiles"
        ordering = ['-last_login_from_sso']
        indexes = [
            models.Index(fields=['sso_id'], name='sso_auth_ss_sso_id_idx'),
            models.Index(fields=['user', 'provider'], name='sso_auth_ss_user_pr_idx'),
        ]
        unique_together = ['user', 'provider']  # User can have one profile per provider
        constraints = [
            models.UniqueConstraint(
                fields=['provider', 'sso_id'],
                name='sso_auth_provider_sso_id_uniq',
            ),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.provider.name}"
    
    def get_attribute(self, key, default=None):
        """
        Get a mapped SSO attribute with fallback to raw attributes.
        """
        # First check mapped attributes
        if key in self.mapped_attributes:
            return self.mapped_attributes[key]
        
        # Then check raw attributes
        if key in self.raw_attributes:
            return self.raw_attributes[key]
        
        return default
    
    def update_attributes(self, raw_attrs, mapped_attrs=None):
        """
        Update SSO attributes and increment login count.
        """
        self.raw_attributes = raw_attrs or {}
        if mapped_attrs:
            self.mapped_attributes = mapped_attrs
        self.sso_login_count += 1
        self.save()
    
    @property
    def department(self):
        """Easy access to department attribute."""
        return self.get_attribute('department')
    
    @property
    def job_title(self):
        """Easy access to job title attribute."""
        return self.get_attribute('job_title') or self.get_attribute('title')
    
    @property
    def phone(self):
        """Easy access to phone attribute."""
        return self.get_attribute('phone') or self.get_attribute('phone_number')
    
    @property
    def organization(self):
        """Easy access to organization attribute."""
        return self.get_attribute('organization') or self.get_attribute('company')
    
    @property
    def manager(self):
        """Easy access to manager attribute."""
        return self.get_attribute('manager')
    
    @property
    def groups(self):
        """Easy access to groups/roles attribute."""
        groups = self.get_attribute('groups') or self.get_attribute('roles')
        if isinstance(groups, str):
            return [g.strip() for g in groups.split(',')]
        elif isinstance(groups, list):
            return groups
        return []
