from django import forms
from django.core.exceptions import ValidationError
from .models import SSOProvider


class SecretTextarea(forms.Textarea):
    """Accept submitted secret text without ever rendering a stored value."""

    def format_value(self, value):
        return ''


class SSOProviderForm(forms.ModelForm):
    """Form for creating and editing SSO providers."""
    
    class Meta:
        model = SSOProvider
        fields = [
            # Basic Information
            'name', 'protocol', 'status', 'description', 'enabled', 
            'allow_registration', 'debug_mode',
            
            # SAML Fields
            'saml_idp_entity_id', 'saml_idp_sso_url', 'saml_idp_sso_binding', 'saml_idp_slo_url',
            'saml_idp_x509cert', 'saml_idp_x509cert_additional',
            'saml_sp_entity_id', 'saml_sp_acs_url', 'saml_sp_slo_url',
            'saml_sp_x509cert', 'saml_sp_private_key',
            'saml_name_id_format', 'saml_identity_policy', 'saml_immutable_attribute_name',
            'saml_want_messages_signed', 'saml_want_assertions_signed',
            'saml_authn_requests_signed', 'saml_logout_requests_signed',
            'saml_logout_responses_signed', 'saml_signature_algorithm',
            'saml_digest_algorithm', 'saml_strict_mode',
            
            # OIDC Fields
            'oidc_client_id', 'oidc_client_secret', 'oidc_discovery_url',
            'oidc_authorization_endpoint', 'oidc_token_endpoint', 'oidc_userinfo_endpoint',
            'oidc_jwks_uri', 'oidc_issuer', 'oidc_scopes',
            
            # Attribute Mapping
            'attr_email', 'attr_first_name', 'attr_last_name', 'attr_username'
        ]
        
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'saml_idp_x509cert': forms.Textarea(attrs={'rows': 8}),
            'saml_idp_x509cert_additional': forms.Textarea(attrs={'rows': 6}),
            'saml_sp_x509cert': forms.Textarea(attrs={'rows': 8}),
            'saml_sp_private_key': SecretTextarea(attrs={'rows': 8}),
            'oidc_client_secret': forms.PasswordInput(),
        }

    metadata_xml = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'rows': 6, 'class': 'form-control'}),
        help_text=(
            'Paste the IdP metadata XML and use "Parse Metadata" to prefill the IdP '
            'fields below. Nothing is saved until you submit the form normally.'
        ),
        label='IdP Metadata XML',
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Add CSS classes
        for field in self.fields:
            self.fields[field].widget.attrs['class'] = 'form-control'
        
        # Special handling for boolean fields
        for field_name in ['enabled', 'allow_registration', 'debug_mode', 
                          'saml_want_messages_signed', 'saml_want_assertions_signed',
                          'saml_authn_requests_signed', 'saml_logout_requests_signed',
                          'saml_logout_responses_signed', 'saml_strict_mode']:
            if field_name in self.fields:
                self.fields[field_name].widget.attrs['class'] = 'form-check-input'

        if self.instance and self.instance.pk:
            if self.instance.oidc_client_secret:
                self.fields['oidc_client_secret'].help_text = (
                    'Configured. Leave blank to keep the existing client secret.'
                )
            if self.instance.saml_sp_private_key:
                self.fields['saml_sp_private_key'].help_text = (
                    'Configured. Leave blank to keep the existing private key.'
                )

    def clean(self):
        cleaned_data = super().clean()

        # Secret fields never return to the browser. Merge blank or fixed-mask edit
        # submissions with the persisted instance rather than trusting a client flag.
        if self.instance and self.instance.pk:
            for field_name in ('oidc_client_secret', 'saml_sp_private_key'):
                submitted_value = cleaned_data.get(field_name)
                if submitted_value in ('', None, '********'):
                    cleaned_data[field_name] = getattr(self.instance, field_name)

        protocol = cleaned_data.get('protocol')
        enabled = cleaned_data.get('enabled')
        
        if enabled and protocol == 'saml':
            # Validate required SAML fields
            required_saml_fields = [
                'saml_idp_entity_id', 'saml_idp_sso_url', 
                'saml_sp_entity_id', 'saml_sp_acs_url'
            ]
            
            for field in required_saml_fields:
                if not cleaned_data.get(field):
                    field_label = self.fields[field].label
                    raise ValidationError(f'{field_label} is required for enabled SAML providers.')

            if not cleaned_data.get('saml_want_assertions_signed'):
                self.add_error(
                    'saml_want_assertions_signed',
                    'Signed assertions are required for active SAML providers.',
                )

            if (
                cleaned_data.get('saml_identity_policy') == 'configured_immutable_attribute'
                and not cleaned_data.get('saml_immutable_attribute_name')
            ):
                self.add_error(
                    'saml_immutable_attribute_name',
                    'An attribute name is required when the SAML Identity Policy is '
                    '"Configured immutable attribute".',
                )

            requires_sp_key = any(cleaned_data.get(field) for field in (
                'saml_authn_requests_signed', 'saml_logout_requests_signed', 'saml_logout_responses_signed',
            ))
            if requires_sp_key and not (
                cleaned_data.get('saml_sp_x509cert') and cleaned_data.get('saml_sp_private_key')
            ):
                raise ValidationError(
                    'Signing AuthnRequests or logout messages requires an SP certificate and private key.'
                )

        elif enabled and protocol == 'oidc':
            # Validate required OIDC fields
            if not cleaned_data.get('oidc_client_id'):
                raise ValidationError('OIDC Client ID is required for enabled OIDC providers.')
            
            if not cleaned_data.get('oidc_client_secret'):
                raise ValidationError('OIDC Client Secret is required for enabled OIDC providers.')
            
            # Either discovery URL or manual endpoints are required
            discovery_url = cleaned_data.get('oidc_discovery_url')
            auth_endpoint = cleaned_data.get('oidc_authorization_endpoint')
            token_endpoint = cleaned_data.get('oidc_token_endpoint')
            userinfo_endpoint = cleaned_data.get('oidc_userinfo_endpoint')
            
            if not discovery_url and not all([auth_endpoint, token_endpoint, userinfo_endpoint]):
                raise ValidationError(
                    'Either OIDC Discovery URL or all manual endpoints '
                    '(Authorization, Token, UserInfo) are required.'
                )
        
        return cleaned_data


class TestConnectionForm(forms.Form):
    """Form for testing SSO provider connections."""
    test_type = forms.ChoiceField(
        choices=[
            ('basic', 'Basic Configuration Test'),
            ('metadata', 'Metadata Validation (SAML only)'),
            ('discovery', 'Discovery Endpoint Test (OIDC only)'),
        ],
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    def __init__(self, provider, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.provider = provider
        
        # Adjust choices based on protocol
        if provider.protocol == 'saml':
            self.fields['test_type'].choices = [
                ('basic', 'Basic Configuration Test'),
                ('metadata', 'Metadata Validation'),
            ]
        elif provider.protocol == 'oidc':
            self.fields['test_type'].choices = [
                ('basic', 'Basic Configuration Test'),
                ('discovery', 'Discovery Endpoint Test'),
            ]
