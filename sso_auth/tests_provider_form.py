import re

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from sso_auth.forms import SSOProviderForm
from sso_auth.models import SSOProvider


class SAMLProviderCreateFormValidationTests(TestCase):
    """Validate realistic SAML provider POST data reaches SSOProviderForm and can save."""

    def setUp(self):
        self.superuser = User.objects.create_superuser(
            'saml-form-admin', 'saml-form-admin@example.test', 'password'
        )
        self.client.force_login(self.superuser)
        self.create_url = reverse('sso:create_provider')

    def _valid_saml_payload(self, **overrides):
        payload = {
            'name': 'SAMLTest.dev',
            'protocol': 'saml',
            'status': 'active',
            'description': '',
            'enabled': 'on',
            'allow_registration': 'on',
            'debug_mode': 'on',
            'saml_idp_entity_id': 'https://www.samltest.dev/idp',
            'saml_idp_sso_url': 'https://www.samltest.dev/idp/sso',
            'saml_idp_sso_binding': 'http_redirect',
            'saml_idp_slo_url': '',
            'saml_idp_x509cert': '',
            'saml_idp_x509cert_additional': '',
            'saml_sp_entity_id': 'https://jefre.djangix.com/sso/saml/metadata/',
            'saml_sp_acs_url': 'https://jefre.djangix.com/sso/saml/acs/',
            'saml_sp_slo_url': 'https://jefre.djangix.com/sso/saml/logout/',
            'saml_sp_x509cert': '',
            'saml_sp_private_key': '',
            'saml_name_id_format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            'saml_identity_policy': 'persistent_nameid',
            'saml_immutable_attribute_name': '',
            'saml_want_messages_signed': 'on',
            'saml_want_assertions_signed': 'on',
            'saml_authn_requests_signed': '',
            'saml_logout_requests_signed': '',
            'saml_logout_responses_signed': '',
            'saml_signature_algorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'saml_digest_algorithm': 'http://www.w3.org/2001/04/xmlenc#sha256',
            'saml_strict_mode': 'on',
            'oidc_client_id': '',
            'oidc_client_secret': '',
            'oidc_discovery_url': '',
            'oidc_authorization_endpoint': '',
            'oidc_token_endpoint': '',
            'oidc_userinfo_endpoint': '',
            'oidc_jwks_uri': '',
            'oidc_issuer': '',
            'oidc_scopes': 'openid email profile',
            'attr_email': 'email',
            'attr_first_name': 'first_name',
            'attr_last_name': 'last_name',
            'attr_username': 'email',
        }
        payload.update(overrides)
        return payload

    def test_valid_saml_provider_post_saves(self):
        response = self.client.post(self.create_url, self._valid_saml_payload(), secure=True)
        self.assertRedirects(response, reverse('sso:management'))
        provider = SSOProvider.objects.get(name='SAMLTest.dev')
        self.assertEqual(provider.protocol, 'saml')
        self.assertTrue(provider.enabled)
        self.assertEqual(provider.saml_identity_policy, 'persistent_nameid')
        self.assertEqual(
            provider.saml_name_id_format,
            'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        )
        self.assertTrue(provider.saml_want_messages_signed)
        self.assertTrue(provider.saml_want_assertions_signed)
        self.assertTrue(provider.saml_strict_mode)
        self.assertFalse(provider.saml_authn_requests_signed)
        self.assertFalse(provider.saml_logout_requests_signed)
        self.assertFalse(provider.saml_logout_responses_signed)

    def test_missing_required_idp_fields_are_reported(self):
        payload = self._valid_saml_payload(
            saml_idp_entity_id='', saml_idp_sso_url='',
        )
        response = self.client.post(self.create_url, payload, secure=True)
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('SAML IdP Entity ID is required for enabled SAML providers.', content)
        self.assertIn(
            'For SAML providers, IdP Entity ID, IdP SSO URL, SP Entity ID, and SP ACS URL are required.',
            content,
        )

    def test_sp_private_key_not_required_when_sp_signing_disabled(self):
        form = SSOProviderForm(data=self._valid_saml_payload())
        self.assertTrue(form.is_valid())

    def test_active_saml_provider_rejects_unsigned_assertions(self):
        form = SSOProviderForm(data=self._valid_saml_payload(saml_want_assertions_signed=''))
        self.assertFalse(form.is_valid())
        self.assertIn(
            'Signed assertions are required for active SAML providers.',
            form.errors['saml_want_assertions_signed'],
        )

    def test_active_saml_provider_accepts_unsigned_outer_response(self):
        form = SSOProviderForm(data=self._valid_saml_payload(saml_want_messages_signed=''))
        self.assertTrue(form.is_valid())
        self.assertFalse(form.cleaned_data['saml_want_messages_signed'])
        self.assertTrue(form.cleaned_data['saml_want_assertions_signed'])

    def test_oidc_fields_not_required_for_saml(self):
        form = SSOProviderForm(data=self._valid_saml_payload())
        self.assertTrue(form.is_valid())


class SSOProviderFormTemplateTests(TestCase):
    """Contract tests for provider_form.html error visibility and field rendering."""

    def setUp(self):
        self.superuser = User.objects.create_superuser(
            'template-admin', 'template-admin@example.test', 'password'
        )
        self.client.force_login(self.superuser)
        self.create_url = reverse('sso:create_provider')

    def _invalid_payload(self):
        return {
            'name': 'template-test',
            'protocol': 'saml',
            'status': 'active',
            'description': '',
            'enabled': 'on',
            'allow_registration': 'on',
            'debug_mode': 'on',
            'saml_idp_entity_id': '',
            'saml_idp_sso_url': '',
            'saml_idp_sso_binding': 'http_redirect',
            'saml_idp_slo_url': '',
            'saml_idp_x509cert': '',
            'saml_idp_x509cert_additional': '',
            'saml_sp_entity_id': '',
            'saml_sp_acs_url': '',
            'saml_sp_slo_url': '',
            'saml_sp_x509cert': '',
            'saml_sp_private_key': '',
            'saml_name_id_format': '',
            'saml_identity_policy': 'disabled',
            'saml_immutable_attribute_name': '',
            'saml_want_messages_signed': 'on',
            'saml_want_assertions_signed': 'on',
            'saml_authn_requests_signed': '',
            'saml_logout_requests_signed': '',
            'saml_logout_responses_signed': '',
            'saml_signature_algorithm': '',
            'saml_digest_algorithm': '',
            'saml_strict_mode': 'on',
            'oidc_client_id': '',
            'oidc_client_secret': '',
            'oidc_discovery_url': '',
            'oidc_authorization_endpoint': '',
            'oidc_token_endpoint': '',
            'oidc_userinfo_endpoint': '',
            'oidc_jwks_uri': '',
            'oidc_issuer': '',
            'oidc_scopes': 'openid email profile',
            'attr_email': 'email',
            'attr_first_name': 'first_name',
            'attr_last_name': 'last_name',
            'attr_username': 'email',
        }

    def test_non_field_errors_render_on_invalid_post(self):
        response = self.client.post(self.create_url, self._invalid_payload(), secure=True)
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('Validation Errors', content)
        self.assertIn('SAML IdP Entity ID is required for enabled SAML providers.', content)

    def test_saml_field_names_present_in_rendered_form(self):
        response = self.client.get(self.create_url, secure=True)
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        required_names = [
            'saml_idp_entity_id', 'saml_idp_sso_url', 'saml_idp_slo_url', 'saml_idp_x509cert',
            'saml_sp_entity_id', 'saml_sp_acs_url', 'saml_sp_slo_url',
            'saml_name_id_format', 'saml_identity_policy',
        ]
        for name in required_names:
            self.assertIn(f'name="{name}"', content, f'Missing form input: {name}')

    def test_saml_security_field_names_present(self):
        response = self.client.get(self.create_url, secure=True)
        content = response.content.decode()
        for name in [
            'saml_want_messages_signed', 'saml_want_assertions_signed',
            'saml_authn_requests_signed', 'saml_logout_requests_signed',
            'saml_logout_responses_signed', 'saml_strict_mode',
        ]:
            self.assertIn(f'name="{name}"', content, f'Missing security checkbox: {name}')

    def test_oidc_field_names_present_but_not_required_for_saml(self):
        response = self.client.get(self.create_url, secure=True)
        content = response.content.decode()
        for name in [
            'oidc_client_id', 'oidc_client_secret', 'oidc_discovery_url',
            'oidc_authorization_endpoint', 'oidc_token_endpoint',
            'oidc_userinfo_endpoint', 'oidc_jwks_uri', 'oidc_issuer', 'oidc_scopes',
        ]:
            self.assertIn(f'name="{name}"', content, f'Missing OIDC input: {name}')

    def test_saml_identity_policy_choices_rendered(self):
        response = self.client.get(self.create_url, secure=True)
        content = response.content.decode()
        self.assertIn('saml_identity_policy', content)
        self.assertIn('value="disabled"', content)
        self.assertIn('value="persistent_nameid"', content)

    def test_required_saml_inputs_are_not_disabled(self):
        response = self.client.get(self.create_url, secure=True)
        content = response.content.decode()
        for name in ['saml_idp_entity_id', 'saml_idp_sso_url', 'saml_sp_entity_id', 'saml_sp_acs_url']:
            matches = re.findall(rf'<[^>]*name="{name}"[^>]*>', content)
            self.assertTrue(matches, f'No input found for {name}')
            for tag in matches:
                self.assertNotIn('disabled', tag, f'{name} input is disabled')

    def test_secret_values_not_rendered_on_create_form(self):
        response = self.client.get(self.create_url, secure=True)
        content = response.content.decode()
        # The private-key textarea uses SecretTextarea which returns empty value.
        self.assertNotIn('value="sensitive-secret"', content)

    def test_generic_onboarding_field_names_present(self):
        response = self.client.get(self.create_url, secure=True)
        content = response.content.decode()
        for name in [
            'metadata_xml', 'saml_idp_sso_binding', 'saml_idp_x509cert_additional',
            'saml_immutable_attribute_name',
        ]:
            self.assertIn(f'name="{name}"', content, f'Missing form input: {name}')


class SAMLProviderValidationTests(TestCase):
    """Phase S: unsupported/incomplete active-provider configuration fails visibly."""

    def setUp(self):
        self.superuser = User.objects.create_superuser(
            'saml-validation-admin', 'saml-validation-admin@example.test', 'password'
        )
        self.client.force_login(self.superuser)
        self.create_url = reverse('sso:create_provider')

    def _valid_saml_payload(self, **overrides):
        payload = {
            'name': 'validation-provider',
            'protocol': 'saml',
            'status': 'active',
            'description': '',
            'enabled': 'on',
            'allow_registration': 'on',
            'debug_mode': '',
            'saml_idp_entity_id': 'https://idp.example.test/entity',
            'saml_idp_sso_url': 'https://idp.example.test/sso',
            'saml_idp_sso_binding': 'http_redirect',
            'saml_idp_slo_url': '',
            'saml_idp_x509cert': 'trusted-idp-certificate',
            'saml_idp_x509cert_additional': '',
            'saml_sp_entity_id': 'https://app.example.test/saml/metadata/',
            'saml_sp_acs_url': 'https://app.example.test/saml/acs/',
            'saml_sp_slo_url': '',
            'saml_sp_x509cert': '',
            'saml_sp_private_key': '',
            'saml_name_id_format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            'saml_identity_policy': 'persistent_nameid',
            'saml_immutable_attribute_name': '',
            'saml_want_messages_signed': 'on',
            'saml_want_assertions_signed': 'on',
            'saml_authn_requests_signed': '',
            'saml_logout_requests_signed': '',
            'saml_logout_responses_signed': '',
            'saml_signature_algorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'saml_digest_algorithm': 'http://www.w3.org/2001/04/xmlenc#sha256',
            'saml_strict_mode': 'on',
            'oidc_client_id': '',
            'oidc_client_secret': '',
            'oidc_discovery_url': '',
            'oidc_authorization_endpoint': '',
            'oidc_token_endpoint': '',
            'oidc_userinfo_endpoint': '',
            'oidc_jwks_uri': '',
            'oidc_issuer': '',
            'oidc_scopes': 'openid email profile',
            'attr_email': 'email',
            'attr_first_name': 'first_name',
            'attr_last_name': 'last_name',
            'attr_username': 'email',
        }
        payload.update(overrides)
        return payload

    def test_unsupported_binding_choice_is_rejected(self):
        form = SSOProviderForm(data=self._valid_saml_payload(saml_idp_sso_binding='http_soap'))
        self.assertFalse(form.is_valid())
        self.assertIn('saml_idp_sso_binding', form.errors)

    def test_configured_immutable_attribute_policy_requires_attribute_name(self):
        form = SSOProviderForm(data=self._valid_saml_payload(
            saml_identity_policy='configured_immutable_attribute', saml_immutable_attribute_name='',
        ))
        self.assertFalse(form.is_valid())
        self.assertIn('saml_immutable_attribute_name', form.errors)

        form = SSOProviderForm(data=self._valid_saml_payload(
            saml_identity_policy='configured_immutable_attribute',
            saml_immutable_attribute_name='employeeID',
        ))
        self.assertTrue(form.is_valid())

    def test_signed_authn_requests_require_sp_certificate_and_key(self):
        form = SSOProviderForm(data=self._valid_saml_payload(saml_authn_requests_signed='on'))
        self.assertFalse(form.is_valid())
        self.assertIn(
            'Signing AuthnRequests or logout messages requires an SP certificate and private key.',
            form.non_field_errors(),
        )

        form = SSOProviderForm(data=self._valid_saml_payload(
            saml_authn_requests_signed='on',
            saml_sp_x509cert='sp-certificate',
            saml_sp_private_key='sp-private-key',
        ))
        self.assertTrue(form.is_valid())

    def test_post_binding_with_signing_and_sp_credentials_is_accepted(self):
        form = SSOProviderForm(data=self._valid_saml_payload(
            saml_idp_sso_binding='http_post',
            saml_authn_requests_signed='on',
            saml_sp_x509cert='sp-certificate',
            saml_sp_private_key='sp-private-key',
        ))
        self.assertTrue(form.is_valid())


class SAMLMetadataParseFlowTests(TestCase):
    """Phase J/M: paste-and-parse metadata prefills the form without saving anything."""

    SAML_METADATA_XML = """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                      entityID="https://idp.example.test/entity">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>MIIFAKECERTDATA==</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                             Location="https://idp.example.test/sso/redirect"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                             Location="https://idp.example.test/slo"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"""

    def setUp(self):
        self.superuser = User.objects.create_superuser(
            'metadata-parse-admin', 'metadata-parse-admin@example.test', 'password'
        )
        self.client.force_login(self.superuser)
        self.create_url = reverse('sso:create_provider')

    def test_parsing_valid_metadata_prefills_fields_without_creating_a_provider(self):
        response = self.client.post(self.create_url, {
            'protocol': 'saml',
            'metadata_xml': self.SAML_METADATA_XML,
            'parse_metadata': '1',
        }, secure=True)

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('value="https://idp.example.test/entity"', content)
        self.assertIn('value="https://idp.example.test/sso/redirect"', content)
        self.assertIn('value="https://idp.example.test/slo"', content)
        self.assertIn('MIIFAKECERTDATA==', content)
        self.assertFalse(SSOProvider.objects.exists())

    def test_parsing_malformed_metadata_shows_an_error_and_creates_nothing(self):
        response = self.client.post(self.create_url, {
            'protocol': 'saml',
            'metadata_xml': '<not-valid-xml',
            'parse_metadata': '1',
        }, secure=True)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'IdP metadata XML is malformed.')
        self.assertFalse(SSOProvider.objects.exists())
