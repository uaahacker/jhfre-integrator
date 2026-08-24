import base64
import datetime
import json
import time
import hmac
import tempfile
from datetime import timedelta
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

import jwt
import requests
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.contrib import admin
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import IntegrityError, connection as django_db_connection, models, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import RequestFactory, TestCase, TransactionTestCase, override_settings
from django.utils import timezone
from django.urls import reverse

from sso_auth.forms import SSOProviderForm
from sso_auth.models import (
    SAML_BINDING_HTTP_POST,
    SAML_BINDING_HTTP_REDIRECT,
    SAMLReplayRecord,
    SSOAuditLog,
    SSOProvider,
    SSOUserProfile,
    parse_pem_certificate_list,
)
from sso_auth.saml_metadata_parser import SAMLMetadataError, parse_idp_metadata_xml
from sso_auth.saml_post_binding import SAMLPostBindingError, build_post_authn_request
from sso_auth.saml_replay import register_validated_assertion
from sso_auth.utils import OIDCClient, OIDCValidationError, SSOUtils, load_trusted_oidc_discovery


def _generate_self_signed_cert_and_key():
    """Generate an ephemeral self-signed cert/key pair for SAML signing tests only."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test-sp.example.test')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return cert_pem, key_pem


class OIDCValidationTests(TestCase):
    issuer = 'https://issuer.example.test'
    discovery_url = 'https://issuer.example.test/.well-known/openid-configuration'
    client_id = 'trusted-client'
    key_id = 'trusted-key'

    def setUp(self):
        self.provider = SSOProvider.objects.create(
            name='trusted-oidc',
            protocol='oidc',
            status='active',
            enabled=True,
            allow_registration=False,
            oidc_client_id=self.client_id,
            oidc_client_secret='test-only-secret',
            oidc_discovery_url=self.discovery_url,
            oidc_issuer=self.issuer,
        )
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private_key.public_key()))
        public_jwk.update({'kid': self.key_id, 'use': 'sig', 'alg': 'RS256'})
        self.jwks = {'keys': [public_jwk]}
        self.discovery = {
            'issuer': self.issuer,
            'authorization_endpoint': f'{self.issuer}/authorize',
            'token_endpoint': f'{self.issuer}/token',
            'userinfo_endpoint': f'{self.issuer}/userinfo',
            'jwks_uri': f'{self.issuer}/jwks',
            'id_token_signing_alg_values_supported': ['RS256', 'HS256'],
        }

    @staticmethod
    def response(payload, *, status=200, redirect=False):
        response = Mock()
        response.is_redirect = redirect
        response.json.return_value = payload
        if status >= 400:
            response.raise_for_status.side_effect = RuntimeError('test HTTP failure')
        else:
            response.raise_for_status.return_value = None
        return response

    def make_token(self, *, nonce='trusted-nonce', algorithm='RS256', key=None, **claims):
        payload = {
            'iss': self.issuer,
            'aud': self.client_id,
            'sub': 'immutable-subject',
            'nonce': nonce,
            'iat': int(time.time()),
            'exp': int(time.time()) + 300,
        }
        payload.update(claims)
        signing_key = self.private_key if key is None else key
        return jwt.encode(payload, signing_key, algorithm=algorithm, headers={'kid': self.key_id})

    def oidc_client(self):
        with patch('sso_auth.utils.requests.get', return_value=self.response(self.discovery)):
            return OIDCClient(self.provider)

    def validate(self, token, nonce='trusted-nonce'):
        client = self.oidc_client()
        with patch('sso_auth.utils.requests.get', return_value=self.response(self.jwks)):
            return client.validate_id_token(token, nonce)

    def test_valid_signed_token_and_nonce_are_accepted(self):
        claims = self.validate(self.make_token())
        self.assertEqual(claims['sub'], 'immutable-subject')

    def test_missing_or_mismatched_nonce_is_denied(self):
        token = self.make_token()
        with self.assertRaises(OIDCValidationError):
            self.validate(token, '')
        with self.assertRaises(OIDCValidationError):
            self.validate(token, 'wrong-nonce')

    def test_invalid_signature_none_and_unsupported_algorithms_are_denied(self):
        another_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises(OIDCValidationError):
            self.validate(self.make_token(key=another_key))
        none_token = jwt.encode(
            {
                'iss': self.issuer, 'aud': self.client_id, 'sub': 'immutable-subject',
                'nonce': 'trusted-nonce', 'iat': int(time.time()), 'exp': int(time.time()) + 300,
            },
            key='', algorithm='none', headers={'kid': self.key_id},
        )
        with self.assertRaises(OIDCValidationError):
            self.validate(none_token)
        unsupported = self.make_token(algorithm='HS256', key='not-an-oidc-public-key')
        with self.assertRaises(OIDCValidationError):
            self.validate(unsupported)

    def test_issuer_audience_and_azp_claims_are_enforced(self):
        for claims in (
            {'iss': 'https://other.example.test'},
            {'aud': 'other-client'},
            {'aud': [self.client_id, 'other-client']},
            {'aud': [self.client_id, 'other-client'], 'azp': 'other-client'},
            {'azp': 'other-client'},
        ):
            with self.subTest(claims=claims), self.assertRaises(OIDCValidationError):
                self.validate(self.make_token(**claims))

    def test_exp_iat_and_nbf_claims_are_enforced(self):
        now = int(time.time())
        for claims in (
            {'exp': now - 61},
            {'iat': now + 61},
            {'nbf': now + 61},
        ):
            with self.subTest(claims=claims), self.assertRaises(OIDCValidationError):
                self.validate(self.make_token(**claims))

    def test_unsafe_discovery_urls_and_metadata_are_denied_without_network(self):
        with patch('sso_auth.utils.requests.get') as getter:
            with self.assertRaises(OIDCValidationError):
                load_trusted_oidc_discovery('http://issuer.example.test/.well-known/openid-configuration')
            getter.assert_not_called()

        mismatched_issuer = dict(self.discovery, issuer='https://other.example.test')
        with patch('sso_auth.utils.requests.get', return_value=self.response(mismatched_issuer)):
            with self.assertRaises(OIDCValidationError):
                load_trusted_oidc_discovery(self.discovery_url, self.issuer)

        unsafe_endpoint = dict(self.discovery, token_endpoint='https://other.example.test/token')
        with patch('sso_auth.utils.requests.get', return_value=self.response(unsafe_endpoint)):
            with self.assertRaises(OIDCValidationError):
                load_trusted_oidc_discovery(self.discovery_url, self.issuer)

    def test_jwks_failure_denies_validation(self):
        client = self.oidc_client()
        with patch('sso_auth.utils.requests.get', side_effect=requests.ConnectionError('no jwks')):
            with self.assertRaises(OIDCValidationError):
                client.validate_id_token(self.make_token(), 'trusted-nonce')


class OIDCCallbackStateTests(TestCase):
    def setUp(self):
        self.provider = SSOProvider.objects.create(
            name='callback-oidc', protocol='oidc', status='active', enabled=True,
            oidc_client_id='callback-client', oidc_client_secret='test-only-secret',
            oidc_discovery_url='https://issuer.example.test/.well-known/openid-configuration',
            oidc_issuer='https://issuer.example.test',
        )
        self.user = User.objects.create_user('oidc-user', 'oidc@example.test', 'password')
        self.url = reverse('sso:oidc_callback', args=[self.provider.name])

    def set_transaction(self, *, state='state-value', nonce='nonce-value', provider_name=None):
        session = self.client.session
        session['oidc_state'] = state
        session['oidc_nonce'] = nonce
        session['oidc_provider'] = provider_name or self.provider.name
        session['oidc_next'] = '/home/'
        session['oidc_started_at'] = time.time()
        session.save()

    def assert_transaction_consumed(self):
        session = self.client.session
        for key in ('oidc_state', 'oidc_nonce', 'oidc_provider', 'oidc_next', 'oidc_started_at'):
            self.assertNotIn(key, session)

    def test_missing_wrong_reused_and_provider_mismatched_state_are_denied_and_consumed(self):
        cases = (
            ({'code': 'code'}, self.provider.name),
            ({'state': 'wrong-state', 'code': 'code'}, self.provider.name),
            ({'state': 'state-value', 'code': 'code'}, 'other-provider'),
        )
        for params, callback_provider in cases:
            with self.subTest(params=params, callback_provider=callback_provider):
                self.set_transaction()
                response = self.client.get(
                    reverse('sso:oidc_callback', args=[callback_provider]), params, secure=True
                )
                self.assertRedirects(response, reverse('login'), fetch_redirect_response=False)
                self.assert_transaction_consumed()

        self.set_transaction()
        with patch('sso_auth.views.OIDCClient') as oidc_client, patch(
            'sso_auth.views.SSOUtils.create_or_update_user', return_value=self.user
        ):
            oidc_client.return_value.exchange_code_for_token.return_value = {
                'id_token': 'validated-token', 'access_token': 'access-token',
            }
            oidc_client.return_value.validate_id_token.return_value = {'sub': 'immutable-subject'}
            oidc_client.return_value.get_user_info.return_value = {
                'sub': 'immutable-subject', 'email': 'oidc@example.test',
            }
            first_response = self.client.get(self.url, {'state': 'state-value', 'code': 'code'}, secure=True)
        self.assertRedirects(first_response, '/home/', fetch_redirect_response=False)
        self.assert_transaction_consumed()
        reused_response = self.client.get(self.url, {'state': 'state-value', 'code': 'code'}, secure=True)
        self.assertRedirects(reused_response, reverse('login'), fetch_redirect_response=False)

    def test_matching_nonce_reaches_provisioning_only_after_token_validation(self):
        self.set_transaction()
        with patch('sso_auth.views.OIDCClient') as oidc_client, patch(
            'sso_auth.views.SSOUtils.create_or_update_user', return_value=self.user
        ) as provision:
            oidc_client.return_value.exchange_code_for_token.return_value = {
                'id_token': 'validated-token', 'access_token': 'access-token',
            }
            oidc_client.return_value.validate_id_token.return_value = {'sub': 'immutable-subject'}
            oidc_client.return_value.get_user_info.return_value = {
                'sub': 'immutable-subject', 'email': 'oidc@example.test',
            }
            response = self.client.get(self.url, {'state': 'state-value', 'code': 'code'}, secure=True)
        self.assertRedirects(response, '/home/', fetch_redirect_response=False)
        oidc_client.return_value.validate_id_token.assert_called_once_with('validated-token', 'nonce-value')
        provision.assert_called_once_with(
            self.provider,
            {'sub': 'immutable-subject', 'email': 'oidc@example.test'},
            sso_id='immutable-subject',
            raw_attributes={'sub': 'immutable-subject', 'email': 'oidc@example.test'},
            email_verified=False,
            require_verified_email=True,
        )

    def test_failed_token_validation_consumes_transaction_before_provisioning(self):
        self.set_transaction()
        with patch('sso_auth.views.OIDCClient') as oidc_client, patch(
            'sso_auth.views.SSOUtils.create_or_update_user'
        ) as provision:
            oidc_client.return_value.exchange_code_for_token.return_value = {
                'id_token': 'invalid-token', 'access_token': 'access-token',
            }
            oidc_client.return_value.validate_id_token.side_effect = OIDCValidationError('invalid')
            response = self.client.get(self.url, {'state': 'state-value', 'code': 'code'}, secure=True)
        self.assertRedirects(response, reverse('login'), fetch_redirect_response=False)
        provision.assert_not_called()
        self.assert_transaction_consumed()


class SSOManagementAuthorizationTests(TestCase):
    def setUp(self):
        self.normal_user = User.objects.create_user('sso-normal', password='password')
        self.staff_user = User.objects.create_user('sso-staff', password='password', is_staff=True)
        self.superuser = User.objects.create_superuser('sso-admin', 'sso-admin@example.test', 'password')
        self.url = reverse('sso:management')

    def test_only_superusers_can_access_custom_sso_management(self):
        self.assertEqual(self.client.get(self.url, secure=True).status_code, 302)
        for user in (self.normal_user, self.staff_user):
            self.client.force_login(user)
            self.assertEqual(self.client.get(self.url, secure=True).status_code, 403)
            self.client.logout()
        self.client.force_login(self.superuser)
        self.assertEqual(self.client.get(self.url, secure=True).status_code, 200)


class SSOProviderEditAuthorizationTests(TestCase):
    """Regression coverage for the redirect loop: create/edit/delete/test used the bare
    user_passes_test decorator, which -- unlike UserPassesTestMixin on SSOManagementView
    above -- redirected an authenticated-but-unauthorized user back to /login/ instead of
    denying outright, and LoginView then bounced them straight back to the same page,
    looping forever."""

    def setUp(self):
        self.normal_user = User.objects.create_user('edit-normal', password='password')
        self.superuser = User.objects.create_superuser('edit-admin', 'edit-admin@example.test', 'password')
        self.provider = SSOProvider.objects.create(name='auth-check-provider', protocol='saml')
        self.edit_url = reverse('sso:edit_provider', args=[self.provider.id])
        self.create_url = reverse('sso:create_provider')
        self.delete_url = reverse('sso:delete_provider', args=[self.provider.id])
        self.test_url = reverse('sso:test_provider', args=[self.provider.id])

    def test_anonymous_request_redirects_to_login_with_safe_next(self):
        response = self.client.get(self.edit_url, secure=True)
        self.assertRedirects(response, f'/login/?next={self.edit_url}', fetch_redirect_response=False)

    def test_authenticated_normal_user_gets_403_not_a_login_redirect(self):
        self.client.force_login(self.normal_user)
        self.assertEqual(self.client.get(self.edit_url, secure=True).status_code, 403)
        self.assertEqual(self.client.get(self.create_url, secure=True).status_code, 403)
        self.assertEqual(self.client.post(self.delete_url, secure=True).status_code, 403)
        self.assertEqual(self.client.post(self.test_url, secure=True).status_code, 403)
        provider = SSOProvider.objects.get(pk=self.provider.pk)
        self.assertEqual(provider.name, 'auth-check-provider')

    def test_superuser_can_reach_edit_page(self):
        self.client.force_login(self.superuser)
        self.assertEqual(self.client.get(self.edit_url, secure=True).status_code, 200)

    def test_authenticated_normal_user_reaching_login_with_next_does_not_loop(self):
        """Simulates the second half of the loop: the browser following the decorator's
        302 to /login/?next=<denied page>. That must resolve in a single further hop,
        not bounce the user back to the protected page and start the cycle again."""
        self.client.force_login(self.normal_user)

        response = self.client.get(reverse('login'), {'next': self.edit_url}, secure=True, follow=True)

        self.assertEqual(response.redirect_chain, [(self.edit_url, 302)])
        self.assertEqual(response.status_code, 403)


class SSOProviderSecretCapacityTests(TestCase):
    def test_oidc_client_secret_field_is_an_unbounded_text_field(self):
        field = SSOProvider._meta.get_field('oidc_client_secret')

        self.assertIsInstance(field, models.TextField)
        self.assertTrue(field.blank)
        self.assertTrue(field.null)
        self.assertEqual(field.verbose_name, 'OIDC Client Secret')

    def test_oidc_client_secrets_over_255_characters_and_existing_short_values_round_trip(self):
        long_secret = 's' * 512
        long_secret_provider = SSOProvider.objects.create(
            name='long-oidc-client-secret',
            protocol='oidc',
            oidc_client_secret=long_secret,
        )
        short_secret_provider = SSOProvider.objects.create(
            name='short-oidc-client-secret',
            protocol='oidc',
            oidc_client_secret='existing-short-secret',
        )

        long_secret_provider.refresh_from_db()
        short_secret_provider.refresh_from_db()

        from sso_auth.secret_encryption import decrypt_sso_secret

        self.assertTrue(long_secret_provider.oidc_client_secret.startswith('enc:v1:'))
        self.assertNotIn(long_secret, long_secret_provider.oidc_client_secret)
        self.assertEqual(decrypt_sso_secret(long_secret_provider.oidc_client_secret), long_secret)
        self.assertEqual(
            decrypt_sso_secret(short_secret_provider.oidc_client_secret),
            'existing-short-secret',
        )


class SSOExternalIdentityConstraintTests(TestCase):
    def setUp(self):
        self.provider_a = SSOProvider.objects.create(name='identity-provider-a', protocol='oidc')
        self.provider_b = SSOProvider.objects.create(name='identity-provider-b', protocol='oidc')

    def create_user(self, username, **attributes):
        return User.objects.create_user(username, password='password', **attributes)

    def test_different_subjects_same_provider_and_same_subject_different_providers_are_allowed(self):
        SSOUserProfile.objects.create(
            user=self.create_user('identity-user-a'), provider=self.provider_a, sso_id='subject-a',
        )
        SSOUserProfile.objects.create(
            user=self.create_user('identity-user-b'), provider=self.provider_a, sso_id='subject-b',
        )
        SSOUserProfile.objects.create(
            user=self.create_user('identity-user-c'), provider=self.provider_b, sso_id='subject-a',
        )

        self.assertEqual(SSOUserProfile.objects.count(), 3)

    def test_duplicate_provider_and_subject_is_rejected_by_database_constraint(self):
        SSOUserProfile.objects.create(
            user=self.create_user('identity-duplicate-a'), provider=self.provider_a, sso_id='duplicate-subject',
        )

        with self.assertRaises(IntegrityError), transaction.atomic():
            SSOUserProfile.objects.create(
                user=self.create_user('identity-duplicate-b'), provider=self.provider_a, sso_id='duplicate-subject',
            )

    def test_existing_one_to_one_user_uniqueness_and_privilege_fields_remain_unchanged(self):
        user = self.create_user('identity-one-to-one', is_staff=False, is_superuser=False)
        SSOUserProfile.objects.create(user=user, provider=self.provider_a, sso_id='first-subject')

        with self.assertRaises(IntegrityError), transaction.atomic():
            SSOUserProfile.objects.create(user=user, provider=self.provider_b, sso_id='second-subject')

        user.refresh_from_db()
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_model_exposes_expected_constraint_and_empty_subject_validation_policy(self):
        constraints = {constraint.name: constraint for constraint in SSOUserProfile._meta.constraints}
        constraint = constraints['sso_auth_provider_sso_id_uniq']
        self.assertEqual(tuple(constraint.fields), ('provider', 'sso_id'))

        empty_subject_profile = SSOUserProfile(
            user=self.create_user('identity-empty-subject'), provider=self.provider_a, sso_id='',
        )
        with self.assertRaises(ValidationError):
            empty_subject_profile.full_clean()


class SSOProviderSubjectProvisioningTests(TestCase):
    def setUp(self):
        self.provider_a = SSOProvider.objects.create(
            name='provisioning-provider-a', protocol='oidc', status='active', enabled=True,
            allow_registration=True, attr_username='username',
        )
        self.provider_b = SSOProvider.objects.create(
            name='provisioning-provider-b', protocol='oidc', status='active', enabled=True,
            allow_registration=True, attr_username='username',
        )
        SSOProvider.objects.filter(pk__in=[self.provider_a.pk, self.provider_b.pk]).update(enabled=True)
        self.provider_a.refresh_from_db()
        self.provider_b.refresh_from_db()

    def claims(self, email='new-user@example.test', username='new-user', **extra):
        claims = {'email': email, 'username': username, 'first_name': 'New', 'last_name': 'User'}
        claims.update(extra)
        return claims

    def provision(self, provider, subject, **claim_overrides):
        return SSOUtils.create_or_update_user(
            provider, self.claims(**claim_overrides), sso_id=subject,
            raw_attributes=self.claims(**claim_overrides), email_verified=True,
        )

    def test_existing_provider_subject_mapping_ignores_changed_email_and_username(self):
        user = User.objects.create_user('mapped-user', 'original@example.test', 'password')
        profile = SSOUserProfile.objects.create(user=user, provider=self.provider_a, sso_id='subject-a')

        resolved = self.provision(
            self.provider_a, 'subject-a', email='changed@example.test', username='changed-user',
            first_name='Changed', last_name='Name',
        )

        self.assertEqual(resolved.pk, user.pk)
        user.refresh_from_db()
        profile.refresh_from_db()
        self.assertEqual(user.email, 'original@example.test')
        self.assertEqual(user.username, 'mapped-user')
        self.assertEqual(user.first_name, 'Changed')
        self.assertEqual(profile.sso_id, 'subject-a')

    def test_provider_namespace_and_same_provider_subjects_remain_isolated(self):
        provider_a_user = self.provision(self.provider_a, 'shared-subject')
        provider_b_user = self.provision(
            self.provider_b, 'shared-subject', email='provider-b@example.test', username='provider-b-user',
        )
        other_subject_user = self.provision(
            self.provider_a, 'different-subject', email='other@example.test', username='other-user',
        )

        self.assertNotEqual(provider_a_user.pk, provider_b_user.pk)
        self.assertNotEqual(provider_a_user.pk, other_subject_user.pk)
        self.assertEqual(SSOUserProfile.objects.count(), 3)

    def test_unknown_subject_collisions_never_link_or_modify_existing_users(self):
        users = (
            User.objects.create_user('normal-user', 'normal@example.test', 'password'),
            User.objects.create_user('staff-user', 'staff@example.test', 'password', is_staff=True),
            User.objects.create_superuser('admin-user', 'admin@example.test', 'password'),
        )
        for index, user in enumerate(users):
            with self.subTest(user=user.pk):
                result = self.provision(
                    self.provider_a, f'collision-subject-{index}', email=user.email,
                    username=f'new-user-{index}', first_name='Attacker', last_name='Claim',
                )
                self.assertIsNone(result)
                user.refresh_from_db()
                self.assertNotEqual(user.first_name, 'Attacker')
                self.assertFalse(SSOUserProfile.objects.filter(user=user).exists())

        username_collision = self.provision(
            self.provider_a, 'username-collision', email='unique@example.test', username='normal-user',
        )
        self.assertIsNone(username_collision)
        self.assertEqual(SSOUserProfile.objects.count(), 0)

    def test_registration_policy_verified_email_and_privilege_protection(self):
        self.provider_a.allow_registration = False
        self.provider_a.save(update_fields=['allow_registration'])
        self.assertIsNone(self.provision(self.provider_a, 'registration-disabled'))

        self.provider_a.allow_registration = True
        self.provider_a.save(update_fields=['allow_registration'])
        self.assertIsNone(SSOUtils.create_or_update_user(
            self.provider_a, self.claims(), sso_id='unverified-email', email_verified=False,
        ))
        user = self.provision(
            self.provider_a, 'registration-created', roles=['admin'], groups=['administrators'],
        )
        self.assertIsNotNone(user)
        user.refresh_from_db()
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertEqual(list(user.groups.all()), [])
        self.assertTrue(SSOUserProfile.objects.filter(user=user, sso_id='registration-created').exists())

    def test_blank_subject_inactive_provider_and_profile_creation_failure_do_not_persist_user(self):
        self.assertIsNone(self.provision(self.provider_a, '   '))
        inactive = SSOProvider.objects.create(
            name='inactive-provisioning-provider', protocol='oidc', status='inactive', enabled=True,
        )
        self.assertIsNone(self.provision(inactive, 'inactive-subject'))

        with patch.object(SSOUserProfile.objects, 'create', side_effect=IntegrityError):
            self.assertIsNone(self.provision(
                self.provider_a, 'profile-create-failure', email='atomic@example.test', username='atomic-user',
            ))
        self.assertFalse(User.objects.filter(username='atomic-user').exists())
        self.assertEqual(SSOUserProfile.objects.count(), 0)

    def test_named_inactive_oidc_provider_and_saml_assertion_do_not_authenticate(self):
        inactive_oidc = SSOProvider.objects.create(
            name='inactive-named-oidc', protocol='oidc', status='inactive', enabled=True,
        )
        self.assertEqual(
            self.client.get(reverse('sso:oidc_login_named', args=[inactive_oidc.name]), secure=True).status_code,
            404,
        )

        saml_provider = SSOProvider.objects.create(
            name='saml-identity-policy', protocol='saml', status='active', enabled=True,
        )
        auth = Mock()
        auth.get_errors.return_value = []
        auth.is_authenticated.return_value = True
        auth.get_attributes.return_value = {'email': ['admin@example.test'], 'username': ['admin-user']}
        auth.get_nameid.return_value = ''
        with patch('sso_auth.views.OneLogin_Saml2_Auth', return_value=auth):
            response = self.client.post(reverse('sso:saml_acs_named', args=[saml_provider.name]), secure=True)
        self.assertRedirects(response, reverse('login'), fetch_redirect_response=False)
        self.assertFalse(SSOUserProfile.objects.filter(provider=saml_provider).exists())


class SAMLRequestCorrelationTests(TestCase):
    def setUp(self):
        self.provider = SSOProvider.objects.create(
            name='correlated-saml-provider', protocol='saml', status='active', enabled=True,
            saml_idp_entity_id='https://idp.example.test/entity',
            saml_idp_sso_url='https://idp.example.test/sso',
            saml_idp_x509cert='trusted-idp-certificate',
            saml_sp_entity_id='https://app.example.test/saml/metadata/',
            saml_sp_acs_url='https://app.example.test/saml/acs/',
            saml_want_messages_signed=True,
            saml_want_assertions_signed=True,
            saml_strict_mode=True,
            saml_identity_policy='persistent_nameid',
        )
        self.login_url = reverse('sso:saml_login_named', args=[self.provider.name])
        self.acs_url = reverse('sso:saml_acs_named', args=[self.provider.name])

    def set_request_state(self, *, request_id='request-id', provider_id=None, started_at=None, next_url='/safe/'):
        session = self.client.session
        session['saml_authn_request_id'] = request_id
        session['saml_authn_provider_id'] = provider_id if provider_id is not None else self.provider.pk
        session['saml_authn_started_at'] = time.time() if started_at is None else started_at
        session['saml_authn_next'] = next_url
        session.save()

    def assert_request_state_consumed(self):
        session = self.client.session
        for key in ('saml_authn_request_id', 'saml_authn_provider_id', 'saml_authn_started_at', 'saml_authn_next'):
            self.assertNotIn(key, session)

    def valid_auth(self):
        auth = Mock()
        auth.get_errors.return_value = []
        auth.is_authenticated.return_value = True
        auth.get_last_assertion_id.return_value = 'validated-assertion-id'
        auth.get_nameid.return_value = 'untrusted-nameid'
        auth.get_nameid_format.return_value = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
        return auth

    def test_login_stores_authnrequest_state_and_safe_target(self):
        auth = Mock()
        auth.login.return_value = 'https://idp.example.test/login'
        auth.get_last_request_id.return_value = 'generated-request-id'

        with patch('sso_auth.views.OneLogin_Saml2_Auth', return_value=auth):
            response = self.client.get(self.login_url, {'next': '/safe/'}, secure=True)

        self.assertRedirects(response, 'https://idp.example.test/login', fetch_redirect_response=False)
        session = self.client.session
        self.assertEqual(session['saml_authn_request_id'], 'generated-request-id')
        self.assertEqual(session['saml_authn_provider_id'], self.provider.pk)
        self.assertEqual(session['saml_authn_next'], '/safe/')
        self.assertIsInstance(session['saml_authn_started_at'], float)

    def test_login_sanitizes_unsafe_external_next_target(self):
        auth = Mock()
        auth.login.return_value = 'https://idp.example.test/login'
        auth.get_last_request_id.return_value = 'generated-request-id-unsafe-next'

        with patch('sso_auth.views.OneLogin_Saml2_Auth', return_value=auth):
            response = self.client.get(
                self.login_url, {'next': 'https://attacker.example.test/steal'}, secure=True,
            )

        self.assertRedirects(response, 'https://idp.example.test/login', fetch_redirect_response=False)
        session = self.client.session
        self.assertEqual(session['saml_authn_next'], reverse('home'))

    def test_acs_passes_request_id_and_consumes_state_on_successful_validation(self):
        self.set_request_state()
        auth = self.valid_auth()

        with patch('sso_auth.views.OneLogin_Saml2_Auth', return_value=auth):
            response = self.client.post(self.acs_url, secure=True)

        auth.process_response.assert_called_once_with(request_id='request-id')
        self.assertRedirects(response, reverse('login'), fetch_redirect_response=False)
        self.assert_request_state_consumed()
        self.assertFalse(SSOUserProfile.objects.exists())
        self.assertEqual(SAMLReplayRecord.objects.filter(provider=self.provider).count(), 1)

    def test_missing_mismatched_expired_and_reused_state_are_denied_and_consumed(self):
        cases = (
            (False, {}, self.acs_url),
            (True, {'provider_id': 999999}, self.acs_url),
            (True, {'started_at': time.time() - 601}, self.acs_url),
            (True, {}, reverse('sso:saml_acs_named', args=['different-provider'])),
        )
        for has_state, state, url in cases:
            with self.subTest(state=state, url=url):
                if has_state:
                    self.set_request_state(**state)
                response = self.client.post(url, secure=True)
                self.assertRedirects(response, reverse('login'), fetch_redirect_response=False)
                self.assert_request_state_consumed()

        self.set_request_state()
        auth = self.valid_auth()
        with patch('sso_auth.views.OneLogin_Saml2_Auth', return_value=auth):
            self.client.post(self.acs_url, secure=True)
        replay = self.client.post(self.acs_url, secure=True)
        self.assertRedirects(replay, reverse('login'), fetch_redirect_response=False)

    def test_failed_validation_and_external_relaystate_do_not_retain_state_or_redirect(self):
        self.set_request_state(next_url='/safe/')
        auth = self.valid_auth()
        auth.get_errors.return_value = ['invalid-response']

        with patch('sso_auth.views.OneLogin_Saml2_Auth', return_value=auth):
            response = self.client.post(self.acs_url, {'RelayState': 'https://attacker.example.test/'}, secure=True)

        self.assertRedirects(response, reverse('login'), fetch_redirect_response=False)
        self.assert_request_state_consumed()

    def test_active_runtime_settings_require_strict_both_signatures_and_idp_certificate(self):
        settings = self.provider.get_saml_settings()
        self.assertTrue(settings['strict'])
        self.assertTrue(settings['security']['wantMessagesSigned'])
        self.assertTrue(settings['security']['wantAssertionsSigned'])

        self.provider.saml_want_messages_signed = False
        settings = self.provider.get_saml_settings()
        self.assertFalse(settings['security']['wantMessagesSigned'])
        self.assertTrue(settings['security']['wantAssertionsSigned'])

        for field_name, value in (
            ('saml_strict_mode', False),
            ('saml_want_assertions_signed', False),
            ('saml_idp_x509cert', ''),
        ):
            with self.subTest(field_name=field_name):
                setattr(self.provider, field_name, value)
                with self.assertRaises(ValueError):
                    self.provider.get_saml_settings()
                setattr(self.provider, field_name, True if field_name != 'saml_idp_x509cert' else 'trusted-idp-certificate')

    def test_active_provider_with_unsigned_outer_response_still_requires_assertion(self):
        self.provider.saml_want_messages_signed = False
        self.provider.saml_want_assertions_signed = True
        settings = self.provider.get_saml_settings()
        self.assertFalse(settings['security']['wantMessagesSigned'])
        self.assertTrue(settings['security']['wantAssertionsSigned'])

        self.provider.saml_want_assertions_signed = False
        with self.assertRaisesMessage(ValueError, 'signed assertions'):
            self.provider.get_saml_settings()

    def test_mocked_unsigned_outer_response_with_signed_assertion_reaches_provisioning(self):
        self.provider.saml_want_messages_signed = False
        auth = self.valid_auth()
        auth.get_nameid.return_value = 'persistent-subject-optional-response'
        auth.get_nameid_format.return_value = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
        auth.get_attributes.return_value = {
            'email': ['optional-response@example.test'],
            'username': ['optional-response-user'],
        }
        self.set_request_state(request_id='optional-response-request')

        with patch('sso_auth.views.OneLogin_Saml2_Auth', return_value=auth):
            response = self.client.post(self.acs_url, secure=True)

        self.assertRedirects(response, '/safe/', fetch_redirect_response=False)
        auth.process_response.assert_called_once_with(request_id='optional-response-request')
        self.assertTrue(SSOUserProfile.objects.filter(
            provider=self.provider,
            sso_id='persistent-subject-optional-response',
        ).exists())

    def test_persistent_nameid_policy_provisions_only_after_replay_registration(self):
        self.set_request_state(next_url='/safe/')
        auth = self.valid_auth()
        auth.get_nameid.return_value = 'persistent-subject-123'
        auth.get_nameid_format.return_value = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
        auth.get_attributes.return_value = {
            'email': ['saml-new@example.test'], 'username': ['saml-new-user'],
            'first_name': ['Saml'], 'last_name': ['User'], 'roles': ['admin'],
        }

        with patch('sso_auth.views.OneLogin_Saml2_Auth', return_value=auth):
            response = self.client.post(self.acs_url, secure=True)

        self.assertRedirects(response, '/safe/', fetch_redirect_response=False)
        profile = SSOUserProfile.objects.get(provider=self.provider, sso_id='persistent-subject-123')
        self.assertFalse(profile.user.is_staff)
        self.assertFalse(profile.user.is_superuser)
        self.assertEqual(SAMLReplayRecord.objects.filter(provider=self.provider).count(), 1)

    def test_saml_login_for_normal_user_targeting_superuser_only_page_does_not_loop(self):
        """Regression for the post-SAML-login redirect loop: a freshly provisioned
        normal user landing on a superuser-only next target must be denied once, not
        bounced through /login/ back to the same page forever."""
        edit_url = reverse('sso:edit_provider', args=[self.provider.id])
        self.set_request_state(next_url=edit_url)
        auth = self.valid_auth()
        auth.get_nameid.return_value = 'normal-user-loop-subject'
        auth.get_nameid_format.return_value = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
        auth.get_attributes.return_value = {
            'email': ['normal-loop-user@example.test'], 'username': ['normal-loop-user'],
        }

        with patch('sso_auth.views.OneLogin_Saml2_Auth', return_value=auth):
            response = self.client.post(self.acs_url, secure=True, follow=True)

        self.assertEqual(response.redirect_chain, [(edit_url, 302)])
        self.assertEqual(response.status_code, 403)
        profile = SSOUserProfile.objects.get(provider=self.provider, sso_id='normal-user-loop-subject')
        self.assertFalse(profile.user.is_superuser)

    def test_saml_login_for_normal_user_targeting_home_still_succeeds(self):
        home_url = reverse('home')
        self.set_request_state(next_url=home_url)
        auth = self.valid_auth()
        auth.get_nameid.return_value = 'normal-user-home-subject'
        auth.get_nameid_format.return_value = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
        auth.get_attributes.return_value = {
            'email': ['normal-home-user@example.test'], 'username': ['normal-home-user'],
        }

        with patch('sso_auth.views.OneLogin_Saml2_Auth', return_value=auth):
            response = self.client.post(self.acs_url, secure=True, follow=True)

        self.assertEqual(response.redirect_chain, [(home_url, 302)])
        self.assertEqual(response.status_code, 200)

    def test_disabled_policy_and_nonpersistent_nameid_remain_denied_after_replay_registration(self):
        for policy, nameid_format in (
            ('disabled', 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'),
            ('persistent_nameid', 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'),
        ):
            with self.subTest(policy=policy, nameid_format=nameid_format):
                self.provider.saml_identity_policy = policy
                self.provider.save(update_fields=['saml_identity_policy'])
                self.set_request_state(request_id=f'request-{policy}-{nameid_format.rsplit(":", 1)[-1]}')
                auth = self.valid_auth()
                auth.get_nameid.return_value = 'not-accepted-subject'
                auth.get_nameid_format.return_value = nameid_format
                auth.get_attributes.return_value = {'email': ['unused@example.test'], 'username': ['unused']}
                with patch('sso_auth.views.OneLogin_Saml2_Auth', return_value=auth):
                    response = self.client.post(self.acs_url, secure=True)
                self.assertRedirects(response, reverse('login'), fetch_redirect_response=False)
                self.assertEqual(SAMLReplayRecord.objects.filter(provider=self.provider).count(), 1)
                SAMLReplayRecord.objects.all().delete()
                self.assertFalse(SSOUserProfile.objects.filter(provider=self.provider).exists())

    def test_inactive_named_provider_is_denied_before_saml_library_use(self):
        inactive = SSOProvider.objects.create(
            name='inactive-correlated-saml', protocol='saml', status='inactive', enabled=True,
        )
        with patch('sso_auth.views.OneLogin_Saml2_Auth') as auth:
            response = self.client.get(reverse('sso:saml_login_named', args=[inactive.name]), secure=True)
        self.assertEqual(response.status_code, 404)
        auth.assert_not_called()


class SAMLACSDiagnosticTests(TestCase):
    def test_known_toolkit_reasons_map_to_sanitized_categories(self):
        from sso_auth.views import _sanitize_saml_validation_category

        cases = (
            ('Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd', 'SAML_SCHEMA_VALIDATION_FAILED'),
            ('The Message of the Response is not signed', 'SAML_RESPONSE_SIGNATURE_MISSING'),
            ('The Assertion of the Response is not signed', 'SAML_ASSERTION_SIGNATURE_MISSING'),
            ('Signature validation failed. SAML Response rejected', 'SAML_SIGNATURE_INVALID'),
            ('Invalid issuer in the Assertion/Response', 'SAML_ISSUER_INVALID'),
            ('is not a valid audience for this Response', 'SAML_AUDIENCE_INVALID'),
            ('The response was received at the wrong destination', 'SAML_DESTINATION_INVALID'),
            ('The InResponseTo does not match', 'SAML_INRESPONSETO_INVALID'),
            ('The assertion has expired', 'SAML_ASSERTION_EXPIRED'),
        )
        for reason, expected in cases:
            with self.subTest(reason=reason):
                self.assertEqual(_sanitize_saml_validation_category(reason=reason), expected)

    def test_unknown_reason_is_not_written_to_logs(self):
        from sso_auth.views import _log_saml_failure, _sanitize_saml_validation_category

        sentinel = '<SAMLResponse>secret-xml-sentinel</SAMLResponse>'
        category = _sanitize_saml_validation_category(reason=sentinel)
        self.assertEqual(category, 'SAML_TOOLKIT_ERROR')
        with self.assertLogs('sso_auth.views', level='WARNING') as captured:
            _log_saml_failure(None, 'toolkit_errors', category)
        output = '\n'.join(captured.output)
        self.assertIn('SAML_TOOLKIT_ERROR', output)
        self.assertNotIn(sentinel, output)

    def test_unknown_toolkit_reason_maps_to_generic_category(self):
        from sso_auth.views import _sanitize_saml_validation_category

        self.assertEqual(
            _sanitize_saml_validation_category(
                errors=['unknown-toolkit-code'], reason='opaque reason sentinel',
            ),
            'SAML_TOOLKIT_ERROR',
        )


@override_settings(ALLOWED_HOSTS=['testserver', 'example.com', '127.0.0.1'])
class SAMLRequestPreparationTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def prepare(self, path='/sso/saml/acs/', **headers):
        from sso_auth.views import prepare_django_request

        request = self.factory.post(path, **headers)
        return prepare_django_request(request)

    def test_local_http_preserves_explicit_internal_port(self):
        request_data = self.prepare(
            HTTP_HOST='127.0.0.1:8000', SERVER_PORT='8000'
        )

        self.assertEqual(request_data['https'], 'off')
        self.assertEqual(request_data['http_host'], '127.0.0.1:8000')
        self.assertEqual(request_data['server_port'], '8000')

    @override_settings(
        SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO', 'https'),
        USE_X_FORWARDED_HOST=False,
    )
    def test_trusted_public_https_uses_standard_external_port(self):
        request_data = self.prepare(
            HTTP_HOST='example.com',
            HTTP_X_FORWARDED_PROTO='https',
            SERVER_PORT='8000',
        )

        self.assertEqual(request_data['https'], 'on')
        self.assertEqual(request_data['http_host'], 'example.com')
        self.assertEqual(request_data['server_port'], '443')

    @override_settings(
        SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO', 'https'),
        USE_X_FORWARDED_HOST=False,
    )
    def test_public_https_explicit_nonstandard_port_is_preserved(self):
        request_data = self.prepare(
            HTTP_HOST='example.com:8443',
            HTTP_X_FORWARDED_PROTO='https',
            SERVER_PORT='8000',
        )

        self.assertEqual(request_data['https'], 'on')
        self.assertEqual(request_data['http_host'], 'example.com:8443')
        self.assertEqual(request_data['server_port'], '8443')

    def test_public_http_without_explicit_port_uses_port_80(self):
        request_data = self.prepare(
            HTTP_HOST='example.com', SERVER_PORT='8000'
        )

        self.assertEqual(request_data['https'], 'off')
        self.assertEqual(request_data['server_port'], '80')

    @override_settings(
        SECURE_PROXY_SSL_HEADER=None,
        USE_X_FORWARDED_HOST=False,
    )
    def test_untrusted_forwarded_headers_do_not_change_public_request(self):
        request_data = self.prepare(
            HTTP_HOST='example.com',
            HTTP_X_FORWARDED_PROTO='https',
            HTTP_X_FORWARDED_HOST='attacker.example',
            SERVER_PORT='8000',
        )

        self.assertEqual(request_data['https'], 'off')
        self.assertEqual(request_data['http_host'], 'example.com')
        self.assertEqual(request_data['server_port'], '80')

    @override_settings(
        SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO', 'https'),
        USE_X_FORWARDED_HOST=False,
    )
    def test_acs_request_data_reconstructs_public_https_url(self):
        from onelogin.saml2.utils import OneLogin_Saml2_Utils

        request_data = self.prepare(
            HTTP_HOST='example.com',
            HTTP_X_FORWARDED_PROTO='https',
            SERVER_PORT='8000',
        )

        reconstructed_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        self.assertEqual(reconstructed_url, 'https://example.com/sso/saml/acs/')
        self.assertNotIn(':8000', reconstructed_url)


class SAMLAssertionReplayTests(TestCase):
    def setUp(self):
        self.provider_a = SSOProvider.objects.create(name='replay-provider-a', protocol='saml')
        self.provider_b = SSOProvider.objects.create(name='replay-provider-b', protocol='saml')

    def test_first_use_is_registered_hashed_and_replay_is_denied_per_provider(self):
        assertion_id = 'assertion-id-not-for-storage'
        self.assertTrue(register_validated_assertion(self.provider_a, assertion_id))
        self.assertFalse(register_validated_assertion(self.provider_a, assertion_id))
        self.assertTrue(register_validated_assertion(self.provider_b, assertion_id))

        records = SAMLReplayRecord.objects.order_by('provider_id')
        self.assertEqual(records.count(), 2)
        self.assertTrue(all(record.expires_at > record.first_seen_at for record in records))
        self.assertTrue(all(assertion_id not in record.assertion_id_hash for record in records))

    def test_missing_identifier_fails_closed_and_expired_cleanup_preserves_nonexpired_records(self):
        with self.assertRaises(ValueError):
            register_validated_assertion(self.provider_a, '   ')

        expired = SAMLReplayRecord.objects.create(
            provider=self.provider_a, assertion_id_hash='a' * 64,
            expires_at=timezone.now() - timedelta(seconds=1),
        )
        retained = SAMLReplayRecord.objects.create(
            provider=self.provider_b, assertion_id_hash='b' * 64,
            expires_at=timezone.now() + timedelta(hours=1),
        )
        self.assertTrue(register_validated_assertion(self.provider_a, 'fresh-assertion-id'))
        self.assertFalse(SAMLReplayRecord.objects.filter(pk=expired.pk).exists())
        self.assertTrue(SAMLReplayRecord.objects.filter(pk=retained.pk).exists())


class SAMLIdentityPolicySchemaTests(TestCase):
    def test_disabled_is_default_and_persistent_nameid_is_explicitly_allowed(self):
        provider = SSOProvider(name='identity-policy-default', protocol='saml')
        self.assertEqual(provider.saml_identity_policy, 'disabled')
        self.assertIn(
            ('persistent_nameid', 'Persistent NameID — require SAML persistent NameID format'),
            provider.SAML_IDENTITY_POLICY_CHOICES,
        )

        provider.saml_identity_policy = 'email_nameid'
        with self.assertRaises(ValidationError):
            provider.full_clean()

    def test_provider_form_exposes_disabled_policy_by_default(self):
        form = SSOProviderForm()
        self.assertIn('saml_identity_policy', form.fields)
        self.assertEqual(form.instance.saml_identity_policy, 'disabled')


class SSOProviderSecretEncryptionRuntimeTests(TestCase):
    def test_new_secrets_are_encrypted_at_rest_and_not_double_encrypted(self):
        from sso_auth.secret_encryption import decrypt_sso_secret

        provider = SSOProvider.objects.create(
            name='encrypted-secret-storage',
            protocol='oidc',
            oidc_client_secret='new-oidc-secret',
            saml_sp_private_key='new-saml-private-key',
        )
        provider.refresh_from_db()
        original_oidc_ciphertext = provider.oidc_client_secret
        original_saml_ciphertext = provider.saml_sp_private_key

        self.assertTrue(original_oidc_ciphertext.startswith('enc:v1:'))
        self.assertTrue(original_saml_ciphertext.startswith('enc:v1:'))
        self.assertNotIn('new-oidc-secret', original_oidc_ciphertext)
        self.assertNotIn('new-saml-private-key', original_saml_ciphertext)
        self.assertEqual(decrypt_sso_secret(original_oidc_ciphertext), 'new-oidc-secret')
        self.assertEqual(decrypt_sso_secret(original_saml_ciphertext), 'new-saml-private-key')

        provider.save()
        provider.refresh_from_db()
        self.assertEqual(provider.oidc_client_secret, original_oidc_ciphertext)
        self.assertEqual(provider.saml_sp_private_key, original_saml_ciphertext)

    def test_oidc_exchange_receives_decrypted_secret_at_runtime_boundary(self):
        provider = SSOProvider.objects.create(
            name='runtime-oidc-secret',
            protocol='oidc',
            oidc_client_id='runtime-client',
            oidc_client_secret='runtime-oidc-secret',
            oidc_authorization_endpoint='https://issuer.example.test/authorize',
            oidc_token_endpoint='https://issuer.example.test/token',
            oidc_userinfo_endpoint='https://issuer.example.test/userinfo',
            oidc_jwks_uri='https://issuer.example.test/jwks',
            oidc_issuer='https://issuer.example.test',
        )
        response = Mock(is_redirect=False)
        response.json.return_value = {'access_token': 'test-access-token'}

        with patch('sso_auth.utils.requests.post', return_value=response) as post:
            self.assertEqual(
                OIDCClient(provider).exchange_code_for_token('test-code', 'https://app.example.test/callback'),
                {'access_token': 'test-access-token'},
            )

        self.assertEqual(post.call_args.kwargs['data']['client_secret'], 'runtime-oidc-secret')
        provider.refresh_from_db()
        self.assertNotIn('runtime-oidc-secret', provider.oidc_client_secret)

    def test_saml_settings_receive_decrypted_private_key_at_runtime_boundary(self):
        provider = SSOProvider.objects.create(
            name='runtime-saml-secret',
            protocol='saml',
            saml_sp_private_key='runtime-saml-private-key',
        )

        settings = provider.get_saml_settings()

        self.assertEqual(settings['sp']['privateKey'], 'runtime-saml-private-key')
        provider.refresh_from_db()
        self.assertNotIn('runtime-saml-private-key', provider.saml_sp_private_key)

    def test_malformed_unknown_and_wrong_key_values_fail_closed(self):
        from sso_auth.secret_encryption import (
            SSOSecretEncryptionError,
            decrypt_sso_secret,
            encrypt_sso_secret,
        )

        with self.assertRaises(SSOSecretEncryptionError):
            encrypt_sso_secret('enc:v1:not-a-valid-token')
        with self.assertRaises(SSOSecretEncryptionError):
            decrypt_sso_secret('enc:v2:unsupported')

        ciphertext = encrypt_sso_secret('wrong-key-secret')
        with override_settings(ENCRYPTION_KEY=Fernet.generate_key().decode()):
            with self.assertRaises(SSOSecretEncryptionError):
                decrypt_sso_secret(ciphertext)


class SSOProviderSecretContainmentTests(TestCase):
    def setUp(self):
        self.superuser = User.objects.create_superuser(
            'secret-admin', 'secret-admin@example.test', 'password'
        )
        self.normal_user = User.objects.create_user('secret-normal', password='password')
        self.staff_user = User.objects.create_user(
            'secret-staff', password='password', is_staff=True
        )
        self.client_secret = 'test-only-oidc-client-secret'
        self.private_key = 'test-only-saml-private-key'
        self.provider = SSOProvider.objects.create(
            name='secret-containment-provider',
            protocol='oidc',
            status='active',
            enabled=True,
            allow_registration=False,
            oidc_client_id='secret-client',
            oidc_client_secret=self.client_secret,
            oidc_discovery_url='https://issuer.example.test/.well-known/openid-configuration',
            oidc_issuer='https://issuer.example.test',
            saml_sp_private_key=self.private_key,
            test_results={'client_secret': self.client_secret, 'success': True},
        )
        self.edit_url = reverse('sso:edit_provider', args=[self.provider.id])
        self.details_url = reverse('sso:provider_details', args=[self.provider.id])
        self.test_url = reverse('sso:test_provider', args=[self.provider.id])

    def provider_payload(self, **overrides):
        payload = {
            'name': self.provider.name,
            'protocol': 'oidc',
            'status': 'active',
            'description': '',
            'enabled': 'on',
            'debug_mode': '',
            'oidc_client_id': 'secret-client',
            'oidc_client_secret': '',
            'oidc_discovery_url': 'https://issuer.example.test/.well-known/openid-configuration',
            'oidc_authorization_endpoint': '',
            'oidc_token_endpoint': '',
            'oidc_userinfo_endpoint': '',
            'oidc_jwks_uri': '',
            'oidc_issuer': 'https://issuer.example.test',
            'oidc_scopes': 'openid email profile',
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
            'saml_name_id_format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            'saml_identity_policy': 'disabled',
            'saml_immutable_attribute_name': '',
            'saml_want_messages_signed': 'on',
            'saml_authn_requests_signed': 'on',
            'saml_logout_requests_signed': 'on',
            'saml_logout_responses_signed': 'on',
            'saml_signature_algorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'saml_digest_algorithm': 'http://www.w3.org/2001/04/xmlenc#sha256',
            'saml_strict_mode': 'on',
            'attr_email': 'email',
            'attr_first_name': 'first_name',
            'attr_last_name': 'last_name',
            'attr_username': 'email',
        }
        payload.update(overrides)
        return payload

    def assert_not_exposed(self, content, secret, message):
        self.assertFalse(secret in content, message)

    def test_edit_html_does_not_render_existing_secrets(self):
        self.client.force_login(self.superuser)
        response = self.client.get(self.edit_url, secure=True)
        self.assertEqual(response.status_code, 200)
        rendered = response.content.decode()
        self.assert_not_exposed(rendered, self.client_secret, 'OIDC secret was rendered in edit HTML.')
        self.assert_not_exposed(rendered, self.private_key, 'SAML private key was rendered in edit HTML.')
        self.assert_not_exposed(rendered, self.provider.oidc_client_secret, 'OIDC ciphertext was rendered in edit HTML.')
        self.assert_not_exposed(rendered, self.provider.saml_sp_private_key, 'SAML ciphertext was rendered in edit HTML.')

    def test_blank_or_masked_secret_edits_preserve_and_replacements_update(self):
        self.client.force_login(self.superuser)
        original_oidc_ciphertext = self.provider.oidc_client_secret
        original_saml_ciphertext = self.provider.saml_sp_private_key
        response = self.client.post(self.edit_url, self.provider_payload(), secure=True)
        self.assertEqual(response.status_code, 302)
        self.provider.refresh_from_db()
        self.assertTrue(hmac.compare_digest(self.provider.oidc_client_secret, original_oidc_ciphertext))
        self.assertTrue(hmac.compare_digest(self.provider.saml_sp_private_key, original_saml_ciphertext))

        response = self.client.post(
            self.edit_url,
            self.provider_payload(oidc_client_secret='********', saml_sp_private_key='********'),
            secure=True,
        )
        self.assertEqual(response.status_code, 302)
        self.provider.refresh_from_db()
        self.assertTrue(hmac.compare_digest(self.provider.oidc_client_secret, original_oidc_ciphertext))
        self.assertTrue(hmac.compare_digest(self.provider.saml_sp_private_key, original_saml_ciphertext))

        response = self.client.post(
            self.edit_url,
            self.provider_payload(
                oidc_client_secret='replacement-client-secret',
                saml_sp_private_key='replacement-private-key',
            ),
            secure=True,
        )
        self.assertEqual(response.status_code, 302)
        self.provider.refresh_from_db()
        from sso_auth.secret_encryption import decrypt_sso_secret

        self.assertNotEqual(self.provider.oidc_client_secret, original_oidc_ciphertext)
        self.assertNotEqual(self.provider.saml_sp_private_key, original_saml_ciphertext)
        self.assertEqual(decrypt_sso_secret(self.provider.oidc_client_secret), 'replacement-client-secret')
        self.assertEqual(decrypt_sso_secret(self.provider.saml_sp_private_key), 'replacement-private-key')

    def test_new_oidc_provider_without_secret_remains_invalid(self):
        form = SSOProviderForm(data=self.provider_payload(name='new-provider', oidc_client_secret=''))
        self.assertFalse(form.is_valid())
        self.assertIn('OIDC Client Secret is required for enabled OIDC providers.', form.non_field_errors())

    def test_provider_json_and_test_route_do_not_return_secret_data(self):
        self.assertEqual(self.client.get(self.details_url, secure=True).status_code, 401)
        for user in (self.normal_user, self.staff_user):
            self.client.force_login(user)
            self.assertEqual(self.client.get(self.details_url, secure=True).status_code, 403)
            self.client.logout()

        self.client.force_login(self.superuser)
        details_response = self.client.get(self.details_url, secure=True)
        self.assertEqual(details_response.status_code, 200)
        details = details_response.json()
        self.assertTrue(details['oidc_client_secret_configured'])
        self.assertTrue(details['saml_sp_private_key_configured'])
        serialized = details_response.content.decode()
        self.assert_not_exposed(serialized, self.client_secret, 'Provider JSON returned an OIDC secret.')
        self.assert_not_exposed(serialized, self.private_key, 'Provider JSON returned a SAML private key.')
        self.assert_not_exposed(serialized, self.provider.oidc_client_secret, 'Provider JSON returned OIDC ciphertext.')
        self.assert_not_exposed(serialized, self.provider.saml_sp_private_key, 'Provider JSON returned SAML ciphertext.')

        with patch.object(SSOProvider, 'test_connection', return_value={'success': False, 'errors': []}):
            test_response = self.client.post(self.test_url, secure=True)
        self.assertEqual(test_response.status_code, 302)
        self.assert_not_exposed(test_response.content.decode(), self.client_secret, 'Provider test returned an OIDC secret.')
        self.assert_not_exposed(test_response.content.decode(), self.private_key, 'Provider test returned a SAML private key.')

    def test_provider_is_not_registered_in_django_admin(self):
        self.assertNotIn(SSOProvider, admin.site._registry)

    def test_default_export_excludes_provider_secrets(self):
        saml_provider = SSOProvider.objects.create(
            name='secret-containment-saml',
            protocol='saml',
            saml_sp_private_key=self.private_key,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / 'sso-export.json'
            output = StringIO()
            call_command('export_sso_config', str(output_path), stdout=output)
            exported = output_path.read_text(encoding='utf-8')

        self.assert_not_exposed(exported, self.client_secret, 'Default export included an OIDC secret.')
        self.assert_not_exposed(exported, self.private_key, 'Default export included a SAML private key.')
        self.assert_not_exposed(exported, self.provider.oidc_client_secret, 'Default export included OIDC ciphertext.')
        self.assert_not_exposed(exported, saml_provider.saml_sp_private_key, 'Default export included SAML ciphertext.')
        self.assertIn('Sensitive fields were excluded from export.', output.getvalue())


class SSOProviderSecretEncryptionMigrationTests(TransactionTestCase):
    reset_sequences = True
    migrate_from = [('sso_auth', '0005_alter_ssoprovider_oidc_client_secret')]
    migrate_to = [('sso_auth', '0006_encrypt_ssoprovider_secrets')]

    def test_data_migration_encrypts_legacy_values_preserves_valid_ciphertext_and_is_irreversible(self):
        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_from)
        old_apps = executor.loader.project_state(self.migrate_from).apps
        old_provider = old_apps.get_model('sso_auth', 'SSOProvider')
        plaintext_oidc = old_provider.objects.create(
            name='migration-plaintext-oidc', protocol='oidc', description='unchanged metadata',
            oidc_client_secret='legacy-oidc-secret',
        )
        plaintext_saml = old_provider.objects.create(
            name='migration-plaintext-saml', protocol='saml',
            saml_sp_private_key='legacy-saml-private-key',
        )
        both = old_provider.objects.create(
            name='migration-both-secrets', protocol='oidc',
            oidc_client_secret='legacy-both-oidc', saml_sp_private_key='legacy-both-saml',
        )
        empty = old_provider.objects.create(
            name='migration-empty-secrets', protocol='saml',
            oidc_client_secret='', saml_sp_private_key=None,
        )
        from sso_auth.secret_encryption import encrypt_sso_secret, decrypt_sso_secret

        existing_ciphertext = encrypt_sso_secret('already-encrypted-secret')
        already_encrypted = old_provider.objects.create(
            name='migration-existing-ciphertext', protocol='oidc',
            oidc_client_secret=existing_ciphertext,
        )

        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_to)
        new_apps = executor.loader.project_state(self.migrate_to).apps
        new_provider = new_apps.get_model('sso_auth', 'SSOProvider')

        migrated_oidc = new_provider.objects.get(pk=plaintext_oidc.pk)
        migrated_saml = new_provider.objects.get(pk=plaintext_saml.pk)
        migrated_both = new_provider.objects.get(pk=both.pk)
        self.assertEqual(migrated_oidc.description, 'unchanged metadata')
        self.assertEqual(decrypt_sso_secret(migrated_oidc.oidc_client_secret), 'legacy-oidc-secret')
        self.assertEqual(decrypt_sso_secret(migrated_saml.saml_sp_private_key), 'legacy-saml-private-key')
        self.assertEqual(decrypt_sso_secret(migrated_both.oidc_client_secret), 'legacy-both-oidc')
        self.assertEqual(decrypt_sso_secret(migrated_both.saml_sp_private_key), 'legacy-both-saml')
        migrated_empty = new_provider.objects.get(pk=empty.pk)
        self.assertEqual(migrated_empty.oidc_client_secret, '')
        self.assertIsNone(migrated_empty.saml_sp_private_key)
        self.assertEqual(new_provider.objects.get(pk=already_encrypted.pk).oidc_client_secret, existing_ciphertext)
        self.assertEqual(new_provider.objects.count(), 5)

        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_from)
        reversed_apps = executor.loader.project_state(self.migrate_from).apps
        reversed_provider = reversed_apps.get_model('sso_auth', 'SSOProvider')
        self.assertEqual(
            reversed_provider.objects.get(pk=plaintext_oidc.pk).oidc_client_secret,
            migrated_oidc.oidc_client_secret,
        )

        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_to)

    def test_malformed_or_unknown_encryption_markers_fail_without_partial_transformation(self):
        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_from)
        old_apps = executor.loader.project_state(self.migrate_from).apps
        old_provider = old_apps.get_model('sso_auth', 'SSOProvider')
        plaintext = old_provider.objects.create(
            name='migration-atomic-plaintext', protocol='oidc', oidc_client_secret='must-remain-plaintext',
        )
        malformed = old_provider.objects.create(
            name='migration-malformed-marker', protocol='saml', saml_sp_private_key='enc:v1:not-valid',
        )

        executor = MigrationExecutor(django_db_connection)
        with self.assertRaises(RuntimeError):
            executor.migrate(self.migrate_to)

        self.assertEqual(old_provider.objects.get(pk=plaintext.pk).oidc_client_secret, 'must-remain-plaintext')
        self.assertEqual(old_provider.objects.get(pk=malformed.pk).saml_sp_private_key, 'enc:v1:not-valid')
        self.assertEqual(old_provider.objects.count(), 2)

        malformed.saml_sp_private_key = 'enc:v2:unsupported'
        malformed.save(update_fields=['saml_sp_private_key'])
        executor = MigrationExecutor(django_db_connection)
        with self.assertRaises(RuntimeError):
            executor.migrate(self.migrate_to)

        malformed.delete()
        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_to)

    def test_data_migration_succeeds_when_no_providers_exist(self):
        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_from)

        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_to)
        new_apps = executor.loader.project_state(self.migrate_to).apps
        new_provider = new_apps.get_model('sso_auth', 'SSOProvider')

        self.assertEqual(new_provider.objects.count(), 0)


class SSOAuditPrivacyTests(TestCase):
    """Ensure audit storage and the management API cannot retain protocol payloads."""

    def setUp(self):
        self.superuser = User.objects.create_superuser(
            'audit-superuser', 'audit-superuser@example.test', 'password'
        )
        self.normal_user = User.objects.create_user('audit-normal', password='password')
        self.staff_user = User.objects.create_user('audit-staff', password='password', is_staff=True)
        self.saml_provider = SSOProvider.objects.create(name='audit-saml', protocol='saml')
        self.oidc_provider = SSOProvider.objects.create(
            name='audit-oidc', protocol='oidc',
            oidc_discovery_url='https://issuer.example.test/.well-known/openid-configuration',
        )
        self.logs_url = reverse('sso:provider_logs', args=[self.saml_provider.id])

    def test_protocol_payloads_and_request_user_agent_are_never_persisted(self):
        markers = {
            'saml-success-marker': {
                'attributes': {'email': 'saml-success-marker', 'groups': ['admin']},
                'nameid': 'saml-success-marker',
            },
            'saml-failure-marker': {
                'assertion_xml': '<Assertion>saml-failure-marker</Assertion>',
            },
            'oidc-success-marker': {
                'userinfo': {'sub': 'oidc-success-marker', 'email': 'oidc-success-marker'},
            },
            'oidc-failure-marker': {
                'access_token': 'oidc-failure-marker',
                'authorization_code': 'oidc-failure-marker',
            },
        }
        for marker, details in markers.items():
            SSOUtils.log_sso_event(
                self.saml_provider if marker.startswith('saml') else self.oidc_provider,
                'login_success' if 'success' in marker else 'login_failure',
                details=details,
                user_agent=marker,
            )

        for log in SSOAuditLog.objects.all():
            serialized = str(log.details)
            self.assertEqual(log.user_agent, None)
            for marker in markers:
                self.assertNotIn(marker, serialized)
            self.assertNotIn('attributes', serialized)
            self.assertNotIn('access_token', serialized)
            self.assertNotIn('assertion_xml', serialized)

    def test_provider_test_retains_only_safe_discovery_summary_and_audit_category(self):
        response = Mock(status_code=200)
        response.json.return_value = {
            'issuer': 'https://issuer.example.test',
            'token_endpoint': 'https://issuer.example.test/token',
            'private_marker': 'provider-test-sensitive-marker',
        }
        with patch('requests.get', return_value=response):
            results = self.oidc_provider.test_connection()

        serialized_results = str(results)
        self.assertTrue(results['success'])
        self.assertEqual(results['discovery'], {'reachable': True, 'status_code': 200})
        self.assertNotIn('discovery_data', results)
        self.assertNotIn('provider-test-sensitive-marker', serialized_results)

        self.client.force_login(self.superuser)
        with patch.object(SSOProvider, 'test_connection', return_value={
            'success': False,
            'failure_category': 'discovery_connection_failed',
            'discovery_data': {'token': 'provider-test-sensitive-marker'},
        }):
            response = self.client.post(
                reverse('sso:test_provider', args=[self.oidc_provider.id]), secure=True,
            )
        self.assertEqual(response.status_code, 302)
        audit = SSOAuditLog.objects.get(provider=self.oidc_provider, event_type='test_connection')
        self.assertEqual(
            audit.details,
            {'success': False, 'failure_category': 'discovery_connection_failed'},
        )
        self.assertNotIn('provider-test-sensitive-marker', str(audit.details))

    def test_audit_api_hides_historical_details_and_preserves_authorization(self):
        marker = 'historical-sensitive-audit-marker'
        SSOAuditLog.objects.create(
            provider=self.saml_provider,
            event_type='login_failure',
            details={'assertion_xml': marker, 'access_token': marker},
        )

        self.assertEqual(self.client.get(self.logs_url, secure=True).status_code, 401)
        for user in (self.normal_user, self.staff_user):
            self.client.force_login(user)
            self.assertEqual(self.client.get(self.logs_url, secure=True).status_code, 403)
            self.client.logout()

        self.client.force_login(self.superuser)
        response = self.client.get(self.logs_url, secure=True)
        self.assertEqual(response.status_code, 200)
        serialized = response.content.decode()
        self.assertNotIn(marker, serialized)
        self.assertNotIn('details', response.json()['logs'][0])


class SSOFrontendTemplateContractTests(TestCase):
    """Ensure active SSO management scripts are rendered by the base layout."""

    def setUp(self):
        self.superuser = User.objects.create_superuser(
            'sso-frontend-admin', 'sso-frontend-admin@example.test', 'password'
        )

    def test_management_and_provider_form_include_their_active_scripts(self):
        self.client.force_login(self.superuser)

        management = self.client.get(reverse('sso:management'), secure=True)
        self.assertEqual(management.status_code, 200)
        self.assertContains(management, 'function viewAuditLogs(providerId)')
        self.assertContains(management, 'bootstrap.Modal.getOrCreateInstance')
        self.assertContains(management, 'emptyTable": "No SSO providers have been configured yet."')
        self.assertNotContains(management, '<td colspan="7"')

        provider_form = self.client.get(reverse('sso:create_provider'), secure=True)
        self.assertEqual(provider_form.status_code, 200)
        self.assertContains(provider_form, 'function toggleProtocolSections()')


class SAMLBindingSettingsTests(TestCase):
    def test_binding_defaults_to_redirect_and_preserves_existing_providers(self):
        provider = SSOProvider.objects.create(name='binding-default', protocol='saml')
        self.assertEqual(provider.saml_idp_sso_binding, 'http_redirect')
        settings = provider.get_saml_settings()
        self.assertEqual(settings['idp']['singleSignOnService']['binding'], SAML_BINDING_HTTP_REDIRECT)

    def test_post_binding_selection_is_reflected_in_settings(self):
        provider = SSOProvider.objects.create(
            name='binding-post', protocol='saml', saml_idp_sso_binding='http_post',
        )
        settings = provider.get_saml_settings()
        self.assertEqual(settings['idp']['singleSignOnService']['binding'], SAML_BINDING_HTTP_POST)


class SAMLCertificateRolloverTests(TestCase):
    CERT_PRIMARY = '-----BEGIN CERTIFICATE-----\nMIIPRIMARYCERTDATA==\n-----END CERTIFICATE-----'
    CERT_ADDITIONAL_A = '-----BEGIN CERTIFICATE-----\nMIIROLLOVERCERTAAA==\n-----END CERTIFICATE-----'
    CERT_ADDITIONAL_B = '-----BEGIN CERTIFICATE-----\nMIIROLLOVERCERTBBB==\n-----END CERTIFICATE-----'

    def test_parse_pem_certificate_list_splits_multiple_blocks(self):
        certs = parse_pem_certificate_list(
            f'{self.CERT_ADDITIONAL_A}\n\n{self.CERT_ADDITIONAL_B}'
        )
        self.assertEqual(len(certs), 2)
        self.assertIn('MIIROLLOVERCERTAAA==', certs[0])
        self.assertIn('MIIROLLOVERCERTBBB==', certs[1])
        self.assertTrue(all(cert.endswith('-----END CERTIFICATE-----') for cert in certs))

    def test_parse_pem_certificate_list_handles_blank_input(self):
        self.assertEqual(parse_pem_certificate_list(''), [])
        self.assertEqual(parse_pem_certificate_list(None), [])

    def test_settings_omit_multi_cert_when_no_additional_certs_configured(self):
        provider = SSOProvider.objects.create(
            name='rollover-none', protocol='saml', saml_idp_x509cert=self.CERT_PRIMARY,
        )
        settings = provider.get_saml_settings()
        self.assertNotIn('x509certMulti', settings['idp'])
        self.assertEqual(settings['idp']['x509cert'], self.CERT_PRIMARY)

    def test_settings_expose_primary_plus_additional_certs_for_rollover(self):
        provider = SSOProvider.objects.create(
            name='rollover-both',
            protocol='saml',
            saml_idp_x509cert=self.CERT_PRIMARY,
            saml_idp_x509cert_additional=f'{self.CERT_ADDITIONAL_A}\n\n{self.CERT_ADDITIONAL_B}',
        )
        settings = provider.get_saml_settings()
        signing_certs = settings['idp']['x509certMulti']['signing']
        self.assertEqual(len(signing_certs), 3)
        self.assertIn('MIIPRIMARYCERTDATA==', signing_certs[0])
        self.assertIn('MIIROLLOVERCERTAAA==', signing_certs[1])
        self.assertIn('MIIROLLOVERCERTBBB==', signing_certs[2])

    def test_settings_expose_additional_certs_even_without_a_primary(self):
        provider = SSOProvider.objects.create(
            name='rollover-additional-only',
            protocol='saml',
            saml_idp_x509cert_additional=self.CERT_ADDITIONAL_A,
        )
        settings = provider.get_saml_settings()
        self.assertEqual(len(settings['idp']['x509certMulti']['signing']), 1)


class SAMLPostBindingConstructionTests(TestCase):
    def setUp(self):
        self.provider = SSOProvider.objects.create(
            name='post-binding-construction',
            protocol='saml',
            saml_idp_sso_binding='http_post',
            saml_idp_entity_id='https://idp.example.test/entity',
            saml_idp_sso_url='https://idp.example.test/sso/post',
            saml_idp_x509cert='trusted-idp-certificate',
            saml_sp_entity_id='https://app.example.test/saml/metadata/',
            saml_sp_acs_url='https://app.example.test/saml/acs/',
            saml_authn_requests_signed=False,
            saml_logout_requests_signed=False,
            saml_logout_responses_signed=False,
        )

    def test_unsigned_post_request_is_plain_base64_without_deflation(self):
        settings = self.provider.get_saml_settings()
        result = build_post_authn_request(self.provider, settings, 'https://app.example.test/home/')

        self.assertEqual(result['sso_url'], 'https://idp.example.test/sso/post')
        self.assertEqual(result['relay_state'], 'https://app.example.test/home/')
        self.assertTrue(result['request_id'])

        decoded = base64.b64decode(result['saml_request']).decode()
        self.assertIn('<samlp:AuthnRequest', decoded)
        self.assertIn(result['request_id'], decoded)
        self.assertNotIn('<ds:Signature', decoded)

    def test_signed_post_request_contains_enveloped_signature(self):
        cert_pem, key_pem = _generate_self_signed_cert_and_key()
        self.provider.saml_authn_requests_signed = True
        self.provider.saml_sp_x509cert = cert_pem
        self.provider.saml_sp_private_key = key_pem
        self.provider.save()

        settings = self.provider.get_saml_settings()
        result = build_post_authn_request(self.provider, settings, 'https://app.example.test/home/')

        decoded = base64.b64decode(result['saml_request']).decode()
        self.assertIn('<samlp:AuthnRequest', decoded)
        self.assertIn('Signature', decoded)

    def test_signed_post_request_without_sp_key_fails_closed(self):
        self.provider.saml_authn_requests_signed = True
        self.provider.save()
        settings = self.provider.get_saml_settings()

        with self.assertRaises(SAMLPostBindingError):
            build_post_authn_request(self.provider, settings, 'https://app.example.test/home/')


class SAMLPostBindingLoginFlowTests(TestCase):
    def setUp(self):
        self.provider = SSOProvider.objects.create(
            name='post-binding-flow',
            protocol='saml',
            status='active',
            enabled=True,
            saml_idp_sso_binding='http_post',
            saml_idp_entity_id='https://idp.example.test/entity',
            saml_idp_sso_url='https://idp.example.test/sso/post',
            saml_idp_x509cert='trusted-idp-certificate',
            saml_sp_entity_id='https://app.example.test/saml/metadata/',
            saml_sp_acs_url='https://app.example.test/saml/acs/',
            saml_identity_policy='persistent_nameid',
            saml_want_assertions_signed=True,
            saml_authn_requests_signed=False,
            saml_logout_requests_signed=False,
            saml_logout_responses_signed=False,
        )
        self.login_url = reverse('sso:saml_login_named', args=[self.provider.name])
        self.acs_url = reverse('sso:saml_acs_named', args=[self.provider.name])

    def test_login_renders_auto_submitting_post_form_and_stores_correlation_state(self):
        response = self.client.get(self.login_url, {'next': '/safe/'}, secure=True)

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('<form method="post" action="https://idp.example.test/sso/post">', content)
        self.assertIn('name="SAMLRequest"', content)
        self.assertIn('name="RelayState"', content)

        session = self.client.session
        self.assertTrue(session['saml_authn_request_id'])
        self.assertEqual(session['saml_authn_provider_id'], self.provider.pk)
        self.assertEqual(session['saml_authn_next'], '/safe/')

    def test_acs_correlates_successfully_after_post_binding_login(self):
        self.client.get(self.login_url, {'next': '/safe/'}, secure=True)
        request_id = self.client.session['saml_authn_request_id']

        auth = Mock()
        auth.get_errors.return_value = []
        auth.is_authenticated.return_value = True
        auth.get_last_assertion_id.return_value = 'post-binding-assertion-id'
        auth.get_nameid.return_value = 'post-binding-subject'
        auth.get_nameid_format.return_value = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
        auth.get_attributes.return_value = {'email': ['post@example.test'], 'username': ['post-user']}

        with patch('sso_auth.views.OneLogin_Saml2_Auth', return_value=auth):
            response = self.client.post(self.acs_url, secure=True)

        auth.process_response.assert_called_once_with(request_id=request_id)
        self.assertRedirects(response, '/safe/', fetch_redirect_response=False)
        self.assertTrue(SSOUserProfile.objects.filter(provider=self.provider, sso_id='post-binding-subject').exists())


class SAMLImmutableAttributeIdentityTests(TestCase):
    def setUp(self):
        self.provider = SSOProvider.objects.create(
            name='immutable-attribute-provider',
            protocol='saml',
            status='active',
            enabled=True,
            saml_idp_entity_id='https://idp.example.test/entity',
            saml_idp_sso_url='https://idp.example.test/sso',
            saml_idp_x509cert='trusted-idp-certificate',
            saml_sp_entity_id='https://app.example.test/saml/metadata/',
            saml_sp_acs_url='https://app.example.test/saml/acs/',
            saml_identity_policy='configured_immutable_attribute',
            saml_immutable_attribute_name='employeeID',
            saml_want_assertions_signed=True,
        )
        self.acs_url = reverse('sso:saml_acs_named', args=[self.provider.name])

    def set_request_state(self):
        session = self.client.session
        session['saml_authn_request_id'] = 'request-id'
        session['saml_authn_provider_id'] = self.provider.pk
        session['saml_authn_started_at'] = time.time()
        session['saml_authn_next'] = '/safe/'
        session.save()

    def base_auth(self):
        auth = Mock()
        auth.get_errors.return_value = []
        auth.is_authenticated.return_value = True
        auth.get_last_assertion_id.return_value = 'immutable-attribute-assertion-id'
        return auth

    def test_configured_attribute_value_becomes_the_external_subject(self):
        self.set_request_state()
        auth = self.base_auth()
        auth.get_attributes.return_value = {
            'employeeID': ['stable-employee-123'],
            'email': ['immutable@example.test'],
            'username': ['immutable-user'],
        }

        with patch('sso_auth.views.OneLogin_Saml2_Auth', return_value=auth):
            response = self.client.post(self.acs_url, secure=True)

        self.assertRedirects(response, '/safe/', fetch_redirect_response=False)
        self.assertTrue(
            SSOUserProfile.objects.filter(provider=self.provider, sso_id='stable-employee-123').exists()
        )

    def test_missing_or_empty_configured_attribute_is_denied(self):
        for attributes in ({'email': ['no-attr@example.test']}, {'employeeID': ['']}, {'employeeID': []}):
            with self.subTest(attributes=attributes):
                self.set_request_state()
                auth = self.base_auth()
                auth.get_attributes.return_value = attributes

                with patch('sso_auth.views.OneLogin_Saml2_Auth', return_value=auth):
                    response = self.client.post(self.acs_url, secure=True)

                self.assertRedirects(response, reverse('login'), fetch_redirect_response=False)
        self.assertFalse(SSOUserProfile.objects.filter(provider=self.provider).exists())

    def test_configured_attribute_never_falls_back_to_email_or_username(self):
        self.set_request_state()
        auth = self.base_auth()
        auth.get_nameid.return_value = 'immutable@example.test'
        auth.get_attributes.return_value = {'email': ['immutable@example.test'], 'username': ['immutable-user']}

        with patch('sso_auth.views.OneLogin_Saml2_Auth', return_value=auth):
            response = self.client.post(self.acs_url, secure=True)

        self.assertRedirects(response, reverse('login'), fetch_redirect_response=False)
        self.assertFalse(SSOUserProfile.objects.filter(sso_id='immutable@example.test').exists())


SAML_METADATA_TEMPLATE = """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                      entityID="https://idp.example.test/entity">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>MIIFAKECERTDATA==</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                             Location="https://idp.example.test/sso/redirect"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                             Location="https://idp.example.test/sso/post"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                             Location="https://idp.example.test/slo"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"""


class SAMLMetadataParserTests(TestCase):
    def test_valid_metadata_extracts_all_onboarding_fields(self):
        result = parse_idp_metadata_xml(SAML_METADATA_TEMPLATE)

        self.assertEqual(result['entity_id'], 'https://idp.example.test/entity')
        self.assertEqual(len(result['sso_endpoints']), 2)
        bindings = {endpoint['binding'] for endpoint in result['sso_endpoints']}
        self.assertEqual(bindings, {SAML_BINDING_HTTP_REDIRECT, SAML_BINDING_HTTP_POST})
        self.assertEqual(result['slo_endpoints'][0]['url'], 'https://idp.example.test/slo')
        self.assertEqual(result['certs'], ['MIIFAKECERTDATA=='])
        self.assertIn('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', result['nameid_formats'])

    def test_missing_or_blank_input_is_rejected(self):
        with self.assertRaises(SAMLMetadataError):
            parse_idp_metadata_xml('')
        with self.assertRaises(SAMLMetadataError):
            parse_idp_metadata_xml('   ')

    def test_malformed_xml_is_rejected(self):
        with self.assertRaises(SAMLMetadataError):
            parse_idp_metadata_xml('<md:EntityDescriptor entityID="broken"')

    def test_oversized_input_is_rejected_before_parsing(self):
        from sso_auth.saml_metadata_parser import MAX_METADATA_BYTES

        with self.assertRaises(SAMLMetadataError):
            parse_idp_metadata_xml('x' * (MAX_METADATA_BYTES + 1))

    def test_dtd_is_rejected(self):
        payload = (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE md:EntityDescriptor [<!ELEMENT md:EntityDescriptor ANY>]>\n'
            + SAML_METADATA_TEMPLATE
        )
        with self.assertRaises(SAMLMetadataError):
            parse_idp_metadata_xml(payload)

    def test_xxe_external_entity_is_rejected(self):
        payload = (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE md:EntityDescriptor [\n'
            '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
            ']>\n'
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&xxe;">'
            '</md:EntityDescriptor>'
        )
        with self.assertRaises(SAMLMetadataError):
            parse_idp_metadata_xml(payload)

    def test_metadata_without_idp_sso_descriptor_is_rejected(self):
        payload = (
            '<?xml version="1.0"?>'
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
            'entityID="https://sp.example.test/entity"></md:EntityDescriptor>'
        )
        with self.assertRaises(SAMLMetadataError):
            parse_idp_metadata_xml(payload)

    def test_metadata_without_usable_sso_endpoint_is_rejected(self):
        payload = (
            '<?xml version="1.0"?>'
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
            'entityID="https://idp.example.test/entity">'
            '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            '</md:IDPSSODescriptor></md:EntityDescriptor>'
        )
        with self.assertRaises(SAMLMetadataError):
            parse_idp_metadata_xml(payload)
