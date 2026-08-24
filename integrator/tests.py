import json
import os
import socket
import tempfile
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from django.apps import apps
from django.contrib.auth.models import User
from django.db import connection as django_db_connection
from django.db.migrations.executor import MigrationExecutor
from django.http import HttpResponse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.urls import resolve, reverse
from PIL import Image

from accounts.admin import UserProfileAdminForm
from integrator.admin import CompanyAdminForm, DynamicFormAdminForm, IntegrationAdminForm

from integrator.models import (
    ApprovedProcedure,
    ApprovedProcedureParameter,
    Company,
    DatabaseConnection,
    DynamicForm,
    FileUpload,
    FormPermission,
    FormSubmission,
    Integration,
    IntegrationCredential,
    ProcedureExecutionAudit,
    SavedProcedureExecution,
    SavedQuery,
)
from integrator.sql_policy import USER_FACING_ERROR, SqlPolicyViolation, validate_read_only_query
from integrator.query_execution import (
    APPLICATION_POLICY_ONLY,
    DEFAULT_ADMIN_MAX_ROWS,
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_DYNAMIC_DROPDOWN_MAX_ROWS,
    DEFAULT_PROCEDURE_MAX_RESULT_SETS,
    DEFAULT_PROCEDURE_MAX_ROWS_PER_RESULT_SET,
    DEFAULT_PROCEDURE_MAX_TOTAL_ROWS,
    DEFAULT_QUERY_TIMEOUT,
    ExternalQueryConfigurationError,
    ExternalQueryTimeoutError,
    ProcedureExecutionLimits,
    ReadOnlyEnforcementError,
    TRANSACTION_READ_ONLY_ENFORCED,
    UNSUPPORTED,
    fetch_limited_rows,
    get_procedure_execution_limits,
    get_external_query_limits,
    read_only_enforcement_status,
)
from integrator.procedure_execution import fetch_bounded_procedure_result_sets
from integrator import webhook_security
from integrator.webhook_security import (
    WebhookDeliveryError,
    WebhookSecurityError,
    WebhookTransportSettings,
    deliver_webhook,
    validate_webhook_url,
)
from integrator.webhook_responses import safe_webhook_response_metadata
from integrator.webhook_headers import (
    DuplicateWebhookHeaderError,
    MASKED_HEADER_VALUE,
    WebhookHeaderError,
    WebhookHeaderSecretError,
    decrypt_webhook_header_value,
    encrypt_webhook_header_value,
    is_sensitive_webhook_header,
    prepare_webhook_headers_for_storage,
)


class AdminBrandingUploadValidationTests(TestCase):
    def image_upload(self, name='branding.png', image_format='PNG'):
        buffer = BytesIO()
        size = (32, 32) if image_format == 'ICO' else (2, 2)
        Image.new('RGB', size, color='blue').save(buffer, format=image_format)
        return SimpleUploadedFile(name, buffer.getvalue(), content_type='image/png')

    def test_admin_forms_reject_invalid_branding_uploads(self):
        user = User.objects.create_user('branding-user', password='password')
        form_cases = (
            (CompanyAdminForm, {
                'name': 'Brand Company', 'email': 'branding@example.test', 'language': 'en', 'timezone': 'UTC',
            }, 'logo'),
            (DynamicFormAdminForm, {
                'uuid': '0e48526d-32c4-4d8e-a34c-4a1ad3a0a8f0', 'formname': 'Brand Form',
                'config': '[]', 'access_level': 'public', 'template_type': 'default',
            }, 'custom_logo'),
            (IntegrationAdminForm, {
                'name': 'Brand Integration', 'description': 'Brand icon validation', 'fields': '{}',
            }, 'icon'),
            (UserProfileAdminForm, {'user': user.pk}, 'avatar'),
        )
        for form_class, data, field_name in form_cases:
            with self.subTest(form=form_class.__name__):
                form = form_class(data=data, files={field_name: SimpleUploadedFile('branding.svg', b'<svg/>')})
                self.assertFalse(form.is_valid())
                self.assertIn(field_name, form.errors)

    def test_company_admin_form_allows_valid_ico_favicon(self):
        form = CompanyAdminForm(
            data={
                'name': 'Favicon Company', 'email': 'favicon@example.test', 'language': 'en', 'timezone': 'UTC',
            },
            files={'favicon': self.image_upload('favicon.ico', 'ICO')},
        )
        self.assertTrue(form.is_valid(), form.errors)


class UserManagementAuthorizationTests(TestCase):
    def setUp(self):
        self.normal_user = User.objects.create_user('normal', password='password')
        self.staff_user = User.objects.create_user('staff', password='password', is_staff=True)
        self.superuser = User.objects.create_superuser('admin', 'admin@example.com', 'password')
        self.target_user = User.objects.create_user('target', 'target@example.com', 'password')

    def json_post(self, url, payload):
        return self.client.post(
            url,
            data=json.dumps(payload),
            content_type='application/json',
            secure=True,
        )

    def user_urls(self):
        return {
            'detail': reverse('user_detail', args=[self.target_user.id]),
            'add': reverse('add_user'),
            'update': reverse('update_user', args=[self.target_user.id]),
            'delete': reverse('delete_user', args=[self.target_user.id]),
            'search': reverse('search_user'),
        }

    def test_anonymous_user_management_access_is_contained(self):
        self.assertEqual(self.client.get(reverse('users_view'), secure=True).status_code, 302)
        urls = self.user_urls()
        self.assertEqual(self.client.get(urls['detail'], secure=True).status_code, 401)
        self.assertEqual(self.json_post(urls['add'], {'username': 'blocked'}).status_code, 401)
        self.assertEqual(self.json_post(urls['update'], {'username': 'blocked'}).status_code, 401)
        self.assertEqual(self.client.delete(urls['delete'], secure=True).status_code, 401)
        self.assertEqual(self.client.get(urls['search'], secure=True).status_code, 401)

    def test_normal_and_staff_users_cannot_access_or_mutate_users(self):
        urls = self.user_urls()
        original_count = User.objects.count()
        original_username = self.target_user.username

        for user in (self.normal_user, self.staff_user):
            self.client.force_login(user)
            self.assertEqual(self.client.get(reverse('users_view'), secure=True).status_code, 403)
            self.assertEqual(self.client.get(urls['detail'], secure=True).status_code, 403)
            self.assertEqual(self.client.get(urls['search'], secure=True).status_code, 403)
            self.assertEqual(
                self.json_post(
                    urls['add'],
                    {
                        'username': f'escalated-{user.username}',
                        'email': 'escalated@example.com',
                        'role': 'Administrator',
                    },
                ).status_code,
                403,
            )
            self.assertEqual(
                self.json_post(
                    urls['update'],
                    {
                        'username': 'changed',
                        'email': 'changed@example.com',
                        'role': 'Administrator',
                    },
                ).status_code,
                403,
            )
            self.assertEqual(self.client.delete(urls['delete'], secure=True).status_code, 403)
            self.client.logout()

        self.target_user.refresh_from_db()
        self.assertEqual(User.objects.count(), original_count)
        self.assertEqual(self.target_user.username, original_username)
        self.assertFalse(User.objects.filter(username='escalated-normal').exists())
        self.assertFalse(User.objects.filter(username='escalated-staff').exists())

    def test_superuser_retains_user_management_functionality(self):
        self.client.force_login(self.superuser)
        urls = self.user_urls()
        self.assertEqual(self.client.get(reverse('users_view'), secure=True).status_code, 200)
        self.assertEqual(self.client.get(urls['detail'], secure=True).status_code, 200)
        self.assertEqual(self.client.get(urls['search'], secure=True).status_code, 200)

        response = self.json_post(
            urls['add'],
            {
                'username': 'new-admin',
                'email': 'new-admin@example.com',
                'role': 'Administrator',
                'is_active': True,
                'password': 'password',
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(User.objects.get(username='new-admin').is_superuser)

        response = self.json_post(
            urls['update'],
            {
                'username': 'updated-target',
                'email': 'updated@example.com',
                'role': 'Staff',
                'is_active': True,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.target_user.refresh_from_db()
        self.assertEqual(self.target_user.username, 'updated-target')
        self.assertTrue(self.target_user.is_staff)

        deletable_user = User.objects.create_user('deletable', password='password')
        response = self.client.delete(reverse('delete_user', args=[deletable_user.id]), secure=True)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(id=deletable_user.id).exists())


class DiagnosticEndpointAuthorizationTests(TestCase):
    def setUp(self):
        self.normal_user = User.objects.create_user('normal', password='password')
        self.superuser = User.objects.create_superuser('admin', 'admin@example.com', 'password')

    @override_settings(DEBUG=True)
    def test_debug_endpoints_require_a_superuser_in_debug_mode(self):
        for url, method in ((reverse('debug_auth'), 'get'), (reverse('testapi'), 'post')):
            self.assertEqual(getattr(self.client, method)(url, secure=True).status_code, 401)
            self.client.force_login(self.normal_user)
            self.assertEqual(getattr(self.client, method)(url, secure=True).status_code, 403)
            self.client.force_login(self.superuser)
            self.assertEqual(getattr(self.client, method)(url, secure=True).status_code, 200)
            self.client.logout()

        self.assertEqual(self.client.get(reverse('sso_test'), secure=True).status_code, 302)
        self.client.force_login(self.normal_user)
        self.assertEqual(self.client.get(reverse('sso_test'), secure=True).status_code, 403)

    @override_settings(DEBUG=False)
    def test_diagnostic_routes_are_hidden_outside_debug_mode(self):
        self.assertEqual(self.client.get(reverse('debug_auth'), secure=True).status_code, 404)
        self.assertEqual(self.client.post(reverse('testapi'), secure=True).status_code, 404)
        self.assertEqual(self.client.get(reverse('testapi'), secure=True).status_code, 404)
        self.assertEqual(self.client.get(reverse('sso_test'), secure=True).status_code, 404)
        self.client.force_login(self.superuser)
        self.assertEqual(self.client.get(reverse('debug_auth'), secure=True).status_code, 404)
        self.assertEqual(self.client.post(reverse('testapi'), secure=True).status_code, 404)
        self.assertEqual(self.client.get(reverse('testapi'), secure=True).status_code, 404)
        self.assertEqual(self.client.get(reverse('sso_test'), secure=True).status_code, 404)


class PermissionManagementAuthorizationTests(TestCase):
    def setUp(self):
        self.normal_user = User.objects.create_user('permission-normal', password='password')
        self.staff_user = User.objects.create_user(
            'permission-staff', password='password', is_staff=True
        )
        self.superuser = User.objects.create_superuser(
            'permission-admin', 'permission-admin@example.com', 'password'
        )
        self.selected_user = User.objects.create_user('permission-selected', password='password')
        self.replacement_user = User.objects.create_user('permission-replacement', password='password')
        self.dynamic_form = DynamicForm.objects.create(
            formname='Permission-managed form',
            config='[]',
            access_level='selected_users',
            auto_redirect_to_sso=False,
        )
        self.permission = FormPermission.objects.create(
            form=self.dynamic_form,
            user=self.selected_user,
        )

    def urls(self):
        return {
            'page': reverse('permissions'),
            'data': reverse('permissions_data'),
            'save': reverse('save_permissions'),
            'edit': reverse('edit_permission', args=[self.permission.id]),
            'delete': reverse('delete_permission', args=[self.permission.id]),
            'refresh': reverse('refresh_cache'),
        }

    def save_payload(self):
        return {
            'form_id': self.dynamic_form.id,
            'access_level': 'selected_users',
            'user_ids': [self.replacement_user.id],
        }

    def json_post(self, url, payload):
        return self.client.post(
            url,
            data=json.dumps(payload),
            content_type='application/json',
            secure=True,
        )

    def json_delete(self, url):
        return self.client.delete(url, content_type='application/json', secure=True)

    def assert_management_json_denied(self, expected_status):
        urls = self.urls()
        self.assertEqual(self.client.get(urls['data'], secure=True).status_code, expected_status)
        self.assertEqual(self.client.get(urls['edit'], secure=True).status_code, expected_status)
        self.assertEqual(self.json_post(urls['save'], self.save_payload()).status_code, expected_status)
        self.assertEqual(self.json_delete(urls['delete']).status_code, expected_status)
        self.assertEqual(
            self.json_post(urls['refresh'], {'user_ids': [self.selected_user.id]}).status_code,
            expected_status,
        )

    def assert_permission_state_unchanged(self):
        self.dynamic_form.refresh_from_db()
        self.assertEqual(self.dynamic_form.access_level, 'selected_users')
        self.assertEqual(
            list(
                FormPermission.objects.filter(form=self.dynamic_form).values_list(
                    'user_id', flat=True
                )
            ),
            [self.selected_user.id],
        )

    def test_anonymous_page_redirects_and_json_endpoints_return_401(self):
        self.assertEqual(self.client.get(self.urls()['page'], secure=True).status_code, 302)
        with patch('integrator.cache_utils.CacheInvalidationManager.invalidate_user_caches') as invalidate:
            self.assert_management_json_denied(401)
            invalidate.assert_not_called()
        self.assert_permission_state_unchanged()

    def test_normal_and_staff_users_cannot_read_mutate_or_refresh_permissions(self):
        for user in (self.normal_user, self.staff_user):
            self.client.force_login(user)
            self.assertEqual(self.client.get(self.urls()['page'], secure=True).status_code, 403)
            with patch('integrator.cache_utils.CacheInvalidationManager.invalidate_user_caches') as invalidate:
                self.assert_management_json_denied(403)
                invalidate.assert_not_called()
            self.assert_permission_state_unchanged()
            self.client.logout()

    def test_superuser_can_read_mutate_delete_and_refresh_permissions(self):
        self.client.force_login(self.superuser)
        urls = self.urls()

        self.assertEqual(self.client.get(urls['page'], secure=True).status_code, 200)
        data_response = self.client.get(urls['data'], secure=True)
        self.assertEqual(data_response.status_code, 200)
        self.assertIn('data', data_response.json())

        edit_response = self.client.get(urls['edit'], secure=True)
        self.assertEqual(edit_response.status_code, 200)
        self.assertEqual(edit_response.json()['form_id'], self.dynamic_form.id)

        save_response = self.json_post(urls['save'], self.save_payload())
        self.assertEqual(save_response.status_code, 200)
        self.assertTrue(save_response.json()['success'])
        self.assertTrue(
            FormPermission.objects.filter(
                form=self.dynamic_form,
                user=self.replacement_user,
            ).exists()
        )
        self.assertFalse(
            FormPermission.objects.filter(form=self.dynamic_form, user=self.selected_user).exists()
        )

        replacement_permission = FormPermission.objects.get(
            form=self.dynamic_form,
            user=self.replacement_user,
        )
        delete_response = self.json_delete(
            reverse('delete_permission', args=[replacement_permission.id])
        )
        self.assertEqual(delete_response.status_code, 200)
        self.assertTrue(delete_response.json()['success'])
        self.assertFalse(FormPermission.objects.filter(pk=replacement_permission.id).exists())

        refresh_response = self.json_post(urls['refresh'], {'user_ids': [self.replacement_user.id]})
        self.assertEqual(refresh_response.status_code, 200)
        self.assertTrue(refresh_response.json()['success'])


class IntegrationCredentialSecretExposureTests(TestCase):
    def setUp(self):
        self.normal_user = User.objects.create_user('credential-normal', password='password')
        self.staff_user = User.objects.create_user('credential-staff', password='password', is_staff=True)
        self.superuser = User.objects.create_superuser(
            'credential-admin', 'credential-admin@example.com', 'password'
        )
        self.integration = Integration.objects.create(
            name='Credential containment integration',
            description='Credential containment test integration',
            fields={
                'host': 'Host',
                'region': {'label': 'Region'},
                'password': {'label': 'Password', 'type': 'password'},
                'api_token': 'API token',
                'client_secret': {'label': 'Client secret', 'sensitive': True},
            },
        )
        from integrator.integration_credentials import encrypt_credentials_for_storage

        self.initial_credentials = encrypt_credentials_for_storage(self.integration.fields, {
            'host': 'db.internal', 'region': 'eu-west', 'password': 'stored-password',
            'api_token': 'stored-token', 'client_secret': 'stored-client-secret',
        })
        self.credential = IntegrationCredential.objects.create(
            user=self.superuser,
            integration=self.integration,
            credentials=self.initial_credentials,
            enabled=True,
        )
        self.fields_url = reverse('fetch_integration_fields', args=[self.integration.id])
        self.save_url = reverse('save_api_credentials')

    def json_post(self, payload):
        return self.client.post(self.save_url, data=json.dumps(payload), content_type='application/json', secure=True)

    def test_browser_receives_non_secret_values_and_secret_configuration_state_only(self):
        self.client.force_login(self.superuser)
        response = self.client.get(self.fields_url, secure=True)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['saved_credentials'], {'host': 'db.internal', 'region': 'eu-west'})
        self.assertEqual(payload['secret_fields'], {
            'password': {'configured': True}, 'api_token': {'configured': True},
            'client_secret': {'configured': True},
        })
        self.assertEqual(payload['fields']['password']['secret'], True)
        rendered = response.content.decode()
        for secret in ('stored-password', 'stored-token', 'stored-client-secret'):
            self.assertNotIn(secret, rendered)

    def test_blank_or_masked_secret_updates_preserve_existing_values_and_new_values_replace(self):
        self.client.force_login(self.superuser)
        preserve_response = self.json_post({
            'integration_id': self.integration.id,
            'credentials': {
                'host': 'new-db.internal', 'region': 'us-east', 'password': '',
                'api_token': '********', 'client_secret': '',
            },
            'enabled': True,
        })
        self.assertEqual(preserve_response.status_code, 200)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.credentials['host'], 'new-db.internal')
        self.assertEqual(self.credential.credentials['region'], 'us-east')
        self.assertEqual(self.credential.credentials['password'], self.initial_credentials['password'])
        self.assertEqual(self.credential.credentials['api_token'], self.initial_credentials['api_token'])
        self.assertEqual(self.credential.credentials['client_secret'], self.initial_credentials['client_secret'])

        replace_response = self.json_post({
            'integration_id': self.integration.id,
            'credentials': {'password': 'new-password', 'api_token': 'new-token'},
            'enabled': True,
        })
        self.assertEqual(replace_response.status_code, 200)
        self.credential.refresh_from_db()
        self.assertNotEqual(self.credential.credentials['password'], self.initial_credentials['password'])
        self.assertNotEqual(self.credential.credentials['api_token'], self.initial_credentials['api_token'])
        self.assertNotEqual(self.credential.credentials['password'], '********')

    def test_unauthorized_users_cannot_read_or_write_credential_configuration(self):
        self.assertEqual(self.client.get(self.fields_url, secure=True).status_code, 401)
        self.assertEqual(self.json_post({'integration_id': self.integration.id, 'credentials': {}, 'enabled': False}).status_code, 401)
        for user in (self.normal_user, self.staff_user):
            self.client.force_login(user)
            self.assertEqual(self.client.get(self.fields_url, secure=True).status_code, 403)
            self.assertEqual(self.json_post({'integration_id': self.integration.id, 'credentials': {}, 'enabled': False}).status_code, 403)
            self.client.logout()
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.credentials['password'], self.initial_credentials['password'])

    def test_django_admin_does_not_register_raw_credential_json(self):
        from django.contrib import admin

        self.assertNotIn(IntegrationCredential, admin.site._registry)


class IntegrationCredentialEncryptionTests(TestCase):
    def setUp(self):
        self.superuser = User.objects.create_superuser(
            'encryption-admin', 'encryption-admin@example.com', 'password'
        )
        self.integration = Integration.objects.create(
            name='Encryption runtime integration',
            description='Integration encryption test',
            fields={'host': 'Host', 'database': 'Database', 'username': 'Username', 'password': 'Password', 'api_token': 'API token'},
        )
        self.save_url = reverse('save_api_credentials')

    def json_post(self, payload):
        return self.client.post(self.save_url, data=json.dumps(payload), content_type='application/json', secure=True)

    def test_new_secrets_are_encrypted_non_secrets_remain_plain_and_runtime_decrypts(self):
        self.client.force_login(self.superuser)
        response = self.json_post({
            'integration_id': self.integration.id,
            'credentials': {'host': 'db.internal', 'database': 'catalog', 'username': 'runtime-user', 'password': 'runtime-password', 'api_token': 'runtime-token'},
            'enabled': True,
        })
        self.assertEqual(response.status_code, 200)
        credential = IntegrationCredential.objects.get(user=self.superuser, integration=self.integration)
        self.assertEqual(credential.credentials['host'], 'db.internal')
        self.assertTrue(credential.credentials['password'].startswith('enc:v1:'))
        self.assertTrue(credential.credentials['api_token'].startswith('enc:v1:'))
        self.assertNotIn('runtime-password', credential.credentials.values())
        self.assertNotIn('runtime-token', credential.credentials.values())
        from integrator.integration_credentials import decrypt_credentials_for_runtime

        decrypted = decrypt_credentials_for_runtime(self.integration.fields, credential.credentials)
        self.assertEqual(decrypted['host'], 'db.internal')
        self.assertEqual(decrypted['password'], 'runtime-password')
        self.assertEqual(decrypted['api_token'], 'runtime-token')

    def test_preserve_replace_double_encryption_and_fail_closed_cases(self):
        self.client.force_login(self.superuser)
        initial = self.json_post({
            'integration_id': self.integration.id,
            'credentials': {'host': 'db.internal', 'database': 'catalog', 'username': 'runtime-user', 'password': 'first-password', 'api_token': 'first-token'},
            'enabled': True,
        })
        self.assertEqual(initial.status_code, 200)
        credential = IntegrationCredential.objects.get(user=self.superuser, integration=self.integration)
        original_password = credential.credentials['password']
        original_token = credential.credentials['api_token']
        preserved = self.json_post({
            'integration_id': self.integration.id,
            'credentials': {'password': '', 'api_token': '********'},
            'enabled': True,
        })
        self.assertEqual(preserved.status_code, 200)
        credential.refresh_from_db()
        self.assertEqual(credential.credentials['password'], original_password)
        self.assertEqual(credential.credentials['api_token'], original_token)
        replaced = self.json_post({
            'integration_id': self.integration.id,
            'credentials': {'password': 'second-password'},
            'enabled': True,
        })
        self.assertEqual(replaced.status_code, 200)
        credential.refresh_from_db()
        self.assertNotEqual(credential.credentials['password'], original_password)

        from integrator.integration_credentials import CredentialEncryptionError, decrypt_secret, encrypt_secret

        self.assertEqual(encrypt_secret(credential.credentials['password']), credential.credentials['password'])
        with self.assertRaises(CredentialEncryptionError):
            decrypt_secret('enc:v1:not-a-valid-token')
        with self.assertRaises(CredentialEncryptionError):
            decrypt_secret('enc:v2:unknown-version')

    def test_runtime_database_consumer_receives_decrypted_password_only_at_connector_boundary(self):
        from integrator.integration_credentials import encrypt_credentials_for_storage
        from integrator.db_utils import fetch_data_from_integration

        credential = IntegrationCredential.objects.create(
            user=self.superuser,
            integration=self.integration,
            credentials=encrypt_credentials_for_storage(self.integration.fields, {
                'host': 'db.internal', 'database': 'catalog', 'username': 'runtime-user', 'password': 'runtime-password',
            }),
            enabled=True,
        )
        cursor = MagicMock()
        cursor.description = [('id',)]
        cursor.fetchmany.return_value = []
        connection = MagicMock()
        connection.cursor.return_value = cursor
        with patch('integrator.db_config.should_use_mssql', return_value=True), patch(
            'integrator.db_config.get_available_odbc_driver', return_value='Mock ODBC Driver'
        ), patch('integrator.db_utils.pyodbc.connect', return_value=connection) as connector:
            self.assertEqual(fetch_data_from_integration(self.superuser, self.integration.id, 'SELECT id FROM records'), [])
        credential.refresh_from_db()
        self.assertTrue(credential.credentials['password'].startswith('enc:v1:'))
        self.assertIn('PWD=runtime-password;', connector.call_args.args[0])


class IntegrationCredentialEncryptionMigrationTests(TransactionTestCase):
    reset_sequences = True
    migrate_from = [('integrator', '0012_procedureexecutionaudit')]
    migrate_to = [('integrator', '0013_encrypt_integrationcredential_secrets')]

    def test_data_migration_encrypts_only_secret_values_and_is_irreversible(self):
        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_from)
        old_apps = executor.loader.project_state(self.migrate_from).apps
        old_user = old_apps.get_model('auth', 'User')
        old_integration = old_apps.get_model('integrator', 'Integration')
        old_credential = old_apps.get_model('integrator', 'IntegrationCredential')
        user = old_user.objects.create(username='migration-encryption-user')
        legacy = old_integration.objects.create(
            name='Legacy encrypted migration integration', description='legacy',
            fields={'host': 'Host', 'api_token': 'API token', 'password': 'Password'},
        )
        structured = old_integration.objects.create(
            name='Structured encrypted migration integration', description='structured',
            fields={'region': {'label': 'Region'}, 'client_secret': {'label': 'Client secret', 'secret': True}},
        )
        empty = old_integration.objects.create(
            name='Empty encrypted migration integration', description='empty', fields={'api_token': 'API token'},
        )
        already_encrypted = old_integration.objects.create(
            name='Already encrypted migration integration', description='already encrypted', fields={'api_token': 'API token'},
        )
        legacy_credential = old_credential.objects.create(
            user_id=user.id, integration_id=legacy.id,
            credentials={'host': 'legacy-host', 'api_token': 'legacy-token', 'password': 'legacy-password'},
        )
        structured_credential = old_credential.objects.create(
            user_id=user.id, integration_id=structured.id,
            credentials={'region': 'us-east', 'client_secret': 'structured-secret'},
        )
        empty_credential = old_credential.objects.create(user_id=user.id, integration_id=empty.id, credentials=None)
        from integrator.integration_credentials import encrypt_secret
        existing_ciphertext = encrypt_secret('existing-token')
        already_encrypted_credential = old_credential.objects.create(
            user_id=user.id, integration_id=already_encrypted.id, credentials={'api_token': existing_ciphertext},
        )

        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_to)
        new_apps = executor.loader.project_state(self.migrate_to).apps
        credential_model = new_apps.get_model('integrator', 'IntegrationCredential')
        migrated_legacy = credential_model.objects.get(pk=legacy_credential.id)
        migrated_structured = credential_model.objects.get(pk=structured_credential.id)
        self.assertEqual(migrated_legacy.credentials['host'], 'legacy-host')
        self.assertTrue(migrated_legacy.credentials['api_token'].startswith('enc:v1:'))
        self.assertTrue(migrated_legacy.credentials['password'].startswith('enc:v1:'))
        self.assertEqual(migrated_structured.credentials['region'], 'us-east')
        self.assertTrue(migrated_structured.credentials['client_secret'].startswith('enc:v1:'))
        self.assertIsNone(credential_model.objects.get(pk=empty_credential.id).credentials)
        self.assertEqual(
            credential_model.objects.get(pk=already_encrypted_credential.id).credentials['api_token'],
            existing_ciphertext,
        )
        legacy_ciphertext = migrated_legacy.credentials['api_token']

        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_from)
        reversed_apps = executor.loader.project_state(self.migrate_from).apps
        reversed_credential = reversed_apps.get_model('integrator', 'IntegrationCredential')
        self.assertEqual(reversed_credential.objects.get(pk=legacy_credential.id).credentials['api_token'], legacy_ciphertext)

        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_to)


class IntegrationAndConfigurationAuthorizationTests(TestCase):
    def setUp(self):
        self.normal_user = User.objects.create_user('config-normal', password='password')
        self.staff_user = User.objects.create_user(
            'config-staff', password='password', is_staff=True
        )
        self.superuser = User.objects.create_superuser(
            'config-admin', 'config-admin@example.com', 'password'
        )
        self.integration = Integration.objects.create(
            name='Configuration test integration',
            description='Integration used only by authorization tests',
            fields={'api_token': 'API token'},
        )
        self.integration_credential = IntegrationCredential.objects.create(
            user=self.superuser,
            integration=self.integration,
            credentials={'api_token': 'test-token'},
            enabled=False,
        )
        self.connection = DatabaseConnection(
            user=self.superuser,
            name='Configuration test connection',
            connection_type='mssql',
            server='test-server',
            port='1433',
            database_name='test-database',
            username='test-user',
        )
        self.connection.set_password('test-password')
        self.connection.save()
        self.saved_query = SavedQuery.objects.create(
            user=self.superuser,
            connection=self.connection,
            name='Configuration test query',
            query_text='SELECT 1',
        )

    def urls(self):
        return {
            'integrations_page': reverse('integrations'),
            'integration_fields': reverse('fetch_integration_fields', args=[self.integration.id]),
            'integration_save': reverse('save_api_credentials'),
            'integration_toggle': reverse('toggle_integration'),
            'configurations_page': reverse('configurations'),
            'pmweb_configurations_page': reverse('pmweb_configurations'),
            'connections': reverse('database_connections'),
            'connection_detail': reverse('database_connection_detail', args=[self.connection.id]),
            'connection_test': reverse('test_database_connection'),
            'connection_save': reverse('save_database_connection'),
            'saved_queries': reverse('saved_queries'),
            'saved_query_detail': reverse('saved_query_detail', args=[self.saved_query.id]),
            'save_query': reverse('save_query'),
            'stored_procedures': reverse('stored_procedures', args=[self.connection.id]),
            'procedure_parameters': reverse(
                'procedure_parameters', args=[self.connection.id, 'dbo.example_procedure']
            ),
            'save_procedure_execution': reverse('save_procedure_execution'),
            'saved_procedure_executions': reverse('saved_procedure_executions'),
        }

    def connection_payload(self, **overrides):
        payload = {
            'name': 'Updated configuration test connection',
            'type': 'mssql',
            'server': 'test-server',
            'port': '1433',
            'database': 'test-database',
            'username': 'test-user',
            'password': 'test-password',
            'is_default': False,
        }
        payload.update(overrides)
        return payload

    def json_post(self, url, payload):
        return self.client.post(
            url,
            data=json.dumps(payload),
            content_type='application/json',
            secure=True,
        )

    def assert_json_management_denied(self, expected_status, connect):
        urls = self.urls()
        self.assertEqual(self.client.get(urls['integration_fields'], secure=True).status_code, expected_status)
        self.assertEqual(
            self.json_post(
                urls['integration_save'],
                {
                    'integration_id': self.integration.id,
                    'credentials': {'api_token': 'replacement-token'},
                    'enabled': True,
                },
            ).status_code,
            expected_status,
        )
        self.assertEqual(
            self.json_post(
                urls['integration_toggle'],
                {'integration_id': self.integration.id, 'enabled': True},
            ).status_code,
            expected_status,
        )
        self.assertEqual(self.client.get(urls['connections'], secure=True).status_code, expected_status)
        self.assertEqual(self.client.get(urls['connection_detail'], secure=True).status_code, expected_status)
        self.assertEqual(
            self.json_post(urls['connection_save'], self.connection_payload()).status_code,
            expected_status,
        )
        self.assertEqual(
            self.client.delete(urls['connection_detail'], secure=True).status_code,
            expected_status,
        )
        self.assertEqual(self.client.get(urls['saved_queries'], secure=True).status_code, expected_status)
        self.assertEqual(
            self.client.get(urls['saved_query_detail'], secure=True).status_code,
            expected_status,
        )
        self.assertEqual(
            self.json_post(
                urls['save_query'],
                {
                    'name': 'Denied query',
                    'connection_id': self.connection.id,
                    'query': 'SELECT 1',
                },
            ).status_code,
            expected_status,
        )
        self.assertEqual(
            self.client.get(urls['stored_procedures'], secure=True).status_code,
            expected_status,
        )
        self.assertEqual(
            self.client.get(urls['procedure_parameters'], secure=True).status_code,
            expected_status,
        )
        self.assertEqual(
            self.json_post(
                urls['save_procedure_execution'],
                {
                    'connection_id': self.connection.id,
                    'name': 'Denied procedure configuration',
                    'procedure_name': 'example_procedure',
                },
            ).status_code,
            expected_status,
        )
        self.assertEqual(
            self.client.get(urls['saved_procedure_executions'], secure=True).status_code,
            expected_status,
        )
        self.assertEqual(
            self.json_post(urls['connection_test'], self.connection_payload()).status_code,
            expected_status,
        )
        connect.assert_not_called()

    def assert_denied_mutations_preserve_records(self):
        self.integration_credential.refresh_from_db()
        self.connection.refresh_from_db()
        self.assertFalse(self.integration_credential.enabled)
        self.assertEqual(self.connection.name, 'Configuration test connection')
        self.assertTrue(DatabaseConnection.objects.filter(pk=self.connection.pk).exists())
        self.assertFalse(IntegrationCredential.objects.filter(user=self.normal_user).exists())
        self.assertFalse(IntegrationCredential.objects.filter(user=self.staff_user).exists())
        self.assertFalse(SavedQuery.objects.filter(name='Denied query').exists())
        self.assertFalse(SavedProcedureExecution.objects.filter(name='Denied procedure configuration').exists())

    def test_anonymous_pages_redirect_and_management_json_returns_401_without_connecting(self):
        urls = self.urls()
        self.assertEqual(self.client.get(urls['integrations_page'], secure=True).status_code, 302)
        self.assertEqual(self.client.get(urls['configurations_page'], secure=True).status_code, 302)
        self.assertEqual(self.client.get(urls['pmweb_configurations_page'], secure=True).status_code, 302)
        with patch('integrator.views.pyodbc.connect') as connect:
            self.assert_json_management_denied(401, connect)
        self.assert_denied_mutations_preserve_records()

    def test_normal_and_staff_users_are_denied_without_mutation_or_connecting(self):
        urls = self.urls()
        for user in (self.normal_user, self.staff_user):
            self.client.force_login(user)
            self.assertEqual(self.client.get(urls['integrations_page'], secure=True).status_code, 403)
            self.assertEqual(self.client.get(urls['configurations_page'], secure=True).status_code, 403)
            self.assertEqual(self.client.get(urls['pmweb_configurations_page'], secure=True).status_code, 403)
            with patch('integrator.views.pyodbc.connect') as connect:
                self.assert_json_management_denied(403, connect)
            self.assert_denied_mutations_preserve_records()
            self.client.logout()

    def test_superuser_retains_management_mutations_and_mocked_connection_testing(self):
        self.client.force_login(self.superuser)
        urls = self.urls()
        self.assertEqual(self.client.get(urls['integrations_page'], secure=True).status_code, 200)
        self.assertEqual(self.client.get(urls['configurations_page'], secure=True).status_code, 200)
        self.assertEqual(self.client.get(urls['pmweb_configurations_page'], secure=True).status_code, 200)
        self.assertEqual(self.client.get(urls['integration_fields'], secure=True).status_code, 200)

        self.assertEqual(
            self.json_post(
                urls['integration_save'],
                {
                    'integration_id': self.integration.id,
                    'credentials': {'api_token': 'replacement-token'},
                    'enabled': True,
                },
            ).status_code,
            200,
        )
        self.integration_credential.refresh_from_db()
        self.assertTrue(self.integration_credential.enabled)
        self.assertEqual(
            self.json_post(
                urls['integration_toggle'],
                {'integration_id': self.integration.id, 'enabled': False},
            ).status_code,
            200,
        )
        self.integration_credential.refresh_from_db()
        self.assertFalse(self.integration_credential.enabled)

        self.assertEqual(self.client.get(urls['connections'], secure=True).status_code, 200)
        self.assertEqual(self.client.get(urls['connection_detail'], secure=True).status_code, 200)
        self.assertEqual(
            self.json_post(
                urls['connection_save'], self.connection_payload(id=self.connection.id)
            ).status_code,
            200,
        )
        self.connection.refresh_from_db()
        self.assertEqual(self.connection.name, 'Updated configuration test connection')

        created_connection_response = self.json_post(
            urls['connection_save'], self.connection_payload(name='Created configuration test connection')
        )
        self.assertEqual(created_connection_response.status_code, 200)
        created_connection_id = created_connection_response.json()['connection_id']
        self.assertTrue(DatabaseConnection.objects.filter(pk=created_connection_id).exists())
        self.assertEqual(
            self.client.delete(
                reverse('database_connection_detail', args=[created_connection_id]), secure=True
            ).status_code,
            200,
        )
        self.assertFalse(DatabaseConnection.objects.filter(pk=created_connection_id).exists())

        self.assertEqual(self.client.get(urls['saved_queries'], secure=True).status_code, 200)
        self.assertEqual(self.client.get(urls['saved_query_detail'], secure=True).status_code, 200)
        self.assertEqual(
            self.json_post(
                urls['save_query'],
                {
                    'id': self.saved_query.id,
                    'name': 'Updated configuration test query',
                    'connection_id': self.connection.id,
                    'query': 'SELECT 1',
                },
            ).status_code,
            200,
        )
        self.saved_query.refresh_from_db()
        self.assertEqual(self.saved_query.name, 'Updated configuration test query')

        self.assertEqual(
            self.json_post(
                urls['save_procedure_execution'],
                {
                    'connection_id': self.connection.id,
                    'name': 'Configuration test procedure',
                    'procedure_name': 'example_procedure',
                },
            ).status_code,
            200,
        )
        self.assertTrue(SavedProcedureExecution.objects.filter(name='Configuration test procedure').exists())
        saved_executions_response = self.client.get(urls['saved_procedure_executions'], secure=True)
        self.assertEqual(saved_executions_response.status_code, 200)
        saved_executions = saved_executions_response.json()['executions']
        self.assertEqual(len(saved_executions), 1)
        self.assertEqual(saved_executions[0]['name'], 'Configuration test procedure')
        self.assertEqual(saved_executions[0]['connection_id'], self.connection.id)
        self.assertEqual(saved_executions[0]['connection_name'], self.connection.name)
        self.assertNotIn('password', saved_executions[0])
        self.assertNotIn('username', saved_executions[0])
        self.assertNotIn('server', saved_executions[0])
        self.assertNotIn('test-password', json.dumps(saved_executions))

        cursor = MagicMock()
        cursor.fetchall.return_value = []
        connection = MagicMock()
        connection.cursor.return_value = cursor
        with patch('integrator.db_config.get_available_odbc_driver', return_value='Mock ODBC Driver'), patch(
            'integrator.views.pyodbc.connect', return_value=connection
        ) as connect:
            self.assertEqual(
                self.json_post(urls['connection_test'], self.connection_payload()).status_code,
                200,
            )
            self.assertEqual(self.client.get(urls['stored_procedures'], secure=True).status_code, 200)
            self.assertEqual(self.client.get(urls['procedure_parameters'], secure=True).status_code, 200)
            self.assertGreaterEqual(connect.call_count, 3)


class ExternalExecutionAuthorizationTests(TestCase):
    def setUp(self):
        self.normal_user = User.objects.create_user('execution-normal', password='password')
        self.staff_user = User.objects.create_user(
            'execution-staff', password='password', is_staff=True
        )
        self.superuser = User.objects.create_superuser(
            'execution-admin', 'execution-admin@example.com', 'password'
        )
        self.connection = DatabaseConnection(
            user=self.superuser,
            name='Execution test connection',
            connection_type='mssql',
            server='test-server',
            port='1433',
            database_name='test-database',
            username='test-user',
        )
        self.connection.set_password('test-password')
        self.connection.save()
        self.saved_query = SavedQuery.objects.create(
            user=self.superuser,
            connection=self.connection,
            name='Execution test query',
            query_text='SELECT 1',
        )

    def urls(self):
        return {
            'initiatives': reverse('initiatives'),
            'table_data': reverse('fetch_table_data'),
            'preview': reverse('fetch_database_data'),
            'run_query': reverse('run_query'),
            'run_saved_query': reverse('run_saved_query', args=[self.saved_query.id]),
            'execute_procedure': reverse('execute_procedure'),
        }

    def json_post(self, url, payload):
        return self.client.post(
            url,
            data=json.dumps(payload),
            content_type='application/json',
            secure=True,
        )

    def execution_payload(self):
        return {'connection_id': self.connection.id, 'query': 'SELECT 1'}

    def procedure_payload(self):
        return {
            'connection_id': self.connection.id,
            'procedure_name': 'example_procedure',
            'parameters': [],
        }

    def assert_json_execution_denied(self, expected_status, connector, preview_helper, mssql_helper):
        urls = self.urls()
        self.assertEqual(self.client.get(urls['table_data'], {'table': 'safe_table'}, secure=True).status_code, expected_status)
        self.assertEqual(
            self.json_post(
                urls['preview'],
                {'connection_id': f'db_{self.connection.id}', 'query': 'SELECT 1'},
            ).status_code,
            expected_status,
        )
        self.assertEqual(self.json_post(urls['run_query'], self.execution_payload()).status_code, expected_status)
        self.assertEqual(
            self.json_post(urls['execute_procedure'], self.procedure_payload()).status_code,
            expected_status,
        )
        connector.assert_not_called()
        preview_helper.assert_not_called()
        mssql_helper.assert_not_called()

    def test_anonymous_execution_requests_are_denied_before_any_execution_boundary(self):
        urls = self.urls()
        self.assertEqual(self.client.get(urls['initiatives'], secure=True).status_code, 302)
        self.assertEqual(self.client.get(urls['run_saved_query'], secure=True).status_code, 302)
        with patch('integrator.views.pyodbc.connect') as connector, patch(
            'integrator.views.fetch_data_from_connection'
        ) as preview_helper, patch('integrator.views.fetch_mssql_data') as mssql_helper:
            self.assert_json_execution_denied(401, connector, preview_helper, mssql_helper)

    def test_normal_and_staff_users_are_denied_before_any_execution_boundary(self):
        urls = self.urls()
        for user in (self.normal_user, self.staff_user):
            self.client.force_login(user)
            self.assertEqual(self.client.get(urls['initiatives'], secure=True).status_code, 403)
            self.assertEqual(self.client.get(urls['run_saved_query'], secure=True).status_code, 403)
            with patch('integrator.views.pyodbc.connect') as connector, patch(
                'integrator.views.fetch_data_from_connection'
            ) as preview_helper, patch('integrator.views.fetch_mssql_data') as mssql_helper:
                self.assert_json_execution_denied(403, connector, preview_helper, mssql_helper)
            self.client.logout()

    def test_superuser_reaches_existing_execution_paths_with_mocked_connectors(self):
        self.client.force_login(self.superuser)
        urls = self.urls()
        cursor = MagicMock()
        cursor.description = [('result',)]
        cursor.fetchmany.return_value = [(1,)]
        cursor.fetchall.return_value = [(1,)]
        cursor.nextset.return_value = False
        connection = MagicMock()
        connection.cursor.return_value = cursor

        with patch(
            'integrator.views.fetch_mssql_data',
            side_effect=[[], [{'TABLE_NAME': 'safe_table'}], []],
        ) as mssql_helper:
            self.assertEqual(self.client.get(urls['initiatives'], secure=True).status_code, 200)
            self.assertEqual(self.client.get(urls['table_data'], {'table': 'safe_table'}, secure=True).status_code, 200)
            self.assertEqual(mssql_helper.call_count, 3)

        with patch('integrator.views.fetch_data_from_connection', return_value=[]) as preview_helper:
            self.assertEqual(
                self.json_post(
                    urls['preview'],
                    {'connection_id': f'db_{self.connection.id}', 'query': 'SELECT 1'},
                ).status_code,
                200,
            )
            preview_helper.assert_called_once_with(
                self.superuser,
                str(self.connection.id),
                'SELECT 1',
                max_rows=DEFAULT_ADMIN_MAX_ROWS,
                execution_context='form-builder database preview',
            )

        with patch('integrator.db_config.get_available_odbc_driver', return_value='Mock ODBC Driver'), patch(
            'integrator.views.pyodbc.connect', return_value=connection
        ) as connector:
            query_response = self.json_post(urls['run_query'], self.execution_payload())
            self.assertEqual(query_response.status_code, 200)
            procedure_response = self.json_post(urls['execute_procedure'], self.procedure_payload())
            self.assertEqual(procedure_response.status_code, 400)
            self.assertEqual(procedure_response.json()['error'], 'Procedure execution is not available.')
            self.assertEqual(connector.call_count, 1)
            self.assertEqual(cursor.execute.call_count, 1)

        with patch('integrator.views.render', return_value=HttpResponse('saved query result')):
            self.assertEqual(self.client.get(urls['run_saved_query'], secure=True).status_code, 200)

    def test_execution_errors_do_not_return_raw_connector_details(self):
        self.client.force_login(self.superuser)
        with patch('integrator.views.fetch_data_from_connection', side_effect=RuntimeError('internal-host-detail')):
            response = self.json_post(
                self.urls()['preview'],
                {'connection_id': f'db_{self.connection.id}', 'query': 'SELECT 1'},
            )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()['error'], 'Database preview failed.')
        self.assertNotIn('internal-host-detail', response.content.decode())

    def test_query_timeout_returns_a_generic_error_and_closes_resources(self):
        self.client.force_login(self.superuser)
        cursor = MagicMock()
        cursor.execute.side_effect = RuntimeError('HYT00 query timeout on hidden host')
        connection = MagicMock()
        connection.cursor.return_value = cursor
        with patch('integrator.db_config.get_available_odbc_driver', return_value='Mock ODBC Driver'), patch(
            'integrator.views.pyodbc.connect', return_value=connection
        ):
            response = self.json_post(self.urls()['run_query'], self.execution_payload())

        self.assertEqual(response.status_code, 504)
        self.assertEqual(response.json()['error'], 'Database query timed out.')
        self.assertNotIn('hidden host', response.content.decode())
        cursor.close.assert_called_once()
        connection.close.assert_called_once()

    def test_preview_timeout_returns_a_generic_error(self):
        self.client.force_login(self.superuser)
        with patch(
            'integrator.views.fetch_data_from_connection',
            side_effect=ExternalQueryTimeoutError('Database query timed out.'),
        ):
            response = self.json_post(
                self.urls()['preview'],
                {'connection_id': f'db_{self.connection.id}', 'query': 'SELECT 1'},
            )
        self.assertEqual(response.status_code, 504)
        self.assertEqual(response.json()['error'], 'Database query timed out.')

    def test_postgresql_read_only_setup_failure_blocks_administrative_execution(self):
        postgresql_connection = DatabaseConnection(
            user=self.superuser,
            name='PostgreSQL execution connection',
            connection_type='postgresql',
            server='test-server',
            port='5432',
            database_name='test-database',
            username='test-user',
        )
        postgresql_connection.set_password('test-password')
        postgresql_connection.save()
        self.client.force_login(self.superuser)

        external_connection = MagicMock()
        external_connection.set_session.side_effect = RuntimeError('read-only setup unavailable')
        with patch('psycopg2.connect', return_value=external_connection):
            response = self.json_post(
                self.urls()['run_query'],
                {'connection_id': postgresql_connection.id, 'query': 'SELECT 1'},
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()['error'], 'Query execution failed.')
        external_connection.cursor.assert_not_called()
        external_connection.close.assert_called_once()

    def test_administrative_query_is_bounded_and_reports_truncation(self):
        self.client.force_login(self.superuser)
        cursor = MagicMock()
        cursor.description = [('id',)]
        cursor.fetchmany.return_value = [(1,), (2,), (3,)]
        connection = MagicMock()
        connection.cursor.return_value = cursor
        with patch.dict(os.environ, {'EXTERNAL_DB_MAX_ROWS': '2'}, clear=False), patch(
            'integrator.db_config.get_available_odbc_driver', return_value='Mock ODBC Driver'
        ), patch('integrator.views.pyodbc.connect', return_value=connection) as connector:
            response = self.json_post(self.urls()['run_query'], self.execution_payload())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['results'], [{'id': 1}, {'id': 2}])
        self.assertTrue(response.json()['truncated'])
        self.assertIn('Connection Timeout=10;', connector.call_args.args[0])
        self.assertEqual(cursor.timeout, 30)
        cursor.fetchmany.assert_called_once_with(3)
        cursor.fetchall.assert_not_called()

    def test_unsafe_administrative_queries_are_rejected_before_connecting(self):
        self.client.force_login(self.superuser)
        with patch('integrator.views.pyodbc.connect') as connector, patch(
            'integrator.views.fetch_data_from_connection'
        ) as preview_helper:
            run_response = self.json_post(
                self.urls()['run_query'],
                {'connection_id': self.connection.id, 'query': 'SELECT 1; DELETE FROM records'},
            )
            preview_response = self.json_post(
                self.urls()['preview'],
                {'connection_id': f'db_{self.connection.id}', 'query': 'DELETE FROM records'},
            )
        self.assertEqual(run_response.status_code, 400)
        self.assertEqual(preview_response.status_code, 400)
        self.assertEqual(run_response.json()['error'], USER_FACING_ERROR)
        self.assertEqual(preview_response.json()['error'], USER_FACING_ERROR)
        connector.assert_not_called()
        preview_helper.assert_not_called()


class ApprovedProcedureExecutionTests(TestCase):
    def setUp(self):
        self.normal_user = User.objects.create_user('procedure-normal', password='password')
        self.staff_user = User.objects.create_user('procedure-staff', password='password', is_staff=True)
        self.superuser = User.objects.create_superuser(
            'procedure-admin', 'procedure-admin@example.com', 'password'
        )
        self.connection = DatabaseConnection(
            user=self.superuser,
            name='Approved procedure connection',
            connection_type='mssql',
            server='approved-server',
            port='1433',
            database_name='approved-catalog',
            username='approved-user',
        )
        self.connection.set_password('test-password')
        self.connection.save()
        self.url = reverse('execute_procedure')

    def json_post(self, payload):
        return self.client.post(self.url, data=json.dumps(payload), content_type='application/json', secure=True)

    def create_approval(self, *, enabled=True, behavior=ApprovedProcedure.READ_EXPECTED, engine=None):
        return ApprovedProcedure.objects.create(
            connection=self.connection,
            engine=engine or self.connection.connection_type,
            database_name='approved-catalog',
            schema='approved_schema',
            procedure_name=f'approved_read_{ApprovedProcedure.objects.filter(connection=self.connection).count() + 1}',
            behavior=behavior,
            enabled=enabled,
            approved_by=self.superuser,
        )

    def add_parameter(self, approval, **overrides):
        defaults = {
            'ordinal': 1,
            'name': 'CustomerId',
            'direction': ApprovedProcedureParameter.INPUT,
            'database_type': 'int',
            'required': True,
            'nullable': False,
        }
        defaults.update(overrides)
        return ApprovedProcedureParameter.objects.create(approved_procedure=approval, **defaults)

    def test_no_approval_disabled_and_mutating_records_are_denied_before_connecting(self):
        self.client.force_login(self.superuser)
        disabled = self.create_approval(enabled=False)
        mutating = self.create_approval(behavior=ApprovedProcedure.MUTATING)
        for procedure_id in (999999, disabled.id, mutating.id):
            with self.subTest(procedure_id=procedure_id), patch('integrator.views.pyodbc.connect') as connector:
                response = self.json_post({'approved_procedure_id': procedure_id, 'parameters': {}})
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()['error'], 'Procedure execution is not available.')
                connector.assert_not_called()

    def test_non_superusers_are_denied_regardless_of_approval(self):
        approval = self.create_approval()
        self.add_parameter(approval)
        for user, expected_status in ((self.normal_user, 403), (self.staff_user, 403)):
            self.client.force_login(user)
            with self.subTest(user=user.username), patch('integrator.views.pyodbc.connect') as connector:
                response = self.json_post({'approved_procedure_id': approval.id, 'parameters': {'CustomerId': 17}})
                self.assertEqual(response.status_code, expected_status)
                connector.assert_not_called()
            self.client.logout()

        with patch('integrator.views.pyodbc.connect') as connector:
            response = self.json_post({'approved_procedure_id': approval.id, 'parameters': {'CustomerId': 17}})
            self.assertEqual(response.status_code, 401)
            connector.assert_not_called()

    def test_enabled_read_expected_approval_uses_server_identity_and_bound_values(self):
        approval = self.create_approval()
        self.add_parameter(approval)
        self.client.force_login(self.superuser)
        cursor = MagicMock()
        cursor.description = None
        cursor.nextset.return_value = False
        external_connection = MagicMock()
        external_connection.cursor.return_value = cursor

        with patch('integrator.db_config.get_available_odbc_driver', return_value='Mock ODBC Driver'), patch(
            'integrator.views.pyodbc.connect', return_value=external_connection
        ) as connector:
            response = self.json_post({'approved_procedure_id': approval.id, 'parameters': {'CustomerId': 17}})

        self.assertEqual(response.status_code, 200)
        connector.assert_called_once()
        cursor.execute.assert_called_once_with('EXEC [approved_schema].[approved_read_1] @CustomerId=?', 17)
        external_connection.rollback.assert_called_once()
        external_connection.close.assert_called_once()

    def test_hostile_identity_and_contract_fields_are_rejected_before_connecting(self):
        approval = self.create_approval()
        self.add_parameter(approval)
        self.client.force_login(self.superuser)
        hostile_payload = {
            'approved_procedure_id': approval.id,
            'parameters': {'CustomerId': 17},
            'connection_id': 999,
            'schema': 'attacker_schema',
            'procedure_name': 'attacker_procedure',
            'database_name': 'attacker_database',
            'engine': 'mysql',
            'data_type': 'text',
            'direction': 'OUT',
        }
        with patch('integrator.views.pyodbc.connect') as connector:
            response = self.json_post(hostile_payload)
        self.assertEqual(response.status_code, 400)
        connector.assert_not_called()

    def test_invalid_parameter_contracts_are_denied_before_connecting(self):
        self.client.force_login(self.superuser)
        approval = self.create_approval()
        self.add_parameter(approval)
        invalid_payloads = [
            {},
            {'Unknown': 17},
            {'CustomerId': '17'},
            {'CustomerId': None},
        ]
        for parameters in invalid_payloads:
            with self.subTest(parameters=parameters), patch('integrator.views.pyodbc.connect') as connector:
                response = self.json_post({'approved_procedure_id': approval.id, 'parameters': parameters})
                self.assertEqual(response.status_code, 400)
                connector.assert_not_called()

    def test_string_decimal_date_boolean_output_and_unsupported_values_are_denied(self):
        self.client.force_login(self.superuser)
        cases = [
            ({'database_type': 'varchar', 'max_length': 2}, {'CustomerId': 'too long'}),
            ({'database_type': 'decimal'}, {'CustomerId': 'not-a-number'}),
            ({'database_type': 'date'}, {'CustomerId': '2026-99-99'}),
            ({'database_type': 'boolean'}, {'CustomerId': 'true'}),
            ({'direction': ApprovedProcedureParameter.OUTPUT}, {'CustomerId': 17}),
            ({'database_type': 'uniqueidentifier'}, {'CustomerId': '00000000-0000-0000-0000-000000000000'}),
        ]
        for index, (parameter_fields, parameters) in enumerate(cases):
            with self.subTest(index=index):
                approval = self.create_approval()
                self.add_parameter(approval, **parameter_fields)
                with patch('integrator.views.pyodbc.connect') as connector:
                    response = self.json_post({'approved_procedure_id': approval.id, 'parameters': parameters})
                self.assertEqual(response.status_code, 400)
                connector.assert_not_called()

    def test_connection_identity_drift_and_discovery_without_approval_are_denied(self):
        self.client.force_login(self.superuser)
        approval = self.create_approval()
        self.add_parameter(approval)
        self.connection.database_name = 'changed-catalog'
        self.connection.save(update_fields=['database_name'])
        with patch('integrator.views.pyodbc.connect') as connector:
            response = self.json_post({'approved_procedure_id': approval.id, 'parameters': {'CustomerId': 17}})
        self.assertEqual(response.status_code, 400)
        connector.assert_not_called()

    def test_mssql_results_are_bounded_and_timeout_is_configured_before_exec(self):
        approval = self.create_approval()
        self.add_parameter(approval)
        self.client.force_login(self.superuser)
        cursor = MagicMock()
        cursor.description = [('id',)]
        cursor.fetchmany.return_value = [(1,), (2,), (3,)]
        cursor.nextset.return_value = False
        external_connection = MagicMock()
        external_connection.cursor.return_value = cursor
        environment = {
            'EXTERNAL_DB_PROCEDURE_TIMEOUT': '7',
            'EXTERNAL_DB_PROCEDURE_MAX_ROWS_PER_RESULT_SET': '2',
            'EXTERNAL_DB_PROCEDURE_MAX_RESULT_SETS': '2',
            'EXTERNAL_DB_PROCEDURE_MAX_TOTAL_ROWS': '4',
        }
        with patch.dict(os.environ, environment, clear=False), patch(
            'integrator.db_config.get_available_odbc_driver', return_value='Mock ODBC Driver'
        ), patch('integrator.views.pyodbc.connect', return_value=external_connection) as connector:
            response = self.json_post({'approved_procedure_id': approval.id, 'parameters': {'CustomerId': 17}})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['truncated'])
        self.assertEqual(response.json()['row_count'], 2)
        self.assertEqual(cursor.timeout, 7)
        cursor.fetchmany.assert_called_once_with(3)
        cursor.fetchall.assert_not_called()
        cursor.execute.assert_called_once_with('EXEC [approved_schema].[approved_read_1] @CustomerId=?', 17)
        self.assertFalse(connector.call_args.kwargs['autocommit'])
        external_connection.rollback.assert_called_once()
        external_connection.close.assert_called_once()

    def test_multiple_result_sets_and_total_rows_are_capped_without_fetchall(self):
        approval = self.create_approval()
        self.add_parameter(approval)
        self.client.force_login(self.superuser)
        cursor = MagicMock()
        cursor.description = [('id',)]
        cursor.fetchmany.side_effect = [[(1,), (2,)], [(3,), (4,)]]
        cursor.nextset.side_effect = [True, False]
        external_connection = MagicMock()
        external_connection.cursor.return_value = cursor
        with patch.dict(os.environ, {
            'EXTERNAL_DB_PROCEDURE_MAX_ROWS_PER_RESULT_SET': '2',
            'EXTERNAL_DB_PROCEDURE_MAX_RESULT_SETS': '2',
            'EXTERNAL_DB_PROCEDURE_MAX_TOTAL_ROWS': '3',
        }, clear=False), patch('integrator.db_config.get_available_odbc_driver', return_value='Mock ODBC Driver'), patch(
            'integrator.views.pyodbc.connect', return_value=external_connection
        ):
            response = self.json_post({'approved_procedure_id': approval.id, 'parameters': {'CustomerId': 17}})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['truncated'])
        self.assertEqual(response.json()['row_count'], 3)
        self.assertEqual(len(response.json()['result_sets']), 2)
        self.assertEqual(cursor.fetchmany.call_args_list, [call(3), call(2)])
        cursor.fetchall.assert_not_called()

    def test_mysql_read_only_setup_failure_and_mssql_timeout_fail_safely(self):
        self.client.force_login(self.superuser)
        self.connection.connection_type = 'mysql'
        self.connection.save(update_fields=['connection_type'])
        mysql_approval = self.create_approval(engine='mysql')
        self.add_parameter(mysql_approval)
        mysql_cursor = MagicMock()
        mysql_cursor.execute.side_effect = RuntimeError('read-only setup failed')
        mysql_connection = MagicMock()
        mysql_connection.cursor.return_value = mysql_cursor
        with patch('pymysql.connect', return_value=mysql_connection):
            response = self.json_post({'approved_procedure_id': mysql_approval.id, 'parameters': {'CustomerId': 17}})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(mysql_cursor.execute.call_args_list, [call('SET TRANSACTION READ ONLY')])
        mysql_connection.rollback.assert_called_once()
        mysql_connection.close.assert_called_once()

        self.connection.connection_type = 'mssql'
        self.connection.save(update_fields=['connection_type'])
        mssql_approval = self.create_approval(engine='mssql')
        self.add_parameter(mssql_approval)
        mssql_cursor = MagicMock()
        mssql_cursor.execute.side_effect = RuntimeError('HYT00 hidden-host timeout')
        mssql_connection = MagicMock()
        mssql_connection.cursor.return_value = mssql_cursor
        with patch('integrator.db_config.get_available_odbc_driver', return_value='Mock ODBC Driver'), patch(
            'integrator.views.pyodbc.connect', return_value=mssql_connection
        ):
            response = self.json_post({'approved_procedure_id': mssql_approval.id, 'parameters': {'CustomerId': 17}})
        self.assertEqual(response.status_code, 504)
        self.assertEqual(response.json()['error'], 'Procedure execution timed out.')
        self.assertNotIn('hidden-host', response.content.decode())
        mssql_connection.rollback.assert_called_once()
        mssql_connection.close.assert_called_once()

    def test_postgresql_read_only_timeout_order_and_cleanup(self):
        self.connection.connection_type = 'postgresql'
        self.connection.port = '5432'
        self.connection.save(update_fields=['connection_type', 'port'])
        approval = self.create_approval(engine='postgresql')
        self.add_parameter(approval)
        self.client.force_login(self.superuser)
        cursor = MagicMock()
        cursor.description = None
        external_connection = MagicMock()
        external_connection.cursor.return_value = cursor
        with patch('psycopg2.connect', return_value=external_connection):
            response = self.json_post({'approved_procedure_id': approval.id, 'parameters': {'CustomerId': 17}})
        self.assertEqual(response.status_code, 200)
        external_connection.set_session.assert_called_once_with(readonly=True, autocommit=False)
        self.assertEqual(
            cursor.execute.call_args_list,
            [call('SET LOCAL statement_timeout = %s', (30000,)), call('CALL "approved_schema"."approved_read_1"(%s)', (17,))],
        )
        external_connection.rollback.assert_called_once()
        external_connection.close.assert_called_once()


class ProcedureExecutionAuditTests(TestCase):
    def setUp(self):
        self.superuser = User.objects.create_superuser(
            'procedure-audit-admin', 'procedure-audit-admin@example.com', 'password'
        )
        self.connection = DatabaseConnection(
            user=self.superuser,
            name='Procedure audit connection',
            connection_type='mssql',
            server='audit-server',
            port='1433',
            database_name='audit-catalog',
            username='audit-user',
        )
        self.connection.set_password('audit-password')
        self.connection.save()
        self.url = reverse('execute_procedure')
        self.client.force_login(self.superuser)

    def json_post(self, payload):
        return self.client.post(self.url, data=json.dumps(payload), content_type='application/json', secure=True)

    def create_approval(self, *, enabled=True, behavior=ApprovedProcedure.READ_EXPECTED):
        approval = ApprovedProcedure.objects.create(
            connection=self.connection,
            engine='mssql',
            database_name='audit-catalog',
            schema='audit_schema',
            procedure_name=f'audit_read_{ApprovedProcedure.objects.filter(connection=self.connection).count() + 1}',
            behavior=behavior,
            enabled=enabled,
            approved_by=self.superuser,
        )
        ApprovedProcedureParameter.objects.create(
            approved_procedure=approval,
            ordinal=1,
            name='CustomerId',
            direction=ApprovedProcedureParameter.INPUT,
            database_type='int',
        )
        return approval

    def successful_connector(self, *, rows=None):
        cursor = MagicMock()
        cursor.description = [('id',)] if rows is not None else None
        cursor.fetchmany.return_value = rows or []
        cursor.nextset.return_value = False
        connection = MagicMock()
        connection.cursor.return_value = cursor
        return connection, cursor

    def execute_successfully(self, approval, *, rows=None, environment=None, parameter_value=17):
        external_connection, cursor = self.successful_connector(rows=rows)
        with patch.dict(os.environ, environment or {}, clear=False), patch(
            'integrator.db_config.get_available_odbc_driver', return_value='Mock ODBC Driver'
        ), patch('integrator.views.pyodbc.connect', return_value=external_connection):
            response = self.json_post({
                'approved_procedure_id': approval.id,
                'parameters': {'CustomerId': parameter_value},
            })
        self.assertEqual(response.status_code, 200)
        return response, cursor

    def test_success_audit_persists_bounded_metadata_without_sensitive_values(self):
        approval = self.create_approval()
        sensitive_parameter = 918273645
        response, _ = self.execute_successfully(
            approval,
            rows=[(1,), (2,), (3,)],
            environment={'EXTERNAL_DB_PROCEDURE_MAX_ROWS_PER_RESULT_SET': '2'},
            parameter_value=sensitive_parameter,
        )

        self.assertTrue(response.json()['truncated'])
        audit = ProcedureExecutionAudit.objects.get()
        self.assertTrue(audit.success)
        self.assertEqual(audit.failure_category, ProcedureExecutionAudit.SUCCESS)
        self.assertEqual((audit.row_count, audit.result_set_count, audit.truncated), (2, 1, True))
        self.assertEqual(audit.user, self.superuser)
        self.assertEqual(audit.approved_procedure, approval)
        self.assertEqual(
            (audit.engine_snapshot, audit.database_name_snapshot, audit.schema_snapshot, audit.procedure_name_snapshot),
            ('mssql', 'audit-catalog', 'audit_schema', approval.procedure_name),
        )
        field_names = {field.name for field in ProcedureExecutionAudit._meta.fields}
        self.assertFalse({'parameters', 'password', 'connection_string'} & field_names)
        persisted_audit_metadata = (
            audit.failure_category,
            audit.engine_snapshot,
            audit.database_name_snapshot,
            audit.schema_snapshot,
            audit.procedure_name_snapshot,
        )
        self.assertFalse(any(str(sensitive_parameter) in value for value in persisted_audit_metadata))
        self.assertFalse(any('audit-password' in value for value in persisted_audit_metadata))
        self.assertFalse(any('PWD=' in value for value in persisted_audit_metadata))

    def test_timeout_and_execution_failure_are_sanitized_in_audit(self):
        approval = self.create_approval()
        timeout_cursor = MagicMock()
        timeout_cursor.execute.side_effect = RuntimeError('HYT00 internal-host timeout')
        timeout_connection = MagicMock()
        timeout_connection.cursor.return_value = timeout_cursor
        with patch('integrator.db_config.get_available_odbc_driver', return_value='Mock ODBC Driver'), patch(
            'integrator.views.pyodbc.connect', return_value=timeout_connection
        ):
            timeout_response = self.json_post({'approved_procedure_id': approval.id, 'parameters': {'CustomerId': 17}})
        self.assertEqual(timeout_response.status_code, 504)
        self.assertEqual(
            ProcedureExecutionAudit.objects.get().failure_category,
            ProcedureExecutionAudit.TIMEOUT,
        )

        failure_cursor = MagicMock()
        failure_cursor.execute.side_effect = RuntimeError('raw database exception: secret-host')
        failure_connection = MagicMock()
        failure_connection.cursor.return_value = failure_cursor
        with patch('integrator.db_config.get_available_odbc_driver', return_value='Mock ODBC Driver'), patch(
            'integrator.views.pyodbc.connect', return_value=failure_connection
        ):
            failure_response = self.json_post({'approved_procedure_id': approval.id, 'parameters': {'CustomerId': 17}})
        self.assertEqual(failure_response.status_code, 500)
        audit = ProcedureExecutionAudit.objects.order_by('-id').first()
        self.assertFalse(audit.success)
        self.assertEqual(audit.failure_category, ProcedureExecutionAudit.EXECUTION_FAILED)
        self.assertNotIn('secret-host', str(vars(audit)))

    def test_validation_disabled_mutating_and_identity_denials_are_audited_without_connecting(self):
        validation_approval = self.create_approval()
        disabled_approval = self.create_approval(enabled=False)
        mutating_approval = self.create_approval(behavior=ApprovedProcedure.MUTATING)
        with patch('integrator.views.pyodbc.connect') as connector:
            validation_response = self.json_post(
                {'approved_procedure_id': validation_approval.id, 'parameters': {'CustomerId': '17'}}
            )
            disabled_response = self.json_post({'approved_procedure_id': disabled_approval.id, 'parameters': {}})
            mutating_response = self.json_post({'approved_procedure_id': mutating_approval.id, 'parameters': {}})
        self.assertEqual([validation_response.status_code, disabled_response.status_code, mutating_response.status_code], [400, 400, 400])
        self.assertEqual(
            list(ProcedureExecutionAudit.objects.order_by('id').values_list('failure_category', flat=True)),
            [
                ProcedureExecutionAudit.VALIDATION_FAILED,
                ProcedureExecutionAudit.APPROVAL_DISABLED,
                ProcedureExecutionAudit.MUTATING_DENIED,
            ],
        )
        connector.assert_not_called()

        self.connection.database_name = 'drifted-catalog'
        self.connection.save(update_fields=['database_name'])
        with patch('integrator.views.pyodbc.connect') as connector:
            drift_response = self.json_post(
                {'approved_procedure_id': validation_approval.id, 'parameters': {'CustomerId': 17}}
            )
        self.assertEqual(drift_response.status_code, 400)
        self.assertEqual(
            ProcedureExecutionAudit.objects.order_by('-id').first().failure_category,
            ProcedureExecutionAudit.IDENTITY_MISMATCH,
        )
        connector.assert_not_called()

    def test_audit_snapshot_survives_approval_change_and_deletion(self):
        approval = self.create_approval()
        self.execute_successfully(approval)
        audit = ProcedureExecutionAudit.objects.get()
        original_name = audit.procedure_name_snapshot
        approval.procedure_name = 'changed_name'
        approval.save(update_fields=['procedure_name'])
        audit.refresh_from_db()
        self.assertEqual(audit.procedure_name_snapshot, original_name)
        approval.delete()
        audit.refresh_from_db()
        self.assertIsNone(audit.approved_procedure)
        self.assertEqual(audit.procedure_name_snapshot, original_name)

    def test_audit_persistence_failure_does_not_change_safe_execution_response(self):
        approval = self.create_approval()
        external_connection, _ = self.successful_connector()
        with patch('integrator.db_config.get_available_odbc_driver', return_value='Mock ODBC Driver'), patch(
            'integrator.views.pyodbc.connect', return_value=external_connection
        ) as connector, patch(
            'integrator.views.ProcedureExecutionAudit.objects.create', side_effect=RuntimeError('audit storage unavailable')
        ):
            response = self.json_post({'approved_procedure_id': approval.id, 'parameters': {'CustomerId': 17}})
        self.assertEqual(response.status_code, 200)
        connector.assert_called_once()
        self.assertEqual(ProcedureExecutionAudit.objects.count(), 0)


class ApprovedProcedureManagementTests(TestCase):
    def setUp(self):
        self.normal_user = User.objects.create_user('approval-normal', password='password')
        self.staff_user = User.objects.create_user('approval-staff', password='password', is_staff=True)
        self.superuser = User.objects.create_superuser('approval-admin', 'approval-admin@example.com', 'password')
        self.connection = DatabaseConnection(
            user=self.superuser, name='Approval connection', connection_type='mssql',
            server='approval-server', port='1433', database_name='approval-catalog', username='approval-user',
        )
        self.connection.set_password('approval-password')
        self.connection.save()
        self.page_url = reverse('approved_procedures')
        self.collection_url = reverse('approved_procedure_collection')

    def json_post(self, url, payload):
        return self.client.post(url, data=json.dumps(payload), content_type='application/json', secure=True)

    def create_approval(self, **overrides):
        defaults = {
            'connection': self.connection, 'engine': 'mssql', 'database_name': 'approval-catalog',
            'schema': 'dbo', 'procedure_name': 'reviewed_proc', 'behavior': ApprovedProcedure.READ_EXPECTED,
            'enabled': False, 'approved_by': self.superuser,
        }
        defaults.update(overrides)
        return ApprovedProcedure.objects.create(**defaults)

    def test_browser_and_json_authorization_are_contained(self):
        self.assertEqual(self.client.get(self.page_url, secure=True).status_code, 302)
        self.assertEqual(self.client.get(self.collection_url, secure=True).status_code, 401)
        for user in (self.normal_user, self.staff_user):
            self.client.force_login(user)
            self.assertEqual(self.client.get(self.page_url, secure=True).status_code, 403)
            self.assertEqual(self.client.get(self.collection_url, secure=True).status_code, 403)
            self.assertEqual(self.json_post(self.collection_url, {}).status_code, 403)
            self.client.logout()
        self.client.force_login(self.superuser)
        self.assertEqual(self.client.get(self.page_url, secure=True).status_code, 200)
        self.assertEqual(self.client.get(self.collection_url, secure=True).status_code, 200)

    def test_superuser_creates_disabled_connection_derived_approval_without_secrets(self):
        self.client.force_login(self.superuser)
        response = self.json_post(self.collection_url, {
            'connection_id': self.connection.id, 'schema': 'dbo', 'procedure_name': 'reviewed_proc',
        })
        self.assertEqual(response.status_code, 201)
        approval = ApprovedProcedure.objects.get()
        self.assertFalse(approval.enabled)
        self.assertEqual((approval.engine, approval.database_name, approval.behavior), ('mssql', 'approval-catalog', ApprovedProcedure.READ_EXPECTED))
        self.assertNotIn('approval-password', response.content.decode())
        self.assertNotIn('approval-user', response.content.decode())
        detail_page = self.client.get(reverse('approved_procedure_management_detail', args=[approval.id]), secure=True)
        self.assertEqual(detail_page.status_code, 200)
        self.assertNotIn('approval-password', detail_page.content.decode())
        configurations_page = self.client.get(reverse('configurations'), secure=True)
        self.assertEqual(configurations_page.status_code, 200)
        self.assertIn('Manage Approved Procedures', configurations_page.content.decode())
        rejected = self.json_post(self.collection_url, {
            'connection_id': self.connection.id, 'schema': 'dbo', 'procedure_name': 'another_proc', 'engine': 'mysql',
        })
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(ApprovedProcedure.objects.count(), 1)

    def test_denied_mutations_change_nothing_and_superuser_can_edit_and_toggle(self):
        approval = self.create_approval()
        detail_url = reverse('approved_procedure_detail', args=[approval.id])
        toggle_url = reverse('approved_procedure_toggle', args=[approval.id])
        self.client.force_login(self.normal_user)
        self.assertEqual(self.json_post(detail_url, {'schema': 'changed', 'procedure_name': 'changed', 'signature': ''}).status_code, 403)
        self.assertEqual(self.json_post(toggle_url, {'enabled': True}).status_code, 403)
        approval.refresh_from_db()
        self.assertEqual((approval.schema, approval.enabled), ('dbo', False))
        self.client.force_login(self.superuser)
        self.assertEqual(self.json_post(detail_url, {'schema': 'reviewed', 'procedure_name': 'renamed_proc', 'signature': ''}).status_code, 200)
        self.assertEqual(self.json_post(toggle_url, {'enabled': True}).status_code, 200)
        approval.refresh_from_db()
        self.assertEqual((approval.schema, approval.procedure_name, approval.enabled), ('reviewed', 'renamed_proc', True))

    def test_parameter_contract_validation_and_read_only_audit_history(self):
        approval = self.create_approval()
        parameters_url = reverse('approved_procedure_parameters', args=[approval.id])
        audits_url = reverse('approved_procedure_audits', args=[approval.id])
        self.client.force_login(self.superuser)
        invalid = self.json_post(parameters_url, {'parameters': [
            {'ordinal': 1, 'name': 'CustomerId', 'direction': 'IN', 'database_type': 'int', 'required': True, 'nullable': False, 'max_length': 3},
        ]})
        self.assertEqual(invalid.status_code, 400)
        valid = self.json_post(parameters_url, {'parameters': [
            {'ordinal': 1, 'name': 'CustomerId', 'direction': 'IN', 'database_type': 'int', 'required': True, 'nullable': False, 'max_length': None},
            {'ordinal': 2, 'name': 'ResultCode', 'direction': 'OUT', 'database_type': 'varchar', 'required': True, 'nullable': True, 'max_length': 20},
        ]})
        self.assertEqual(valid.status_code, 200)
        self.assertEqual(approval.parameters.count(), 2)
        ProcedureExecutionAudit.objects.create(
            user=self.superuser, approved_procedure=approval, success=False,
            failure_category=ProcedureExecutionAudit.EXECUTION_FAILED, duration_ms=5,
            engine_snapshot='mssql', database_name_snapshot='approval-catalog', schema_snapshot='dbo',
            procedure_name_snapshot='reviewed_proc',
        )
        history = self.client.get(audits_url, secure=True)
        self.assertEqual(history.status_code, 200)
        self.assertIn('EXECUTION_FAILED', history.content.decode())
        self.assertNotIn('approval-password', history.content.decode())
        self.assertNotIn('CustomerId', history.content.decode())

    def test_disabling_blocks_execution_and_mutating_cannot_be_enabled_or_executed(self):
        approval = self.create_approval(enabled=True)
        ApprovedProcedureParameter.objects.create(
            approved_procedure=approval, ordinal=1, name='CustomerId', direction='IN', database_type='int'
        )
        toggle_url = reverse('approved_procedure_toggle', args=[approval.id])
        self.client.force_login(self.superuser)
        self.assertEqual(self.json_post(toggle_url, {'enabled': False}).status_code, 200)
        with patch('integrator.views.pyodbc.connect') as connector:
            denied = self.json_post(reverse('execute_procedure'), {'approved_procedure_id': approval.id, 'parameters': {'CustomerId': 17}})
        self.assertEqual(denied.status_code, 400)
        connector.assert_not_called()
        mutating = self.create_approval(procedure_name='mutating_proc', behavior=ApprovedProcedure.MUTATING)
        mutating_toggle = self.json_post(reverse('approved_procedure_toggle', args=[mutating.id]), {'enabled': True})
        self.assertEqual(mutating_toggle.status_code, 400)
        with patch('integrator.views.pyodbc.connect') as connector:
            mutating_response = self.json_post(reverse('execute_procedure'), {'approved_procedure_id': mutating.id, 'parameters': {}})
        self.assertEqual(mutating_response.status_code, 400)
        connector.assert_not_called()


class ApprovedProcedureMigrationTests(TransactionTestCase):
    reset_sequences = True
    migrate_from = [('integrator', '0010_remove_menuitem_parent_delete_menu_delete_menuitem')]
    migrate_to = [('integrator', '0011_approvedprocedure_approvedprocedureparameter_and_more')]
    audit_migrate_to = [('integrator', '0012_procedureexecutionaudit')]

    def test_migration_creates_empty_approval_tables_without_auto_approval(self):
        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_from)
        old_apps = executor.loader.project_state(self.migrate_from).apps
        old_user = old_apps.get_model('auth', 'User')
        old_connection = old_apps.get_model('integrator', 'DatabaseConnection')
        old_saved_execution = old_apps.get_model('integrator', 'SavedProcedureExecution')
        user = old_user.objects.create(username='migration-admin', is_superuser=True, is_staff=True)
        connection = old_connection.objects.create(
            user_id=user.id,
            name='Legacy connection',
            connection_type='mssql',
            server='server',
            port='1433',
            database_name='catalog',
            username='user',
            password='encrypted-value',
        )
        old_saved_execution.objects.create(
            user_id=user.id,
            connection_id=connection.id,
            name='Legacy saved execution',
            procedure_name='legacy_proc',
            parameters={},
        )

        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_to)
        new_apps = executor.loader.project_state(self.migrate_to).apps
        approved_procedure = new_apps.get_model('integrator', 'ApprovedProcedure')
        saved_execution = new_apps.get_model('integrator', 'SavedProcedureExecution')
        self.assertEqual(approved_procedure.objects.count(), 0)
        self.assertEqual(saved_execution.objects.count(), 1)

        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.audit_migrate_to)
        audit_apps = executor.loader.project_state(self.audit_migrate_to).apps
        procedure_audit = audit_apps.get_model('integrator', 'ProcedureExecutionAudit')
        self.assertEqual(procedure_audit.objects.count(), 0)


class SqlPolicyTests(TestCase):
    def assert_allowed(self, query):
        result = validate_read_only_query(query)
        self.assertTrue(result.allowed, result.code)

    def assert_denied(self, query):
        result = validate_read_only_query(query)
        self.assertFalse(result.allowed, result.code)

    def test_allows_single_read_only_selects_and_safe_ctes(self):
        for query in (
            'SELECT * FROM example',
            'SELECT id, name FROM example WHERE id = ?',
            ' /* leading comment */\n SELECT id FROM example -- trailing comment',
            'WITH filtered AS (SELECT id FROM example) SELECT * FROM filtered',
        ):
            self.assert_allowed(query)

    def test_rejects_writes_ddl_control_select_into_and_multiple_statements(self):
        for query in (
            'INSERT INTO example VALUES (1)',
            'UPDATE example SET name = \'changed\'',
            'DELETE FROM example',
            'MERGE example USING source ON 1 = 1 WHEN MATCHED THEN UPDATE SET id = 1',
            'CREATE TABLE example (id int)',
            'DROP TABLE example',
            'ALTER TABLE example ADD name text',
            'TRUNCATE TABLE example',
            'GRANT SELECT ON example TO user_name',
            'REVOKE SELECT ON example FROM user_name',
            'EXEC example_procedure',
            'EXECUTE example_procedure',
            'CALL example_procedure()',
            'SET TRANSACTION READ ONLY',
            'USE another_database',
            'SELECT * INTO archived_example FROM example',
            'SELECT 1; DELETE FROM example',
            '-- leading comment\nDELETE FROM example',
            'WITH changed AS (DELETE FROM example RETURNING id) SELECT * FROM changed',
            'WITH ambiguous AS (INSERT INTO example VALUES (1) RETURNING id) SELECT * FROM ambiguous',
        ):
            self.assert_denied(query)

    def test_ignores_comment_only_and_empty_statement_fragments(self):
        self.assert_allowed('SELECT 1;; -- comment only fragment')
        self.assert_denied('-- comment only')


class SqlHelperPolicyBoundaryTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('sql-helper-user', password='password')
        self.connection = DatabaseConnection(
            user=self.user,
            name='SQL helper connection',
            connection_type='mssql',
            server='test-server',
            port='1433',
            database_name='test-database',
            username='test-user',
        )
        self.connection.set_password('test-password')
        self.connection.save()

    def test_unsafe_queries_do_not_reach_any_shared_connector_boundary(self):
        from integrator.db_config import fetch_mssql_data
        from integrator.db_utils import fetch_data_from_connection, fetch_data_from_integration

        with patch('integrator.db_utils.pyodbc.connect') as odbc_connect, patch(
            'integrator.db_utils.pymysql.connect'
        ) as mysql_connect, patch('integrator.db_utils.psycopg2.connect') as postgresql_connect, patch(
            'integrator.db_config.get_mssql_connection'
        ) as mssql_connection:
            with self.assertRaises(SqlPolicyViolation):
                fetch_data_from_connection(self.user, self.connection.id, 'UPDATE example SET id = 1')
            with self.assertRaises(SqlPolicyViolation):
                fetch_data_from_integration(self.user, 999, 'DELETE FROM example')
            self.assertEqual(fetch_mssql_data(self.user, 'SELECT 1; DROP TABLE example'), [])

        odbc_connect.assert_not_called()
        mysql_connect.assert_not_called()
        postgresql_connect.assert_not_called()
        mssql_connection.assert_not_called()

    def test_allowed_shared_query_reaches_mocked_connector_unchanged(self):
        from integrator.db_utils import fetch_data_from_connection

        cursor = MagicMock()
        cursor.description = [('id',)]
        cursor.fetchmany.return_value = [(1,)]
        connection = MagicMock()
        connection.cursor.return_value = cursor
        query = 'SELECT id FROM example WHERE id = ?'

        with patch('integrator.db_utils.pyodbc.connect', return_value=connection) as connector:
            result = fetch_data_from_connection(self.user, self.connection.id, query)

        self.assertEqual(result, [{'id': 1}])
        connector.assert_called_once()
        cursor.execute.assert_called_once_with(query)
        cursor.fetchmany.assert_called_once_with(DEFAULT_ADMIN_MAX_ROWS + 1)
        cursor.fetchall.assert_not_called()


class ProcedureResultLimitTests(SimpleTestCase):
    def procedure_limits(self, *, rows_per_set=2, result_sets=2, total_rows=4):
        return ProcedureExecutionLimits(
            connect_timeout=10,
            procedure_timeout=30,
            max_rows_per_result_set=rows_per_set,
            max_result_sets=result_sets,
            max_total_rows=total_rows,
        )

    def test_bounded_procedure_fetch_handles_empty_fewer_exact_and_over_limit_rows(self):
        cases = (
            ('empty', [], [], False),
            ('fewer', [(1,)], [(1,)], False),
            ('exact', [(1,), (2,)], [(1,), (2,)], False),
            ('over', [(1,), (2,), (3,)], [(1,), (2,)], True),
        )
        for name, fetched_rows, expected_rows, expected_truncated in cases:
            with self.subTest(name=name):
                cursor = MagicMock()
                cursor.description = [('id',)]
                cursor.fetchmany.return_value = fetched_rows
                result_sets, truncated, result_set_count, total_rows = fetch_bounded_procedure_result_sets(
                    cursor,
                    self.procedure_limits(),
                    supports_multiple_result_sets=False,
                )
                self.assertEqual(result_sets[0]['rows'], [{'id': row[0]} for row in expected_rows])
                self.assertEqual(truncated, expected_truncated)
                self.assertEqual(result_set_count, 1)
                self.assertEqual(total_rows, len(expected_rows))
                cursor.fetchmany.assert_called_once_with(3)
                cursor.fetchall.assert_not_called()

    def test_procedure_fetch_stops_before_a_result_set_over_the_cap(self):
        cursor = MagicMock()
        cursor.description = [('id',)]
        cursor.fetchmany.return_value = []
        cursor.nextset.side_effect = [True, True]

        result_sets, truncated, result_set_count, total_rows = fetch_bounded_procedure_result_sets(
            cursor,
            self.procedure_limits(result_sets=1),
            supports_multiple_result_sets=True,
        )

        self.assertEqual(result_sets, [{'columns': ['id'], 'rows': []}])
        self.assertTrue(truncated)
        self.assertEqual(result_set_count, 1)
        self.assertEqual(total_rows, 0)
        cursor.fetchmany.assert_called_once_with(3)
        cursor.nextset.assert_called_once_with()
        cursor.fetchall.assert_not_called()


class ExternalQueryLimitTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('limit-user', password='password')

    def create_connection(self, connection_type):
        connection = DatabaseConnection(
            user=self.user,
            name=f'{connection_type} limit connection',
            connection_type=connection_type,
            server='test-server',
            port='1433',
            database_name='test-database',
            username='test-user',
        )
        connection.set_password('test-password')
        connection.save()
        return connection

    def test_limit_configuration_defaults_and_strict_parsing(self):
        with patch.dict(os.environ, {}, clear=True):
            limits = get_external_query_limits()
        self.assertEqual(limits.connect_timeout, DEFAULT_CONNECT_TIMEOUT)
        self.assertEqual(limits.query_timeout, DEFAULT_QUERY_TIMEOUT)
        self.assertEqual(limits.admin_max_rows, DEFAULT_ADMIN_MAX_ROWS)
        self.assertEqual(limits.dynamic_dropdown_max_rows, DEFAULT_DYNAMIC_DROPDOWN_MAX_ROWS)

        with patch.dict(
            os.environ,
            {
                'EXTERNAL_DB_CONNECT_TIMEOUT': '12',
                'EXTERNAL_DB_QUERY_TIMEOUT': '45',
                'EXTERNAL_DB_MAX_ROWS': '600',
                'DYNAMIC_DROPDOWN_MAX_ROWS': '75',
            },
            clear=True,
        ):
            limits = get_external_query_limits()
        self.assertEqual((limits.connect_timeout, limits.query_timeout), (12, 45))
        self.assertEqual((limits.admin_max_rows, limits.dynamic_dropdown_max_rows), (600, 75))

        for invalid_value in ('0', '-1', '1.5', 'many', ''):
            with patch.dict(os.environ, {'EXTERNAL_DB_MAX_ROWS': invalid_value}, clear=True):
                with self.assertRaises(ExternalQueryConfigurationError):
                    get_external_query_limits()

        with patch.dict(os.environ, {}, clear=True):
            procedure_limits = get_procedure_execution_limits()
        self.assertEqual(procedure_limits.procedure_timeout, DEFAULT_QUERY_TIMEOUT)
        self.assertEqual(procedure_limits.max_rows_per_result_set, DEFAULT_PROCEDURE_MAX_ROWS_PER_RESULT_SET)
        self.assertEqual(procedure_limits.max_result_sets, DEFAULT_PROCEDURE_MAX_RESULT_SETS)
        self.assertEqual(procedure_limits.max_total_rows, DEFAULT_PROCEDURE_MAX_TOTAL_ROWS)
        for setting_name in (
            'EXTERNAL_DB_PROCEDURE_TIMEOUT',
            'EXTERNAL_DB_PROCEDURE_MAX_ROWS_PER_RESULT_SET',
            'EXTERNAL_DB_PROCEDURE_MAX_RESULT_SETS',
            'EXTERNAL_DB_PROCEDURE_MAX_TOTAL_ROWS',
        ):
            with patch.dict(os.environ, {setting_name: '0'}, clear=True):
                with self.assertRaises(ExternalQueryConfigurationError):
                    get_procedure_execution_limits()

    def test_bounded_fetch_uses_one_sentinel_without_fetchall(self):
        for rows, expected_rows, expected_truncated in (
            ([(1,)], [(1,)], False),
            ([(1,), (2,)], [(1,), (2,)], False),
            ([(1,), (2,), (3,)], [(1,), (2,)], True),
        ):
            cursor = MagicMock()
            cursor.fetchmany.return_value = rows
            returned_rows, truncated = fetch_limited_rows(cursor, 2)
            self.assertEqual(returned_rows, expected_rows)
            self.assertEqual(truncated, expected_truncated)
            cursor.fetchmany.assert_called_once_with(3)
            cursor.fetchall.assert_not_called()

    def test_supported_connector_paths_receive_timeouts_before_execute(self):
        from integrator.db_utils import fetch_data_from_connection

        mssql = self.create_connection('mssql')
        mssql_cursor = MagicMock()
        mssql_cursor.description = [('id',)]
        mssql_cursor.fetchmany.return_value = []
        mssql_connection = MagicMock()
        mssql_connection.cursor.return_value = mssql_cursor
        with patch('integrator.db_utils.pyodbc.connect', return_value=mssql_connection) as connect:
            self.assertEqual(fetch_data_from_connection(self.user, mssql.id, 'SELECT id FROM example'), [])
        self.assertIn('Connection Timeout=10;', connect.call_args.args[0])
        self.assertEqual(mssql_cursor.timeout, 30)
        mssql_cursor.execute.assert_called_once_with('SELECT id FROM example')
        mssql_cursor.fetchmany.assert_called_once_with(DEFAULT_ADMIN_MAX_ROWS + 1)

        mysql = self.create_connection('mysql')
        mysql_cursor = MagicMock()
        mysql_cursor.fetchmany.return_value = []
        mysql_connection = MagicMock()
        mysql_connection.cursor.return_value = mysql_cursor
        with patch('integrator.db_utils.pymysql.connect', return_value=mysql_connection) as connect:
            self.assertEqual(fetch_data_from_connection(self.user, mysql.id, 'SELECT id FROM example'), [])
        self.assertEqual(connect.call_args.kwargs['connect_timeout'], 10)
        self.assertEqual(connect.call_args.kwargs['read_timeout'], 30)
        self.assertEqual(connect.call_args.kwargs['write_timeout'], 30)
        self.assertFalse(connect.call_args.kwargs['autocommit'])
        self.assertEqual(
            mysql_cursor.execute.call_args_list,
            [call('SET TRANSACTION READ ONLY'), call('SELECT id FROM example')],
        )
        mysql_connection.rollback.assert_called_once()

        postgresql = self.create_connection('postgresql')
        postgresql_cursor = MagicMock()
        postgresql_cursor.fetchmany.return_value = []
        postgresql_connection = MagicMock()
        postgresql_connection.cursor.return_value = postgresql_cursor
        with patch('integrator.db_utils.psycopg2.connect', return_value=postgresql_connection) as connect:
            self.assertEqual(
                fetch_data_from_connection(self.user, postgresql.id, 'SELECT id FROM example'), []
            )
        self.assertEqual(connect.call_args.kwargs['connect_timeout'], 10)
        self.assertNotIn('options', connect.call_args.kwargs)
        postgresql_connection.set_session.assert_called_once_with(readonly=True, autocommit=False)
        self.assertEqual(
            postgresql_cursor.execute.call_args_list,
            [
                call('SET LOCAL statement_timeout = %s', (DEFAULT_QUERY_TIMEOUT * 1000,)),
                call('SELECT id FROM example'),
            ],
        )
        postgresql_connection.rollback.assert_called_once()

    def test_read_only_capability_matrix_is_explicit(self):
        self.assertEqual(read_only_enforcement_status('postgresql'), TRANSACTION_READ_ONLY_ENFORCED)
        self.assertEqual(read_only_enforcement_status('mysql'), TRANSACTION_READ_ONLY_ENFORCED)
        self.assertEqual(read_only_enforcement_status('mssql'), APPLICATION_POLICY_ONLY)
        self.assertEqual(read_only_enforcement_status('oracle'), UNSUPPORTED)

    def test_postgresql_read_only_setup_failure_prevents_application_execute(self):
        from integrator.db_utils import fetch_data_from_connection

        connection_record = self.create_connection('postgresql')
        cursor = MagicMock()
        connection = MagicMock()
        connection.set_session.side_effect = RuntimeError('read-only setup unavailable')
        connection.cursor.return_value = cursor
        with patch('integrator.db_utils.psycopg2.connect', return_value=connection):
            with self.assertRaises(ReadOnlyEnforcementError):
                fetch_data_from_connection(self.user, connection_record.id, 'SELECT id FROM example')

        connection.cursor.assert_not_called()
        cursor.execute.assert_not_called()
        connection.close.assert_called_once()

    def test_mysql_read_only_setup_precedes_a_simulated_policy_bypass(self):
        from integrator.db_utils import fetch_data_from_connection

        connection_record = self.create_connection('mysql')
        cursor = MagicMock()
        cursor.fetchmany.return_value = []
        connection = MagicMock()
        connection.cursor.return_value = cursor
        with patch('integrator.db_utils.require_read_only_query'), patch(
            'integrator.db_utils.pymysql.connect', return_value=connection
        ):
            fetch_data_from_connection(self.user, connection_record.id, 'DELETE FROM example')

        self.assertEqual(
            cursor.execute.call_args_list,
            [call('SET TRANSACTION READ ONLY'), call('DELETE FROM example')],
        )
        connection.rollback.assert_called_once()

    def test_mysql_read_only_setup_failure_prevents_application_execute(self):
        from integrator.db_utils import fetch_data_from_connection

        connection_record = self.create_connection('mysql')
        cursor = MagicMock()
        cursor.execute.side_effect = RuntimeError('read-only setup unavailable')
        connection = MagicMock()
        connection.cursor.return_value = cursor
        with patch('integrator.db_utils.pymysql.connect', return_value=connection):
            with self.assertRaises(ReadOnlyEnforcementError):
                fetch_data_from_connection(self.user, connection_record.id, 'SELECT id FROM example')

        cursor.execute.assert_called_once_with('SET TRANSACTION READ ONLY')
        cursor.fetchmany.assert_not_called()
        connection.close.assert_called_once()

    def test_mssql_browse_helper_uses_a_bounded_fetch_and_closes_resources(self):
        from integrator.db_config import fetch_mssql_data

        cursor = MagicMock()
        cursor.description = [('id',)]
        cursor.fetchmany.return_value = [(1,), (2,), (3,)]
        connection = MagicMock()
        connection.cursor.return_value = cursor
        with patch('integrator.db_config.get_mssql_connection', return_value=connection):
            result = fetch_mssql_data(self.user, 'SELECT id FROM example', max_rows=2)

        self.assertEqual(result, [{'id': 1}, {'id': 2}])
        self.assertEqual(cursor.timeout, DEFAULT_QUERY_TIMEOUT)
        cursor.fetchmany.assert_called_once_with(3)
        cursor.fetchall.assert_not_called()
        cursor.close.assert_called_once()
        connection.close.assert_called_once()


class DynamicDropdownExecutionTests(TestCase):
    def setUp(self):
        self.selected_user = User.objects.create_user('dropdown-selected', password='password')
        self.unselected_user = User.objects.create_user('dropdown-unselected', password='password')
        self.dynamic_form = DynamicForm.objects.create(
            formname='Configured dropdown form',
            config=json.dumps([{'name': 'country', 'type': 'select'}]),
            access_level='selected_users',
            auto_redirect_to_sso=False,
            dynamic_options_config={
                'country': {
                    'connection_id': 'db_77',
                    'query_mode': 'custom',
                    'custom_query': 'SELECT configured_value, configured_label',
                }
            },
        )
        FormPermission.objects.create(form=self.dynamic_form, user=self.selected_user)

    def test_authorized_form_delivery_uses_persisted_dropdown_configuration_only(self):
        self.client.force_login(self.selected_user)
        with patch(
            'integrator.db_utils.fetch_data_from_connection',
            return_value=[{'configured_value': '1', 'configured_label': 'One'}],
        ) as fetch_data:
            response = self.client.get(
                reverse('fill_form', args=[self.dynamic_form.uuid]),
                {
                    'connection_id': 'db_999',
                    'query': 'DELETE FROM arbitrary_table',
                    'field': 'different_field',
                },
                secure=True,
            )
        self.assertEqual(response.status_code, 200)
        fetch_data.assert_called_once_with(
            self.selected_user,
            '77',
            'SELECT configured_value, configured_label',
            max_rows=DEFAULT_DYNAMIC_DROPDOWN_MAX_ROWS,
            execution_context='dynamic dropdown',
        )

    def test_unauthorized_form_delivery_cannot_trigger_configured_dropdown_execution(self):
        self.client.force_login(self.unselected_user)
        with patch('integrator.db_utils.fetch_data_from_connection') as fetch_data:
            response = self.client.get(reverse('fill_form', args=[self.dynamic_form.uuid]), secure=True)
        self.assertEqual(response.status_code, 403)
        fetch_data.assert_not_called()

    def test_safe_persisted_dropdown_query_reaches_a_mocked_connector(self):
        connection = DatabaseConnection(
            user=self.selected_user,
            name='Dropdown connection',
            connection_type='mssql',
            server='test-server',
            port='1433',
            database_name='test-database',
            username='test-user',
        )
        connection.set_password('test-password')
        connection.save()
        self.dynamic_form.dynamic_options_config['country']['connection_id'] = f'db_{connection.id}'
        self.dynamic_form.save(update_fields=['dynamic_options_config'])
        self.client.force_login(self.selected_user)

        cursor = MagicMock()
        cursor.description = [('value',), ('label',)]
        cursor.fetchmany.return_value = [('1', 'One'), ('2', 'Two'), ('3', 'Three')]
        external_connection = MagicMock()
        external_connection.cursor.return_value = cursor
        with patch.dict(os.environ, {'DYNAMIC_DROPDOWN_MAX_ROWS': '2'}, clear=False), patch(
            'integrator.db_utils.pyodbc.connect', return_value=external_connection
        ) as connector:
            response = self.client.get(reverse('fill_form', args=[self.dynamic_form.uuid]), secure=True)

        self.assertEqual(response.status_code, 200)
        connector.assert_called_once()
        cursor.execute.assert_called_once_with('SELECT configured_value, configured_label')
        cursor.fetchmany.assert_called_once_with(3)
        cursor.fetchall.assert_not_called()
        form_config = json.loads(response.context['form_config'])
        self.assertEqual(
            form_config[0]['choices'],
            [
                {'value': '1', 'label': 'One'},
                {'value': '2', 'label': 'Two'},
            ],
        )

    def test_unsafe_persisted_dropdown_query_returns_empty_choices_without_connecting(self):
        self.dynamic_form.dynamic_options_config['country']['custom_query'] = 'DELETE FROM example'
        self.dynamic_form.save(update_fields=['dynamic_options_config'])
        self.client.force_login(self.selected_user)

        with patch('integrator.db_utils.pyodbc.connect') as connector:
            response = self.client.get(reverse('fill_form', args=[self.dynamic_form.uuid]), secure=True)

        self.assertEqual(response.status_code, 200)
        connector.assert_not_called()

    def test_dynamic_dropdown_timeout_falls_back_to_empty_choices(self):
        self.client.force_login(self.selected_user)
        with patch(
            'integrator.db_utils.fetch_data_from_connection',
            side_effect=ExternalQueryTimeoutError('Database query timed out.'),
        ):
            response = self.client.get(reverse('fill_form', args=[self.dynamic_form.uuid]), secure=True)

        self.assertEqual(response.status_code, 200)
        form_config = json.loads(response.context['form_config'])
        self.assertEqual(form_config[0]['choices'], [])

    def test_dynamic_dropdown_read_only_setup_failure_falls_back_to_empty_choices(self):
        self.client.force_login(self.selected_user)
        with patch(
            'integrator.db_utils.fetch_data_from_connection',
            side_effect=ReadOnlyEnforcementError('read-only setup failed'),
        ):
            response = self.client.get(reverse('fill_form', args=[self.dynamic_form.uuid]), secure=True)

        self.assertEqual(response.status_code, 200)
        form_config = json.loads(response.context['form_config'])
        self.assertEqual(form_config[0]['choices'], [])


class FormDeliveryAuthorizationTests(TestCase):
    def setUp(self):
        self.authenticated_user = User.objects.create_user('form-user', password='password')
        self.selected_user = User.objects.create_user('selected-user', password='password')
        self.unselected_user = User.objects.create_user('unselected-user', password='password')

    def create_form(self, access_level, login_required=True, **kwargs):
        defaults = {
            'formname': f'{access_level} form',
            'config': '[]',
            'access_level': access_level,
            'login_required': login_required,
            'auto_redirect_to_sso': False,
        }
        defaults.update(kwargs)
        return DynamicForm.objects.create(**defaults)

    def form_get(self, dynamic_form):
        return self.client.get(reverse('fill_form', args=[dynamic_form.uuid]), secure=True)

    def form_post(self, dynamic_form, value='answer'):
        return self.client.post(
            reverse('submit_form', args=[dynamic_form.uuid]),
            {'answer': value},
            secure=True,
        )

    def test_public_forms_allow_anonymous_and_authenticated_delivery(self):
        dynamic_form = self.create_form('public', login_required=True)

        self.assertEqual(self.form_get(dynamic_form).status_code, 200)
        self.assertEqual(self.form_post(dynamic_form, 'anonymous').status_code, 200)
        self.assertEqual(FormSubmission.objects.filter(form=dynamic_form).count(), 1)

        self.client.force_login(self.authenticated_user)
        self.assertEqual(self.form_get(dynamic_form).status_code, 200)
        self.assertEqual(self.form_post(dynamic_form, 'authenticated').status_code, 200)
        self.assertEqual(FormSubmission.objects.filter(form=dynamic_form).count(), 2)

    def test_authenticated_forms_require_authentication_for_get_and_post(self):
        dynamic_form = self.create_form('authenticated', login_required=False)

        self.assertEqual(self.form_get(dynamic_form).status_code, 302)
        self.assertEqual(self.form_post(dynamic_form).status_code, 302)
        self.assertFalse(FormSubmission.objects.filter(form=dynamic_form).exists())

        self.client.force_login(self.authenticated_user)
        self.assertEqual(self.form_get(dynamic_form).status_code, 200)
        self.assertEqual(self.form_post(dynamic_form).status_code, 200)
        self.assertEqual(FormSubmission.objects.filter(form=dynamic_form).count(), 1)

    def test_selected_user_forms_apply_the_same_policy_to_get_and_post(self):
        dynamic_form = self.create_form('selected_users', login_required=False)
        FormPermission.objects.create(form=dynamic_form, user=self.selected_user)

        self.assertEqual(self.form_get(dynamic_form).status_code, 302)
        self.assertEqual(self.form_post(dynamic_form).status_code, 302)
        self.assertFalse(FormSubmission.objects.filter(form=dynamic_form).exists())

        self.client.force_login(self.unselected_user)
        self.assertEqual(self.form_get(dynamic_form).status_code, 403)
        self.assertEqual(self.form_post(dynamic_form).status_code, 403)
        self.assertFalse(FormSubmission.objects.filter(form=dynamic_form).exists())

        self.client.force_login(self.selected_user)
        self.assertEqual(self.form_get(dynamic_form).status_code, 200)
        self.assertEqual(self.form_post(dynamic_form).status_code, 200)
        self.assertEqual(FormSubmission.objects.filter(form=dynamic_form).count(), 1)

    def test_direct_post_cannot_bypass_form_delivery_policy(self):
        public_form = self.create_form('public')
        authenticated_form = self.create_form('authenticated')
        selected_form = self.create_form('selected_users')
        FormPermission.objects.create(form=selected_form, user=self.selected_user)

        self.assertEqual(self.form_post(public_form).status_code, 200)
        self.assertEqual(self.form_post(authenticated_form).status_code, 302)
        self.client.force_login(self.unselected_user)
        self.assertEqual(self.form_post(selected_form).status_code, 403)
        self.client.force_login(self.selected_user)
        self.assertEqual(self.form_post(selected_form).status_code, 200)

        self.assertEqual(FormSubmission.objects.filter(form=public_form).count(), 1)
        self.assertFalse(FormSubmission.objects.filter(form=authenticated_form).exists())
        self.assertEqual(FormSubmission.objects.filter(form=selected_form).count(), 1)

    def test_denied_delivery_does_not_load_dynamic_dropdowns(self):
        dynamic_form = self.create_form(
            'selected_users',
            config=json.dumps([{'name': 'external_option', 'type': 'select'}]),
            dynamic_options_config={
                'external_option': {
                    'connection_id': 'db_1',
                    'query_mode': 'custom',
                    'custom_query': 'SELECT forbidden',
                }
            },
        )
        self.client.force_login(self.unselected_user)

        with patch('integrator.views.FillFormView.load_dynamic_choices') as load_choices:
            self.assertEqual(self.form_get(dynamic_form).status_code, 403)
            load_choices.assert_not_called()


class StaticLogoReferenceTests(SimpleTestCase):
    def test_missing_jhu_logo_references_are_not_emitted_by_runtime_templates(self):
        template_root = Path(__file__).resolve().parent.parent / 'templates'
        for relative_path in (
            'base.html',
            'pages/forms/access_denied.html',
            'authentication/layouts/corporate/sign-in.html',
            'dashboard.html',
        ):
            with self.subTest(template=relative_path):
                contents = (template_root / relative_path).read_text(encoding='utf-8')
                self.assertNotIn('assets/media/logos/jhu.svg', contents)
                self.assertNotIn('assets/media/logos/jhuicon.png', contents)


class HardcodedSidebarTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.normal_user = User.objects.create_user('nav-user', password='password')
        self.superuser = User.objects.create_superuser(
            'nav-admin', 'nav-admin@example.com', 'password'
        )

    def render_sidebar(self, route_name, user, *args):
        path = reverse(route_name, args=args)
        request = self.factory.get(path)
        request.user = user
        request.resolver_match = resolve(path)
        return render_to_string('partials/sidebar.html', {'request': request})

    def test_normal_users_only_see_dashboard_and_account_navigation(self):
        rendered = self.render_sidebar('home', self.normal_user)
        for label in ('Dashboard', 'Account', 'Profile', 'Profile Settings'):
            self.assertIn(label, rendered)
        for label in ('Forms', 'Administration', 'SSO Providers'):
            self.assertNotIn(label, rendered)

    def test_superusers_see_the_complete_navigation_tree(self):
        rendered = self.render_sidebar('home', self.superuser)
        for label in ('Dashboard', 'Forms', 'Create Form', 'Manage Forms', 'Form Submissions', 'Administration', 'Users', 'Permissions', 'Integrations', 'Configurations', 'SSO Providers', 'Account', 'Profile', 'Profile Settings'):
            self.assertIn(label, rendered)

    def test_active_route_opens_its_parent_and_marks_its_child(self):
        form = DynamicForm.objects.create(formname='Sidebar Form')
        rendered = self.render_sidebar('edit_form', self.superuser, form.uuid)
        self.assertIn('menu-accordion here show', rendered)
        self.assertIn('menu-link active" href="/manage-forms/"', rendered)

        rendered = self.render_sidebar('users_view', self.superuser)
        self.assertIn('menu-accordion here show', rendered)
        self.assertIn('menu-link active" href="/users/view/"', rendered)

        rendered = self.render_sidebar('user_profile_setting', self.normal_user)
        self.assertIn('menu-accordion here show', rendered)
        self.assertIn('menu-link active" href="/profile/setting/"', rendered)

    def test_sidebar_uses_named_routes_and_has_no_menu_models(self):
        for route_name in ('home', 'create_forms', 'manage_forms', 'view_form_submissions', 'users_view', 'permissions', 'integrations', 'configurations', 'sso:management', 'user_profile', 'user_profile_setting'):
            self.assertTrue(reverse(route_name))
        with self.assertRaises(LookupError):
            apps.get_model('integrator', 'Menu')
        with self.assertRaises(LookupError):
            apps.get_model('integrator', 'MenuItem')
        with self.assertNumQueries(0):
            rendered = self.render_sidebar('home', self.normal_user)
        self.assertIn('Dashboard', rendered)


class FormManagementAuthorizationTests(TestCase):
    def setUp(self):
        self.normal_user = User.objects.create_user('management-normal', password='password')
        self.staff_user = User.objects.create_user(
            'management-staff', password='password', is_staff=True
        )
        self.superuser = User.objects.create_superuser(
            'management-admin', 'admin@example.com', 'password'
        )
        self.dynamic_form = DynamicForm.objects.create(
            formname='Managed form',
            config='[]',
            access_level='public',
            auto_redirect_to_sso=False,
        )
        self.submission = FormSubmission.objects.create(
            form=self.dynamic_form,
            submissionID='managed-submission',
            submission_data={'answer': 'value'},
        )

    def browser_get(self, url):
        return self.client.get(url, secure=True)

    def browser_post(self, url, data=None):
        return self.client.post(url, data or {}, secure=True)

    def management_urls(self):
        return {
            'manage': reverse('manage_forms'),
            'create_page': reverse('create_forms'),
            'edit': reverse('edit_form', args=[self.dynamic_form.uuid]),
            'preview': reverse('preview_template', args=['Management Preview']),
            'submission_list': reverse('view_form_submissions'),
            'form_submissions': reverse('open_form_submissions', args=[self.dynamic_form.uuid]),
            'submission_detail': reverse('submission_details', args=[self.submission.submissionID]),
        }

    def create_form_json(self):
        return self.client.post(
            reverse('generate_form'),
            data=json.dumps({'formname': 'Created by management test', 'fields': []}),
            content_type='application/json',
            secure=True,
        )

    def test_anonymous_management_pages_redirect_and_json_creation_returns_401(self):
        for url in self.management_urls().values():
            self.assertEqual(self.browser_get(url).status_code, 302)
        self.assertEqual(self.create_form_json().status_code, 401)
        self.assertEqual(self.browser_post(reverse('delete_form', args=[self.dynamic_form.uuid])).status_code, 302)
        self.assertTrue(DynamicForm.objects.filter(pk=self.dynamic_form.pk).exists())

    def test_normal_and_staff_users_are_denied_management_and_cannot_delete(self):
        for user in (self.normal_user, self.staff_user):
            self.client.force_login(user)
            for url in self.management_urls().values():
                self.assertEqual(self.browser_get(url).status_code, 403)
            self.assertEqual(self.create_form_json().status_code, 403)
            self.assertEqual(
                self.browser_post(reverse('delete_form', args=[self.dynamic_form.uuid])).status_code,
                403,
            )
            self.client.logout()

        self.assertTrue(DynamicForm.objects.filter(pk=self.dynamic_form.pk).exists())
        self.assertEqual(FormSubmission.objects.filter(pk=self.submission.pk).count(), 1)

    def test_superuser_can_manage_forms_and_submissions(self):
        self.client.force_login(self.superuser)
        urls = self.management_urls()
        for url in urls.values():
            self.assertEqual(self.browser_get(url).status_code, 200)

        original_count = DynamicForm.objects.count()
        response = self.create_form_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(DynamicForm.objects.count(), original_count + 1)

        response = self.browser_post(reverse('delete_form', args=[self.dynamic_form.uuid]))
        self.assertEqual(response.status_code, 302)
        self.assertFalse(DynamicForm.objects.filter(pk=self.dynamic_form.pk).exists())


class WebhookTransportContainmentTests(TestCase):
    def setUp(self):
        self.superuser = User.objects.create_superuser(
            'webhook-admin', 'webhook-admin@example.test', 'password'
        )

    def dns_result(self, *addresses):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 443)) for address in addresses]

    def create_form(self, webhook_url=''):
        return DynamicForm.objects.create(
            formname='Webhook containment form',
            config='[]',
            access_level='public',
            auto_redirect_to_sso=False,
            webhook_url=webhook_url,
        )

    def submit_form(self, dynamic_form):
        return self.client.post(
            reverse('submit_form', args=[dynamic_form.uuid]), {'answer': 'value'}, secure=True,
        )

    @patch('integrator.webhook_security.socket.getaddrinfo')
    def test_url_policy_accepts_public_https_and_rejects_unsafe_syntax_and_addresses(self, getaddrinfo):
        getaddrinfo.return_value = self.dns_result('8.8.8.8')
        self.assertEqual(validate_webhook_url('https://webhook.example.test/path'), 'https://webhook.example.test/path')

        for url in (
            'http://webhook.example.test',
            'ftp://webhook.example.test',
            'https://user:password@webhook.example.test',
            'https://webhook.example.test/#fragment',
            'https://localhost/hook',
            'https://127.0.0.1/hook',
            'https://10.0.0.1/hook',
            'https://169.254.169.254/latest/meta-data',
            'https://[::1]/hook',
            'https://[fe80::1]/hook',
            'https:///missing-host',
        ):
            with self.subTest(url=url):
                with self.assertRaises(WebhookSecurityError):
                    validate_webhook_url(url)

    @patch('integrator.webhook_security.socket.getaddrinfo')
    def test_dns_validation_requires_only_public_answers_and_fails_closed(self, getaddrinfo):
        getaddrinfo.return_value = self.dns_result('8.8.4.4')
        self.assertEqual(validate_webhook_url('https://public.example.test'), 'https://public.example.test')

        getaddrinfo.return_value = self.dns_result('8.8.4.4', '192.168.1.10')
        with self.assertRaisesRegex(WebhookSecurityError, 'WEBHOOK_URL_BLOCKED'):
            validate_webhook_url('https://mixed.example.test')

        getaddrinfo.side_effect = socket.gaierror('resolver details must not escape')
        with self.assertRaisesRegex(WebhookSecurityError, 'WEBHOOK_DNS_FAILED'):
            validate_webhook_url('https://unresolvable.example.test')

    def test_transport_disables_redirects_environment_proxies_and_insecure_tls(self):
        response = MagicMock(status_code=302, encoding='utf-8')
        session = MagicMock()
        session.post.return_value = response
        transport = WebhookTransportSettings(connect_timeout=2, read_timeout=3)
        stored_headers = prepare_webhook_headers_for_storage(
            {'Authorization': 'Bearer retained', 'Host': 'blocked'}
        )

        with patch('integrator.webhook_security.validate_webhook_url'), patch(
            'integrator.webhook_security.requests.Session', return_value=session,
        ):
            result = deliver_webhook(
                'https://webhook.example.test', data={'answer': 'value'}, files=[],
                headers=stored_headers, transport_settings=transport,
            )

        self.assertEqual(result, {
            'status': 'WEBHOOK_REDIRECT_NOT_FOLLOWED',
            'status_code': 302,
        })
        self.assertFalse(session.trust_env)
        request_kwargs = session.post.call_args.kwargs
        self.assertFalse(request_kwargs['allow_redirects'])
        self.assertEqual(request_kwargs['timeout'], (2, 3))
        self.assertTrue(request_kwargs['verify'])
        self.assertTrue(request_kwargs['stream'])
        self.assertEqual(request_kwargs['headers'], {'Authorization': 'Bearer retained'})

    def test_transport_timeout_is_redacted(self):
        session = MagicMock()
        session.post.side_effect = webhook_security.requests.Timeout('raw timeout details')
        with patch('integrator.webhook_security.validate_webhook_url'), patch(
            'integrator.webhook_security.requests.Session', return_value=session,
        ):
            with self.assertRaisesRegex(WebhookDeliveryError, 'WEBHOOK_TIMEOUT') as context:
                deliver_webhook('https://webhook.example.test', data={}, files=[], headers={})

        self.assertNotIn('raw timeout details', str(context.exception))

    def test_response_body_is_not_read_or_retained_and_response_is_closed(self):
        class Response:
            status_code = 200
            headers = {'X-Webhook-Response-Secret': 'RESPONSE_HEADER_SENTINEL'}

            @property
            def text(self):
                raise AssertionError('Response text must not be read.')

            def iter_content(self, *args, **kwargs):
                raise AssertionError('Response body must not be read.')

            def close(self):
                self.closed = True

        response = Response()
        session = MagicMock()
        session.post.return_value = response
        transport = WebhookTransportSettings(connect_timeout=1, read_timeout=1)
        with patch('integrator.webhook_security.validate_webhook_url'), patch(
            'integrator.webhook_security.requests.Session', return_value=session,
        ):
            result = deliver_webhook('https://webhook.example.test', data={}, files=[], headers={}, transport_settings=transport)

        self.assertEqual(result, {'status': 'WEBHOOK_DELIVERED', 'status_code': 200})
        self.assertTrue(response.closed)

    def test_configuration_rejects_unsafe_values_and_allows_safe_or_empty_webhooks(self):
        self.client.force_login(self.superuser)
        unsafe = self.client.post(
            reverse('generate_form'),
            data=json.dumps({'formname': 'Unsafe webhook', 'fields': [], 'webhookurl': 'http://127.0.0.1'}),
            content_type='application/json', secure=True,
        )
        self.assertEqual(unsafe.status_code, 400)
        self.assertEqual(unsafe.json()['error'], 'Webhook configuration is not allowed.')
        self.assertFalse(DynamicForm.objects.filter(formname='Unsafe webhook').exists())

        with patch('integrator.views.validate_webhook_url', side_effect=lambda value: value):
            safe = self.client.post(
                reverse('generate_form'),
                data=json.dumps({
                    'formname': 'Safe webhook', 'fields': [],
                    'webhookurl': 'https://webhook.example.test/hook',
                    'headers': {'Authorization': 'Bearer configuration-secret'},
                }),
                content_type='application/json', secure=True,
            )
            empty = self.client.post(
                reverse('generate_form'), data=json.dumps({'formname': 'No webhook', 'fields': []}),
                content_type='application/json', secure=True,
            )

        self.assertEqual(safe.status_code, 200)
        self.assertEqual(empty.status_code, 200)
        self.assertEqual(DynamicForm.objects.get(formname='Safe webhook').webhook_url, 'https://webhook.example.test/hook')
        self.assertEqual(DynamicForm.objects.get(formname='No webhook').webhook_url, '')

    def test_edit_configuration_rejects_unsafe_url_and_transport_headers(self):
        dynamic_form = self.create_form()
        self.client.force_login(self.superuser)

        response = self.client.post(
            reverse('edit_form', args=[dynamic_form.uuid]),
            data=json.dumps({'webhook_url': 'http://127.0.0.1'}), content_type='application/json', secure=True,
        )
        self.assertEqual(response.status_code, 400)
        dynamic_form.refresh_from_db()
        self.assertEqual(dynamic_form.webhook_url, '')

        with patch('integrator.views.validate_webhook_url', side_effect=lambda value: value):
            response = self.client.post(
                reverse('edit_form', args=[dynamic_form.uuid]),
                data=json.dumps({
                    'webhook_url': 'https://webhook.example.test/hook',
                    'headers': '{"Host": "internal.example.test"}',
                }), content_type='application/json', secure=True,
            )
        self.assertEqual(response.status_code, 400)
        dynamic_form.refresh_from_db()
        self.assertEqual(dynamic_form.webhook_url, '')

    def test_legacy_unsafe_url_is_blocked_at_delivery_without_a_request(self):
        dynamic_form = self.create_form('http://127.0.0.1/legacy')
        session = MagicMock()
        with patch('integrator.webhook_security.requests.Session', return_value=session):
            response = self.submit_form(dynamic_form)

        self.assertEqual(response.status_code, 200)
        submission = FormSubmission.objects.get(form=dynamic_form)
        self.assertEqual(submission.response, {'status': 'WEBHOOK_URL_BLOCKED'})
        session.post.assert_not_called()

    def test_delivery_failure_is_controlled_and_does_not_log_or_return_raw_details(self):
        dynamic_form = self.create_form('https://webhook.example.test/hook')
        with patch(
            'integrator.views.deliver_webhook',
            side_effect=WebhookDeliveryError('WEBHOOK_TIMEOUT'),
        ), patch('integrator.views.logger') as logger:
            response = self.submit_form(dynamic_form)

        self.assertEqual(response.status_code, 200)
        self.assertNotIn('WEBHOOK_TIMEOUT', response.content.decode())
        submission = FormSubmission.objects.get(form=dynamic_form)
        self.assertEqual(submission.response, {'status': 'WEBHOOK_TIMEOUT'})
        self.assertNotIn('webhook.example.test', str(logger.warning.call_args_list))


class WebhookResponseRetentionTests(TestCase):
    body_marker = 'WEBHOOK_RESPONSE_BODY_SENTINEL_7b1f4a'
    header_marker = 'WEBHOOK_RESPONSE_HEADER_SENTINEL_9e2c6d'

    def setUp(self):
        self.superuser = User.objects.create_superuser(
            'response-admin', 'response-admin@example.test', 'password'
        )

    def create_form(self, webhook_url='https://webhook.example.test/hook'):
        return DynamicForm.objects.create(
            formname='Webhook response retention form', config='[]', access_level='public',
            auto_redirect_to_sso=False, webhook_url=webhook_url,
        )

    def submit(self, dynamic_form):
        return self.client.post(
            reverse('submit_form', args=[dynamic_form.uuid]), {'answer': 'value'}, secure=True,
        )

    def test_successful_delivery_persists_only_safe_metadata_and_never_reads_body_or_headers(self):
        dynamic_form = self.create_form()
        response = MagicMock(status_code=204)
        response.headers = {'X-Webhook-Response-Secret': self.header_marker}
        response.iter_content.return_value = [self.body_marker.encode()]
        session = MagicMock()
        session.post.return_value = response

        with patch('integrator.webhook_security.validate_webhook_url'), patch(
            'integrator.webhook_security.requests.Session', return_value=session,
        ):
            submitted = self.submit(dynamic_form)

        self.assertEqual(submitted.status_code, 200)
        stored = FormSubmission.objects.get(form=dynamic_form).response
        self.assertEqual(stored, {'status': 'WEBHOOK_DELIVERED', 'status_code': 204})
        self.assertNotIn(self.body_marker, str(stored))
        self.assertNotIn(self.header_marker, str(stored))
        response.iter_content.assert_not_called()
        response.close.assert_called_once()

    def test_redirect_is_not_followed_and_persists_safe_metadata_only(self):
        dynamic_form = self.create_form()
        response = MagicMock(status_code=302)
        response.headers = {'Location': f'https://other.example.test/{self.body_marker}'}
        session = MagicMock()
        session.post.return_value = response

        with patch('integrator.webhook_security.validate_webhook_url'), patch(
            'integrator.webhook_security.requests.Session', return_value=session,
        ):
            submitted = self.submit(dynamic_form)

        self.assertEqual(submitted.status_code, 200)
        stored = FormSubmission.objects.get(form=dynamic_form).response
        self.assertEqual(stored, {
            'status': 'WEBHOOK_REDIRECT_NOT_FOLLOWED',
            'status_code': 302,
        })
        self.assertNotIn(self.body_marker, str(stored))
        self.assertFalse(session.post.call_args.kwargs['allow_redirects'])

    def test_failure_categories_persist_only_sanitized_statuses(self):
        for category in (
            'WEBHOOK_TIMEOUT',
            'WEBHOOK_DELIVERY_FAILED',
            'WEBHOOK_HEADER_CONFIGURATION_FAILED',
        ):
            with self.subTest(category=category):
                dynamic_form = self.create_form()
                with patch(
                    'integrator.views.deliver_webhook', side_effect=WebhookDeliveryError(category),
                ):
                    submitted = self.submit(dynamic_form)
                self.assertEqual(submitted.status_code, 200)
                self.assertEqual(
                    FormSubmission.objects.get(form=dynamic_form).response,
                    {'status': category},
                )

    def test_blocked_url_persists_only_the_sanitized_category(self):
        dynamic_form = self.create_form('http://127.0.0.1/blocked')
        submitted = self.submit(dynamic_form)

        self.assertEqual(submitted.status_code, 200)
        self.assertEqual(
            FormSubmission.objects.get(form=dynamic_form).response,
            {'status': 'WEBHOOK_URL_BLOCKED'},
        )

    def test_historical_body_is_not_rendered_or_exposed_in_admin_and_is_not_mutated(self):
        dynamic_form = self.create_form(webhook_url='')
        historical_response = {
            'status_code': 200,
            'content': self.body_marker,
            'headers': {'X-Historical-Secret': self.header_marker},
            'truncated': False,
        }
        submission = FormSubmission.objects.create(
            form=dynamic_form,
            submissionID='historical-response-submission',
            submission_data={'answer': 'value'},
            response=historical_response,
        )

        self.client.force_login(self.superuser)
        submission_list = self.client.get(
            reverse('open_form_submissions', args=[dynamic_form.uuid]), secure=True,
        )
        admin_change = self.client.get(
            reverse('admin:integrator_formsubmission_change', args=[submission.pk]), secure=True,
        )

        self.assertEqual(submission_list.status_code, 200)
        self.assertEqual(admin_change.status_code, 200)
        list_rendered = submission_list.content.decode()
        admin_rendered = admin_change.content.decode()
        self.assertIn('HTTP 200', list_rendered)
        for rendered in (list_rendered, admin_rendered):
            self.assertIn('WEBHOOK_DELIVERED', rendered)
            self.assertNotIn(self.body_marker, rendered)
            self.assertNotIn(self.header_marker, rendered)
        submission.refresh_from_db()
        self.assertEqual(submission.response, historical_response)

    def test_legacy_response_shape_normalizes_to_safe_display_metadata_only(self):
        metadata = safe_webhook_response_metadata({
            'status_code': 200,
            'content': self.body_marker,
            'body': self.body_marker,
            'headers': {'X-Secret': self.header_marker},
            'url': 'https://webhook.example.test/secret',
            'exception': 'raw exception details',
            'truncated': False,
        })
        self.assertEqual(metadata, {
            'status': 'WEBHOOK_DELIVERED',
            'status_code': 200,
            'truncated': False,
        })
        self.assertNotIn(self.body_marker, str(metadata))
        self.assertNotIn(self.header_marker, str(metadata))

    def test_submission_list_no_longer_uses_legacy_payload_specific_response_lookup(self):
        template_path = (
            Path(__file__).resolve().parent.parent / 'templates' / 'pages' / 'forms'
            / 'open-form-submissions.html'
        )
        template_source = template_path.read_text(encoding='utf-8')
        self.assertNotIn('response.0.DocStatusId', template_source)
        self.assertIn('delivery_metadata.status', template_source)


class WebhookHeaderSecretContainmentTests(TestCase):
    secret_marker = 'WEBHOOK_SECRET_MARKER_91f4c2'

    def setUp(self):
        self.superuser = User.objects.create_superuser(
            'header-admin', 'header-admin@example.test', 'password'
        )
        self.normal_user = User.objects.create_user('header-user', password='password')

    def create_form(self, headers=None, webhook_url=''):
        return DynamicForm.objects.create(
            formname='Header containment form', config='[]', access_level='public',
            auto_redirect_to_sso=False, headers=headers or {}, webhook_url=webhook_url,
        )

    def edit_headers(self, dynamic_form, headers):
        return self.client.post(
            reverse('edit_form', args=[dynamic_form.uuid]),
            data=json.dumps({'headers': headers}), content_type='application/json', secure=True,
        )

    def test_sensitive_classifier_is_case_insensitive_and_token_aware(self):
        for name in ('Authorization', 'authorization', 'X-API-Key', 'X-Auth-Token', 'customerSecret', 'access_key'):
            with self.subTest(name=name):
                self.assertTrue(is_sensitive_webhook_header(name))
        for name in ('Accept', 'User-Agent', 'Monkey', 'X-Request-Id'):
            with self.subTest(name=name):
                self.assertFalse(is_sensitive_webhook_header(name))

    def test_storage_encrypts_only_sensitive_values_and_validates_ciphertext(self):
        stored = prepare_webhook_headers_for_storage({
            'Authorization': self.secret_marker,
            'Accept': 'application/json',
        })
        self.assertTrue(stored['Authorization'].startswith('enc:v1:'))
        self.assertNotIn(self.secret_marker, stored.values())
        self.assertEqual(stored['Accept'], 'application/json')
        self.assertEqual(decrypt_webhook_header_value(stored['Authorization']), self.secret_marker)
        self.assertEqual(encrypt_webhook_header_value(stored['Authorization']), stored['Authorization'])
        with self.assertRaises(WebhookHeaderSecretError):
            encrypt_webhook_header_value('enc:v1:not-valid')
        with self.assertRaises(WebhookHeaderSecretError):
            encrypt_webhook_header_value('enc:v2:unknown')

    def test_create_encrypts_secrets_and_rejects_duplicate_or_non_string_values(self):
        self.client.force_login(self.superuser)
        with patch('integrator.views.validate_webhook_url', side_effect=lambda value: value):
            response = self.client.post(
                reverse('generate_form'),
                data=json.dumps({
                    'formname': 'Encrypted form', 'fields': [],
                    'webhookurl': 'https://webhook.example.test/hook',
                    'headers': {'Authorization': self.secret_marker, 'Accept': 'application/json'},
                }), content_type='application/json', secure=True,
            )
        self.assertEqual(response.status_code, 200)
        encrypted = DynamicForm.objects.get(formname='Encrypted form').headers
        self.assertTrue(encrypted['Authorization'].startswith('enc:v1:'))
        self.assertNotIn(self.secret_marker, encrypted.values())
        self.assertEqual(encrypted['Accept'], 'application/json')

        duplicate_payload = (
            '{"formname":"Duplicate headers","fields":[],"headers":'
            '{"Authorization":"one","authorization":"two"}}'
        )
        duplicate = self.client.post(
            reverse('generate_form'), data=duplicate_payload,
            content_type='application/json', secure=True,
        )
        self.assertEqual(duplicate.status_code, 400)
        self.assertEqual(duplicate.json()['error'], 'Duplicate webhook header name.')

        non_string = self.client.post(
            reverse('generate_form'),
            data=json.dumps({'formname': 'Bad header', 'fields': [], 'headers': {'Accept': ['not-a-string']}}),
            content_type='application/json', secure=True,
        )
        self.assertEqual(non_string.status_code, 400)
        self.assertEqual(non_string.json()['error'], 'Invalid webhook header configuration.')

    def test_edit_masks_preserves_replaces_and_removes_sensitive_values(self):
        initial = prepare_webhook_headers_for_storage({
            'Authorization': self.secret_marker,
            'Accept': 'application/json',
        })
        dynamic_form = self.create_form(initial)
        original_ciphertext = initial['Authorization']
        self.client.force_login(self.superuser)

        rendered = self.client.get(reverse('edit_form', args=[dynamic_form.uuid]), secure=True)
        self.assertEqual(rendered.status_code, 200)
        self.assertIn(MASKED_HEADER_VALUE, rendered.content.decode())
        self.assertNotIn(self.secret_marker, rendered.content.decode())
        self.assertNotIn(original_ciphertext, rendered.content.decode())

        response = self.edit_headers(dynamic_form, {
            'authorization': '', 'Accept': 'application/json',
        })
        self.assertEqual(response.status_code, 200)
        dynamic_form.refresh_from_db()
        self.assertEqual(dynamic_form.headers['authorization'], original_ciphertext)

        response = self.edit_headers(dynamic_form, {
            'authorization': MASKED_HEADER_VALUE, 'Accept': 'application/json',
        })
        self.assertEqual(response.status_code, 200)
        dynamic_form.refresh_from_db()
        self.assertEqual(dynamic_form.headers['authorization'], original_ciphertext)

        replacement = 'WEBHOOK_REPLACEMENT_8de1'
        response = self.edit_headers(dynamic_form, {
            'authorization': replacement, 'Accept': 'application/json',
        })
        self.assertEqual(response.status_code, 200)
        dynamic_form.refresh_from_db()
        self.assertNotEqual(dynamic_form.headers['authorization'], original_ciphertext)
        self.assertEqual(decrypt_webhook_header_value(dynamic_form.headers['authorization']), replacement)

        response = self.edit_headers(dynamic_form, {'Accept': 'application/json'})
        self.assertEqual(response.status_code, 200)
        dynamic_form.refresh_from_db()
        self.assertNotIn('authorization', dynamic_form.headers)

    def test_new_blank_or_masked_secret_is_rejected(self):
        dynamic_form = self.create_form()
        self.client.force_login(self.superuser)
        for value in ('', MASKED_HEADER_VALUE):
            with self.subTest(value=value):
                response = self.edit_headers(dynamic_form, {'Authorization': value})
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()['error'], 'Secret value configuration is invalid.')

    def test_runtime_decrypts_only_at_delivery_and_rejects_legacy_plaintext(self):
        stored = prepare_webhook_headers_for_storage({'Authorization': self.secret_marker, 'Host': 'blocked'})
        dynamic_form = self.create_form(stored, webhook_url='https://webhook.example.test/hook')
        response = MagicMock(status_code=200, encoding='utf-8')
        response.iter_content.return_value = [b'ok']
        session = MagicMock()
        session.post.return_value = response

        with patch('integrator.webhook_security.validate_webhook_url'), patch(
            'integrator.webhook_security.requests.Session', return_value=session,
        ):
            submitted = self.client.post(
                reverse('submit_form', args=[dynamic_form.uuid]), {'answer': 'value'}, secure=True,
            )
        self.assertEqual(submitted.status_code, 200)
        self.assertEqual(session.post.call_args.kwargs['headers'], {'Authorization': self.secret_marker})
        dynamic_form.refresh_from_db()
        self.assertEqual(dynamic_form.headers['Authorization'], stored['Authorization'])

        legacy_form = self.create_form({'Authorization': self.secret_marker}, webhook_url='https://webhook.example.test/hook')
        with patch('integrator.webhook_security.validate_webhook_url'), patch(
            'integrator.webhook_security.requests.Session', return_value=MagicMock(),
        ) as session_factory, patch('integrator.views.logger') as logger:
            submitted = self.client.post(
                reverse('submit_form', args=[legacy_form.uuid]), {'answer': 'value'}, secure=True,
            )
        self.assertEqual(submitted.status_code, 200)
        self.assertEqual(
            FormSubmission.objects.get(form=legacy_form).response,
            {'status': 'WEBHOOK_HEADER_CONFIGURATION_FAILED'},
        )
        session_factory.return_value.post.assert_not_called()
        self.assertNotIn(self.secret_marker, str(logger.warning.call_args_list))

        malformed_form = self.create_form(
            {'Authorization': 'enc:v1:not-valid'}, webhook_url='https://webhook.example.test/hook',
        )
        with patch('integrator.webhook_security.validate_webhook_url'), patch(
            'integrator.webhook_security.requests.Session', return_value=MagicMock(),
        ) as session_factory:
            submitted = self.client.post(
                reverse('submit_form', args=[malformed_form.uuid]), {'answer': 'value'}, secure=True,
            )
        self.assertEqual(submitted.status_code, 200)
        self.assertEqual(
            FormSubmission.objects.get(form=malformed_form).response,
            {'status': 'WEBHOOK_HEADER_CONFIGURATION_FAILED'},
        )
        session_factory.return_value.post.assert_not_called()

    def test_admin_excludes_raw_headers_and_keeps_admin_authorization(self):
        from django.contrib import admin

        stored = prepare_webhook_headers_for_storage({'Authorization': self.secret_marker})
        dynamic_form = self.create_form(stored)
        model_admin = admin.site._registry[DynamicForm]
        integration_fields = next(fields for title, fields in model_admin.fieldsets if title == 'Integration')
        self.assertNotIn('headers', integration_fields['fields'])

        self.client.force_login(self.superuser)
        response = self.client.get(reverse('admin:integrator_dynamicform_change', args=[dynamic_form.pk]), secure=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.secret_marker, response.content.decode())
        self.assertNotIn(stored['Authorization'], response.content.decode())

        self.client.force_login(self.normal_user)
        self.assertEqual(
            self.client.get(reverse('admin:integrator_dynamicform_change', args=[dynamic_form.pk]), secure=True).status_code,
            302,
        )


class DynamicFormWebhookHeaderEncryptionMigrationTests(TransactionTestCase):
    reset_sequences = True
    migrate_from = [('integrator', '0013_encrypt_integrationcredential_secrets')]
    migrate_to = [('integrator', '0014_encrypt_dynamicform_webhook_header_secrets')]

    def test_data_migration_encrypts_sensitive_headers_and_preserves_valid_ciphertext(self):
        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_from)
        old_apps = executor.loader.project_state(self.migrate_from).apps
        old_form = old_apps.get_model('integrator', 'DynamicForm')
        existing_ciphertext = encrypt_webhook_header_value('migration-existing-secret')
        plaintext = old_form.objects.create(
            formname='Migration plaintext headers',
            headers={'Authorization': 'migration-plaintext-secret', 'Accept': 'application/json'},
        )
        preserved = old_form.objects.create(
            formname='Migration encrypted headers',
            headers={'X-API-Key': existing_ciphertext, 'X-Request-Id': 'stable'},
        )

        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_to)
        new_apps = executor.loader.project_state(self.migrate_to).apps
        new_form = new_apps.get_model('integrator', 'DynamicForm')
        migrated_plaintext = new_form.objects.get(pk=plaintext.pk)
        migrated_preserved = new_form.objects.get(pk=preserved.pk)
        self.assertTrue(migrated_plaintext.headers['Authorization'].startswith('enc:v1:'))
        self.assertEqual(
            decrypt_webhook_header_value(migrated_plaintext.headers['Authorization']),
            'migration-plaintext-secret',
        )
        self.assertEqual(migrated_plaintext.headers['Accept'], 'application/json')
        self.assertEqual(migrated_preserved.headers['X-API-Key'], existing_ciphertext)
        self.assertEqual(migrated_preserved.headers['X-Request-Id'], 'stable')

        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_from)
        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_to)

        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_from)
        old_apps = executor.loader.project_state(self.migrate_from).apps
        old_form = old_apps.get_model('integrator', 'DynamicForm')
        malformed = old_form.objects.create(
            formname='Migration malformed header', headers={'Authorization': 'enc:v1:not-valid'},
        )
        executor = MigrationExecutor(django_db_connection)
        with self.assertRaisesRegex(RuntimeError, 'invalid webhook header encrypted secret'):
            executor.migrate(self.migrate_to)

        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_from)
        old_apps = executor.loader.project_state(self.migrate_from).apps
        old_apps.get_model('integrator', 'DynamicForm').objects.filter(pk=malformed.pk).delete()
        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_to)


class SubmissionReadAndFileDownloadAuthorizationTests(TestCase):
    def setUp(self):
        self.media_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.media_directory.cleanup)
        self.media_settings = override_settings(MEDIA_ROOT=self.media_directory.name)
        self.media_settings.enable()
        self.addCleanup(self.media_settings.disable)

        self.normal_user = User.objects.create_user('submission-normal', password='password')
        self.staff_user = User.objects.create_user('submission-staff', password='password', is_staff=True)
        self.selected_user = User.objects.create_user('submission-selected', password='password')
        self.superuser = User.objects.create_superuser(
            'submission-admin', 'submission-admin@example.test', 'password'
        )
        self.public_form = DynamicForm.objects.create(
            formname='Public upload form', config='[]', access_level='public', auto_redirect_to_sso=False,
        )
        self.selected_form = DynamicForm.objects.create(
            formname='Selected upload form', config='[]', access_level='selected_users', auto_redirect_to_sso=False,
        )
        FormPermission.objects.create(form=self.selected_form, user=self.selected_user)
        self.submission = FormSubmission.objects.create(
            form=self.selected_form,
            submissionID='protected-submission',
            submission_data={'answer': 'sensitive submission value'},
        )
        self.file_upload = FileUpload.objects.create(
            submission=self.submission,
            field_name='attachment',
            file=SimpleUploadedFile('protected-report.txt', b'protected file contents', content_type='text/plain'),
        )

    def test_administrative_submission_views_remain_superuser_only(self):
        urls = (
            reverse('view_form_submissions'),
            reverse('open_form_submissions', args=[self.selected_form.uuid]),
            reverse('submission_details', args=[self.submission.submissionID]),
        )
        for url in urls:
            self.assertEqual(self.client.get(url, secure=True).status_code, 302)

        for user in (self.normal_user, self.staff_user):
            self.client.force_login(user)
            for url in urls:
                self.assertEqual(self.client.get(url, secure=True).status_code, 403)
            self.client.logout()

        self.client.force_login(self.superuser)
        for url in urls:
            self.assertEqual(self.client.get(url, secure=True).status_code, 200)

    def test_user_submission_history_routes_fail_closed_without_ownership(self):
        routes = (
            reverse('my_submissions', args=[self.public_form.uuid]),
            reverse('my_submissions', args=[self.selected_form.uuid]),
            reverse('user_submission_details', args=[self.submission.submissionID]),
        )
        for user in (self.normal_user, self.selected_user):
            self.client.force_login(user)
            for url in routes:
                self.assertEqual(self.client.get(url, secure=True).status_code, 404)
            self.client.logout()

    def test_protected_file_download_requires_superuser_and_streams_safe_content(self):
        url = reverse('download_submission_file', args=[self.file_upload.id])
        self.assertEqual(self.client.get(url, secure=True).status_code, 302)

        for user in (self.normal_user, self.staff_user, self.selected_user):
            self.client.force_login(user)
            self.assertEqual(self.client.get(url, secure=True).status_code, 403)
            self.client.logout()

        self.client.force_login(self.superuser)
        response = self.client.get(url, secure=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b''.join(response.streaming_content), b'protected file contents')
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertIn('protected-report.txt', response['Content-Disposition'])
        self.assertNotIn(self.media_directory.name, response['Content-Disposition'])

    def test_missing_protected_file_returns_a_safe_not_found_response(self):
        self.file_upload.file.storage.delete(self.file_upload.file.name)
        self.client.force_login(self.superuser)
        response = self.client.get(
            reverse('download_submission_file', args=[self.file_upload.id]), secure=True,
        )
        self.assertEqual(response.status_code, 404)
        self.assertNotIn(self.media_directory.name, response.content.decode())

    def test_submission_template_uses_the_protected_download_route(self):
        template_path = Path(__file__).resolve().parent.parent / 'templates' / 'pages' / 'forms' / 'submission_details.html'
        template_source = template_path.read_text(encoding='utf-8')
        self.assertNotIn('file.file.url', template_source)
        self.assertIn("download_submission_file", template_source)


class DynamicUploadContainmentTests(TestCase):
    def setUp(self):
        self.media_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.media_directory.cleanup)
        self.media_settings = override_settings(MEDIA_ROOT=self.media_directory.name)
        self.media_settings.enable()
        self.addCleanup(self.media_settings.disable)

        self.authenticated_user = User.objects.create_user('upload-authenticated', password='password')
        self.selected_user = User.objects.create_user('upload-selected', password='password')
        self.unselected_user = User.objects.create_user('upload-unselected', password='password')

    def create_upload_form(self, fields=None, access_level='public'):
        return DynamicForm.objects.create(
            formname='Contained upload form',
            config=json.dumps(fields or [{
                'name': 'attachment',
                'type': 'file',
                'accept': '.txt',
            }]),
            access_level=access_level,
            auto_redirect_to_sso=False,
        )

    def upload(self, name, content, content_type='text/plain'):
        return SimpleUploadedFile(name, content, content_type=content_type)

    def submit(self, dynamic_form, data):
        return self.client.post(reverse('submit_form', args=[dynamic_form.uuid]), data, secure=True)

    def stored_files(self):
        return [path for path in Path(self.media_directory.name).rglob('*') if path.is_file()]

    def test_configured_file_field_accepts_a_safe_upload(self):
        dynamic_form = self.create_upload_form()

        response = self.submit(dynamic_form, {'attachment': self.upload('report.txt', b'report')})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(FormSubmission.objects.filter(form=dynamic_form).count(), 1)
        self.assertEqual(FileUpload.objects.filter(submission__form=dynamic_form).count(), 1)
        self.assertEqual(len(self.stored_files()), 1)

    def test_unknown_or_non_file_multipart_fields_are_rejected_without_persistence(self):
        dynamic_form = self.create_upload_form()
        response = self.submit(dynamic_form, {'unexpected': self.upload('report.txt', b'report')})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'Unexpected file field.')
        self.assertFalse(FormSubmission.objects.filter(form=dynamic_form).exists())
        self.assertFalse(FileUpload.objects.filter(submission__form=dynamic_form).exists())
        self.assertEqual(self.stored_files(), [])

        non_file_form = self.create_upload_form(fields=[{'name': 'comment', 'type': 'text'}])
        response = self.submit(non_file_form, {'comment': self.upload('report.txt', b'report')})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'Unexpected file field.')
        self.assertFalse(FileUpload.objects.filter(submission__form=non_file_form).exists())
        self.assertEqual(self.stored_files(), [])

    @override_settings(DYNAMIC_UPLOAD_MAX_FILE_SIZE=3)
    def test_per_file_limit_accepts_below_and_at_limit_but_rejects_above(self):
        dynamic_form = self.create_upload_form()

        self.assertEqual(self.submit(dynamic_form, {'attachment': self.upload('below.txt', b'ab')}).status_code, 200)
        self.assertEqual(self.submit(dynamic_form, {'attachment': self.upload('equal.txt', b'abc')}).status_code, 200)
        response = self.submit(dynamic_form, {'attachment': self.upload('above.txt', b'abcd')})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'File exceeds allowed size.')
        self.assertEqual(FileUpload.objects.filter(submission__form=dynamic_form).count(), 2)

    @override_settings(DYNAMIC_UPLOAD_MAX_FILE_COUNT=2)
    def test_file_count_accepts_at_limit_but_rejects_above(self):
        dynamic_form = self.create_upload_form(fields=[{
            'name': 'attachment', 'type': 'file', 'accept': '.txt', 'multiple': True, 'maxFileCount': 5,
        }])

        response = self.submit(dynamic_form, {'attachment': [
            self.upload('one.txt', b'1'), self.upload('two.txt', b'2'),
        ]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(FileUpload.objects.filter(submission__form=dynamic_form).count(), 2)

        response = self.submit(dynamic_form, {'attachment': [
            self.upload('three.txt', b'3'), self.upload('four.txt', b'4'), self.upload('five.txt', b'5'),
        ]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'Too many files were uploaded.')
        self.assertEqual(FileUpload.objects.filter(submission__form=dynamic_form).count(), 2)

    @override_settings(DYNAMIC_UPLOAD_MAX_FILE_SIZE=3, DYNAMIC_UPLOAD_MAX_TOTAL_SIZE=6, DYNAMIC_UPLOAD_MAX_FILE_COUNT=3)
    def test_total_upload_limit_accepts_below_and_at_limit_but_rejects_above(self):
        dynamic_form = self.create_upload_form(fields=[{
            'name': 'attachment', 'type': 'file', 'accept': '.txt', 'multiple': True, 'maxFileCount': 3,
        }])

        self.assertEqual(self.submit(dynamic_form, {'attachment': [
            self.upload('below-one.txt', b'ab'), self.upload('below-two.txt', b'abc'),
        ]}).status_code, 200)
        self.assertEqual(self.submit(dynamic_form, {'attachment': [
            self.upload('equal-one.txt', b'abc'), self.upload('equal-two.txt', b'abc'),
        ]}).status_code, 200)
        response = self.submit(dynamic_form, {'attachment': [
            self.upload('above-one.txt', b'abc'), self.upload('above-two.txt', b'abc'), self.upload('above-three.txt', b'a'),
        ]})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'Total upload size exceeds the allowed limit.')
        self.assertEqual(FileUpload.objects.filter(submission__form=dynamic_form).count(), 4)

    def test_type_policy_rejects_active_content_and_does_not_trust_browser_content_type(self):
        dynamic_form = self.create_upload_form(fields=[{
            'name': 'attachment', 'type': 'file', 'accept': '.txt,.jpg',
        }])

        self.assertEqual(self.submit(dynamic_form, {
            'attachment': self.upload('notes.txt', b'plain text'),
        }).status_code, 200)
        response = self.submit(dynamic_form, {
            'attachment': self.upload('attack.html', b'<script>alert(1)</script>', 'text/plain'),
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'Unsupported file type.')

        response = self.submit(dynamic_form, {
            'attachment': self.upload('not-an-image.jpg', b'not an image', 'image/jpeg'),
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'Unsupported file type.')
        self.assertEqual(FileUpload.objects.filter(submission__form=dynamic_form).count(), 1)

    def test_invalid_configured_limits_fail_closed(self):
        dynamic_form = self.create_upload_form(fields=[{
            'name': 'attachment', 'type': 'file', 'accept': '.txt', 'maxFileSizeMB': 'not-a-number',
        }])

        response = self.submit(dynamic_form, {'attachment': self.upload('report.txt', b'report')})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'File exceeds allowed size.')
        self.assertFalse(FileUpload.objects.filter(submission__form=dynamic_form).exists())
        self.assertEqual(self.stored_files(), [])

    def test_multiple_upload_with_one_invalid_file_leaves_no_partial_records_or_files(self):
        dynamic_form = self.create_upload_form(fields=[{
            'name': 'attachment', 'type': 'file', 'accept': '.txt', 'multiple': True, 'maxFileCount': 2,
        }])

        response = self.submit(dynamic_form, {'attachment': [
            self.upload('valid.txt', b'valid'),
            self.upload('invalid.html', b'<html>not allowed</html>', 'text/html'),
        ]})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'Unsupported file type.')
        self.assertFalse(FormSubmission.objects.filter(form=dynamic_form).exists())
        self.assertFalse(FileUpload.objects.filter(submission__form=dynamic_form).exists())
        self.assertEqual(self.stored_files(), [])

    def test_upload_validation_preserves_public_authenticated_and_selected_delivery_policy(self):
        public_form = self.create_upload_form()
        authenticated_form = self.create_upload_form(access_level='authenticated')
        selected_form = self.create_upload_form(access_level='selected_users')
        FormPermission.objects.create(form=selected_form, user=self.selected_user)

        self.assertEqual(self.submit(public_form, {
            'attachment': self.upload('public.txt', b'public'),
        }).status_code, 200)
        self.assertEqual(self.submit(authenticated_form, {
            'attachment': self.upload('anonymous.txt', b'anonymous'),
        }).status_code, 302)
        self.assertFalse(FileUpload.objects.filter(submission__form=authenticated_form).exists())

        self.client.force_login(self.authenticated_user)
        self.assertEqual(self.submit(authenticated_form, {
            'attachment': self.upload('authenticated.txt', b'authenticated'),
        }).status_code, 200)
        self.client.logout()

        self.assertEqual(self.submit(selected_form, {
            'attachment': self.upload('selected-anonymous.txt', b'anonymous'),
        }).status_code, 302)
        self.client.force_login(self.unselected_user)
        self.assertEqual(self.submit(selected_form, {
            'attachment': self.upload('unselected.txt', b'unselected'),
        }).status_code, 403)
        self.client.force_login(self.selected_user)
        self.assertEqual(self.submit(selected_form, {
            'attachment': self.upload('selected.txt', b'selected'),
        }).status_code, 200)

        self.assertEqual(FileUpload.objects.filter(submission__form=public_form).count(), 1)
        self.assertEqual(FileUpload.objects.filter(submission__form=authenticated_form).count(), 1)
        self.assertEqual(FileUpload.objects.filter(submission__form=selected_form).count(), 1)


class InformationLeakageContainmentTests(TestCase):
    """Regression coverage for technical detail escaping management responses."""

    def setUp(self):
        self.superuser = User.objects.create_superuser(
            'leakage-admin', 'leakage-admin@example.com', 'password'
        )
        self.integration = Integration.objects.create(
            name='Leakage containment integration',
            fields={'api_token': 'API token'},
        )
        self.credential = IntegrationCredential.objects.create(
            user=self.superuser,
            integration=self.integration,
            credentials={'api_token': 'stored-browser-secret'},
            enabled=True,
        )
        self.connection = DatabaseConnection(
            user=self.superuser,
            name='Leakage containment connection',
            connection_type='mssql',
            server='internal-db.example.test',
            port='1433',
            database_name='private_catalog',
            username='private_user',
        )
        self.connection.set_password('stored-db-password')
        self.connection.save()
        self.approval = ApprovedProcedure.objects.create(
            connection=self.connection,
            engine='mssql',
            database_name='private_catalog',
            schema='dbo',
            procedure_name='safe_read',
            behavior=ApprovedProcedure.READ_EXPECTED,
            enabled=True,
            approved_by=self.superuser,
        )
        ApprovedProcedureParameter.objects.create(
            approved_procedure=self.approval,
            ordinal=1,
            name='CustomerId',
            direction=ApprovedProcedureParameter.INPUT,
            database_type='int',
            required=True,
            nullable=False,
        )
        self.client.force_login(self.superuser)

    def json_post(self, url, payload):
        return self.client.post(
            url, data=json.dumps(payload), content_type='application/json', secure=True
        )

    def assert_response_hides(self, response, *sensitive_values):
        body = response.content.decode()
        for value in sensitive_values:
            self.assertNotIn(value, body)

    def test_integration_toggle_failure_hides_exception_and_secret(self):
        leaked = 'api_token=browser-secret; path=C:/private/integration.py'
        with patch.object(IntegrationCredential, 'save', side_effect=RuntimeError(leaked)):
            response = self.json_post(
                reverse('toggle_integration'),
                {'integration_id': self.integration.id, 'enabled': False},
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()['message'], 'Integration operation failed.')
        self.assert_response_hides(response, leaked, 'browser-secret', 'C:/private')

    def test_database_test_failure_hides_connection_string_details(self):
        leaked = 'SERVER=internal-db.example.test;PWD=browser-db-secret'
        payload = {
            'type': 'mssql',
            'server': 'internal-db.example.test',
            'port': '1433',
            'database': 'private_catalog',
            'username': 'private_user',
            'password': 'browser-db-secret',
        }
        with patch('integrator.db_config.get_available_odbc_driver', return_value='Mock ODBC Driver'), patch(
            'integrator.views.pyodbc.connect', side_effect=RuntimeError(leaked)
        ):
            response = self.json_post(reverse('test_database_connection'), payload)

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()['error'], 'Database connection test failed.')
        self.assert_response_hides(response, leaked, 'internal-db.example.test', 'browser-db-secret')

    def test_procedure_discovery_failure_hides_database_exception(self):
        leaked = 'DRIVER=Mock;SERVER=internal-db.example.test;PWD=browser-db-secret'
        with patch('integrator.db_config.get_available_odbc_driver', return_value='Mock ODBC Driver'), patch(
            'integrator.views.pyodbc.connect', side_effect=RuntimeError(leaked)
        ):
            response = self.client.get(
                reverse('stored_procedures', args=[self.connection.id]), secure=True
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()['error'], 'Database operation failed.')
        self.assert_response_hides(response, leaked, 'internal-db.example.test', 'browser-db-secret')

    def test_procedure_execution_failure_hides_submitted_parameter_and_driver_error(self):
        leaked = 'procedure CustomerId=4242 failed for SERVER=internal-db.example.test'
        with patch('integrator.db_config.get_available_odbc_driver', return_value='Mock ODBC Driver'), patch(
            'integrator.views.pyodbc.connect', side_effect=RuntimeError(leaked)
        ):
            response = self.json_post(
                reverse('execute_procedure'),
                {'approved_procedure_id': self.approval.id, 'parameters': {'CustomerId': 4242}},
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()['error'], 'Procedure execution failed.')
        self.assert_response_hides(response, leaked, 'CustomerId=4242', 'internal-db.example.test')
