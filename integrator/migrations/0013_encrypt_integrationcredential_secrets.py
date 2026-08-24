from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.db import migrations


ENCRYPTED_SECRET_PREFIX = 'enc:v1:'
LEGACY_SECRET_FIELD_NAMES = frozenset({
    'password', 'api_key', 'api_token', 'token', 'access_token', 'refresh_token',
    'client_secret', 'database_password', 'db_password',
})


def _secret_field(name, definition):
    if isinstance(definition, dict):
        return (
            definition.get('type') == 'password'
            or definition.get('secret') is True
            or definition.get('sensitive') is True
        )
    return isinstance(name, str) and name.lower() in LEGACY_SECRET_FIELD_NAMES


def _fernet():
    try:
        return Fernet(settings.ENCRYPTION_KEY.encode())
    except (AttributeError, TypeError, ValueError) as exc:
        raise RuntimeError('Integration credential encryption configuration is invalid.') from exc


def encrypt_existing_secrets(apps, schema_editor):
    IntegrationCredential = apps.get_model('integrator', 'IntegrationCredential')
    cipher = _fernet()
    for credential in IntegrationCredential.objects.select_related('integration').iterator():
        credentials = credential.credentials
        fields = credential.integration.fields
        if not isinstance(credentials, dict) or not isinstance(fields, dict):
            continue
        updated = dict(credentials)
        changed = False
        for name, definition in fields.items():
            if not _secret_field(name, definition) or updated.get(name) in (None, ''):
                continue
            value = updated[name]
            if not isinstance(value, str):
                raise RuntimeError(f'IntegrationCredential {credential.pk} has an invalid secret value.')
            if value.startswith('enc:'):
                if not value.startswith(ENCRYPTED_SECRET_PREFIX):
                    raise RuntimeError(f'IntegrationCredential {credential.pk} has an unsupported encryption version.')
                try:
                    cipher.decrypt(value[len(ENCRYPTED_SECRET_PREFIX):].encode())
                except (InvalidToken, UnicodeError, ValueError) as exc:
                    raise RuntimeError(f'IntegrationCredential {credential.pk} has an invalid encrypted secret.') from exc
                continue
            updated[name] = ENCRYPTED_SECRET_PREFIX + cipher.encrypt(value.encode()).decode()
            changed = True
        if changed:
            credential.credentials = updated
            credential.save(update_fields=['credentials'])


class Migration(migrations.Migration):

    dependencies = [
        ('integrator', '0012_procedureexecutionaudit'),
    ]

    operations = [
        migrations.RunPython(encrypt_existing_secrets, migrations.RunPython.noop),
    ]
