"""Trusted field metadata and browser-safe handling for integration credentials."""

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings

# Legacy Integration.fields values are display-label strings, not typed metadata.
# These exact stored credential keys are the existing sensitive compatibility set.
LEGACY_SECRET_FIELD_NAMES = frozenset({
    'password', 'api_key', 'api_token', 'token', 'access_token', 'refresh_token',
    'client_secret', 'database_password', 'db_password',
})
MASKED_SECRET_VALUE = '********'
ENCRYPTED_SECRET_PREFIX = 'enc:v1:'


class CredentialEncryptionError(ValueError):
    """Raised when a stored integration secret is not safely decryptable."""


def _fernet():
    try:
        return Fernet(settings.ENCRYPTION_KEY.encode())
    except (AttributeError, TypeError, ValueError) as exc:
        raise CredentialEncryptionError('Integration credential encryption is unavailable.') from exc


def is_encrypted_secret(value):
    return isinstance(value, str) and value.startswith(ENCRYPTED_SECRET_PREFIX)


def encrypt_secret(value):
    """Encrypt plaintext once; preserve a recognized v1 representation unchanged."""
    if not isinstance(value, str):
        raise CredentialEncryptionError('Integration secret is invalid.')
    if value.startswith('enc:'):
        if not is_encrypted_secret(value):
            raise CredentialEncryptionError('Integration secret encryption version is unsupported.')
        return value
    try:
        return ENCRYPTED_SECRET_PREFIX + _fernet().encrypt(value.encode()).decode()
    except (UnicodeError, ValueError) as exc:
        raise CredentialEncryptionError('Integration secret encryption failed.') from exc


def decrypt_secret(value):
    """Decrypt a recognized v1 secret only for an authorized runtime consumer."""
    if not isinstance(value, str) or not is_encrypted_secret(value):
        if isinstance(value, str) and value.startswith('enc:'):
            raise CredentialEncryptionError('Integration secret encryption version is unsupported.')
        raise CredentialEncryptionError('Integration secret is not encrypted.')
    try:
        return _fernet().decrypt(value[len(ENCRYPTED_SECRET_PREFIX):].encode()).decode()
    except (InvalidToken, UnicodeError, ValueError) as exc:
        raise CredentialEncryptionError('Integration secret cannot be decrypted.') from exc


def integration_field_definitions(fields):
    """Normalize trusted Integration.fields without treating browser input as metadata."""
    definitions = {}
    for name, definition in (fields or {}).items():
        if not isinstance(name, str):
            continue
        if isinstance(definition, dict):
            label = definition.get('label', name)
            secret = (
                definition.get('type') == 'password'
                or definition.get('secret') is True
                or definition.get('sensitive') is True
            )
        else:
            label = definition if isinstance(definition, str) else name
            secret = name.lower() in LEGACY_SECRET_FIELD_NAMES
        definitions[name] = {'label': label, 'secret': secret}
    return definitions


def browser_credential_state(fields, credentials):
    """Return field definitions and values without returning an existing secret."""
    definitions = integration_field_definitions(fields)
    stored = credentials if isinstance(credentials, dict) else {}
    values = {}
    secret_state = {}
    for name, definition in definitions.items():
        if definition['secret']:
            secret_state[name] = {'configured': bool(stored.get(name))}
        elif name in stored:
            values[name] = stored[name]
    return definitions, values, secret_state


def merge_submitted_credentials(fields, existing_credentials, submitted_credentials):
    """Preserve blank or masked submitted secrets while applying actual replacements."""
    if not isinstance(submitted_credentials, dict):
        raise ValueError('Credentials must be an object.')
    definitions = integration_field_definitions(fields)
    if set(submitted_credentials) - set(definitions):
        raise ValueError('Unknown credential field.')
    merged = dict(existing_credentials) if isinstance(existing_credentials, dict) else {}
    for name, value in submitted_credentials.items():
        if not isinstance(value, str):
            raise ValueError('Credential values must be strings.')
        if definitions[name]['secret'] and (not value or value == MASKED_SECRET_VALUE):
            continue
        merged[name] = value
    return merged


def encrypt_credentials_for_storage(fields, credentials):
    """Return a copy with trusted secret fields encrypted and non-secret values untouched."""
    definitions = integration_field_definitions(fields)
    stored = dict(credentials) if isinstance(credentials, dict) else {}
    for name, definition in definitions.items():
        if definition['secret'] and stored.get(name) not in (None, ''):
            stored[name] = encrypt_secret(stored[name])
    return stored


def decrypt_credentials_for_runtime(fields, credentials):
    """Return a transient copy containing plaintext only for trusted secret fields."""
    definitions = integration_field_definitions(fields)
    runtime = dict(credentials) if isinstance(credentials, dict) else {}
    for name, definition in definitions.items():
        if definition['secret'] and runtime.get(name) not in (None, ''):
            runtime[name] = decrypt_secret(runtime[name])
    return runtime
