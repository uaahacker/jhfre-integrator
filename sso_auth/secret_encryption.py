"""Fail-closed encryption helpers for SSO provider secret storage."""

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


ENCRYPTED_SSO_SECRET_PREFIX = 'enc:v1:'


class SSOSecretEncryptionError(ValueError):
    """Raised when an SSO secret cannot be safely stored or used at runtime."""


def _fernet():
    try:
        return Fernet(settings.ENCRYPTION_KEY.encode())
    except (AttributeError, TypeError, ValueError) as exc:
        raise SSOSecretEncryptionError('SSO secret encryption is unavailable.') from exc


def is_encrypted_sso_secret(value):
    return isinstance(value, str) and value.startswith(ENCRYPTED_SSO_SECRET_PREFIX)


def decrypt_sso_secret(value):
    """Decrypt a v1 secret only at an authorized SSO runtime boundary."""
    if not isinstance(value, str) or not is_encrypted_sso_secret(value):
        if isinstance(value, str) and value.startswith('enc:'):
            raise SSOSecretEncryptionError('SSO secret encryption version is unsupported.')
        raise SSOSecretEncryptionError('SSO secret is not encrypted.')
    try:
        return _fernet().decrypt(value[len(ENCRYPTED_SSO_SECRET_PREFIX):].encode()).decode()
    except (InvalidToken, UnicodeError, ValueError) as exc:
        raise SSOSecretEncryptionError('SSO secret cannot be decrypted.') from exc


def encrypt_sso_secret(value):
    """Encrypt plaintext once and validate, but do not replace, existing v1 values."""
    if not isinstance(value, str):
        raise SSOSecretEncryptionError('SSO secret is invalid.')
    if value.startswith('enc:'):
        if not is_encrypted_sso_secret(value):
            raise SSOSecretEncryptionError('SSO secret encryption version is unsupported.')
        decrypt_sso_secret(value)
        return value
    try:
        return ENCRYPTED_SSO_SECRET_PREFIX + _fernet().encrypt(value.encode()).decode()
    except (UnicodeError, ValueError) as exc:
        raise SSOSecretEncryptionError('SSO secret encryption failed.') from exc
