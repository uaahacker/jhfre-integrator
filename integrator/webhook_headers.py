"""Secret-safe storage and runtime preparation for dynamic webhook headers."""

import json
import re

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


ENCRYPTED_HEADER_PREFIX = 'enc:v1:'
MASKED_HEADER_VALUE = '********'
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_HEADER_TOKEN_RE = re.compile(r'[A-Z]+(?=[A-Z][a-z]|[^A-Z]|$)|[A-Z]?[a-z]+|[0-9]+')
_EXACT_SECRET_HEADER_NAMES = frozenset({
    'authorization', 'proxyauthorization', 'cookie', 'setcookie',
    'apikey', 'xapikey', 'authtoken', 'xauthtoken',
    'accesstoken', 'xaccesstoken', 'refreshtoken', 'clientsecret',
})
_SECRET_TOKENS = frozenset({'token', 'secret', 'password'})
_SECRET_KEY_TOKEN_PAIRS = frozenset({('api', 'key'), ('access', 'key'), ('auth', 'key')})


class WebhookHeaderError(ValueError):
    """A generic, safe webhook-header configuration or decryption failure."""


class DuplicateWebhookHeaderError(WebhookHeaderError):
    """Raised when two names have the same HTTP case-insensitive identity."""


class WebhookHeaderSecretError(WebhookHeaderError):
    """Raised when sensitive storage cannot safely be encrypted or decrypted."""


class _JSONObjectWithPairs(dict):
    def __init__(self, pairs):
        super().__init__(pairs)
        self.pairs = pairs


def _header_identity(name):
    return name.casefold()


def _header_tokens(name):
    separated = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', name)
    separated = re.sub(r'(?<=[A-Z])(?=[A-Z][a-z])', ' ', separated)
    return tuple(token.casefold() for token in re.findall(r'[A-Za-z0-9]+', separated))


def is_sensitive_webhook_header(name):
    """Classify explicit and separator/camel-case secret-bearing header names."""
    if not isinstance(name, str):
        return False
    compact_name = re.sub(r'[^a-z0-9]+', '', name.casefold())
    if compact_name in _EXACT_SECRET_HEADER_NAMES:
        return True
    tokens = _header_tokens(name)
    if any(token in _SECRET_TOKENS for token in tokens):
        return True
    return any(pair in _SECRET_KEY_TOKEN_PAIRS for pair in zip(tokens, tokens[1:]))


def _fernet():
    try:
        return Fernet(settings.ENCRYPTION_KEY.encode())
    except (AttributeError, TypeError, ValueError) as exc:
        raise WebhookHeaderSecretError('Secret value configuration is invalid.') from exc


def _validate_header_name(name):
    if not isinstance(name, str) or not name or not _HEADER_NAME_RE.fullmatch(name):
        raise WebhookHeaderError('Invalid webhook header configuration.')


def parse_webhook_configuration_json(raw_value):
    """Retain JSON object pairs so case-variant duplicate headers are detectable."""
    try:
        return json.loads(raw_value, object_pairs_hook=_JSONObjectWithPairs)
    except (TypeError, ValueError) as exc:
        raise WebhookHeaderError('Invalid webhook header configuration.') from exc


def parse_webhook_headers_json(raw_value):
    parsed = parse_webhook_configuration_json(raw_value)
    if not isinstance(parsed, dict):
        raise WebhookHeaderError('Invalid webhook header configuration.')
    return parsed


def validate_header_object(headers, *, allow_legacy_empty=False):
    """Validate object shape, HTTP header names, string values, and duplicates."""
    if headers is None and allow_legacy_empty:
        return {}
    if isinstance(headers, str) and allow_legacy_empty:
        if not headers.strip():
            return {}
        try:
            headers = json.loads(headers)
        except (TypeError, ValueError) as exc:
            raise WebhookHeaderError('Invalid webhook header configuration.') from exc
    if not isinstance(headers, dict):
        raise WebhookHeaderError('Invalid webhook header configuration.')
    seen = set()
    validated = {}
    items = getattr(headers, 'pairs', headers.items())
    for name, value in items:
        _validate_header_name(name)
        identity = _header_identity(name)
        if identity in seen:
            raise DuplicateWebhookHeaderError('Duplicate webhook header name.')
        if not isinstance(value, str):
            raise WebhookHeaderError('Invalid webhook header configuration.')
        seen.add(identity)
        validated[name] = value
    return validated


def is_encrypted_webhook_header_value(value):
    return isinstance(value, str) and value.startswith(ENCRYPTED_HEADER_PREFIX)


def encrypt_webhook_header_value(value):
    if not isinstance(value, str):
        raise WebhookHeaderSecretError('Secret value configuration is invalid.')
    if value.startswith('enc:'):
        decrypt_webhook_header_value(value)
        return value
    try:
        return ENCRYPTED_HEADER_PREFIX + _fernet().encrypt(value.encode()).decode()
    except (UnicodeError, ValueError) as exc:
        raise WebhookHeaderSecretError('Secret value configuration is invalid.') from exc


def decrypt_webhook_header_value(value):
    if not isinstance(value, str) or not is_encrypted_webhook_header_value(value):
        raise WebhookHeaderSecretError('Secret value configuration is invalid.')
    try:
        return _fernet().decrypt(value[len(ENCRYPTED_HEADER_PREFIX):].encode()).decode()
    except (InvalidToken, UnicodeError, ValueError) as exc:
        raise WebhookHeaderSecretError('Secret value configuration is invalid.') from exc


def prepare_webhook_headers_for_storage(submitted_headers, existing_headers=None):
    """Encrypt sensitive submitted values and preserve masked existing values."""
    submitted = validate_header_object(submitted_headers)
    existing = validate_header_object(existing_headers or {}, allow_legacy_empty=True)
    existing_by_identity = {_header_identity(name): (name, value) for name, value in existing.items()}
    stored = {}
    for name, value in submitted.items():
        if not is_sensitive_webhook_header(name):
            stored[name] = value
            continue
        existing_value = existing_by_identity.get(_header_identity(name))
        if value in ('', MASKED_HEADER_VALUE):
            if existing_value is None:
                raise WebhookHeaderSecretError('Secret value configuration is invalid.')
            preserved_value = existing_value[1]
            if preserved_value:
                decrypt_webhook_header_value(preserved_value)
            stored[name] = preserved_value
            continue
        stored[name] = encrypt_webhook_header_value(value)
    return stored


def browser_safe_webhook_headers(headers):
    """Return values safe to render; ciphertext and sensitive plaintext are masked."""
    try:
        stored = validate_header_object(headers, allow_legacy_empty=True)
    except WebhookHeaderError:
        return {}
    return {
        name: MASKED_HEADER_VALUE if is_sensitive_webhook_header(name) else value
        for name, value in stored.items()
    }


def prepare_webhook_headers_for_runtime(headers):
    """Decrypt only validated ciphertext immediately before outbound delivery."""
    stored = validate_header_object(headers, allow_legacy_empty=True)
    runtime = {}
    for name, value in stored.items():
        if not is_sensitive_webhook_header(name):
            runtime[name] = value
        elif value == '':
            runtime[name] = value
        else:
            runtime[name] = decrypt_webhook_header_value(value)
    return runtime
