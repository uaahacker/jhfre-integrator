import re

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.db import migrations


ENCRYPTED_HEADER_PREFIX = 'enc:v1:'
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
HEADER_TOKEN_RE = re.compile(r'[A-Z]+(?=[A-Z][a-z]|[^A-Z]|$)|[A-Z]?[a-z]+|[0-9]+')
EXACT_SECRET_HEADER_NAMES = frozenset({
    'authorization', 'proxyauthorization', 'cookie', 'setcookie',
    'apikey', 'xapikey', 'authtoken', 'xauthtoken',
    'accesstoken', 'xaccesstoken', 'refreshtoken', 'clientsecret',
})
SECRET_TOKENS = frozenset({'token', 'secret', 'password'})
SECRET_KEY_TOKEN_PAIRS = frozenset({('api', 'key'), ('access', 'key'), ('auth', 'key')})


def _fernet():
    try:
        return Fernet(settings.ENCRYPTION_KEY.encode())
    except (AttributeError, TypeError, ValueError) as exc:
        raise RuntimeError('Webhook header encryption configuration is invalid.') from exc


def _header_tokens(name):
    separated = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', name)
    separated = re.sub(r'(?<=[A-Z])(?=[A-Z][a-z])', ' ', separated)
    return tuple(token.casefold() for token in re.findall(r'[A-Za-z0-9]+', separated))


def _sensitive_header(name):
    compact_name = re.sub(r'[^a-z0-9]+', '', name.casefold())
    if compact_name in EXACT_SECRET_HEADER_NAMES:
        return True
    tokens = _header_tokens(name)
    if any(token in SECRET_TOKENS for token in tokens):
        return True
    return any(pair in SECRET_KEY_TOKEN_PAIRS for pair in zip(tokens, tokens[1:]))


def _migration_error(form_id, category):
    return RuntimeError(f'DynamicForm {form_id} has invalid webhook header {category}.')


def encrypt_dynamicform_webhook_header_secrets(apps, schema_editor):
    DynamicForm = apps.get_model('integrator', 'DynamicForm')
    cipher = _fernet()
    for form in DynamicForm.objects.iterator():
        headers = form.headers
        if headers in (None, '', {}):
            continue
        if not isinstance(headers, dict):
            raise _migration_error(form.pk, 'structure')
        seen = set()
        updated = dict(headers)
        changed = False
        for name, value in headers.items():
            if not isinstance(name, str) or not name or not HEADER_NAME_RE.fullmatch(name):
                raise _migration_error(form.pk, 'name')
            identity = name.casefold()
            if identity in seen:
                raise _migration_error(form.pk, 'duplicate name')
            seen.add(identity)
            if not _sensitive_header(name):
                continue
            if value == '':
                continue
            if not isinstance(value, str):
                raise _migration_error(form.pk, 'secret value')
            if value.startswith('enc:'):
                if not value.startswith(ENCRYPTED_HEADER_PREFIX):
                    raise _migration_error(form.pk, 'encryption version')
                try:
                    cipher.decrypt(value[len(ENCRYPTED_HEADER_PREFIX):].encode())
                except (InvalidToken, UnicodeError, ValueError) as exc:
                    raise _migration_error(form.pk, 'encrypted secret') from exc
                continue
            try:
                updated[name] = ENCRYPTED_HEADER_PREFIX + cipher.encrypt(value.encode()).decode()
            except (UnicodeError, ValueError) as exc:
                raise _migration_error(form.pk, 'secret value') from exc
            changed = True
        if changed:
            form.headers = updated
            form.save(update_fields=['headers'])


class Migration(migrations.Migration):

    dependencies = [
        ('integrator', '0013_encrypt_integrationcredential_secrets'),
    ]

    operations = [
        migrations.RunPython(
            encrypt_dynamicform_webhook_header_secrets,
            migrations.RunPython.noop,
        ),
    ]
