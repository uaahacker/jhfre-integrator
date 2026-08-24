"""Server-side validation for files submitted through dynamic forms."""

import json
import re
import warnings
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings
from PIL import Image, UnidentifiedImageError


class UploadValidationError(ValueError):
    """A controlled validation failure that is safe to return to a submitter."""


@dataclass(frozen=True)
class UploadFieldRules:
    allowed_extensions: frozenset
    max_file_size: int
    max_file_count: int


_IMAGE_EXTENSIONS = frozenset({'.jpg', '.jpeg', '.png', '.gif', '.webp'})
_ACCEPT_MIME_EXTENSIONS = {
    'application/pdf': {'.pdf'},
    'text/plain': {'.txt'},
    'text/csv': {'.csv'},
    'application/msword': {'.doc'},
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': {'.docx'},
    'application/vnd.ms-excel': {'.xls'},
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': {'.xlsx'},
    'application/vnd.ms-powerpoint': {'.ppt'},
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': {'.pptx'},
    'image/jpeg': {'.jpg', '.jpeg'},
    'image/png': {'.png'},
    'image/gif': {'.gif'},
    'image/webp': {'.webp'},
    'image/*': _IMAGE_EXTENSIONS,
}


def _submitted_field_name(name):
    return re.sub(r'\s+', '_', str(name))


def _positive_integer(value):
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    if str(value).strip() != str(parsed) or parsed <= 0:
        return None
    return parsed


def _configured_extensions(value):
    safe_extensions = frozenset(settings.DYNAMIC_UPLOAD_ALLOWED_EXTENSIONS)
    if value is None or not str(value).strip():
        return safe_extensions
    if not isinstance(value, str):
        return frozenset()

    allowed = set()
    for item in value.split(','):
        token = item.strip().lower()
        if not token:
            return frozenset()
        if token.startswith('.'):
            extensions = {token}
        else:
            extensions = _ACCEPT_MIME_EXTENSIONS.get(token)
        if not extensions:
            return frozenset()
        allowed.update(extensions)
    return frozenset(allowed & safe_extensions)


def _field_rules(field):
    max_file_size = settings.DYNAMIC_UPLOAD_MAX_FILE_SIZE
    if 'maxFileSizeMB' in field:
        configured_megabytes = _positive_integer(field['maxFileSizeMB'])
        if configured_megabytes is None:
            raise UploadValidationError('File exceeds allowed size.')
        max_file_size = min(max_file_size, configured_megabytes * 1024 * 1024)

    multiple = field.get('multiple', False)
    if not isinstance(multiple, bool):
        raise UploadValidationError('Too many files were uploaded.')

    max_file_count = 1
    if multiple:
        max_file_count = settings.DYNAMIC_UPLOAD_MAX_FILE_COUNT
        if 'maxFileCount' in field:
            configured_count = _positive_integer(field['maxFileCount'])
            if configured_count is None:
                raise UploadValidationError('Too many files were uploaded.')
            max_file_count = min(max_file_count, configured_count)

    return UploadFieldRules(
        allowed_extensions=_configured_extensions(field.get('accept')),
        max_file_size=max_file_size,
        max_file_count=max_file_count,
    )


def _file_fields(form_config):
    if isinstance(form_config, str):
        try:
            form_config = json.loads(form_config)
        except (TypeError, ValueError):
            return {}
    if not isinstance(form_config, list):
        return {}

    fields = {}
    for field in form_config:
        if not isinstance(field, dict) or field.get('type') != 'file':
            continue
        name = field.get('name')
        if not isinstance(name, str) or not name.strip():
            raise UploadValidationError('Unexpected file field.')
        submitted_name = _submitted_field_name(name)
        if submitted_name in fields:
            raise UploadValidationError('Unexpected file field.')
        fields[submitted_name] = _field_rules(field)
    return fields


def _validate_image(upload):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(upload) as image:
                image.verify()
                if image.width * image.height > settings.DYNAMIC_UPLOAD_MAX_IMAGE_PIXELS:
                    raise UploadValidationError('Unsupported file type.')
    except UploadValidationError:
        raise
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        OSError,
        UnidentifiedImageError,
    ):
        raise UploadValidationError('Unsupported file type.')
    finally:
        upload.seek(0)


def validate_dynamic_uploads(form_config, uploaded_files):
    """Validate every upload before any submission or file record is saved."""
    field_rules = _file_fields(form_config)
    validated_uploads = []

    for field_name in uploaded_files:
        rules = field_rules.get(field_name)
        if rules is None:
            raise UploadValidationError('Unexpected file field.')
        files = uploaded_files.getlist(field_name)
        if len(files) > rules.max_file_count:
            raise UploadValidationError('Too many files were uploaded.')
        for upload in files:
            validated_uploads.append((field_name, upload, rules))

    if len(validated_uploads) > settings.DYNAMIC_UPLOAD_MAX_FILE_COUNT:
        raise UploadValidationError('Too many files were uploaded.')
    if sum(upload.size for _, upload, _ in validated_uploads) > settings.DYNAMIC_UPLOAD_MAX_TOTAL_SIZE:
        raise UploadValidationError('Total upload size exceeds the allowed limit.')

    for _, upload, rules in validated_uploads:
        extension = Path(upload.name).suffix.lower()
        if extension not in rules.allowed_extensions:
            raise UploadValidationError('Unsupported file type.')
        if upload.size > rules.max_file_size:
            raise UploadValidationError('File exceeds allowed size.')
        if extension in _IMAGE_EXTENSIONS:
            _validate_image(upload)

    return [(field_name, upload) for field_name, upload, _ in validated_uploads]
