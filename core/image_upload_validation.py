"""Reusable validation for small, trusted-admin branding image uploads."""

from pathlib import Path
import warnings

from django.core.exceptions import ValidationError
from PIL import Image, UnidentifiedImageError


MAX_BRANDING_IMAGE_BYTES = 5 * 1024 * 1024
MAX_BRANDING_IMAGE_PIXELS = 20_000_000
IMAGE_EXTENSIONS = frozenset({'.jpg', '.jpeg', '.png', '.gif', '.webp'})
FAVICON_EXTENSIONS = IMAGE_EXTENSIONS | {'.ico'}
IMAGE_FORMATS = frozenset({'JPEG', 'PNG', 'GIF', 'WEBP'})
FAVICON_FORMATS = IMAGE_FORMATS | {'ICO'}


def validate_branding_image(upload, *, favicon=False):
    """Validate a small raster branding asset and restore its stream position."""
    if not upload:
        return upload

    allowed_extensions = FAVICON_EXTENSIONS if favicon else IMAGE_EXTENSIONS
    allowed_formats = FAVICON_FORMATS if favicon else IMAGE_FORMATS
    extension = Path(upload.name).suffix.lower()
    if extension not in allowed_extensions:
        raise ValidationError('Upload a JPG, PNG, GIF, or WebP image' + (' or ICO favicon.' if favicon else '.'))
    if upload.size > MAX_BRANDING_IMAGE_BYTES:
        raise ValidationError('Image files must be 5 MB or smaller.')

    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(upload) as image:
                image.load()
                if image.format not in allowed_formats or image.width * image.height > MAX_BRANDING_IMAGE_PIXELS:
                    raise ValidationError('Upload a supported raster image.')
    except ValidationError:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning, OSError, UnidentifiedImageError):
        raise ValidationError('Upload a valid supported raster image.') from None
    finally:
        upload.seek(0)
    return upload
