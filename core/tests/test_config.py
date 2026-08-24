import os
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import ValidationError
from PIL import Image

from core.config import (
    ConfigurationError,
    parse_allowed_hosts,
    parse_bool,
    parse_csrf_trusted_origins,
    parse_samesite,
    read_optional_file_from_env,
    require_secret,
)
from core.image_upload_validation import (
    MAX_BRANDING_IMAGE_BYTES,
    validate_branding_image,
)


class ConfigurationHelperTests(unittest.TestCase):
    def test_parse_bool_accepts_explicit_true_and_false(self):
        self.assertTrue(parse_bool("true", default=False, name="TEST_BOOL"))
        self.assertFalse(parse_bool("False", default=True, name="TEST_BOOL"))

    def test_parse_bool_rejects_ambiguous_values(self):
        with self.assertRaises(ConfigurationError):
            parse_bool("sometimes", default=False, name="TEST_BOOL")

    def test_allowed_hosts_are_comma_separated_hostnames_only(self):
        self.assertEqual(
            parse_allowed_hosts("localhost, 127.0.0.1, app.example.test"),
            ["localhost", "127.0.0.1", "app.example.test"],
        )
        with self.assertRaises(ConfigurationError):
            parse_allowed_hosts("https://app.example.test, *")

    def test_required_secret_does_not_accept_missing_or_placeholder_values(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ConfigurationError):
                require_secret("TEST_SECRET")
        with patch.dict(os.environ, {"TEST_SECRET": "CHANGE_ME"}, clear=True):
            with self.assertRaises(ConfigurationError):
                require_secret("TEST_SECRET")

    def test_required_secret_returns_supplied_value(self):
        with patch.dict(os.environ, {"TEST_SECRET": "test-value"}, clear=True):
            self.assertEqual(require_secret("TEST_SECRET"), "test-value")

    def test_csrf_trusted_origins_are_comma_separated_full_origins_only(self):
        self.assertEqual(
            parse_csrf_trusted_origins("https://app.example.test, http://other.example.test:8443"),
            ["https://app.example.test", "http://other.example.test:8443"],
        )
        self.assertEqual(parse_csrf_trusted_origins(None), [])
        self.assertEqual(parse_csrf_trusted_origins(""), [])

    def test_csrf_trusted_origins_reject_bare_hosts_paths_and_wildcards(self):
        for value in ("app.example.test", "https://app.example.test/", "https://*.example.test", "ftp://app.example.test"):
            with self.subTest(value=value):
                with self.assertRaises(ConfigurationError):
                    parse_csrf_trusted_origins(value)

    def test_parse_samesite_accepts_only_the_three_valid_values(self):
        self.assertEqual(parse_samesite("Lax", default="Lax", name="TEST_SAMESITE"), "Lax")
        self.assertEqual(parse_samesite("Strict", default="Lax", name="TEST_SAMESITE"), "Strict")
        self.assertEqual(parse_samesite("None", default="Lax", name="TEST_SAMESITE"), "None")

    def test_parse_samesite_uses_default_when_unset(self):
        self.assertEqual(parse_samesite(None, default="Lax", name="TEST_SAMESITE"), "Lax")
        self.assertEqual(parse_samesite("", default="Lax", name="TEST_SAMESITE"), "Lax")
        self.assertEqual(parse_samesite("   ", default="Lax", name="TEST_SAMESITE"), "Lax")

    def test_parse_samesite_rejects_invalid_or_wrong_case_values(self):
        for value in ("lax", "LAX", "none", "invalid", "Lax;None"):
            with self.subTest(value=value):
                with self.assertRaises(ConfigurationError):
                    parse_samesite(value, default="Lax", name="TEST_SAMESITE")

    def test_optional_file_material_requires_an_explicit_readable_path(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(read_optional_file_from_env("TEST_KEY_PATH"), "")
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "key.pem"
            path.write_text("test key material", encoding="utf-8")
            with patch.dict(os.environ, {"TEST_KEY_PATH": str(path)}, clear=True):
                self.assertEqual(read_optional_file_from_env("TEST_KEY_PATH"), "test key material")
        with patch.dict(os.environ, {"TEST_KEY_PATH": "does-not-exist"}, clear=True):
            with self.assertRaises(ConfigurationError):
                read_optional_file_from_env("TEST_KEY_PATH")


class BrandingImageValidationTests(unittest.TestCase):
    def image_upload(self, name, image_format='PNG'):
        buffer = BytesIO()
        size = (32, 32) if image_format == 'ICO' else (2, 2)
        Image.new('RGB', size, color='blue').save(buffer, format=image_format)
        return SimpleUploadedFile(name, buffer.getvalue(), content_type='image/png')

    def test_valid_raster_images_and_ico_favicons_are_accepted(self):
        self.assertIsNotNone(validate_branding_image(self.image_upload('logo.png')))
        self.assertIsNotNone(
            validate_branding_image(self.image_upload('favicon.ico', 'ICO'), favicon=True)
        )

    def test_invalid_extension_content_and_size_are_rejected(self):
        with self.assertRaisesRegex(ValidationError, 'JPG, PNG, GIF, or WebP'):
            validate_branding_image(self.image_upload('logo.svg'))
        with self.assertRaisesRegex(ValidationError, 'valid supported raster image'):
            validate_branding_image(SimpleUploadedFile('logo.png', b'not-an-image'))
        with self.assertRaisesRegex(ValidationError, '5 MB or smaller'):
            validate_branding_image(
                SimpleUploadedFile('logo.png', b'x' * (MAX_BRANDING_IMAGE_BYTES + 1))
            )
