"""Small configuration helpers used by project settings."""

import os
from pathlib import Path

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}
_PLACEHOLDER_VALUES = {"change_me", "changeme", "replace_me"}


class ConfigurationError(ValueError):
    """Raised when a required environment configuration value is invalid."""


def parse_bool(value: str | None, *, default: bool, name: str) -> bool:
    """Parse an explicit boolean environment value."""
    if value is None or not value.strip():
        return default
    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ConfigurationError(
        f"{name} must be one of: true, false, 1, 0, yes, no, on, or off."
    )


def require_secret(name: str) -> str:
    """Read a required secret without accepting documentation placeholders."""
    value = os.environ.get(name, "").strip()
    if not value or value.lower() in _PLACEHOLDER_VALUES:
        raise ConfigurationError(
            f"{name} must be supplied through the environment with a real secret value."
        )
    return value


_VALID_SAMESITE_VALUES = {"Lax", "Strict", "None"}


def parse_samesite(value: str | None, *, default: str, name: str) -> str:
    """Parse a cookie SameSite value, restricted to Django's three accepted values."""
    if value is None or not value.strip():
        return default
    normalized = value.strip()
    if normalized not in _VALID_SAMESITE_VALUES:
        raise ConfigurationError(
            f"{name} must be one of: Lax, Strict, or None."
        )
    return normalized


def parse_allowed_hosts(value: str | None) -> list[str]:
    """Parse comma-separated hostnames/IPs and reject URLs or wildcards."""
    if not value or not value.strip():
        return []
    hosts = []
    for item in value.split(","):
        host = item.strip()
        if not host:
            continue
        if host == "*" or "://" in host or "/" in host:
            raise ConfigurationError(
                "DJANGO_ALLOWED_HOSTS must contain only comma-separated hostnames or IPs."
            )
        hosts.append(host)
    return hosts


def parse_csrf_trusted_origins(value: str | None) -> list[str]:
    """Parse comma-separated CSRF trusted origins as full scheme://host[:port] values."""
    if not value or not value.strip():
        return []
    origins = []
    for item in value.split(","):
        origin = item.strip()
        if not origin:
            continue
        scheme, sep, rest = origin.partition("://")
        if not sep or scheme not in ("http", "https") or not rest or "/" in rest or "*" in origin:
            raise ConfigurationError(
                "DJANGO_CSRF_TRUSTED_ORIGINS must contain comma-separated http(s) origins "
                "without a path, e.g. https://host or https://host:port."
            )
        origins.append(origin)
    return origins


def read_optional_file_from_env(name: str) -> str:
    """Read UTF-8 key/certificate material from a configured external path."""
    configured_path = os.environ.get(name, "").strip()
    if not configured_path:
        return ""
    try:
        return Path(configured_path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"{name} could not be read from its configured path.") from exc
