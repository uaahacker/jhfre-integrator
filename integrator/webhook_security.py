"""Contained outbound transport helpers for dynamic-form webhooks."""

from dataclasses import dataclass
import ipaddress
import os
import socket
from urllib.parse import urlsplit

import requests

from .webhook_headers import WebhookHeaderError, prepare_webhook_headers_for_runtime


DEFAULT_CONNECT_TIMEOUT = 5
DEFAULT_READ_TIMEOUT = 10
MAX_CONNECT_TIMEOUT = 30
MAX_READ_TIMEOUT = 60
_UNSAFE_HEADER_NAMES = frozenset({
    'host', 'content-length', 'transfer-encoding', 'connection', 'proxy-authorization',
})


class WebhookSecurityError(ValueError):
    """A redacted URL or DNS policy failure."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


class WebhookDeliveryError(RuntimeError):
    """A redacted outbound delivery failure."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class WebhookTransportSettings:
    connect_timeout: int
    read_timeout: int


def _bounded_positive_environment_value(environ, name, default, maximum):
    raw_value = environ.get(name)
    if raw_value is None:
        return default
    value = str(raw_value).strip()
    if not value.isdecimal():
        return default
    parsed = int(value)
    if not 0 < parsed <= maximum:
        return default
    return parsed


def get_webhook_transport_settings(environ=None):
    environment = os.environ if environ is None else environ
    return WebhookTransportSettings(
        connect_timeout=_bounded_positive_environment_value(
            environment, 'WEBHOOK_CONNECT_TIMEOUT', DEFAULT_CONNECT_TIMEOUT, MAX_CONNECT_TIMEOUT,
        ),
        read_timeout=_bounded_positive_environment_value(
            environment, 'WEBHOOK_READ_TIMEOUT', DEFAULT_READ_TIMEOUT, MAX_READ_TIMEOUT,
        ),
    )


def _is_prohibited_address(address):
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return not address.ipv4_mapped.is_global
    return not address.is_global


def _resolve_host(hostname, port):
    try:
        results = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise WebhookSecurityError('WEBHOOK_DNS_FAILED') from exc
    addresses = set()
    for result in results:
        try:
            addresses.add(ipaddress.ip_address(result[4][0]))
        except (IndexError, ValueError):
            raise WebhookSecurityError('WEBHOOK_DNS_FAILED')
    if not addresses:
        raise WebhookSecurityError('WEBHOOK_DNS_FAILED')
    if any(_is_prohibited_address(address) for address in addresses):
        raise WebhookSecurityError('WEBHOOK_URL_BLOCKED')


def validate_webhook_url(url):
    """Validate syntax and every current DNS answer without contacting the URL."""
    if url is None or not str(url).strip():
        return ''
    if not isinstance(url, str):
        raise WebhookSecurityError('WEBHOOK_URL_BLOCKED')
    try:
        parsed = urlsplit(url)
        port = parsed.port or 443
    except ValueError as exc:
        raise WebhookSecurityError('WEBHOOK_URL_BLOCKED') from exc
    hostname = parsed.hostname
    if (
        parsed.scheme.lower() != 'https'
        or not parsed.netloc
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise WebhookSecurityError('WEBHOOK_URL_BLOCKED')
    hostname = hostname.rstrip('.').lower()
    if hostname in {'localhost', 'localhost.localdomain'} or hostname.endswith(('.localhost', '.local')):
        raise WebhookSecurityError('WEBHOOK_URL_BLOCKED')
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        _resolve_host(hostname, port)
    else:
        if _is_prohibited_address(address):
            raise WebhookSecurityError('WEBHOOK_URL_BLOCKED')
    return url


def validate_webhook_headers(headers):
    """Reject configured headers that can change HTTP transport semantics."""
    if headers is None:
        return {}
    if not isinstance(headers, dict):
        raise WebhookSecurityError('WEBHOOK_HEADERS_BLOCKED')
    for name in headers:
        if not isinstance(name, str) or name.lower() in _UNSAFE_HEADER_NAMES:
            raise WebhookSecurityError('WEBHOOK_HEADERS_BLOCKED')
    return headers.copy()


def runtime_webhook_headers(headers):
    """Defensively remove unsafe legacy header rows before delivery."""
    if not isinstance(headers, dict):
        return {}
    return {
        name: value for name, value in headers.items()
        if isinstance(name, str) and name.lower() not in _UNSAFE_HEADER_NAMES | {'content-type'}
    }


def deliver_webhook(url, *, data, files, headers, transport_settings=None):
    """Deliver once without redirects, proxies, or response-body retention."""
    validate_webhook_url(url)
    settings = transport_settings or get_webhook_transport_settings()
    session = requests.Session()
    session.trust_env = False
    response = None
    try:
        runtime_headers = prepare_webhook_headers_for_runtime(headers)
        response = session.post(
            url,
            data=data,
            files=files,
            headers=runtime_webhook_headers(runtime_headers),
            timeout=(settings.connect_timeout, settings.read_timeout),
            allow_redirects=False,
            stream=True,
            verify=True,
        )
        # The response is streamed so it is never decoded, logged, or retained.
        # Closing it below releases the connection without consuming its body.
        from .webhook_responses import build_webhook_response_metadata
        return build_webhook_response_metadata(status_code=response.status_code)
    except requests.Timeout as exc:
        raise WebhookDeliveryError('WEBHOOK_TIMEOUT') from exc
    except requests.RequestException as exc:
        raise WebhookDeliveryError('WEBHOOK_DELIVERY_FAILED') from exc
    except WebhookHeaderError as exc:
        raise WebhookDeliveryError('WEBHOOK_HEADER_CONFIGURATION_FAILED') from exc
    finally:
        if response is not None:
            response.close()
        session.close()
