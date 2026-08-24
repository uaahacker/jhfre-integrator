"""Safe, bounded metadata for dynamic-form webhook deliveries."""


WEBHOOK_DELIVERED = 'WEBHOOK_DELIVERED'
WEBHOOK_REDIRECT_NOT_FOLLOWED = 'WEBHOOK_REDIRECT_NOT_FOLLOWED'
WEBHOOK_FAILURE_STATUSES = frozenset({
    'WEBHOOK_URL_BLOCKED',
    'WEBHOOK_DNS_FAILED',
    'WEBHOOK_TIMEOUT',
    'WEBHOOK_DELIVERY_FAILED',
    'WEBHOOK_HEADER_CONFIGURATION_FAILED',
})
SAFE_WEBHOOK_STATUSES = WEBHOOK_FAILURE_STATUSES | {
    WEBHOOK_DELIVERED,
    WEBHOOK_REDIRECT_NOT_FOLLOWED,
}


def _valid_status_code(value):
    return isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599


def _status_for_http_response(status_code):
    if 300 <= status_code < 400:
        return WEBHOOK_REDIRECT_NOT_FOLLOWED
    return WEBHOOK_DELIVERED


def build_webhook_response_metadata(*, status_code=None, status=None):
    """Construct the only response shape written for a new webhook delivery."""
    if _valid_status_code(status_code):
        resolved_status = status if status in SAFE_WEBHOOK_STATUSES else _status_for_http_response(status_code)
        return {'status': resolved_status, 'status_code': status_code}
    if status in SAFE_WEBHOOK_STATUSES:
        return {'status': status}
    raise ValueError('Webhook delivery metadata requires a recognized status or HTTP status code.')


def safe_webhook_response_metadata(response):
    """Return display-safe metadata from either a legacy or current response row.

    Unknown fields, including historical response bodies, headers, URLs, and exception
    details, are deliberately ignored.  This does not mutate the stored row.
    """
    if not isinstance(response, dict):
        return {}

    status_code = response.get('status_code')
    status = response.get('status')
    try:
        metadata = build_webhook_response_metadata(status_code=status_code, status=status)
    except ValueError:
        return {}

    if isinstance(response.get('truncated'), bool):
        metadata['truncated'] = response['truncated']
    return metadata
