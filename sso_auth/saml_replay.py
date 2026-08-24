"""Database-backed one-time-use protection for validated SAML assertion IDs."""

import hashlib
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.utils import timezone

from .models import SAMLReplayRecord


SAML_REPLAY_RETENTION = timedelta(hours=8)


def register_validated_assertion(provider, assertion_id):
    """Atomically register a validated assertion ID; return False for a replay."""
    if not isinstance(assertion_id, str) or not assertion_id.strip():
        raise ValueError('Validated SAML assertion has no usable identifier.')
    assertion_id_hash = hashlib.sha256(assertion_id.encode()).hexdigest()
    now = timezone.now()
    try:
        with transaction.atomic():
            SAMLReplayRecord.objects.filter(expires_at__lt=now).delete()
            SAMLReplayRecord.objects.create(
                provider=provider,
                assertion_id_hash=assertion_id_hash,
                expires_at=now + SAML_REPLAY_RETENTION,
            )
    except IntegrityError:
        return False
    return True
