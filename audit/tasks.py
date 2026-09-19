"""Celery task for exporting audit events to a SIEM via HTTPS webhook.

The forwarder drains AuditLog rows above SIEMConfig.watermark in id order,
capped at 200 per run. Delivery is at-least-once: on any failure the
watermark is not advanced and the same batch is retried on the next beat
tick. select_for_update serializes concurrent workers.
"""

import json
import logging
import socket
from urllib.error import URLError
from urllib.request import Request, urlopen

from celery import shared_task
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import AuditLog, SIEMConfig

logger = logging.getLogger(__name__)

BATCH_LIMIT = 200


def _serialize_event(entry):
    """Serialize an AuditLog row into the SIEM event dict."""
    return {
        'id': entry.pk,
        'action': entry.action,
        'actor': entry.actor.username if entry.actor else None,
        'actor_email': entry.actor.email if entry.actor else None,
        'target_type': entry.target_type,
        'target_id': entry.target_id,
        'details': entry.details,
        'ip_address': entry.ip_address,
        'timestamp': entry.timestamp.isoformat(),
    }


def _build_http_payload(config, event):
    """Shape the HTTP body for the configured payload mode."""
    if config.payload_mode == SIEMConfig.PayloadMode.SPLUNK_HEC:
        return {
            'event': event,
            'sourcetype': 'pam:audit',
            'source': 'pam',
            'host': settings.PAM_BASE_URL or socket.gethostname(),
        }
    if config.payload_mode == SIEMConfig.PayloadMode.SENTINEL:
        return [event]
    return event


def _post(config, payload):
    """POST the payload to the configured webhook. Returns True on 2xx."""
    try:
        data = json.dumps(payload).encode('utf-8')
        headers = {'Content-Type': 'application/json'}
        token = config.get_effective_token()
        if token:
            headers[config.token_header] = f'{config.token_prefix}{token}'
        req = Request(config.webhook_url, data=data, headers=headers, method='POST')
        with urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        logger.error('SIEM forward failed: %s', e)
        return False


@shared_task
def forward_audit_events():
    """Drain unsent AuditLog rows to the SIEM webhook."""
    with transaction.atomic():
        # get_or_create: the row may not exist until someone opens the
        # SIEM settings page; the task must not crash on a fresh deployment.
        config, _ = SIEMConfig.objects.select_for_update().get_or_create(pk=1)
        if not (config.enabled and config.webhook_url):
            return

        actions = [a.strip().upper() for a in config.action_filter.split(',') if a.strip()]
        qs = AuditLog.objects.filter(id__gt=config.watermark).order_by('id')
        if actions:
            qs = qs.filter(action__in=actions)

        watermark_advanced = False
        for entry in qs[:BATCH_LIMIT]:
            event = _serialize_event(entry)
            payload = _build_http_payload(config, event)
            if not _post(config, payload):
                config.last_error = f'Failed to forward AuditLog id={entry.pk}'
                config.last_error_at = timezone.now()
                config.last_run_at = timezone.now()
                config.save(update_fields=['last_error', 'last_error_at', 'last_run_at'])
                # Stop: watermark NOT advanced, batch retried next tick
                return
            config.watermark = entry.pk
            watermark_advanced = True

        config.last_run_at = timezone.now()
        update_fields = ['last_run_at']
        if watermark_advanced:
            config.last_success_at = timezone.now()
            config.last_error = ''
            config.last_error_at = None
            update_fields += ['watermark', 'last_success_at', 'last_error', 'last_error_at']
        config.save(update_fields=update_fields)
