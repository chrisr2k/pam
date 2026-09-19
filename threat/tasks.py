"""Celery task that scans the audit stream with the detection rules."""

import logging
from datetime import timedelta

from celery import shared_task
from django.db import transaction
from django.utils import timezone

from audit.middleware import log_action
from audit.models import AuditLog
from .models import ThreatAlert, ThreatConfig
from .rules import RULES

logger = logging.getLogger(__name__)

MAX_ALERTS_PER_SCAN = 50


@shared_task
def scan_threats():
    """Evaluate all enabled rules over the audit window; create alerts."""
    created = []
    with transaction.atomic():
        # get_or_create: the row may not exist until someone opens the
        # settings page; the task must not crash on a fresh deployment.
        config, _ = ThreatConfig.objects.select_for_update().get_or_create(pk=1)
        now = timezone.now()
        if not config.scan_enabled:
            config.last_run_at = now
            config.save(update_fields=['last_run_at'])
            return

        for name, rule in RULES.items():
            if not config.enabled_for(name):
                continue
            # Window is at least the cooldown so events between ticks are
            # never missed (cooldown suppresses duplicates, not first sees).
            window = max(config.window_for(name), config.cooldown_minutes)
            since = now - timedelta(minutes=window)
            for finding in rule.evaluate(config, now, since):
                if len(created) >= MAX_ALERTS_PER_SCAN:
                    logger.warning(
                        'Threat scan alert cap (%s) reached; suppressing further alerts this run',
                        MAX_ALERTS_PER_SCAN)
                    break
                if ThreatAlert.objects.filter(
                        rule=name, dedup_key=finding.dedup_key,
                        created_at__gte=now - timedelta(minutes=config.cooldown_minutes),
                ).exists():
                    continue  # cooldown: suppress the whole artifact
                alert = ThreatAlert.objects.create(
                    rule=name,
                    severity=rule.severity,
                    summary=finding.summary,
                    details=finding.details,
                    dedup_key=finding.dedup_key,
                    related_audit_ids=finding.related_audit_ids,
                )
                log_action(
                    actor=None,
                    action=AuditLog.Action.ALERT_RAISED,
                    target_type='ThreatAlert',
                    target_id=alert.pk,
                    details={
                        'rule': name,
                        'severity': rule.severity,
                        'summary': alert.summary,
                        'dedup_key': finding.dedup_key,
                    },
                )
                created.append(alert)

        config.last_run_at = now
        config.save(update_fields=['last_run_at'])

    # Network I/O after the lock is released
    if created:
        from notifications.services import send_alert_notification
        for alert in created:
            try:
                send_alert_notification(alert)
            except Exception:
                logger.exception('Threat alert notification failed for alert %s', alert.pk)
