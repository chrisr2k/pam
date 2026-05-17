"""Notification service for sending alerts via Email, Slack, and Teams."""

import json
import logging
import smtplib
from email.mime.text import MIMEText
from urllib.request import Request, urlopen
from urllib.error import URLError

from django.urls import reverse
from django.utils import timezone

from .models import NotificationConfig

logger = logging.getLogger(__name__)


def _build_request_url(request_obj):
    """Build an absolute URL to the request detail page.

    Uses PAM_BASE_URL from settings. If not set, falls back to
    EXTERNAL_URL env var, then to a localhost default for development.
    """
    from django.conf import settings
    import os
    try:
        path = reverse('requests:detail', kwargs={'pk': request_obj.pk})
        # Try PAM_BASE_URL first, then EXTERNAL_URL, then localhost default
        base_url = (
            getattr(settings, 'PAM_BASE_URL', '')
            or os.getenv('EXTERNAL_URL', '')
            or 'http://localhost:8080'
        )
        return f'{base_url.rstrip("/")}{path}'
    except Exception:
        return f'http://localhost:8080/requests/{request_obj.pk}/'


def _format_datetime(dt):
    """Format a datetime for display in notifications."""
    if not dt:
        return 'N/A'
    return dt.strftime('%Y-%m-%d %H:%M UTC')


def _build_notification_payload(request_obj, event_type, extra_context=None):
    """Build a common context dict for all notification channels."""
    context = {
        'request_id': request_obj.id,
        'requester': request_obj.requester.get_full_name() or request_obj.requester.username,
        'requester_email': request_obj.requester.email,
        'role_name': request_obj.role.name,
        'role_provider': request_obj.role.provider,
        'justification': request_obj.justification,
        'duration_minutes': request_obj.requested_duration_minutes,
        'status': request_obj.status,
        'created_at': _format_datetime(request_obj.created_at),
        'approved_at': _format_datetime(request_obj.approved_at),
        'expires_at': _format_datetime(request_obj.expires_at),
        'request_url': _build_request_url(request_obj),
        'event_type': event_type,
    }
    if extra_context:
        context.update(extra_context)
    return context


# ─── Email ───────────────────────────────────────────────────────────────────


def _send_email(config, subject, body_html, recipients):
    """Send an email via SMTP."""
    if not config.email_enabled or not config.smtp_host:
        logger.debug('Email notifications are not configured.')
        return False

    msg = MIMEText(body_html, 'html')
    msg['Subject'] = subject
    msg['From'] = config.email_from or config.smtp_username
    msg['To'] = ', '.join(recipients)

    try:
        if config.smtp_use_tls:
            server = smtplib.SMTP(config.smtp_host, config.smtp_port)
            server.starttls()
        else:
            server = smtplib.SMTP(config.smtp_host, config.smtp_port)

        if config.smtp_username and config.smtp_password:
            server.login(config.smtp_username, config.smtp_password)

        server.send_message(msg)
        server.quit()
        logger.info(f'Email notification sent to {recipients}: {subject}')
        return True
    except Exception as e:
        logger.error(f'Failed to send email notification: {e}')
        return False


def _email_subject_and_body(payload):
    """Generate email subject and HTML body from a notification payload."""
    event = payload['event_type']
    role = payload['role_name']
    requester = payload['requester']

    subjects = {
        'request_created': f'[PAM] New Access Request #{payload["request_id"]} - {role}',
        'request_approved': f'[PAM] Request #{payload["request_id"]} Approved - {role}',
        'request_denied': f'[PAM] Request #{payload["request_id"]} Denied - {role}',
        'access_provisioned': f'[PAM] Access Provisioned - {role} for {requester}',
        'access_expiring': f'[PAM] Access Expiring Soon - {role} for {requester}',
    }
    subject = subjects.get(event, f'[PAM] Notification - Request #{payload["request_id"]}')

    body = f"""
    <html><body style="font-family: Arial, sans-serif; max-width: 600px;">
    <h2 style="color: #0d6efd;">Privileged Access Manager</h2>
    <hr>
    <h3>{subject}</h3>
    <table style="border-collapse: collapse; width: 100%;">
        <tr><td style="padding: 8px; font-weight: bold;">Requester:</td><td>{requester} ({payload['requester_email']})</td></tr>
        <tr><td style="padding: 8px; font-weight: bold;">Role:</td><td>{role}</td></tr>
        <tr><td style="padding: 8px; font-weight: bold;">Provider:</td><td>{payload['role_provider']}</td></tr>
        <tr><td style="padding: 8px; font-weight: bold;">Duration:</td><td>{payload['duration_minutes']} minutes</td></tr>
        <tr><td style="padding: 8px; font-weight: bold;">Justification:</td><td>{payload['justification']}</td></tr>
        <tr><td style="padding: 8px; font-weight: bold;">Status:</td><td>{payload['status']}</td></tr>
        <tr><td style="padding: 8px; font-weight: bold;">Created:</td><td>{payload['created_at']}</td></tr>
    </table>
    <p><a href="{payload['request_url']}" style="display: inline-block; padding: 10px 20px; background: #0d6efd; color: white; text-decoration: none; border-radius: 4px;">View Request</a></p>
    <hr>
    <p style="color: #6c757d; font-size: 12px;">This is an automated notification from PAM.</p>
    </body></html>
    """
    return subject, body


# ─── Slack ───────────────────────────────────────────────────────────────────


def _send_slack(config, payload):
    """Send a notification to a Slack webhook."""
    if not config.slack_enabled or not config.slack_webhook_url:
        logger.debug('Slack notifications are not configured.')
        return False

    event = payload['event_type']
    role = payload['role_name']
    requester = payload['requester']

    colors = {
        'request_created': '#0d6efd',
        'request_approved': '#198754',
        'request_denied': '#dc3545',
        'access_provisioned': '#198754',
        'access_expiring': '#ffc107',
    }
    color = colors.get(event, '#6c757d')

    blocks = [
        {
            'type': 'header',
            'text': {'type': 'plain_text', 'text': f'🔐 PAM Notification - {event.replace("_", " ").title()}'},
        },
        {'type': 'divider'},
        {
            'type': 'section',
            'fields': [
                {'type': 'mrkdwn', 'text': f'*Requester:*\n{requester}'},
                {'type': 'mrkdwn', 'text': f'*Role:*\n{role}'},
                {'type': 'mrkdwn', 'text': f'*Provider:*\n{payload["role_provider"]}'},
                {'type': 'mrkdwn', 'text': f'*Duration:*\n{payload["duration_minutes"]} min'},
                {'type': 'mrkdwn', 'text': f'*Status:*\n{payload["status"]}'},
                {'type': 'mrkdwn', 'text': f'*Created:*\n{payload["created_at"]}'},
            ],
        },
        {
            'type': 'section',
            'text': {'type': 'mrkdwn', 'text': f'*Justification:*\n{payload["justification"]}'},
        },
        {
            'type': 'actions',
            'elements': [
                {
                    'type': 'button',
                    'text': {'type': 'plain_text', 'text': 'View Request'},
                    'url': payload['request_url'],
                    'style': 'primary',
                },
            ],
        },
    ]

    slack_payload = {
        'text': f'PAM: {event.replace("_", " ").title()} - {role} for {requester}',
        'attachments': [{'color': color, 'blocks': blocks}],
    }

    if config.slack_channel:
        slack_payload['channel'] = config.slack_channel

    return _post_webhook(config.slack_webhook_url, slack_payload)


# ─── Microsoft Teams ─────────────────────────────────────────────────────────


def _send_teams(config, payload):
    """Send a notification to a Teams webhook (via Adaptive Card)."""
    if not config.teams_enabled or not config.teams_webhook_url:
        logger.debug('Teams notifications are not configured.')
        return False

    event = payload['event_type']
    role = payload['role_name']
    requester = payload['requester']

    facts = [
        {'title': 'Requester', 'value': f'{requester} ({payload["requester_email"]})'},
        {'title': 'Role', 'value': role},
        {'title': 'Provider', 'value': payload['role_provider']},
        {'title': 'Duration', 'value': f'{payload["duration_minutes"]} minutes'},
        {'title': 'Justification', 'value': payload['justification']},
        {'title': 'Status', 'value': payload['status']},
        {'title': 'Created', 'value': payload['created_at']},
    ]

    card = {
        '@type': 'MessageCard',
        '@context': 'https://schema.org/extensions',
        'summary': f'PAM: {event.replace("_", " ").title()} - {role}',
        'themeColor': '0d6efd',
        'title': f'🔐 PAM Notification - {event.replace("_", " ").title()}',
        'sections': [
            {
                'activityTitle': f'Request #{payload["request_id"]} - {role}',
                'facts': facts,
                'markdown': True,
            },
            {
                'potentialAction': [
                    {
                        '@type': 'OpenUri',
                        'name': 'View Request',
                        'targets': [{'os': 'default', 'uri': payload['request_url']}],
                    },
                ],
            },
        ],
    }

    return _post_webhook(config.teams_webhook_url, card)


# ─── Webhook Helper ──────────────────────────────────────────────────────────


def _post_webhook(url, payload):
    """POST a JSON payload to a webhook URL."""
    try:
        data = json.dumps(payload).encode('utf-8')
        req = Request(url, data=data, headers={'Content-Type': 'application/json'}, method='POST')
        with urlopen(req, timeout=10) as resp:
            logger.info(f'Webhook notification sent to {url[:50]}... (status {resp.status})')
            return True
    except URLError as e:
        logger.error(f'Webhook request failed to {url[:50]}...: {e}')
        return False
    except Exception as e:
        logger.error(f'Unexpected error sending webhook: {e}')
        return False


# ─── Public API ──────────────────────────────────────────────────────────────


def send_notification(request_obj, event_type, extra_context=None, recipients=None):
    """Send a notification across all enabled channels.

    Args:
        request_obj: The AccessRequest instance.
        event_type: One of 'request_created', 'request_approved', 'request_denied',
                    'access_provisioned', 'access_expiring'.
        extra_context: Optional dict of additional context.
        recipients: Optional list of email addresses (for email channel).
    """
    config = NotificationConfig.get_config()
    if not config.is_any_enabled():
        logger.debug('No notification channels are enabled. Skipping.')
        return

    payload = _build_notification_payload(request_obj, event_type, extra_context)

    # Check event-specific toggle
    event_flags = {
        'request_created': config.notify_on_request_created,
        'request_approved': config.notify_on_request_approved,
        'request_denied': config.notify_on_request_denied,
        'access_provisioned': config.notify_on_access_provisioned,
        'access_expiring': config.notify_on_access_expiring,
    }

    if not event_flags.get(event_type, True):
        logger.debug(f'Event type "{event_type}" is disabled in notification config.')
        return

    # Send via Email
    if config.email_enabled:
        subject, body = _email_subject_and_body(payload)
        email_recipients = recipients or [payload['requester_email']]
        _send_email(config, subject, body, email_recipients)

    # Send via Slack
    if config.slack_enabled:
        _send_slack(config, payload)

    # Send via Teams
    if config.teams_enabled:
        _send_teams(config, payload)
