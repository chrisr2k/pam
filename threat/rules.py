"""Threat detection rules.

Each rule is a read-only evaluation over AuditLog rows; the scan task
(threat/tasks.py) owns all writes. Evaluations are keyed to the current
ThreatConfig, so thresholds and windows are operator-tunable.
"""

import ipaddress
from dataclasses import dataclass, field

from django.utils import timezone

from audit.models import AuditLog
from .models import ThreatAlert


@dataclass
class Finding:
    dedup_key: str
    summary: str
    details: dict = field(default_factory=dict)
    related_audit_ids: list = field(default_factory=list)


class BaseThreatRule:
    name = ''
    label = ''
    severity = ThreatAlert.Severity.WARNING

    def evaluate(self, config, now, since):
        raise NotImplementedError


def _network_key(ip_str):
    """Group IPs into coarse networks: IPv4 /16, IPv6 /64."""
    ip = ipaddress.ip_address(str(ip_str))
    if ip.version == 4:
        return str(ipaddress.ip_network(f'{ip}/16', strict=False))
    return str(ipaddress.ip_network(f'{ip}/64', strict=False))


def _parse_hhmm(value):
    try:
        hour, minute = str(value).split(':')
        return int(hour), int(minute)
    except (ValueError, AttributeError):
        return 0, 0


class ImpossibleTravelRule(BaseThreatRule):
    """Logins from multiple distinct IP networks in a short window.

    Geo-free heuristic: at least `min_distinct_ips` distinct IPs with at
    least two falling in different /16 (IPv4) or /64 (IPv6) networks.
    Corporate NATs cause false negatives; VPN travel causes false positives.
    """

    name = 'impossible_travel'
    label = 'Impossible Travel'
    severity = ThreatAlert.Severity.WARNING

    def evaluate(self, config, now, since):
        rows = AuditLog.objects.filter(
            action=AuditLog.Action.LOGIN,
            actor__isnull=False,
            ip_address__isnull=False,
            timestamp__gte=since,
            timestamp__lte=now,
        ).values('id', 'actor_id', 'actor__username', 'ip_address').order_by('timestamp')

        by_actor = {}
        for row in rows:
            by_actor.setdefault(row['actor_id'], []).append(row)

        findings = []
        for actor_id, actor_rows in by_actor.items():
            ips = list(dict.fromkeys(r['ip_address'] for r in actor_rows))
            if len(ips) < config.impossible_travel_min_distinct_ips:
                continue
            networks = {_network_key(ip) for ip in ips}
            if len(networks) < 2:
                continue
            findings.append(Finding(
                dedup_key=f'actor:{actor_id}',
                summary=(f'{actor_rows[0]["actor__username"]} logged in from '
                         f'{len(ips)} distinct IPs across {len(networks)} networks '
                         f'in {config.impossible_travel_window_minutes}m'),
                details={
                    'actor': actor_rows[0]['actor__username'],
                    'ips': ips,
                    'networks': sorted(networks),
                    'window_minutes': config.impossible_travel_window_minutes,
                },
                related_audit_ids=[r['id'] for r in actor_rows],
            ))
        return findings


class OffHoursElevationRule(BaseThreatRule):
    """Privileged actions outside business hours."""

    name = 'off_hours_elevation'
    label = 'Off-Hours Elevation'
    severity = ThreatAlert.Severity.WARNING
    ACTIONS = (
        AuditLog.Action.BREAK_GLASS_TRIGGERED,
        AuditLog.Action.REQUEST_APPROVED,
        AuditLog.Action.ADMIN_REVOKED,
    )

    def evaluate(self, config, now, since):
        rows = AuditLog.objects.filter(
            action__in=self.ACTIONS,
            timestamp__gte=since,
            timestamp__lte=now,
        ).values('id', 'action', 'actor_id', 'actor__username', 'timestamp')

        start_h, start_m = _parse_hhmm(config.off_hours_start)
        end_h, end_m = _parse_hhmm(config.off_hours_end)

        findings = []
        for row in rows:
            lt = timezone.localtime(row['timestamp'])
            hour = lt.hour
            weekend = lt.weekday() >= 5
            if start_h == end_h:
                weekday_hit = False  # documented: no weekday window
            elif start_h < end_h:
                weekday_hit = not (start_h <= hour < end_h)
            else:  # overnight range, e.g. 18:00-07:00 (off-hours wrap midnight)
                weekday_hit = hour >= start_h or hour < end_h

            if not ((config.off_hours_weekend and weekend) or weekday_hit):
                continue

            action_label = AuditLog.Action(row['action']).label
            findings.append(Finding(
                dedup_key=f"{row['action']}:{row['actor_id'] or 0}",
                summary=(f'{action_label} at {lt:%H:%M} (off-hours) '
                         f'by {row["actor__username"] or "system"}'),
                details={
                    'action': row['action'],
                    'actor': row['actor__username'],
                    'local_time': f'{lt:%H:%M}',
                    'weekend': weekend,
                },
                related_audit_ids=[row['id']],
            ))
        return findings


class MfaStormRule(BaseThreatRule):
    """A burst of failed MFA challenges from one account."""

    name = 'mfa_storm'
    label = 'MFA Storm'
    severity = ThreatAlert.Severity.CRITICAL

    def evaluate(self, config, now, since):
        from django.db.models import Count
        rows = AuditLog.objects.filter(
            action=AuditLog.Action.MFA_CHALLENGE_FAILED,
            actor__isnull=False,
            timestamp__gte=since,
            timestamp__lte=now,
        ).values('actor_id', 'actor__username').annotate(n=Count('id')).filter(
            n__gte=config.mfa_storm_threshold)
        findings = []
        for row in rows:
            findings.append(Finding(
                dedup_key=f'actor:{row["actor_id"]}',
                summary=(f'{row["actor__username"]} failed MFA '
                         f'{row["n"]} times in {config.mfa_storm_window_minutes}m'),
                details={
                    'actor': row['actor__username'],
                    'failures': row['n'],
                    'window_minutes': config.mfa_storm_window_minutes,
                },
            ))
        return findings


class CheckoutSpikeRule(BaseThreatRule):
    """An unusual burst of access requests from one user."""

    name = 'checkout_spike'
    label = 'Checkout Spike'
    severity = ThreatAlert.Severity.WARNING

    def evaluate(self, config, now, since):
        from django.db.models import Count
        rows = AuditLog.objects.filter(
            action=AuditLog.Action.REQUEST_CREATED,
            actor__isnull=False,
            timestamp__gte=since,
            timestamp__lte=now,
        ).values('actor_id', 'actor__username').annotate(n=Count('id')).filter(
            n__gte=config.checkout_spike_threshold)
        findings = []
        for row in rows:
            findings.append(Finding(
                dedup_key=f'actor:{row["actor_id"]}',
                summary=(f'{row["actor__username"]} submitted '
                         f'{row["n"]} access requests in {config.checkout_spike_window_minutes}m'),
                details={
                    'actor': row['actor__username'],
                    'requests': row['n'],
                    'window_minutes': config.checkout_spike_window_minutes,
                },
            ))
        return findings


class RevealSpikeRule(BaseThreatRule):
    """Repeated vault secret reveals for the same entry."""

    name = 'reveal_spike'
    label = 'Vault Reveal Spike'
    severity = ThreatAlert.Severity.WARNING

    def evaluate(self, config, now, since):
        from django.db.models import Count
        rows = AuditLog.objects.filter(
            action=AuditLog.Action.VAULT_SECRET_REVEALED,
            timestamp__gte=since,
            timestamp__lte=now,
        ).exclude(target_id='').values('target_id').annotate(n=Count('id')).filter(
            n__gte=config.reveal_spike_threshold)
        findings = []
        for row in rows:
            first = AuditLog.objects.filter(
                action=AuditLog.Action.VAULT_SECRET_REVEALED,
                target_id=row['target_id'],
                timestamp__gte=since,
                timestamp__lte=now,
            ).first()
            entry_name = (first.details or {}).get('entry', 'unknown') if first else 'unknown'
            findings.append(Finding(
                dedup_key=f'entry:{row["target_id"]}',
                summary=(f'Vault entry {entry_name} revealed '
                         f'{row["n"]} times in {config.reveal_spike_window_minutes}m'),
                details={
                    'entry': entry_name,
                    'entry_id': row['target_id'],
                    'reveals': row['n'],
                    'window_minutes': config.reveal_spike_window_minutes,
                },
            ))
        return findings


RULES = {
    'impossible_travel': ImpossibleTravelRule(),
    'off_hours_elevation': OffHoursElevationRule(),
    'mfa_storm': MfaStormRule(),
    'checkout_spike': CheckoutSpikeRule(),
    'reveal_spike': RevealSpikeRule(),
}
