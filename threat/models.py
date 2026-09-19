"""Threat analytics models: detected alerts and their configuration."""

from django.conf import settings
from django.db import models


class ThreatAlert(models.Model):
    """A single detection-rule firing."""

    class Severity(models.TextChoices):
        INFO = 'INFO', 'Info'
        WARNING = 'WARNING', 'Warning'
        CRITICAL = 'CRITICAL', 'Critical'

    rule = models.CharField(
        max_length=40,
        help_text='Detection rule registry key (e.g. impossible_travel)',
    )
    severity = models.CharField(
        max_length=10, choices=Severity.choices, default=Severity.WARNING,
    )
    summary = models.CharField(max_length=255)
    details = models.JSONField(default=dict, blank=True)
    dedup_key = models.CharField(
        max_length=255,
        help_text='Rule-scoped subject key used for cooldown suppression',
    )
    related_audit_ids = models.JSONField(
        default=list, blank=True,
        help_text='IDs of the AuditLog rows that triggered this alert',
    )
    acknowledged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='acknowledged_threat_alerts',
    )
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['rule', 'created_at']),
            models.Index(fields=['rule', 'dedup_key']),
        ]

    def __str__(self):
        return f'[{self.severity}] {self.rule}: {self.summary}'


class ThreatConfig(models.Model):
    """Singleton configuration for the threat scan (one row, pk=1)."""

    # Global
    scan_enabled = models.BooleanField(default=True, verbose_name='Enable Threat Scanning')
    cooldown_minutes = models.PositiveIntegerField(
        default=30,
        help_text='Suppress duplicate alerts for the same rule + subject within this window',
    )

    # impossible_travel
    impossible_travel_enabled = models.BooleanField(default=True)
    impossible_travel_window_minutes = models.PositiveIntegerField(default=30)
    impossible_travel_min_distinct_ips = models.PositiveIntegerField(default=2)

    # off_hours_elevation
    off_hours_enabled = models.BooleanField(default=True)
    off_hours_start = models.CharField(
        max_length=5, default='18:00', help_text='HH:MM; start > end wraps midnight',
    )
    off_hours_end = models.CharField(max_length=5, default='07:00', help_text='HH:MM')
    off_hours_weekend = models.BooleanField(
        default=True,
        help_text='Treat all of Saturday/Sunday as off-hours regardless of the time window',
    )
    off_hours_window_minutes = models.PositiveIntegerField(default=60)

    # mfa_storm
    mfa_storm_enabled = models.BooleanField(default=True)
    mfa_storm_threshold = models.PositiveIntegerField(default=5)
    mfa_storm_window_minutes = models.PositiveIntegerField(default=10)

    # checkout_spike
    checkout_spike_enabled = models.BooleanField(default=True)
    checkout_spike_threshold = models.PositiveIntegerField(default=10)
    checkout_spike_window_minutes = models.PositiveIntegerField(default=60)

    # reveal_spike
    reveal_spike_enabled = models.BooleanField(default=True)
    reveal_spike_threshold = models.PositiveIntegerField(default=5)
    reveal_spike_window_minutes = models.PositiveIntegerField(default=10)

    # State
    last_run_at = models.DateTimeField(null=True, blank=True)
    configured_at = models.DateTimeField(auto_now=True)
    configured_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, verbose_name='Configured by',
    )

    # rule_name -> (enabled field, window field)
    RULE_FIELDS = {
        'impossible_travel': ('impossible_travel_enabled', 'impossible_travel_window_minutes'),
        'off_hours_elevation': ('off_hours_enabled', 'off_hours_window_minutes'),
        'mfa_storm': ('mfa_storm_enabled', 'mfa_storm_window_minutes'),
        'checkout_spike': ('checkout_spike_enabled', 'checkout_spike_window_minutes'),
        'reveal_spike': ('reveal_spike_enabled', 'reveal_spike_window_minutes'),
    }

    class Meta:
        verbose_name = 'Threat Configuration'
        verbose_name_plural = 'Threat Configuration'

    def __str__(self):
        return f'Threat scan: {"enabled" if self.scan_enabled else "disabled"}'

    def save(self, *args, **kwargs):
        self.pk = 1  # Singleton
        super().save(*args, **kwargs)

    @classmethod
    def get_config(cls):
        config, _ = cls.objects.get_or_create(pk=1)
        return config

    def enabled_for(self, rule_name) -> bool:
        return getattr(self, self.RULE_FIELDS[rule_name][0])

    def window_for(self, rule_name) -> int:
        return getattr(self, self.RULE_FIELDS[rule_name][1])
