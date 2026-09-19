"""SCIM provisioning configuration (singleton)."""

from django.conf import settings
from django.core.signing import Signer, BadSignature
from django.db import models


class ScimConfig(models.Model):
    """Singleton configuration for the SCIM v2 endpoint."""

    _signer = Signer(salt='scim.ScimConfig.bearer_token')

    enabled = models.BooleanField(default=False, verbose_name='Enable SCIM Endpoint')
    bearer_token = models.CharField(
        max_length=512, blank=True, default='',
        verbose_name='Bearer Token',
        help_text='Secret token pasted into Entra (encrypted at rest)',
    )
    configured_at = models.DateTimeField(auto_now=True)
    configured_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, verbose_name='Configured by',
    )

    class Meta:
        verbose_name = 'SCIM Configuration'
        verbose_name_plural = 'SCIM Configuration'

    def __str__(self):
        return f'SCIM: {"enabled" if self.enabled else "disabled"}'

    def save(self, *args, **kwargs):
        # Encrypt the token before saving if not already encrypted
        raw = self.bearer_token
        if raw and ':' not in raw:
            self.bearer_token = self._signer.sign(raw)
        self.pk = 1  # Singleton
        super().save(*args, **kwargs)

    @classmethod
    def get_config(cls):
        config, _ = cls.objects.get_or_create(pk=1)
        return config

    def get_bearer_token(self) -> str:
        """Decrypt and return the bearer token."""
        raw = self.bearer_token
        if not raw:
            return ''
        if ':' in raw:
            try:
                return self._signer.unsign(raw)
            except BadSignature:
                return raw
        return raw

    def set_bearer_token(self, value: str) -> None:
        """Encrypt and store the bearer token."""
        if not value:
            self.bearer_token = ''
        else:
            self.bearer_token = self._signer.sign(value)

    def get_effective_token(self) -> str:
        """DB token, falling back to the SCIM_BEARER_TOKEN env/vault secret."""
        from django.conf import settings
        return self.get_bearer_token() or getattr(settings, 'SCIM_BEARER_TOKEN', '')
