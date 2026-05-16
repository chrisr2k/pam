"""
Multi-cloud secrets resolver for PAM.

Auto-detects the cloud environment and fetches secrets from the appropriate
secrets management service. Supports Azure Key Vault, AWS Secrets Manager,
GCP Secret Manager, OCI Vault, and local .env file fallback.

Usage:
    from pam.secrets_resolver import get_secret, detect_cloud

    secret_key = get_secret('DJANGO_SECRET_KEY', 'fallback-dev-key')
    cloud = detect_cloud()  # 'azure', 'aws', 'gcp', 'oci', or 'local'

Override auto-detection with PAM_SECRETS_BACKEND env var:
    PAM_SECRETS_BACKEND=azure|aws|gcp|oci|local
"""

import json
import logging
import os
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Known secret keys that the resolver can fetch ──────────────────────────
SENSITIVE_SECRET_KEYS = [
    'DJANGO_SECRET_KEY',
    'ENTRA_CLIENT_SECRET',
    'ENTRA_PIM_CLIENT_SECRET',
    'ENTRA_PIM_CERTIFICATE_B64',
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_SSO_INSTANCE_ARN',
]

# ── Cloud detection ────────────────────────────────────────────────────────


def _detect_cloud():
    """Detect the current cloud environment (internal, no override check).

    Returns one of: 'azure', 'aws', 'gcp', 'oci', 'local'
    """
    # Azure: Managed Identity sets IDENTITY_ENDPOINT
    if os.getenv('IDENTITY_ENDPOINT'):
        return 'azure'
    if os.getenv('AZURE_CLIENT_ID'):
        return 'azure'

    # AWS: ECS, EKS, EC2 signals
    if os.getenv('AWS_EXECUTION_ENV') or os.getenv('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'):
        return 'aws'
    if os.getenv('AWS_LAMBDA_FUNCTION_NAME'):
        return 'aws'

    # GCP: GCE metadata server or workload identity
    if os.getenv('GOOGLE_CLOUD_PROJECT'):
        return 'gcp'
    if os.getenv('KUBERNETES_SERVICE_HOST') and os.getenv('GCP_METADATA'):
        return 'gcp'

    # OCI: resource principal
    if os.getenv('OCI_RESOURCE_PRINCIPAL_VERSION'):
        return 'oci'

    return 'local'


# ── Resolver base ──────────────────────────────────────────────────────────


class BaseSecretsResolver:
    """Base class for cloud-specific secrets resolvers."""

    # Map our internal key names to cloud-specific secret names
    SECRET_NAME_MAP = {}

    def __init__(self):
        self._cache = {}

    def get_secret(self, key, default=None):
        """Fetch a secret by key. Results are cached."""
        if key in self._cache:
            return self._cache[key]

        secret_name = self.SECRET_NAME_MAP.get(key)
        if not secret_name:
            # Not a mapped secret, fall back to env var
            value = os.getenv(key, default)
            self._cache[key] = value
            return value

        try:
            value = self._fetch_secret(secret_name)
            self._cache[key] = value
            return value
        except Exception as exc:
            logger.warning(
                'Failed to fetch secret "%s" from %s: %s. '
                'Falling back to environment variable.',
                secret_name, self.__class__.__name__, exc,
            )
            value = os.getenv(key, default)
            self._cache[key] = value
            return value

    def resolve_all(self):
        """Pre-fetch all known secrets."""
        for key in SENSITIVE_SECRET_KEYS:
            try:
                self.get_secret(key)
            except Exception:
                pass  # Individual failures are logged in get_secret

    def _fetch_secret(self, secret_name):
        """Fetch a single secret from the cloud provider. Override in subclass."""
        raise NotImplementedError


# ── Azure Key Vault ────────────────────────────────────────────────────────


class AzureSecretsResolver(BaseSecretsResolver):
    """Resolves secrets from Azure Key Vault using Managed Identity."""

    SECRET_NAME_MAP = {
        'DJANGO_SECRET_KEY': 'pam-django-secret-key',
        'ENTRA_CLIENT_SECRET': 'pam-entra-client-secret',
        'ENTRA_PIM_CLIENT_SECRET': 'pam-entra-pim-client-secret',
        'ENTRA_PIM_CERTIFICATE_B64': 'pam-entra-pim-cert',
        'AWS_ACCESS_KEY_ID': 'pam-aws-access-key',
        'AWS_SECRET_ACCESS_KEY': 'pam-aws-secret-key',
        'AWS_SSO_INSTANCE_ARN': 'pam-aws-sso-instance-arn',
    }

    def __init__(self):
        super().__init__()
        self._client = None

    @property
    def client(self):
        if self._client is None:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient

            vault_url = os.getenv('AZURE_KEY_VAULT_URL', '')
            if not vault_url:
                raise ValueError(
                    'AZURE_KEY_VAULT_URL environment variable is required '
                    'for Azure Key Vault integration.'
                )
            credential = DefaultAzureCredential()
            self._client = SecretClient(vault_url=vault_url, credential=credential)
        return self._client

    def _fetch_secret(self, secret_name):
        secret = self.client.get_secret(secret_name)
        return secret.value


# ── AWS Secrets Manager ────────────────────────────────────────────────────


class AwsSecretsResolver(BaseSecretsResolver):
    """Resolves secrets from AWS Secrets Manager using the default session (task role / instance profile)."""

    SECRET_NAME_MAP = {
        'DJANGO_SECRET_KEY': 'pam/DJANGO_SECRET_KEY',
        'ENTRA_CLIENT_SECRET': 'pam/ENTRA_CLIENT_SECRET',
        'ENTRA_PIM_CLIENT_SECRET': 'pam/ENTRA_PIM_CLIENT_SECRET',
        'ENTRA_PIM_CERTIFICATE_B64': 'pam/ENTRA_PIM_CERTIFICATE_B64',
        'AWS_ACCESS_KEY_ID': 'pam/AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY': 'pam/AWS_SECRET_ACCESS_KEY',
        'AWS_SSO_INSTANCE_ARN': 'pam/AWS_SSO_INSTANCE_ARN',
    }

    def __init__(self):
        super().__init__()
        self._client = None

    @property
    def client(self):
        if self._client is None:
            import boto3
            self._client = boto3.client(
                'secretsmanager',
                region_name=os.getenv('AWS_REGION', 'us-east-1'),
            )
        return self._client

    def _fetch_secret(self, secret_name):
        response = self.client.get_secret_value(SecretId=secret_name)
        return response.get('SecretString', '')


# ── GCP Secret Manager ─────────────────────────────────────────────────────


class GcpSecretsResolver(BaseSecretsResolver):
    """Resolves secrets from GCP Secret Manager using default credentials (Workload Identity / GCE SA)."""

    SECRET_NAME_MAP = {
        'DJANGO_SECRET_KEY': 'pam-django-secret-key',
        'ENTRA_CLIENT_SECRET': 'pam-entra-client-secret',
        'ENTRA_PIM_CLIENT_SECRET': 'pam-entra-pim-client-secret',
        'ENTRA_PIM_CERTIFICATE_B64': 'pam-entra-pim-cert',
        'AWS_ACCESS_KEY_ID': 'pam-aws-access-key',
        'AWS_SECRET_ACCESS_KEY': 'pam-aws-secret-key',
        'AWS_SSO_INSTANCE_ARN': 'pam-aws-sso-instance-arn',
    }

    def __init__(self):
        super().__init__()
        self._client = None
        self._project_id = os.getenv('GOOGLE_CLOUD_PROJECT', '')

    @property
    def client(self):
        if self._client is None:
            from google.cloud import secretmanager
            self._client = secretmanager.SecretManagerServiceClient()
        return self._client

    def _fetch_secret(self, secret_name):
        if not self._project_id:
            raise ValueError(
                'GOOGLE_CLOUD_PROJECT environment variable is required '
                'for GCP Secret Manager integration.'
            )
        name = f'projects/{self._project_id}/secrets/{secret_name}/versions/latest'
        response = self.client.access_secret_version(request={'name': name})
        return response.payload.data.decode('utf-8')


# ── OCI Vault ──────────────────────────────────────────────────────────────


class OciSecretsResolver(BaseSecretsResolver):
    """Resolves secrets from OCI Vault using resource principal (instance principal / OKE workload identity)."""

    SECRET_NAME_MAP = {
        'DJANGO_SECRET_KEY': 'pam_django_secret_key',
        'ENTRA_CLIENT_SECRET': 'pam_entra_client_secret',
        'ENTRA_PIM_CLIENT_SECRET': 'pam_entra_pim_client_secret',
        'ENTRA_PIM_CERTIFICATE_B64': 'pam_entra_pim_cert',
        'AWS_ACCESS_KEY_ID': 'pam_aws_access_key_id',
        'AWS_SECRET_ACCESS_KEY': 'pam_aws_secret_access_key',
        'AWS_SSO_INSTANCE_ARN': 'pam_aws_sso_instance_arn',
    }

    def __init__(self):
        super().__init__()
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                from oci.auth.signers import InstancePrincipalsSecurityTokenSigner
                from oci.secrets import SecretsClient

                signer = InstancePrincipalsSecurityTokenSigner()
                self._client = SecretsClient(
                    config={},
                    signer=signer,
                )
            except Exception:
                # Fall back to config file auth (for local testing with OCI CLI)
                import oci
                config = oci.config.from_file()
                self._client = SecretsClient(config)
        return self._client

    def _fetch_secret(self, secret_name):
        vault_ocid = os.getenv('OCI_VAULT_OCID', '')
        if not vault_ocid:
            raise ValueError(
                'OCI_VAULT_OCID environment variable is required '
                'for OCI Vault integration.'
            )
        # OCI secrets are referenced by OCID
        response = self.client.get_secret_bundle(secret_id=vault_ocid)
        return response.data.secret_bundle_content.content


# ── Local fallback ─────────────────────────────────────────────────────────


class LocalSecretsResolver(BaseSecretsResolver):
    """Resolves secrets from environment variables / .env file."""

    def _fetch_secret(self, secret_name):
        # For local resolver, we just read from env vars
        # The actual key name is the env var name, not the cloud-specific name
        return os.getenv(secret_name, '')


# ── Resolver registry ──────────────────────────────────────────────────────

RESOLVERS = {
    'azure': AzureSecretsResolver,
    'aws': AwsSecretsResolver,
    'gcp': GcpSecretsResolver,
    'oci': OciSecretsResolver,
    'local': LocalSecretsResolver,
}


# ── Public API ─────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _get_resolver():
    """Get the appropriate resolver for the current environment (cached)."""
    cloud = detect_cloud()
    resolver_cls = RESOLVERS.get(cloud, LocalSecretsResolver)
    resolver = resolver_cls()
    logger.info('PAM secrets resolver: %s (%s)', resolver.__class__.__name__, cloud)
    # Pre-fetch all secrets at startup
    resolver.resolve_all()
    return resolver


def get_secret(key, default=None):
    """Fetch a secret from the cloud secrets store.

    Auto-detects the cloud environment. Falls back to environment variables
    if the secrets store is unreachable or the secret doesn't exist.

    Args:
        key: The secret key name (e.g., 'DJANGO_SECRET_KEY').
        default: Default value if the secret is not found.

    Returns:
        The secret value as a string.
    """
    resolver = _get_resolver()
    return resolver.get_secret(key, default)


def detect_cloud():
    """Detect the current cloud environment.

    Returns one of: 'azure', 'aws', 'gcp', 'oci', 'local'
    """
    # Manual override
    override = os.getenv('PAM_SECRETS_BACKEND', '').strip().lower()
    if override in ('azure', 'aws', 'gcp', 'oci', 'local'):
        return override

    # Azure: Managed Identity sets IDENTITY_ENDPOINT
    if os.getenv('IDENTITY_ENDPOINT'):
        return 'azure'
    if os.getenv('AZURE_CLIENT_ID'):
        return 'azure'

    # AWS
    if os.getenv('AWS_EXECUTION_ENV') or os.getenv('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'):
        return 'aws'
    if os.getenv('AWS_LAMBDA_FUNCTION_NAME'):
        return 'aws'

    # GCP
    if os.getenv('GOOGLE_CLOUD_PROJECT'):
        return 'gcp'
    if os.getenv('KUBERNETES_SERVICE_HOST') and os.getenv('GCP_METADATA'):
        return 'gcp'

    # OCI
    if os.getenv('OCI_RESOURCE_PRINCIPAL_VERSION'):
        return 'oci'

    return 'local'


def resolve_all():
    """Pre-fetch all known secrets. Called at startup."""
    resolver = _get_resolver()
    resolver.resolve_all()
