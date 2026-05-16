"""
Credential factory for Entra ID authentication.

Auto-selects the appropriate credential type based on the runtime environment:

1. ManagedIdentityCredential - when running in Azure (App Service, VM, Functions, etc.)
2. ClientCertificateCredential - when running outside Azure with a certificate
3. ClientSecretCredential - fallback for development/testing only

Usage:
    factory = EntraCredentialFactory()
    credential = factory.get_credential(tenant_id, client_id)
    token = credential.get_token('https://graph.microsoft.com/.default')
"""

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


class EntraCredentialFactory:
    """
    Factory that creates the appropriate Azure Identity credential
    based on the runtime environment.
    """

    # Well-known Azure environment variables that indicate managed identity
    AZURE_IDENTITY_ENDPOINT_ENV = 'IDENTITY_ENDPOINT'
    AZURE_MSI_ENDPOINT_ENV = 'MSI_ENDPOINT'
    AZURE_MSI_SECRET_ENV = 'MSI_SECRET'

    def __init__(self):
        self._credential = None
        self._credential_type = None

    @property
    def credential_type(self) -> str:
        """Return the type of credential currently in use."""
        if self._credential_type:
            return self._credential_type
        self._detect_environment()
        return self._credential_type or 'unknown'

    def _is_running_in_azure(self) -> bool:
        """Detect if we're running in an Azure environment with managed identity."""
        # Check for Azure App Service / Functions / Container Apps
        if os.getenv(self.AZURE_IDENTITY_ENDPOINT_ENV):
            return True
        # Check for Azure VM / VMSS
        if os.getenv(self.AZURE_MSI_ENDPOINT_ENV) and os.getenv(self.AZURE_MSI_SECRET_ENV):
            return True
        # Check for Azure Arc
        if os.getenv('IDENTITY_HEADER'):
            return True
        # Check for Azure CLI (dev environments)
        if os.getenv('AZURE_CLIENT_ID') and os.getenv('AZURE_TENANT_ID'):
            return True
        return False

    def _detect_environment(self) -> str:
        """
        Detect the runtime environment and return the credential type to use.

        Returns:
            'managed_identity', 'certificate', 'client_secret', or 'none'
        """
        # 1. Check for managed identity (Azure environment)
        if self._is_running_in_azure():
            logger.info('Detected Azure environment - using ManagedIdentityCredential')
            self._credential_type = 'managed_identity'
            return self._credential_type

        # 2. Check for certificate-based auth
        cert_path = os.getenv('ENTRA_PIM_CERTIFICATE_PATH', '')
        if cert_path and os.path.exists(cert_path):
            logger.info(f'Found certificate at {cert_path} - using ClientCertificateCredential')
            self._credential_type = 'certificate'
            return self._credential_type

        # 3. Check for certificate in OCI Vault (OCI deployment)
        oci_cert_secret = os.getenv('ENTRA_PIM_CERT_OCI_SECRET', '')
        if oci_cert_secret:
            logger.info('OCI Vault certificate configured - using ClientCertificateCredential')
            self._credential_type = 'certificate'
            return self._credential_type

        # 4. Fall back to client secret (development only)
        logger.warning(
            'No managed identity or certificate found. '
            'Falling back to ClientSecretCredential. '
            'This is NOT recommended for production.'
        )
        self._credential_type = 'client_secret'
        return self._credential_type

    def get_credential(self, tenant_id: str, client_id: str, client_secret: str = ''):
        """
        Get the appropriate credential object for the current environment.

        Args:
            tenant_id: Entra ID tenant ID
            client_id: Entra ID application (client) ID
            client_secret: Client secret (only used as fallback)

        Returns:
            An Azure Identity credential object with a get_token method,
            or None if no credential could be created.
        """
        if self._credential:
            return self._credential

        cred_type = self._detect_environment()

        try:
            if cred_type == 'managed_identity':
                from azure.identity import ManagedIdentityCredential
                self._credential = ManagedIdentityCredential(
                    client_id=client_id,
                )
                logger.info('Created ManagedIdentityCredential')

            elif cred_type == 'certificate':
                from azure.identity import ClientCertificateCredential

                cert_path = os.getenv('ENTRA_PIM_CERTIFICATE_PATH', '')
                cert_password = os.getenv('ENTRA_PIM_CERTIFICATE_PASSWORD', '')

                if cert_path and os.path.exists(cert_path):
                    # Load certificate from file
                    with open(cert_path, 'rb') as f:
                        cert_data = f.read()

                    self._credential = ClientCertificateCredential(
                        tenant_id=tenant_id,
                        client_id=client_id,
                        certificate_data=cert_data,
                        password=cert_password if cert_password else None,
                    )
                    logger.info(f'Created ClientCertificateCredential from file: {cert_path}')
                else:
                    # Try OCI Vault or other secret store
                    # The certificate data should be in the env var
                    cert_b64 = os.getenv('ENTRA_PIM_CERTIFICATE_B64', '')
                    if cert_b64:
                        import base64
                        cert_data = base64.b64decode(cert_b64)
                        self._credential = ClientCertificateCredential(
                            tenant_id=tenant_id,
                            client_id=client_id,
                            certificate_data=cert_data,
                            password=cert_password if cert_password else None,
                        )
                        logger.info('Created ClientCertificateCredential from base64 env var')
                    else:
                        logger.error('Certificate path not found and no base64 cert in env')
                        return None

            else:  # client_secret fallback
                from azure.identity import ClientSecretCredential
                if not client_secret:
                    logger.error('ClientSecretCredential fallback requires a client_secret')
                    return None
                self._credential = ClientSecretCredential(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret,
                )
                logger.warning('Created ClientSecretCredential (not recommended for production)')

            return self._credential

        except ImportError as e:
            logger.error(f'Azure Identity library not installed: {e}')
            return None
        except Exception as e:
            logger.error(f'Failed to create credential: {e}')
            return None

    def get_graph_token(self, tenant_id: str, client_id: str, client_secret: str = '') -> Optional[str]:
        """
        Convenience method: get an access token for Microsoft Graph API.

        Returns:
            Access token string, or None on failure.
        """
        credential = self.get_credential(tenant_id, client_id, client_secret)
        if not credential:
            return None

        try:
            token = credential.get_token('https://graph.microsoft.com/.default')
            return token.token
        except Exception as e:
            logger.error(f'Failed to acquire Graph API token: {e}')
            return None
