from abc import ABC, abstractmethod
from typing import Optional


class BasePrivilegedAccessProvider(ABC):
    """
    Abstract base class for privileged access providers.
    Each provider (AWS Identity Center, Entra ID PIM) implements this interface.
    """

    @abstractmethod
    def provision_access(self, user_entra_oid: str, role_config: dict, duration_minutes: int) -> dict:
        """
        Provision privileged access for a user.

        Args:
            user_entra_oid: The user's Entra ID object ID
            role_config: Configuration dict for the role/permission set
            duration_minutes: How long the access should last

        Returns:
            dict with at least {'success': bool, 'reference_id': str}
        """
        pass

    @abstractmethod
    def deprovision_access(self, reference_id: str) -> bool:
        """
        Remove privileged access for a user.

        Args:
            reference_id: The provider-specific reference ID from provision_access

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    def list_available_roles(self) -> list[dict]:
        """
        List all available roles/permission sets from the provider.

        Returns:
            List of dicts with role information
        """
        pass

    @abstractmethod
    def check_access_status(self, reference_id: str) -> str:
        """
        Check the status of a provisioned access.

        Returns:
            Status string: 'active', 'expired', 'not_found'
        """
        pass
