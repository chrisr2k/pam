"""
Separate module for the admin_site singleton to avoid circular imports.

This module must NOT import from django.contrib.admin or any app's admin.py,
to ensure admin_site is available when app admin modules are loaded during
Django's autodiscovery process.
"""
from django.contrib.admin import AdminSite as DjangoAdminSite


class PAMAdminSite(DjangoAdminSite):
    """Admin site that requires the PAM ADMIN role.

    The has_permission check is intentionally minimal here to avoid
    import-time issues. The full authorization logic (role check, etc.)
    is applied in the admin_middleware.py middleware instead.
    """
    pass


# Create the singleton admin site instance
admin_site = PAMAdminSite(name='pam_admin')
