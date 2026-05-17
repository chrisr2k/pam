"""
Custom admin site configuration.

The admin_site singleton is defined in admin_site.py using a lazy proxy
pattern to avoid circular imports. This module re-exports it.
"""
from .admin_site import admin_site, get_admin_site  # noqa: F401
