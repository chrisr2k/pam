"""
Separate module for the admin_site singleton to avoid circular imports.

This module uses a lazy initialization pattern to avoid the circular import
that occurs when Django's autodiscover() imports app admin modules before
the admin_site singleton is fully initialized.

The PAMAdminSite class is defined here, but the actual singleton is created
lazily via get_admin_site() to ensure it's available when app admin modules
are loaded during autodiscovery.
"""
import logging

logger = logging.getLogger(__name__)

# Module-level singleton, initially None
_admin_site = None


class PAMAdminSite:
    """Placeholder that delegates to the real AdminSite once initialized.

    This proxy pattern allows app admin modules to use @admin_site.register()
    during import time, even though the real AdminSite hasn't been created yet.
    Registrations are queued and applied when the real site is initialized.
    """

    def __init__(self):
        self._registrations = []  # (model_or_config, admin_class_or_none) tuples
        self._real_site = None

    def register(self, model_or_iterable, admin_class=None, **options):
        """Queue registration or delegate to real site."""
        if self._real_site is not None:
            return self._real_site.register(model_or_iterable, admin_class, **options)
        self._registrations.append((model_or_iterable, admin_class, options))
        # Return something callable for decorator use
        if admin_class is None:
            # Used as a decorator: @admin_site.register(Model)
            def decorator(klass):
                self._registrations.append((model_or_iterable, klass, options))
                return klass
            return decorator
        return None

    def unregister(self, model_or_iterable):
        """Delegate to real site."""
        if self._real_site is not None:
            return self._real_site.unregister(model_or_iterable)

    @property
    def urls(self):
        """Delegate to real site's urls property."""
        if self._real_site is None:
            self._initialize()
        return self._real_site.urls

    def _initialize(self):
        """Lazily create the real AdminSite and replay registrations."""
        from django.contrib.admin import AdminSite as DjangoAdminSite

        class RealPAMAdminSite(DjangoAdminSite):
            """Admin site that requires the PAM ADMIN role."""

            def has_permission(self, request):
                """Require is_staff AND PAM Admin role."""
                has_base_perm = super().has_permission(request)
                if not has_base_perm:
                    return False

                user = request.user
                if not user.is_authenticated:
                    return False

                if not user.is_admin_user:
                    logger.warning(
                        f'Blocked admin access for user={user.username} '
                        f'role={user.role} — PAM Admin role required'
                    )
                    return False

                return True

            def login(self, request, extra_context=None):
                """Override login to redirect to the PAM login page."""
                if request.method == 'GET' and not request.user.is_authenticated:
                    from django.http import HttpResponseRedirect
                    from django.urls import reverse
                    return HttpResponseRedirect(reverse('accounts:login'))
                return super().login(request, extra_context)

            def index(self, request, extra_context=None):
                """Show a message if the user lacks admin access."""
                if not self.has_permission(request):
                    if request.user.is_authenticated:
                        from django.contrib import messages
                        self.message_user(
                            request,
                            'You do not have Admin privileges to access this page.',
                            level=messages.ERROR,
                        )
                        from django.http import HttpResponseRedirect
                        from django.urls import reverse
                        return HttpResponseRedirect(reverse('requests:dashboard'))
                return super().index(request, extra_context)

        self._real_site = RealPAMAdminSite(name='pam_admin')

        # Replay all queued registrations
        for model_or_iterable, admin_class, options in self._registrations:
            try:
                self._real_site.register(model_or_iterable, admin_class, **options)
            except Exception as e:
                logger.warning(f'Failed to replay admin registration for {model_or_iterable}: {e}')

        self._registrations.clear()


# Create the proxy singleton
admin_site = PAMAdminSite()


def get_admin_site():
    """Get the fully initialized admin site (for use after Django setup)."""
    if admin_site._real_site is None:
        admin_site._initialize()
    return admin_site._real_site
