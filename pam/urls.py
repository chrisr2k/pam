import os

from django.urls import path, include
from django.views.generic import RedirectView

from .admin import admin_site

# Admin URL is configurable via env var for security-through-obscurity.
# Default: /pam-admin/ (instead of the well-known /admin/)
ADMIN_URL = os.getenv('PAM_ADMIN_URL', 'pam-admin/').strip('/')

urlpatterns = [
    path(f'{ADMIN_URL}/', admin_site.urls),
    path('accounts/', include('accounts.urls')),
    path('roles/', include('roles.urls')),
    path('requests/', include('access_requests.urls')),
    path('reviews/', include('reviews.urls')),
    path('audit/', include('audit.urls')),
    path('notifications/', include('notifications.urls')),
    path('', RedirectView.as_view(pattern_name='requests:dashboard', permanent=False)),
]
