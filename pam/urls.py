from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    path('roles/', include('roles.urls')),
    path('requests/', include('access_requests.urls')),
    path('reviews/', include('reviews.urls')),
    path('audit/', include('audit.urls')),
    path('', RedirectView.as_view(pattern_name='requests:dashboard', permanent=False)),
]
