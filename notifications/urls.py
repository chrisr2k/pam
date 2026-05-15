from django.urls import path
from . import views

app_name = 'notifications'

urlpatterns = [
    path('settings/', views.NotificationSettingsView.as_view(), name='settings'),
]
