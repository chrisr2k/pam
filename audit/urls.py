from django.urls import path
from . import views

app_name = 'audit'

urlpatterns = [
    path('', views.AuditLogListView.as_view(), name='log'),
    path('siem-settings/', views.SIEMSettingsView.as_view(), name='siem_settings'),
]
