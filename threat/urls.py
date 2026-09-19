from django.urls import path
from . import views

app_name = 'threat'

urlpatterns = [
    path('', views.ThreatAlertListView.as_view(), name='list'),
    path('settings/', views.ThreatSettingsView.as_view(), name='settings'),
    path('acknowledge/<int:pk>/', views.ThreatAcknowledgeView.as_view(), name='acknowledge'),
]
