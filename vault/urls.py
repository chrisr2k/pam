from django.urls import path
from . import views

app_name = 'vault'

urlpatterns = [
    path('', views.VaultEntryListView.as_view(), name='list'),
    path('new/', views.VaultEntryCreateView.as_view(), name='create'),
    path('<int:pk>/', views.VaultEntryDetailView.as_view(), name='detail'),
    path('<int:pk>/reveal/', views.VaultRevealView.as_view(), name='reveal'),
    path('<int:pk>/rotate/', views.VaultRotateView.as_view(), name='rotate'),
]
