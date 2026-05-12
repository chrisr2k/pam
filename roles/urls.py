from django.urls import path
from . import views

app_name = 'roles'

urlpatterns = [
    path('', views.RoleListView.as_view(), name='list'),
    path('<int:pk>/', views.RoleDetailView.as_view(), name='detail'),
]
