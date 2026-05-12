from django.urls import path
from . import views
from . import live_updates

app_name = 'requests'

urlpatterns = [
    path('', views.DashboardView.as_view(), name='dashboard'),
    path('new/', views.RequestCreateView.as_view(), name='create'),
    path('<int:pk>/', views.RequestDetailView.as_view(), name='detail'),
    path('<int:pk>/approve/', views.ApproveRequestView.as_view(), name='approve'),
    path('<int:pk>/deny/', views.DenyRequestView.as_view(), name='deny'),
    path('pending/', views.PendingApprovalsView.as_view(), name='pending_approvals'),
    path('my/', views.MyRequestsView.as_view(), name='my_requests'),
    path('<int:pk>/revoke/', views.RevokeAccessView.as_view(), name='revoke'),
    path('admin/revoke/<int:pk>/', views.AdminRevokeAccessView.as_view(), name='admin_revoke'),
    path('sessions/', views.ActiveSessionsView.as_view(), name='active_sessions'),
    path('poll/', live_updates.poll_updates, name='poll'),
]
