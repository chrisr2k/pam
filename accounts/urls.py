from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('login/', views.LoginView.as_view(), name='login'),
    path('local-login/', views.LocalLoginView.as_view(), name='local_login'),
    path('callback/', views.OIDCCallbackView.as_view(), name='callback'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('profile/', views.ProfileView.as_view(), name='profile'),
    path('entra-setup/', views.EntraSetupView.as_view(), name='entra_setup'),
    path('aws-setup/', views.AWSSetupView.as_view(), name='aws_setup'),
]


