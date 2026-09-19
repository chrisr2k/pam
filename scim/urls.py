from django.urls import path
from . import views

app_name = 'scim'

urlpatterns = [
    path('v2/', views.service_provider_config, name='v2_root'),
    path('v2/Users', views.users_collection, name='users'),
    path('v2/Users/<str:resource_id>', views.user_resource, name='user'),
    path('v2/Groups', views.groups_collection, name='groups'),
    path('v2/Groups/<str:resource_id>', views.group_resource, name='group'),
    path('v2/ServiceProviderConfig', views.service_provider_config,
         name='service_provider_config'),
    path('v2/Schemas', views.schemas, name='schemas'),
    path('v2/Schemas/<str:schema_id>', views.schema_resource, name='schema'),
    path('v2/ResourceTypes', views.resource_types, name='resource_types'),
    path('settings/', views.SCIMSettingsView.as_view(), name='settings'),
]
