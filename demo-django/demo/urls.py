from django.contrib import admin
from django.urls import path

from .views import sso, slo, sls, acs, index, player_sso, metadata
admin.autodiscover()

urlpatterns = [
    path('', index, name='index'),
    path('sso/<str:provider>/', sso, name="sso"),
    path('acs/<str:provider>/', acs, name="acs"),
    path('slo/<str:provider>/', slo, name="slo"),
    path('sls/<str:provider>/', sls, name="sls"),
    path('player_sso/<str:provider>/<str:player_uuid>/', player_sso, name="player_sso"),
    path('metadata/<str:provider>/', metadata, name='metadata'),
]
