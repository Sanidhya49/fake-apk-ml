from django.urls import path
from .views import scan_apk

urlpatterns = [
    path("scan/", scan_apk, name="scan_apk"),
]


