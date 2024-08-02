from django.conf.urls.static import static
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import  PreacherViewSet, SermonViewSet


router = DefaultRouter()
router.register(r'preachers', PreacherViewSet)
router.register(r'sermons', SermonViewSet)

urlpatterns = [
    path('', include(router.urls)),
]


