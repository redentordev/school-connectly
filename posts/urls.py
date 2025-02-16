from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework.authtoken import views as token_views
from .views import UserViewSet, PostViewSet, CommentViewSet

# Create a router and register our viewsets with it.
router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'posts', PostViewSet)
router.register(r'comments', CommentViewSet)

urlpatterns = [
    # Authentication endpoints
    path('api-token-auth/', token_views.obtain_auth_token, name='api-token-auth'),
    
    # API endpoints
    path('', include(router.urls)),
] 