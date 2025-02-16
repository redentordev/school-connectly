from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework.authtoken.views import obtain_auth_token
from .views import UserViewSet, PostViewSet, CommentViewSet

# Create a router and register our viewsets with it.
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'posts', PostViewSet, basename='post')
router.register(r'comments', CommentViewSet, basename='comment')

# Wire up our API using automatic URL routing.
urlpatterns = [
    # Authentication endpoints
    path('auth/token/', obtain_auth_token, name='api-token-auth'),
    
    # API endpoints
    path('', include(router.urls)),
] 