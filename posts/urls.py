from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework.authtoken import views as auth_views
from .views import UserViewSet, PostViewSet, CommentViewSet

# Create a router and register our viewsets with it.
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'posts', PostViewSet, basename='post')
router.register(r'comments', CommentViewSet, basename='comment')

# Register custom actions
post_feed = PostViewSet.as_view({
    'get': 'feed',
})

# Wire up our API using automatic URL routing.
urlpatterns = [
    # Authentication endpoints
    path('auth-token/', auth_views.obtain_auth_token, name='api-token-auth'),
    
    # API endpoints
    path('', include(router.urls)),
    path('feed/', post_feed, name='post-feed'),
] 