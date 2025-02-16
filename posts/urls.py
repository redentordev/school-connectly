from django.urls import path
from rest_framework.authtoken import views as token_views
from .views import UserListCreate, PostListCreate, PostDetailView, CommentListCreate

urlpatterns = [
    # Authentication endpoints
    path('api-token-auth/', token_views.obtain_auth_token, name='api-token-auth'),
    
    # User endpoints
    path('users/', UserListCreate.as_view(), name='user-list-create'),
    
    # Post endpoints
    path('posts/', PostListCreate.as_view(), name='post-list-create'),
    path('posts/<int:pk>/', PostDetailView.as_view(), name='post-detail'),
    
    # Comment endpoints
    path('comments/', CommentListCreate.as_view(), name='comment-list-create'),
] 