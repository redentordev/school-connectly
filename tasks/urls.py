from django.urls import path
from .views import UserListCreate, TaskListCreate


urlpatterns = [
    path('users/', UserListCreate.as_view(), name='user-list-create'),
    path('tasks/', TaskListCreate.as_view(), name='task-list-create'),
] 