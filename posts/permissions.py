from rest_framework.permissions import BasePermission, SAFE_METHODS

class IsPostAuthor(BasePermission):
    """
    Custom permission to only allow authors of a post to edit or delete it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in SAFE_METHODS:
            return True

        # Write permissions are only allowed to the author of the post
        return obj.author == request.user

class IsAdminOrReadOnly(BasePermission):
    """
    Custom permission to only allow admins to create/edit/delete,
    but allow anyone to view.
    """
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True
        return request.user and request.user.is_staff 