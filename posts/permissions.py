from rest_framework import permissions
from authentication.models import UserProfile

class IsPostAuthor(permissions.BasePermission):
    """
    Custom permission to only allow authors of a post to edit or delete it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            # For private posts, additional checks needed even for read operations
            if hasattr(obj, 'privacy') and obj.privacy == 'private':
                if not request.user.is_authenticated:
                    return False
                
                # Author can always see their own posts
                if obj.author == request.user:
                    return True
                
                # Admins can see all posts
                if request.user.is_staff or (hasattr(request.user, 'profile') and request.user.profile.role == 'admin'):
                    return True
                
                # Deny access for non-admins to private posts
                return False
            
            # For public posts, allow read access
            return True

        # Anonymous users cannot edit or delete
        if not request.user.is_authenticated:
            return False

        # Write permissions are only allowed to the author of the post
        # or admin users
        if request.user.is_staff or (hasattr(request.user, 'profile') and request.user.profile.role == 'admin'):
            return True
            
        return obj.author == request.user

class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow admins to create/edit/delete,
    but allow anyone to view.
    """
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
            
        # Check authentication first
        if not request.user.is_authenticated:
            return False
            
        return request.user.is_staff

class IsAuthorOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow authors of an object to edit it.
    """

    def has_permission(self, request, view):
        # Read permissions are allowed to any request
        if request.method in permissions.SAFE_METHODS:
            return True
            
        # Write permissions are only allowed to authenticated users
        return request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            # For posts, check privacy settings
            if hasattr(obj, 'privacy') and obj.privacy == 'private':
                if not request.user.is_authenticated:
                    return False
                    
                # Author can see their own posts
                if hasattr(obj, 'author') and obj.author == request.user:
                    return True
                    
                # Admins can see all posts
                if request.user.is_staff or (hasattr(request.user, 'profile') and request.user.profile.role == 'admin'):
                    return True
                    
                # Deny access for non-admins to private posts
                return False
                
            return True

        # Anonymous users cannot edit or delete
        if not request.user.is_authenticated:
            return False

        # Write permissions are only allowed to the author of the object
        # or admin users
        if request.user.is_staff or (hasattr(request.user, 'profile') and request.user.profile.role == 'admin'):
            return True
            
        # For author-owned objects
        if hasattr(obj, 'author'):
            return obj.author == request.user
            
        # For user-owned objects
        if hasattr(obj, 'user'):
            return obj.user == request.user
            
        return False

class HasAdminRole(permissions.BasePermission):
    """
    Permission that checks if the user has admin role.
    """
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        
        try:
            return request.user.profile.role == 'admin' or request.user.is_staff
        except UserProfile.DoesNotExist:
            return False

class HasUserRole(permissions.BasePermission):
    """
    Permission that checks if the user has at least user role (not guest).
    """
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        
        try:
            return request.user.profile.role in ['user', 'admin'] or request.user.is_staff
        except UserProfile.DoesNotExist:
            return False

class CanAccessPrivatePost(permissions.BasePermission):
    """
    Permission for accessing posts based on privacy settings.
    """
    def has_object_permission(self, request, view, obj):
        # If the post is public, anyone can access
        if not hasattr(obj, 'privacy'):
            return True
            
        if obj.privacy == 'public':
            return True
        
        # For private posts, user must be authenticated
        if not request.user.is_authenticated:
            return False
            
        # If the post is private, only the author or admins can access
        if obj.author == request.user:
            return True
            
        if request.user.is_staff:
            return True
            
        if hasattr(request.user, 'profile') and request.user.profile.role == 'admin':
            return True
            
        # If the user doesn't meet any of the above conditions, deny access
        return False

class AllowAnyForPublicPostsOnly(permissions.BasePermission):
    """
    Permission that allows anyone to view public posts, but requires 
    authentication for private posts.
    """
    def has_permission(self, request, view):
        # Always allow listing (we'll filter in the queryset)
        if view.action == 'list':
            return True
            
        # For other actions, defer to object permission checks
        return True
        
    def has_object_permission(self, request, view, obj):
        # For public posts, allow anyone
        if hasattr(obj, 'privacy') and obj.privacy == 'public':
            return True
            
        # For private posts, require authentication
        if not request.user.is_authenticated:
            return False
            
        # Author can always access their own posts
        if obj.author == request.user:
            return True
            
        # Admins can access any post
        if request.user.is_staff or (hasattr(request.user, 'profile') and request.user.profile.role == 'admin'):
            return True
            
        # Otherwise deny access to private posts
        return False

class GuestCannotDeleteContent(permissions.BasePermission):
    """
    Permission that prevents guest users from deleting any content
    """
    def has_permission(self, request, view):
        # Only check for DELETE requests
        if request.method != 'DELETE':
            return True
            
        # Anonymous users cannot delete
        if not request.user.is_authenticated:
            return False
            
        # Guests cannot delete
        if hasattr(request.user, 'profile') and request.user.profile.role == 'guest':
            return False
            
        return True
        
    def has_object_permission(self, request, view, obj):
        # Only check for DELETE requests
        if request.method != 'DELETE':
            return True
            
        # Anonymous users cannot delete
        if not request.user.is_authenticated:
            return False
            
        # Guests cannot delete
        if hasattr(request.user, 'profile') and request.user.profile.role == 'guest':
            return False
            
        # Admin can delete any content
        if request.user.is_staff or (hasattr(request.user, 'profile') and request.user.profile.role == 'admin'):
            return True
            
        # Authors can delete their own content
        if hasattr(obj, 'author') and obj.author == request.user:
            return True
            
        # Users can delete their own likes, etc.
        if hasattr(obj, 'user') and obj.user == request.user:
            return True
            
        return False 