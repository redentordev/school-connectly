from rest_framework import serializers
from .models import User, Task


# Serializer for User model
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'created_at']


# Serializer for Task model with validation for assigned_to
class TaskSerializer(serializers.ModelSerializer):
    # String representation of the assigned user for readability in GET requests
    assigned_to_name = serializers.StringRelatedField(source='assigned_to', read_only=True)

    class Meta:
        model = Task
        fields = ['id', 'title', 'description', 'assigned_to', 'assigned_to_name', 'created_at']

    def validate_assigned_to(self, value):
        try:
            # Check if the user exists
            if isinstance(value, User):
                user_id = value.id
            else:
                user_id = int(value)
            
            if not User.objects.filter(id=user_id).exists():
                raise serializers.ValidationError("Assigned user does not exist.")
            return value
        except (ValueError, TypeError):
            raise serializers.ValidationError("Invalid user ID format.") 