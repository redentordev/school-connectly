from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Post, Comment


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'date_joined']
        read_only_fields = ['date_joined']

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = User.objects.create_user(**validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class PostSerializer(serializers.ModelSerializer):
    comments = serializers.StringRelatedField(many=True, read_only=True)
    metadata = serializers.JSONField(required=False)

    class Meta:
        model = Post
        fields = ['id', 'title', 'content', 'author', 'created_at', 'comments', 'post_type', 'metadata']
        read_only_fields = ['author']

    def create(self, validated_data):
        validated_data['author'] = self.context['request'].user
        return super().create(validated_data)

    def validate(self, data):
        """Validate the post data based on post type."""
        post_type = data.get('post_type')
        metadata = data.get('metadata', {})

        if post_type == 'image':
            if not metadata.get('file_size'):
                raise serializers.ValidationError({'metadata': 'Image posts require file_size in metadata'})
            if not metadata.get('dimensions'):
                raise serializers.ValidationError({'metadata': 'Image posts require dimensions in metadata'})
        elif post_type == 'video':
            if not metadata.get('duration'):
                raise serializers.ValidationError({'metadata': 'Video posts require duration in metadata'})
            if not metadata.get('file_size'):
                raise serializers.ValidationError({'metadata': 'Video posts require file_size in metadata'})
        elif post_type == 'link':
            if not metadata.get('url'):
                raise serializers.ValidationError({'metadata': 'Link posts require url in metadata'})

        return data


class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = ['id', 'text', 'author', 'post', 'created_at']
        read_only_fields = ['author']

    def create(self, validated_data):
        validated_data['author'] = self.context['request'].user
        return super().create(validated_data)

    def validate_post(self, value):
        if not Post.objects.filter(id=value.id).exists():
            raise serializers.ValidationError("Post not found.")
        return value 