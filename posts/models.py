from django.db import models
from django.core.exceptions import ValidationError
import json

# Create your models here.

class User(models.Model):
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.username


class Post(models.Model):
    POST_TYPES = [
        ('text', 'Text Post'),
        ('image', 'Image Post'),
        ('video', 'Video Post'),
        ('link', 'Link Post'),
    ]

    title = models.CharField(max_length=200, null=True, blank=True)
    content = models.TextField()
    author = models.ForeignKey(User, related_name='posts', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    post_type = models.CharField(max_length=10, choices=POST_TYPES, default='text')
    _metadata = models.TextField(blank=True, null=True, db_column='metadata')

    @property
    def metadata(self):
        """Get the metadata as a dictionary."""
        if self._metadata:
            return json.loads(self._metadata)
        return {}

    @metadata.setter
    def metadata(self, value):
        """Set the metadata, storing it as a JSON string."""
        if value is not None:
            self._metadata = json.dumps(value)
        else:
            self._metadata = None

    def clean(self):
        """Validate the post based on its type."""
        super().clean()
        metadata = self.metadata

        if self.post_type == 'image':
            if not metadata.get('file_size'):
                raise ValidationError({'metadata': 'Image posts require file_size in metadata'})
            if not metadata.get('dimensions'):
                raise ValidationError({'metadata': 'Image posts require dimensions in metadata'})

        elif self.post_type == 'video':
            if not metadata.get('duration'):
                raise ValidationError({'metadata': 'Video posts require duration in metadata'})
            if not metadata.get('file_size'):
                raise ValidationError({'metadata': 'Video posts require file_size in metadata'})

        elif self.post_type == 'link':
            if not metadata.get('url'):
                raise ValidationError({'metadata': 'Link posts require url in metadata'})

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.post_type.capitalize()} post by {self.author.username} at {self.created_at}"


class Comment(models.Model):
    text = models.TextField()
    author = models.ForeignKey(User, related_name='comments', on_delete=models.CASCADE)
    post = models.ForeignKey(Post, related_name='comments', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Comment by {self.author.username} on Post {self.post.id}"
