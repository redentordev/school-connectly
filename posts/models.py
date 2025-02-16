from django.db import models
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
import json

# Create your models here.

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

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.post_type.capitalize()} post by {self.author.username} at {self.created_at}"


class Comment(models.Model):
    text = models.TextField()
    author = models.ForeignKey(User, related_name='comments', on_delete=models.CASCADE)
    post = models.ForeignKey(Post, related_name='comments', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Comment by {self.author.username} on {self.post.title}'
