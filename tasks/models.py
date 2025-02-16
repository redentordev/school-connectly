from django.db import models

# Create your models here.

# User model representing system users
class User(models.Model):
    username = models.CharField(max_length=100, unique=True)  # Ensure unique usernames
    email = models.EmailField(unique=True)  # Enforce unique email addresses
    created_at = models.DateTimeField(auto_now_add=True)  # Automatically set creation timestamp

    def __str__(self):
        return self.username


# Task model linked to User through a ForeignKey
class Task(models.Model):
    title = models.CharField(max_length=255)  # Task title with a max length
    description = models.TextField()  # Optional detailed task description
    assigned_to = models.ForeignKey(
        User,
        related_name='tasks',
        on_delete=models.CASCADE  # Delete tasks if the user is deleted
    )
    created_at = models.DateTimeField(auto_now_add=True)  # Automatically set creation timestamp

    def __str__(self):
        return f"Task: {self.title} assigned to {self.assigned_to.username}"
