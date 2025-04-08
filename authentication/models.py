from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class UserProfile(models.Model):
    """Extended user profile with additional fields"""
    
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('user', 'Regular User'),
        ('guest', 'Guest User'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    
    def __str__(self):
        return f"{self.user.username}'s profile"

# Signal to create UserProfile when a User is created
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        # Automatically set admin role for staff users
        if instance.is_staff:
            UserProfile.objects.create(user=instance, role='admin')
        else:
            UserProfile.objects.create(user=instance, role='user')

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    # Check if profile exists before saving
    if hasattr(instance, 'profile'):
        instance.profile.save()
