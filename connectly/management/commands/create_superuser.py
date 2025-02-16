from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db import DatabaseError
from django.conf import settings
import os
import time

class Command(BaseCommand):
    help = 'Creates a superuser if none exists'

    def handle(self, *args, **options):
        User = get_user_model()
        
        # Wait for database to be ready
        max_tries = 5
        current_try = 0
        while current_try < max_tries:
            try:
                self.stdout.write('Attempting to create superuser...')
                
                # Check if superuser exists
                if User.objects.filter(is_superuser=True).exists():
                    self.stdout.write(self.style.SUCCESS('Superuser already exists. Skipping creation.'))
                    return
                
                # Get credentials from environment
                username = os.getenv('DJANGO_SUPERUSER_USERNAME')
                email = os.getenv('DJANGO_SUPERUSER_EMAIL')
                password = os.getenv('DJANGO_SUPERUSER_PASSWORD')
                
                # Validate credentials
                if not all([username, email, password]):
                    self.stdout.write(self.style.WARNING(
                        'Missing required environment variables for superuser creation.\n'
                        'Required variables: DJANGO_SUPERUSER_USERNAME, DJANGO_SUPERUSER_EMAIL, DJANGO_SUPERUSER_PASSWORD'
                    ))
                    return
                
                # Create superuser
                self.stdout.write(f'Creating superuser with username: {username}')
                superuser = User.objects.create_superuser(
                    username=username,
                    email=email,
                    password=password
                )
                self.stdout.write(self.style.SUCCESS(f'Superuser {username} created successfully!'))
                return
                
            except DatabaseError as e:
                current_try += 1
                if current_try == max_tries:
                    self.stdout.write(self.style.ERROR(
                        f'Failed to connect to database after {max_tries} attempts. Error: {str(e)}'
                    ))
                    raise
                self.stdout.write(self.style.WARNING(
                    f'Database not ready (attempt {current_try}/{max_tries}). Waiting 2 seconds...'
                ))
                time.sleep(2) 