#!/bin/sh

# Wait for database
echo "Waiting for database..."
python manage.py wait_for_db

# Apply database migrations
echo "Applying database migrations..."
python manage.py migrate

# Create superuser if needed
echo "Creating/updating superuser..."
python manage.py create_superuser

# Start Gunicorn
echo "Starting Gunicorn..."
exec gunicorn --bind 0.0.0.0:8000 connectly.wsgi:application 