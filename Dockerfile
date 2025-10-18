# Use Python 3.11 slim image as the base
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        postgresql-client \
        build-essential \
        libpq-dev \
        curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create directories for static files and logs
RUN mkdir -p /app/staticfiles /app/logs && \
    chmod -R 755 /app/staticfiles /app/logs

# Collect static files
RUN python manage.py collectstatic --noinput

# Create non-root user and set permissions
RUN useradd -m appuser && \
    chown -R appuser:appuser /app && \
    touch /app/logs/connectly.log && \
    chown appuser:appuser /app/logs/connectly.log
USER appuser

# Run gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "connectly.wsgi:application"] 