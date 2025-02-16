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
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Verify management commands are present
RUN test -d connectly/management/commands || (echo "Management commands directory not found" && exit 1)
RUN test -f connectly/management/commands/wait_for_db.py || (echo "wait_for_db.py not found" && exit 1)

# Create directory for static files and set permissions
RUN mkdir -p /app/staticfiles && \
    chmod -R 755 /app/staticfiles

# Collect static files
RUN python manage.py collectstatic --noinput

# Set up entrypoint script
RUN chmod +x /app/docker-entrypoint.sh

# Create non-root user and set permissions
RUN useradd -m appuser && \
    chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/admin/')"

# Use entrypoint script
CMD ["/app/docker-entrypoint.sh"] 