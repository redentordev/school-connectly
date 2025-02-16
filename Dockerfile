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
        dos2unix \
        netcat-traditional \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Fix line endings and make entrypoint executable
RUN dos2unix docker-entrypoint.sh && \
    chmod +x docker-entrypoint.sh

# Verify management commands are present
RUN test -d connectly/management/commands || (echo "Management commands directory not found" && exit 1)
RUN test -f connectly/management/commands/wait_for_db.py || (echo "wait_for_db.py not found" && exit 1)

# Create directory for static files and set permissions
RUN mkdir -p /app/staticfiles && \
    chmod -R 755 /app/staticfiles

# Collect static files
RUN python manage.py collectstatic --noinput

# Create non-root user and set permissions
RUN useradd -m appuser && \
    chown -R appuser:appuser /app
USER appuser

# Health check using netcat
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD nc -z localhost 8000 || exit 1

# Use entrypoint script
CMD ["/app/docker-entrypoint.sh"] 