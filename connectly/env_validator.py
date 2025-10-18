"""
Environment variable validator for Connectly API.
Ensures all required configuration is present before application starts.
"""

import os
import sys
from django.core.exceptions import ImproperlyConfigured


# Required environment variables for all environments
REQUIRED_ENV_VARS = [
    'SECRET_KEY',
    'DATABASE_URL',
]

# Required environment variables for production (when DEBUG=False)
PRODUCTION_REQUIRED_ENV_VARS = [
    'DJANGO_ALLOWED_HOSTS',
    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',
]

# Optional but recommended environment variables
RECOMMENDED_ENV_VARS = [
    'REDIS_URL',
    'ADMIN_EMAIL',
]


def validate_environment():
    """
    Validate that required environment variables are set.
    
    Raises:
        ImproperlyConfigured: If required environment variables are missing
    """
    missing_vars = []
    warnings = []
    
    # Check required vars
    for var in REQUIRED_ENV_VARS:
        value = os.getenv(var)
        if not value:
            missing_vars.append(var)
        elif var == 'SECRET_KEY' and 'django-insecure' in value:
            warnings.append(
                f"WARNING: {var} contains 'django-insecure' - "
                "this should not be used in production!"
            )
    
    # Check production-specific vars if not in debug mode
    debug = os.getenv('DEBUG', 'False').lower() in ('true', '1', 't')
    if not debug:
        for var in PRODUCTION_REQUIRED_ENV_VARS:
            if not os.getenv(var):
                missing_vars.append(var)
        
        # Check ALLOWED_HOSTS is not empty in production
        allowed_hosts = os.getenv('DJANGO_ALLOWED_HOSTS', '')
        if not allowed_hosts or allowed_hosts.strip() == '':
            warnings.append(
                "WARNING: DJANGO_ALLOWED_HOSTS is empty in production mode. "
                "The application will not accept any requests!"
            )
    
    # Check recommended vars
    for var in RECOMMENDED_ENV_VARS:
        if not os.getenv(var):
            warnings.append(
                f"RECOMMENDED: {var} is not set. "
                f"Some features may not work optimally."
            )
    
    # Print warnings to stderr
    for warning in warnings:
        sys.stderr.write(f"\033[93m{warning}\033[0m\n")
    
    # Raise exception if required vars are missing
    if missing_vars:
        raise ImproperlyConfigured(
            f"\n\nMissing required environment variables: {', '.join(missing_vars)}\n"
            f"Please set these in your .env file or environment.\n"
            f"See .env.example for a template.\n"
        )
    
    return True


def get_secret_key():
    """
    Get SECRET_KEY from environment with validation.
    
    Returns:
        str: The SECRET_KEY value
        
    Raises:
        ImproperlyConfigured: If SECRET_KEY is not set or invalid
    """
    secret_key = os.getenv('SECRET_KEY')
    
    if not secret_key:
        raise ImproperlyConfigured(
            "SECRET_KEY environment variable is required. "
            "Generate one with: python -c 'from django.core.management.utils "
            "import get_random_secret_key; print(get_random_secret_key())'"
        )
    
    if len(secret_key) < 50:
        sys.stderr.write(
            "\033[93mWARNING: SECRET_KEY is very short. "
            "Consider generating a longer key for better security.\033[0m\n"
        )
    
    return secret_key


def get_debug_mode():
    """
    Get DEBUG mode from environment with safe defaults.
    
    Returns:
        bool: True if DEBUG mode is enabled, False otherwise
    """
    debug_str = os.getenv('DEBUG', 'False')
    debug = debug_str.lower() in ('true', '1', 't', 'yes')
    
    if debug:
        sys.stderr.write(
            "\033[93mWARNING: DEBUG mode is ENABLED. "
            "This should be False in production!\033[0m\n"
        )
    
    return debug


def get_allowed_hosts():
    """
    Get ALLOWED_HOSTS from environment with validation.
    
    Returns:
        list: List of allowed host names
    """
    allowed_hosts_str = os.getenv('DJANGO_ALLOWED_HOSTS', '')
    
    if not allowed_hosts_str:
        debug = get_debug_mode()
        if not debug:
            sys.stderr.write(
                "\033[91mERROR: DJANGO_ALLOWED_HOSTS is empty in production mode!\033[0m\n"
            )
        return []
    
    # Split by comma and strip whitespace
    allowed_hosts = [host.strip() for host in allowed_hosts_str.split(',') if host.strip()]
    
    return allowed_hosts

