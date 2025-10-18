"""
Rate limiting decorators and utilities for Connectly API.
Provides protection against brute force and credential stuffing attacks.
"""

from django_ratelimit.decorators import ratelimit
from django.http import JsonResponse
from functools import wraps
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


def rate_limit_auth(view_func):
    """
    Rate limiter decorator for authentication endpoints.
    
    Applies two-tier rate limiting:
    - 5 attempts per minute per IP address
    - 20 attempts per hour per IP address
    
    This prevents brute force and credential stuffing attacks while
    allowing legitimate users to retry after minor mistakes.
    
    Args:
        view_func: The view function to protect
        
    Returns:
        wrapped: The decorated view function with rate limiting
    """
    @wraps(view_func)
    @ratelimit(key='ip', rate='5/m', method='POST', block=True)
    @ratelimit(key='ip', rate='20/h', method='POST', block=True)
    def wrapped(request, *args, **kwargs):
        # Check if rate limit was hit
        was_limited = getattr(request, 'limited', False)
        if was_limited:
            logger.warning(
                f"Rate limit exceeded for authentication endpoint: "
                f"{request.path} from {get_client_ip(request)}"
            )
            return JsonResponse(
                {
                    'error': 'Too many login attempts. Please try again later.',
                    'detail': 'Rate limit exceeded',
                    'retry_after': '60 seconds'
                },
                status=429
            )
        return view_func(request, *args, **kwargs)
    return wrapped


def rate_limit_api(rate='100/h'):
    """
    General purpose rate limiter for API endpoints.
    
    Args:
        rate: Rate limit string (e.g., '100/h', '10/m')
        
    Returns:
        decorator: A decorator function that applies rate limiting
    """
    def decorator(view_func):
        @wraps(view_func)
        @ratelimit(key='user_or_ip', rate=rate, method=ratelimit.ALL, block=True)
        def wrapped(request, *args, **kwargs):
            was_limited = getattr(request, 'limited', False)
            if was_limited:
                logger.warning(
                    f"Rate limit exceeded for API endpoint: "
                    f"{request.path} from {get_client_ip(request)}"
                )
                return JsonResponse(
                    {
                        'error': 'Too many requests. Please try again later.',
                        'detail': 'Rate limit exceeded'
                    },
                    status=429
                )
            return view_func(request, *args, **kwargs)
        return wrapped
    return decorator


def get_client_ip(request):
    """
    Get the client IP address from the request.
    
    Handles X-Forwarded-For header for proxied requests.
    
    Args:
        request: The HTTP request object
        
    Returns:
        str: The client IP address
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Get the first IP in the chain
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', 'unknown')
    return ip

