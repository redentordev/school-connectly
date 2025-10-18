"""
Custom error handlers for Connectly API.
Provides secure error responses that don't leak sensitive information.
"""

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import logging

logger = logging.getLogger(__name__)


@csrf_exempt
def custom_404(request, exception=None):
    """
    Custom 404 error handler.
    
    Returns a JSON response with a generic not found message without
    revealing any sensitive information about the application structure.
    
    Args:
        request: The HTTP request object
        exception: Optional exception that triggered the 404
        
    Returns:
        JsonResponse: JSON error response with 404 status
    """
    logger.warning(
        f"404 error: {request.method} {request.path} from {get_client_ip(request)}"
    )
    return JsonResponse({
        'error': 'Not Found',
        'detail': 'The requested resource was not found.',
        'status_code': 404
    }, status=404)


@csrf_exempt
def custom_500(request):
    """
    Custom 500 error handler.
    
    Returns a JSON response with a generic server error message without
    revealing any internal application details, stack traces, or file paths.
    
    Args:
        request: The HTTP request object
        
    Returns:
        JsonResponse: JSON error response with 500 status
    """
    logger.error(
        f"500 error: {request.method} {request.path} from {get_client_ip(request)}",
        exc_info=True
    )
    return JsonResponse({
        'error': 'Internal Server Error',
        'detail': 'An unexpected error occurred. Please try again later.',
        'status_code': 500
    }, status=500)


@csrf_exempt
def custom_403(request, exception=None):
    """
    Custom 403 error handler.
    
    Returns a JSON response for forbidden access attempts without
    revealing details about the permission system.
    
    Args:
        request: The HTTP request object
        exception: Optional exception that triggered the 403
        
    Returns:
        JsonResponse: JSON error response with 403 status
    """
    logger.warning(
        f"403 error: {request.method} {request.path} from {get_client_ip(request)}"
    )
    return JsonResponse({
        'error': 'Forbidden',
        'detail': 'You do not have permission to access this resource.',
        'status_code': 403
    }, status=403)


@csrf_exempt
def custom_400(request, exception=None):
    """
    Custom 400 error handler.
    
    Returns a JSON response for bad requests without revealing
    details about the expected request format.
    
    Args:
        request: The HTTP request object
        exception: Optional exception that triggered the 400
        
    Returns:
        JsonResponse: JSON error response with 400 status
    """
    logger.warning(
        f"400 error: {request.method} {request.path} from {get_client_ip(request)}"
    )
    return JsonResponse({
        'error': 'Bad Request',
        'detail': 'The request could not be understood by the server.',
        'status_code': 400
    }, status=400)


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

