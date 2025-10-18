"""
Custom middleware for Connectly API.
Provides security-focused middleware including rate limit monitoring and security headers.
"""

import logging
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings

logger = logging.getLogger(__name__)


class RateLimitLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log rate limit violations.
    
    This middleware monitors for 429 (Too Many Requests) responses
    and logs the client IP address for security monitoring.
    """
    
    def process_response(self, request, response):
        """
        Log rate limit violations when 429 status code is returned.
        
        Args:
            request: The HTTP request object
            response: The HTTP response object
            
        Returns:
            response: The unmodified HTTP response
        """
        if response.status_code == 429:
            client_ip = self.get_client_ip(request)
            logger.warning(
                f"Rate limit exceeded: {request.method} {request.path} "
                f"from {client_ip} - User: {request.user if request.user.is_authenticated else 'Anonymous'}"
            )
        return response
    
    def get_client_ip(self, request):
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


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Add comprehensive security headers and remove server information disclosure headers.
    
    This middleware adds modern security headers following OWASP recommendations
    and removes headers that disclose server/framework information.
    """
    
    def process_response(self, request, response):
        """
        Add security headers and remove information disclosure headers.
        
        Args:
            request: The HTTP request object
            response: The HTTP response object
            
        Returns:
            response: The modified HTTP response with security headers
        """
        # Remove server information headers
        if 'Server' in response:
            del response['Server']
        
        if 'X-Powered-By' in response:
            del response['X-Powered-By']
        
        # Add security headers if not already present
        
        # Content Security Policy
        if not response.get('Content-Security-Policy') and not settings.DEBUG:
            csp_directives = [
                "default-src 'self'",
                "script-src 'self' 'unsafe-inline' https://accounts.google.com",
                "style-src 'self' 'unsafe-inline'",
                "img-src 'self' data: https:",
                "font-src 'self' data:",
                "connect-src 'self' https://accounts.google.com https://www.googleapis.com",
                "frame-ancestors 'none'",
                "base-uri 'self'",
                "form-action 'self'",
            ]
            response['Content-Security-Policy'] = '; '.join(csp_directives)
        
        # Permissions Policy (formerly Feature-Policy)
        if not response.get('Permissions-Policy'):
            permissions_policy = [
                "geolocation=()",
                "microphone=()",
                "camera=()",
                "payment=()",
                "usb=()",
                "magnetometer=()",
                "gyroscope=()",
                "accelerometer=()",
            ]
            response['Permissions-Policy'] = ', '.join(permissions_policy)
        
        # Referrer Policy
        if not response.get('Referrer-Policy'):
            response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # X-Content-Type-Options (additional enforcement)
        response['X-Content-Type-Options'] = 'nosniff'
        
        # Remove deprecated X-XSS-Protection header
        # Modern browsers use CSP instead
        if 'X-XSS-Protection' in response:
            del response['X-XSS-Protection']
        
        # Cross-Origin-Opener-Policy
        if not response.get('Cross-Origin-Opener-Policy'):
            response['Cross-Origin-Opener-Policy'] = 'same-origin'
        
        # Cross-Origin-Resource-Policy
        if not response.get('Cross-Origin-Resource-Policy'):
            response['Cross-Origin-Resource-Policy'] = 'same-origin'
        
        # Cross-Origin-Embedder-Policy
        if not response.get('Cross-Origin-Embedder-Policy'):
            response['Cross-Origin-Embedder-Policy'] = 'require-corp'
        
        return response

