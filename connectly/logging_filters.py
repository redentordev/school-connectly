"""
Logging filters for Connectly API.
Provides security-focused filtering to redact sensitive information from logs.
"""

import re
import logging


class SensitiveDataFilter(logging.Filter):
    """
    Filter to redact sensitive information from logs.
    
    This filter prevents the following sensitive data from appearing in logs:
    - DRF Authentication Tokens (40-character hex strings)
    - JWT Bearer tokens
    - Authorization headers
    - OAuth access tokens
    - API keys
    - Google OAuth tokens
    """
    
    # Compiled regex patterns for performance
    PATTERNS = [
        # DRF Token format: Token abc123...
        (re.compile(r'(Token\s+)([a-f0-9]{40})', re.IGNORECASE), r'\1[REDACTED-TOKEN]'),
        
        # Bearer token format (JWT)
        (re.compile(r'(Bearer\s+)([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)', re.IGNORECASE), r'\1[REDACTED-JWT]'),
        
        # Authorization header in various formats
        (re.compile(r'(Authorization["\']?\s*[:=]\s*["\']?)([^"\'}\s\n]+)'), r'\1[REDACTED-AUTH]'),
        
        # access_token in JSON/query strings
        (re.compile(r'(access_token["\']?\s*[:=]\s*["\']?)([^"\'&\s}\n]+)'), r'\1[REDACTED-ACCESS-TOKEN]'),
        
        # token field in JSON responses
        (re.compile(r'(["\']?token["\']?\s*:\s*["\']?)([a-f0-9]{40}|[A-Za-z0-9\-_]{20,})'), r'\1[REDACTED-TOKEN]'),
        
        # API keys (generic pattern)
        (re.compile(r'(api[_-]?key["\']?\s*[:=]\s*["\']?)([^"\'&\s}\n]+)', re.IGNORECASE), r'\1[REDACTED-API-KEY]'),
        
        # Password fields in logs
        (re.compile(r'(password["\']?\s*[:=]\s*["\']?)([^"\'&\s}\n]+)', re.IGNORECASE), r'\1[REDACTED-PASSWORD]'),
        
        # Secret fields
        (re.compile(r'(secret["\']?\s*[:=]\s*["\']?)([^"\'&\s}\n]+)', re.IGNORECASE), r'\1[REDACTED-SECRET]'),
        
        # Google OAuth tokens (longer format)
        (re.compile(r'(ya29\.[A-Za-z0-9\-_]+)'), r'[REDACTED-GOOGLE-TOKEN]'),
    ]
    
    def filter(self, record):
        """
        Filter a log record, redacting sensitive information.
        
        Args:
            record: The log record to filter
            
        Returns:
            bool: Always returns True to allow the record through after redaction
        """
        # Redact the main message
        if isinstance(record.msg, str):
            record.msg = self._redact_string(record.msg)
        
        # Also filter args if they exist
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._redact_value(v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self._redact_value(arg) for arg in record.args)
        
        return True
    
    def _redact_string(self, text):
        """
        Apply all redaction patterns to a string.
        
        Args:
            text: The string to redact
            
        Returns:
            str: The redacted string
        """
        if not isinstance(text, str):
            return text
            
        for pattern, replacement in self.PATTERNS:
            text = pattern.sub(replacement, text)
        
        return text
    
    def _redact_value(self, value):
        """
        Redact a value of any type.
        
        Args:
            value: The value to redact (can be str, dict, list, etc.)
            
        Returns:
            The redacted value
        """
        if isinstance(value, str):
            return self._redact_string(value)
        elif isinstance(value, dict):
            return {k: self._redact_value(v) for k, v in value.items()}
        elif isinstance(value, (list, tuple)):
            return type(value)(self._redact_value(item) for item in value)
        else:
            return value

