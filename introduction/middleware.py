"""
Logging Middleware for SymbPyGoat
=================================

This middleware provides automatic request/response logging and security event tracking
for all incoming HTTP requests. It integrates with the SecurityLogger service to provide
comprehensive logging capabilities.

Features:
- Automatic request/response logging
- Request correlation IDs
- Security event detection
- Rate limiting protection
- Performance monitoring
- Error tracking
"""

import json
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.urls import resolve, Resolver404
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin

from .logging_service import (
    security_logger, 
    set_request_context, 
    clear_request_context,
    LogSanitizer
)


class SecurityLoggingMiddleware(MiddlewareMixin):
    """
    Middleware for comprehensive security logging and monitoring.
    
    This middleware automatically logs all requests and responses,
    tracks security events, and provides rate limiting capabilities.
    """
    
    def __init__(self, get_response):
        """Initialize the middleware."""
        self.get_response = get_response
        self.request_counts = defaultdict(list)  # IP -> list of timestamps
        self.rate_limit_window = getattr(settings, 'LOGGING_RATE_LIMIT_WINDOW', 300)  # 5 minutes
        self.rate_limit_max_requests = getattr(settings, 'LOGGING_RATE_LIMIT_MAX_REQUESTS', 100)
        self.sensitive_paths = getattr(settings, 'LOGGING_SENSITIVE_PATHS', [
            '/admin/', '/login/', '/register/', '/password/', '/api/auth/'
        ])
        self.excluded_paths = getattr(settings, 'LOGGING_EXCLUDED_PATHS', [
            '/static/', '/media/', '/favicon.ico', '/health/', '/ping/'
        ])
        super().__init__(get_response)
    
    def __call__(self, request):
        """Process the request and response."""
        # Skip logging for excluded paths
        if self._should_exclude_path(request.path):
            return self.get_response(request)
        
        # Set up request context
        set_request_context(request)
        
        # Check rate limiting
        if self._is_rate_limited(request):
            security_logger.log_security_event(
                'RATE_LIMIT_EXCEEDED',
                'WARNING',
                'Rate limit exceeded for IP address',
                getattr(request, 'user', {}).get('username', 'anonymous'),
                self._get_client_ip(request),
                {'path': request.path, 'method': request.method}
            )
        
        # Record request start time
        start_time = time.time()
        
        # Log the incoming request
        self._log_request(request)
        
        # Process the request
        response = self.get_response(request)
        
        # Calculate response time
        response_time = time.time() - start_time
        
        # Log the response
        self._log_response(request, response, response_time)
        
        # Detect security events
        self._detect_security_events(request, response)
        
        # Clean up request context
        clear_request_context()
        
        return response
    
    def process_exception(self, request, exception):
        """Log exceptions that occur during request processing."""
        security_logger.log_security_event(
            'REQUEST_EXCEPTION',
            'CRITICAL',
            f'Unhandled exception: {str(exception)}',
            getattr(request, 'user', {}).get('username', 'anonymous'),
            self._get_client_ip(request),
            {
                'exception_type': type(exception).__name__,
                'path': request.path,
                'method': request.method,
                'stack_trace': str(exception)
            }
        )
        return None  # Let Django handle the exception normally
    
    def _should_exclude_path(self, path: str) -> bool:
        """Check if the path should be excluded from logging."""
        return any(path.startswith(excluded) for excluded in self.excluded_paths)
    
    def _is_rate_limited(self, request: HttpRequest) -> bool:
        """Check if the request should be rate limited."""
        ip_address = self._get_client_ip(request)
        current_time = datetime.now()
        
        # Clean old entries
        self.request_counts[ip_address] = [
            timestamp for timestamp in self.request_counts[ip_address]
            if current_time - timestamp < timedelta(seconds=self.rate_limit_window)
        ]
        
        # Add current request
        self.request_counts[ip_address].append(current_time)
        
        # Check if rate limit exceeded
        return len(self.request_counts[ip_address]) > self.rate_limit_max_requests
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip.strip()
    
    def _log_request(self, request: HttpRequest):
        """Log incoming request details."""
        user = getattr(request, 'user', None)
        username = user.username if user and user.is_authenticated else 'anonymous'
        ip_address = self._get_client_ip(request)
        
        # Enhanced logging for sensitive paths
        is_sensitive = any(request.path.startswith(path) for path in self.sensitive_paths)
        
        extra_data = {
            'is_sensitive_path': is_sensitive,
            'content_type': request.content_type,
            'content_length': request.META.get('CONTENT_LENGTH', 0),
            'referer': request.META.get('HTTP_REFERER', ''),
            'accept': request.META.get('HTTP_ACCEPT', ''),
            'accept_language': request.META.get('HTTP_ACCEPT_LANGUAGE', ''),
        }
        
        # Log additional details for sensitive paths
        if is_sensitive:
            security_logger.log_security_event(
                'SENSITIVE_PATH_ACCESS',
                'INFO',
                f'Access to sensitive path: {request.path}',
                username,
                ip_address,
                extra_data
            )
        
        # Log the request using the security logger
        security_logger.log_request(request, extra_data)
    
    def _log_response(self, request: HttpRequest, response: HttpResponse, response_time: float):
        \"\"\"Log response details.\"\"\"
        extra_data = {
            'response_time': response_time,
            'content_type': response.get('Content-Type', ''),
            'content_length': len(getattr(response, 'content', '')),
        }
        
        # Log slow responses
        slow_response_threshold = getattr(settings, 'LOGGING_SLOW_RESPONSE_THRESHOLD', 2.0)
        if response_time > slow_response_threshold:
            security_logger.log_security_event(
                'SLOW_RESPONSE',
                'WARNING',
                f'Slow response detected: {response_time:.2f}s',
                getattr(request, 'user', {}).get('username', 'anonymous'),
                self._get_client_ip(request),
                {
                    'path': request.path,
                    'method': request.method,
                    'response_time': response_time
                }
            )
        
        # Log the response
        security_logger.log_response(request, response, extra_data)
    
    def _detect_security_events(self, request: HttpRequest, response: HttpResponse):
        \"\"\"Detect potential security events based on request/response patterns.\"\"\"
        user = getattr(request, 'user', None)
        username = user.username if user and user.is_authenticated else 'anonymous'
        ip_address = self._get_client_ip(request)
        
        # Detect potential attacks based on status codes
        if response.status_code == 401:
            security_logger.log_security_event(
                'UNAUTHORIZED_ACCESS',
                'WARNING',
                'Unauthorized access attempt detected',
                username,
                ip_address,
                {'path': request.path, 'method': request.method}
            )
        
        elif response.status_code == 403:
            security_logger.log_security_event(
                'FORBIDDEN_ACCESS',
                'WARNING',
                'Forbidden access attempt detected',
                username,
                ip_address,
                {'path': request.path, 'method': request.method}
            )
        
        elif response.status_code == 404:
            # Log 404s for sensitive paths as potential reconnaissance
            if any(request.path.startswith(path) for path in ['/admin/', '/api/', '/.']):
                security_logger.log_security_event(
                    'RECONNAISSANCE_ATTEMPT',
                    'INFO',
                    'Potential reconnaissance attempt detected',
                    username,
                    ip_address,
                    {'path': request.path, 'method': request.method}
                )
        
        elif response.status_code >= 500:
            security_logger.log_security_event(
                'SERVER_ERROR',
                'CRITICAL',
                'Server error occurred',
                username,
                ip_address,
                {
                    'path': request.path,
                    'method': request.method,
                    'status_code': response.status_code
                }
            )
        
        # Detect potential injection attempts in URL parameters
        self._detect_injection_attempts(request, username, ip_address)
        
        # Detect potential file upload attacks
        if request.method == 'POST' and request.FILES:
            self._detect_file_upload_attacks(request, username, ip_address)
    
    def _detect_injection_attempts(self, request: HttpRequest, username: str, ip_address: str):
        \"\"\"Detect potential injection attempts in request parameters.\"\"\"
        suspicious_patterns = [
            # SQL Injection patterns
            r\"(?i)(union|select|insert|update|delete|drop|create|alter)\\s\",
            r\"(?i)(or|and)\\s+\\d+\\s*=\\s*\\d+\",
            r\"(?i)'\\s*(or|and)\\s*'\\w+'\",
            
            # XSS patterns
            r\"(?i)<script[^>]*>\",
            r\"(?i)javascript:\",
            r\"(?i)on\\w+\\s*=\",
            
            # Command injection patterns
            r\"(?i)(;|\\||&|\\$\\()\\s*(ls|cat|pwd|whoami|id|uname)\",
            r\"(?i)\\.\\.[\\/\\\\]\",
            
            # LDAP injection patterns
            r\"(?i)\\(\\|\\(\\w+=\",
            r\"(?i)\\)\\(\\w+=\",
        ]
        
        # Check GET parameters
        for key, value in request.GET.items():
            for pattern in suspicious_patterns:
                import re
                if re.search(pattern, str(value)):
                    security_logger.log_vulnerability_exploitation(
                        'INJECTION_ATTEMPT',
                        username,
                        ip_address,
                        f'{key}={value}',
                        {
                            'parameter': key,
                            'value': LogSanitizer.sanitize(str(value)),
                            'path': request.path,
                            'method': request.method
                        }
                    )
                    break
        
        # Check POST parameters
        if hasattr(request, 'POST'):
            for key, value in request.POST.items():
                for pattern in suspicious_patterns:
                    import re
                    if re.search(pattern, str(value)):
                        security_logger.log_vulnerability_exploitation(
                            'INJECTION_ATTEMPT',
                            username,
                            ip_address,
                            f'{key}=[REDACTED]',
                            {
                                'parameter': key,
                                'path': request.path,
                                'method': request.method
                            }
                        )
                        break
    
    def _detect_file_upload_attacks(self, request: HttpRequest, username: str, ip_address: str):
        \"\"\"Detect potential file upload attacks.\"\"\"
        dangerous_extensions = [
            '.php', '.asp', '.aspx', '.jsp', '.jspx', '.py', '.rb', '.pl',
            '.exe', '.bat', '.cmd', '.sh', '.ps1', '.vbs', '.jar', '.war'
        ]
        
        for field_name, uploaded_file in request.FILES.items():
            file_name = uploaded_file.name.lower() if uploaded_file.name else ''
            
            # Check for dangerous file extensions
            if any(file_name.endswith(ext) for ext in dangerous_extensions):
                security_logger.log_vulnerability_exploitation(
                    'MALICIOUS_FILE_UPLOAD',
                    username,
                    ip_address,
                    f'Dangerous file: {file_name}',
                    {
                        'field_name': field_name,
                        'file_name': file_name,
                        'file_size': uploaded_file.size,
                        'content_type': uploaded_file.content_type,
                        'path': request.path
                    }
                )
            
            # Check for overly large files
            max_file_size = getattr(settings, 'LOGGING_MAX_FILE_SIZE', 10 * 1024 * 1024)  # 10MB
            if uploaded_file.size > max_file_size:
                security_logger.log_security_event(
                    'LARGE_FILE_UPLOAD',
                    'WARNING',
                    f'Large file upload attempt: {uploaded_file.size} bytes',
                    username,
                    ip_address,
                    {
                        'field_name': field_name,
                        'file_name': file_name,
                        'file_size': uploaded_file.size,
                        'path': request.path
                    }
                )


class RequestCorrelationMiddleware(MiddlewareMixin):
    \"\"\"Simple middleware to add correlation IDs to requests.\"\"\"
    
    def process_request(self, request):
        \"\"\"Add a correlation ID to the request.\"\"\"
        import uuid
        request.correlation_id = str(uuid.uuid4())
        return None


class SecurityHeadersMiddleware(MiddlewareMixin):
    \"\"\"Middleware to add security headers and log their usage.\"\"\"
    
    def process_response(self, request, response):
        \"\"\"Add security headers to the response.\"\"\"
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Log when security headers are added
        if hasattr(request, 'user') and request.user.is_authenticated:
            security_logger.log_security_event(
                'SECURITY_HEADERS_ADDED',
                'INFO',
                'Security headers added to response',
                request.user.username,
                self._get_client_ip(request),
                {'path': request.path, 'headers_added': 4}
            )
        
        return response
    
    def _get_client_ip(self, request):
        \"\"\"Get client IP address.\"\"\"
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')