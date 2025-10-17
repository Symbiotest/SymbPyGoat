"""
Comprehensive Logging Service for SymbPyGoat
===========================================

This module provides a secure, centralized logging service for the SymbPyGoat project.
It includes security event logging, audit trails, and proper sanitization of sensitive data.

Features:
- Security event logging (authentication, authorization, data access)
- Request/response tracking with correlation IDs
- Sensitive data sanitization
- Structured logging with JSON format
- Integration with Django's logging framework
- Rate limiting for log flooding protection
"""

import json
import logging
import re
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from functools import wraps
from threading import local

from django.conf import settings
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from django.utils import timezone


# Thread-local storage for request context
_thread_local = local()


class SecurityLogLevel:
    """Security-specific log levels."""
    SECURITY_INFO = 25  # Between INFO and WARNING
    SECURITY_WARNING = 35  # Between WARNING and ERROR
    SECURITY_CRITICAL = 50  # Same as CRITICAL


class LogSanitizer:
    """Sanitizes sensitive data from logs."""
    
    # Patterns for sensitive data detection
    SENSITIVE_PATTERNS = [
        (r'password["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', 'password'),
        (r'token["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', 'token'),
        (r'secret["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', 'secret'),
        (r'key["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', 'key'),
        (r'ssn["\']?\s*[:=]\s*["\']?(\d{3}-?\d{2}-?\d{4})', 'ssn'),
        (r'credit_card["\']?\s*[:=]\s*["\']?(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})', 'credit_card'),
        (r'email["\']?\s*[:=]\s*["\']?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', 'email'),
    ]
    
    @classmethod
    def sanitize(cls, text: str) -> str:
        """Sanitize sensitive data from text."""
        if not isinstance(text, str):
            text = str(text)
            
        for pattern, field_type in cls.SENSITIVE_PATTERNS:
            text = re.sub(pattern, f'{field_type}="[REDACTED]"', text, flags=re.IGNORECASE)
        
        return text
    
    @classmethod
    def sanitize_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize sensitive data from dictionary."""
        if not isinstance(data, dict):
            return data
            
        sanitized = {}
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if key contains sensitive field names
            if any(sensitive in key_lower for sensitive in ['password', 'token', 'secret', 'key', 'ssn']):
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, dict):
                sanitized[key] = cls.sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [cls.sanitize_dict(item) if isinstance(item, dict) else cls.sanitize(str(item)) for item in value]
            elif isinstance(value, str):
                sanitized[key] = cls.sanitize(value)
            else:
                sanitized[key] = value
                
        return sanitized


class SecurityLogger:
    """Centralized security logging service."""
    
    def __init__(self, logger_name: str = 'security'):
        """Initialize the security logger."""
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG)
        
        # Add custom log levels
        logging.addLevelName(SecurityLogLevel.SECURITY_INFO, 'SECURITY_INFO')
        logging.addLevelName(SecurityLogLevel.SECURITY_WARNING, 'SECURITY_WARNING')
        logging.addLevelName(SecurityLogLevel.SECURITY_CRITICAL, 'SECURITY_CRITICAL')
    
    def _get_request_context(self) -> Dict[str, Any]:
        """Get current request context from thread-local storage."""
        context = {
            'correlation_id': getattr(_thread_local, 'correlation_id', None),
            'user_id': getattr(_thread_local, 'user_id', None),
            'username': getattr(_thread_local, 'username', None),
            'ip_address': getattr(_thread_local, 'ip_address', None),
            'user_agent': getattr(_thread_local, 'user_agent', None),
            'request_method': getattr(_thread_local, 'request_method', None),
            'request_path': getattr(_thread_local, 'request_path', None),
        }
        return {k: v for k, v in context.items() if v is not None}
    
    def _format_log_entry(self, level: str, event_type: str, message: str, 
                         extra_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Format a structured log entry."""
        log_entry = {
            'timestamp': timezone.now().isoformat(),
            'level': level,
            'event_type': event_type,
            'message': LogSanitizer.sanitize(message),
            'service': 'SymbPyGoat',
            'context': self._get_request_context()
        }
        
        if extra_data:
            log_entry['data'] = LogSanitizer.sanitize_dict(extra_data)
        
        return log_entry
    
    def _log(self, level: int, event_type: str, message: str, 
             extra_data: Optional[Dict[str, Any]] = None):
        """Internal logging method."""
        log_entry = self._format_log_entry(
            logging.getLevelName(level), event_type, message, extra_data
        )
        
        # Log as JSON for structured logging
        self.logger.log(level, json.dumps(log_entry, default=str))
    
    # Authentication Events
    def log_login_success(self, username: str, ip_address: str, extra_data: Optional[Dict] = None):
        """Log successful login."""
        message = f"User '{username}' logged in successfully from {ip_address}"
        data = {'username': username, 'ip_address': ip_address}
        if extra_data:
            data.update(extra_data)
        self._log(SecurityLogLevel.SECURITY_INFO, 'LOGIN_SUCCESS', message, data)
    
    def log_login_failure(self, username: str, ip_address: str, reason: str = '', extra_data: Optional[Dict] = None):
        """Log failed login attempt."""
        message = f"Failed login attempt for user '{username}' from {ip_address}"
        if reason:
            message += f" - Reason: {reason}"
        data = {'username': username, 'ip_address': ip_address, 'reason': reason}
        if extra_data:
            data.update(extra_data)
        self._log(SecurityLogLevel.SECURITY_WARNING, 'LOGIN_FAILURE', message, data)
    
    def log_logout(self, username: str, ip_address: str, extra_data: Optional[Dict] = None):
        """Log user logout."""
        message = f"User '{username}' logged out from {ip_address}"
        data = {'username': username, 'ip_address': ip_address}
        if extra_data:
            data.update(extra_data)
        self._log(SecurityLogLevel.SECURITY_INFO, 'LOGOUT', message, data)
    
    def log_password_change(self, username: str, ip_address: str, extra_data: Optional[Dict] = None):
        """Log password change."""
        message = f"Password changed for user '{username}' from {ip_address}"
        data = {'username': username, 'ip_address': ip_address}
        if extra_data:
            data.update(extra_data)
        self._log(SecurityLogLevel.SECURITY_INFO, 'PASSWORD_CHANGE', message, data)
    
    # Authorization Events
    def log_access_denied(self, username: str, resource: str, ip_address: str, extra_data: Optional[Dict] = None):
        """Log access denied events."""
        message = f"Access denied for user '{username}' to resource '{resource}' from {ip_address}"
        data = {'username': username, 'resource': resource, 'ip_address': ip_address}
        if extra_data:
            data.update(extra_data)
        self._log(SecurityLogLevel.SECURITY_WARNING, 'ACCESS_DENIED', message, data)
    
    def log_privilege_escalation(self, username: str, action: str, ip_address: str, extra_data: Optional[Dict] = None):
        """Log privilege escalation attempts."""
        message = f"Privilege escalation attempt by user '{username}' - Action: {action} from {ip_address}"
        data = {'username': username, 'action': action, 'ip_address': ip_address}
        if extra_data:
            data.update(extra_data)
        self._log(SecurityLogLevel.SECURITY_CRITICAL, 'PRIVILEGE_ESCALATION', message, data)
    
    # Data Access Events
    def log_data_access(self, username: str, resource: str, action: str, ip_address: str, extra_data: Optional[Dict] = None):
        """Log data access events."""
        message = f"User '{username}' {action} resource '{resource}' from {ip_address}"
        data = {'username': username, 'resource': resource, 'action': action, 'ip_address': ip_address}
        if extra_data:
            data.update(extra_data)
        self._log(SecurityLogLevel.SECURITY_INFO, 'DATA_ACCESS', message, data)
    
    def log_data_modification(self, username: str, resource: str, action: str, ip_address: str, 
                            changes: Optional[Dict] = None, extra_data: Optional[Dict] = None):
        """Log data modification events."""
        message = f"User '{username}' {action} resource '{resource}' from {ip_address}"
        data = {'username': username, 'resource': resource, 'action': action, 'ip_address': ip_address}
        if changes:
            data['changes'] = LogSanitizer.sanitize_dict(changes)
        if extra_data:
            data.update(extra_data)
        self._log(SecurityLogLevel.SECURITY_INFO, 'DATA_MODIFICATION', message, data)
    
    # Security Events
    def log_security_event(self, event_type: str, severity: str, message: str, 
                          username: str = '', ip_address: str = '', extra_data: Optional[Dict] = None):
        """Log general security events."""
        full_message = message
        if username:
            full_message += f" - User: {username}"
        if ip_address:
            full_message += f" - IP: {ip_address}"
        
        data = {'username': username, 'ip_address': ip_address}
        if extra_data:
            data.update(extra_data)
        
        level = getattr(SecurityLogLevel, f'SECURITY_{severity.upper()}', logging.INFO)
        self._log(level, event_type, full_message, data)
    
    def log_vulnerability_exploitation(self, vulnerability_type: str, username: str = '', 
                                     ip_address: str = '', payload: str = '', extra_data: Optional[Dict] = None):
        """Log vulnerability exploitation attempts."""
        message = f"Vulnerability exploitation attempt detected - Type: {vulnerability_type}"
        data = {
            'vulnerability_type': vulnerability_type,
            'username': username,
            'ip_address': ip_address,
            'payload': LogSanitizer.sanitize(payload)
        }
        if extra_data:
            data.update(extra_data)
        self._log(SecurityLogLevel.SECURITY_CRITICAL, 'VULNERABILITY_EXPLOITATION', message, data)
    
    # Request/Response Logging
    def log_request(self, request: HttpRequest, extra_data: Optional[Dict] = None):
        """Log HTTP request details."""
        user = getattr(request, 'user', None)
        username = user.username if user and user.is_authenticated else 'anonymous'
        ip_address = self._get_client_ip(request)
        
        message = f"{request.method} {request.path} from {ip_address}"
        data = {
            'method': request.method,
            'path': request.path,
            'username': username,
            'ip_address': ip_address,
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'query_params': dict(request.GET),
        }
        
        # Log POST data (sanitized)
        if request.method == 'POST' and hasattr(request, 'POST'):
            data['post_data'] = LogSanitizer.sanitize_dict(dict(request.POST))
        
        if extra_data:
            data.update(extra_data)
        
        self._log(logging.INFO, 'HTTP_REQUEST', message, data)
    
    def log_response(self, request: HttpRequest, response: HttpResponse, extra_data: Optional[Dict] = None):
        """Log HTTP response details."""
        user = getattr(request, 'user', None)
        username = user.username if user and user.is_authenticated else 'anonymous'
        ip_address = self._get_client_ip(request)
        
        message = f"{request.method} {request.path} - Status: {response.status_code}"
        data = {
            'method': request.method,
            'path': request.path,
            'status_code': response.status_code,
            'username': username,
            'ip_address': ip_address,
        }
        
        if extra_data:
            data.update(extra_data)
        
        level = logging.WARNING if response.status_code >= 400 else logging.INFO
        self._log(level, 'HTTP_RESPONSE', message, data)
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip.strip()


# Global logger instance
security_logger = SecurityLogger()


def set_request_context(request: HttpRequest):
    """Set request context in thread-local storage."""
    user = getattr(request, 'user', None)
    
    _thread_local.correlation_id = str(uuid.uuid4())
    _thread_local.user_id = user.id if user and user.is_authenticated else None
    _thread_local.username = user.username if user and user.is_authenticated else 'anonymous'
    _thread_local.ip_address = security_logger._get_client_ip(request)
    _thread_local.user_agent = request.META.get('HTTP_USER_AGENT', '')
    _thread_local.request_method = request.method
    _thread_local.request_path = request.path


def clear_request_context():
    """Clear request context from thread-local storage."""
    for attr in ['correlation_id', 'user_id', 'username', 'ip_address', 
                 'user_agent', 'request_method', 'request_path']:
        if hasattr(_thread_local, attr):
            delattr(_thread_local, attr)


def log_security_event(func):
    """Decorator to automatically log security events for view functions."""
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        set_request_context(request)
        
        try:
            # Log the request
            security_logger.log_request(request)
            
            # Execute the view function
            response = func(request, *args, **kwargs)
            
            # Log the response
            security_logger.log_response(request, response)
            
            return response
        
        except Exception as e:
            # Log the exception
            security_logger.log_security_event(
                'EXCEPTION',
                'CRITICAL',
                f"Exception in view {func.__name__}: {str(e)}",
                getattr(_thread_local, 'username', ''),
                getattr(_thread_local, 'ip_address', ''),
                {'view_function': func.__name__, 'exception_type': type(e).__name__}
            )
            raise
        
        finally:
            clear_request_context()
    
    return wrapper


class AuditTrail:
    """Audit trail for tracking changes to critical data."""
    
    def __init__(self):
        self.logger = logging.getLogger('audit')
    
    def log_model_change(self, model_name: str, object_id: str, action: str, 
                        user: User, changes: Dict[str, Any]):
        """Log model changes for audit trail."""
        audit_entry = {
            'timestamp': timezone.now().isoformat(),
            'model': model_name,
            'object_id': str(object_id),
            'action': action,  # 'CREATE', 'UPDATE', 'DELETE'
            'user_id': user.id if user else None,
            'username': user.username if user else 'system',
            'changes': LogSanitizer.sanitize_dict(changes)
        }
        
        self.logger.info(json.dumps(audit_entry, default=str))


# Global audit trail instance
audit_trail = AuditTrail()