"""
Logging Utilities and Helpers for SymbPyGoat
==========================================

This module provides utility functions and helper classes for working with the
logging service. It includes decorators, context managers, and convenience
functions for common logging tasks.
"""

import functools
import json
import time
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Callable

from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from django.core.management.base import BaseCommand

from .views.vulnerabilities.logging_service import security_logger, audit_trail


def log_authentication(func: Callable) -> Callable:
    """
    Decorator for logging authentication-related events.
    
    Usage:
        @log_authentication
        def login_view(request):
            # Your login logic here
            pass
    """
    @functools.wraps(func)
    def wrapper(request: HttpRequest, *args, **kwargs):
        ip_address = _get_client_ip(request)
        
        try:
            response = func(request, *args, **kwargs)
            
            # Log based on response status or user authentication state
            if hasattr(request, 'user') and request.user.is_authenticated:
                security_logger.log_login_success(
                    request.user.username, 
                    ip_address,
                    {'view_function': func.__name__}
                )
            elif hasattr(response, 'status_code') and response.status_code == 401:
                username = request.POST.get('username', 'unknown')
                security_logger.log_login_failure(
                    username, 
                    ip_address,
                    'Invalid credentials',
                    {'view_function': func.__name__}
                )
            
            return response
            
        except Exception as e:
            username = request.POST.get('username', 'unknown')
            security_logger.log_login_failure(
                username, 
                ip_address,
                f'Exception: {str(e)}',
                {'view_function': func.__name__, 'exception': type(e).__name__}
            )
            raise
    
    return wrapper


def log_data_access(resource_name: str, action: str = 'access'):
    """
    Decorator for logging data access events.
    
    Args:
        resource_name: Name of the resource being accessed
        action: Type of action (access, create, update, delete)
    
    Usage:
        @log_data_access('user_profile', 'view')
        def profile_view(request):
            # Your view logic here
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(request: HttpRequest, *args, **kwargs):
            user = getattr(request, 'user', None)
            username = user.username if user and user.is_authenticated else 'anonymous'
            ip_address = _get_client_ip(request)
            
            # Log the data access
            security_logger.log_data_access(
                username,
                resource_name,
                action,
                ip_address,
                {
                    'view_function': func.__name__,
                    'args': str(args),
                    'method': request.method
                }
            )
            
            return func(request, *args, **kwargs)
        
        return wrapper
    return decorator


def log_vulnerability_test(vulnerability_type: str):
    """
    Decorator for logging vulnerability test attempts in lab environments.
    
    Args:
        vulnerability_type: Type of vulnerability being tested
    
    Usage:
        @log_vulnerability_test('SQL_INJECTION')
        def sql_injection_lab(request):
            # Your lab logic here
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(request: HttpRequest, *args, **kwargs):
            user = getattr(request, 'user', None)
            username = user.username if user and user.is_authenticated else 'anonymous'
            ip_address = _get_client_ip(request)
            
            # Log the vulnerability test
            security_logger.log_security_event(
                'VULNERABILITY_TEST',
                'INFO',
                f'Vulnerability test: {vulnerability_type}',
                username,
                ip_address,
                {
                    'vulnerability_type': vulnerability_type,
                    'view_function': func.__name__,
                    'lab_session': True
                }
            )
            
            return func(request, *args, **kwargs)
        
        return wrapper
    return decorator


def log_admin_action(action: str):
    """
    Decorator for logging administrative actions.
    
    Args:
        action: Description of the administrative action
    
    Usage:
        @log_admin_action('user_creation')
        def create_user_view(request):
            # Your admin logic here
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(request: HttpRequest, *args, **kwargs):
            user = getattr(request, 'user', None)
            username = user.username if user and user.is_authenticated else 'anonymous'
            ip_address = _get_client_ip(request)
            
            # Check if user has admin privileges
            if not (user and user.is_authenticated and user.is_staff):
                security_logger.log_privilege_escalation(
                    username,
                    action,
                    ip_address,
                    {'view_function': func.__name__, 'unauthorized_attempt': True}
                )
            else:
                security_logger.log_security_event(
                    'ADMIN_ACTION',
                    'INFO',
                    f'Administrative action: {action}',
                    username,
                    ip_address,
                    {
                        'action': action,
                        'view_function': func.__name__,
                        'is_staff': user.is_staff,
                        'is_superuser': user.is_superuser
                    }
                )
            
            return func(request, *args, **kwargs)
        
        return wrapper
    return decorator


@contextmanager
def log_operation_time(operation_name: str, username: str = '', ip_address: str = ''):
    """
    Context manager for logging operation execution time.
    
    Args:
        operation_name: Name of the operation being timed
        username: Username performing the operation
        ip_address: IP address of the user
    
    Usage:
        with log_operation_time('database_query', username, ip_address):
            # Your time-sensitive operation here
            result = expensive_database_query()
    """
    start_time = time.time()
    
    try:
        yield
    finally:
        execution_time = time.time() - start_time
        
        # Log slow operations
        if execution_time > 1.0:  # Log operations taking more than 1 second
            security_logger.log_security_event(
                'SLOW_OPERATION',
                'WARNING',
                f'Slow operation detected: {operation_name}',
                username,
                ip_address,
                {
                    'operation': operation_name,
                    'execution_time': execution_time,
                    'slow_operation_threshold': 1.0
                }
            )


class LoggingCommand(BaseCommand):
    """
    Base class for management commands that includes automatic logging.
    
    Usage:
        class MyCommand(LoggingCommand):
            help = 'My custom command'
            
            def add_arguments(self, parser):
                # Add your arguments here
                pass
            
            def handle_with_logging(self, *args, **options):
                # Your command logic here
                pass
    """
    
    def handle(self, *args, **options):
        """Override the standard handle method to add logging."""
        command_name = self.__class__.__module__.split('.')[-1]
        
        security_logger.log_security_event(
            'MANAGEMENT_COMMAND',
            'INFO',
            f'Management command started: {command_name}',
            'system',
            'localhost',
            {
                'command': command_name,
                'args': str(args),
                'options': str(options)
            }
        )
        
        try:
            result = self.handle_with_logging(*args, **options)
            
            security_logger.log_security_event(
                'MANAGEMENT_COMMAND',
                'INFO',
                f'Management command completed: {command_name}',
                'system',
                'localhost',
                {'command': command_name, 'status': 'success'}
            )
            
            return result
            
        except Exception as e:
            security_logger.log_security_event(
                'MANAGEMENT_COMMAND',
                'CRITICAL',
                f'Management command failed: {command_name}',
                'system',
                'localhost',
                {
                    'command': command_name,
                    'error': str(e),
                    'exception_type': type(e).__name__
                }
            )
            raise
    
    def handle_with_logging(self, *args, **options):
        """
        Override this method in your command classes instead of handle().
        """
        raise NotImplementedError('Subclasses must implement handle_with_logging()')


class SecurityEventCollector:
    """
    Utility class for collecting and batch-logging security events.
    
    Useful for scenarios where you want to collect multiple related events
    and log them together for better analysis.
    """
    
    def __init__(self, username: str = '', ip_address: str = ''):
        """Initialize the event collector."""
        self.username = username
        self.ip_address = ip_address
        self.events = []
    
    def add_event(self, event_type: str, severity: str, message: str, extra_data: Optional[Dict] = None):
        """Add an event to the collection."""
        self.events.append({
            'event_type': event_type,
            'severity': severity,
            'message': message,
            'extra_data': extra_data or {}
        })
    
    def log_all_events(self):
        """Log all collected events."""
        for event in self.events:
            security_logger.log_security_event(
                event['event_type'],
                event['severity'],
                event['message'],
                self.username,
                self.ip_address,
                event['extra_data']
            )
        
        # Clear events after logging
        self.events.clear()
    
    def log_batch_event(self, batch_name: str):
        """Log all events as a single batch event."""
        if not self.events:
            return
        
        security_logger.log_security_event(
            'BATCH_SECURITY_EVENT',
            'INFO',
            f'Batch security event: {batch_name}',
            self.username,
            self.ip_address,
            {
                'batch_name': batch_name,
                'event_count': len(self.events),
                'events': self.events
            }
        )
        
        # Clear events after logging
        self.events.clear()


def create_audit_entry(model_instance, action: str, user: User, changes: Optional[Dict] = None):
    """
    Convenience function for creating audit trail entries.
    
    Args:
        model_instance: The model instance being audited
        action: The action being performed ('CREATE', 'UPDATE', 'DELETE')
        user: The user performing the action
        changes: Dictionary of changes (for UPDATE actions)
    
    Usage:
        # In your view or model save method
        create_audit_entry(user_profile, 'UPDATE', request.user, {'email': 'new@example.com'})
    """
    model_name = model_instance.__class__.__name__
    object_id = getattr(model_instance, 'id', 'unknown')
    
    audit_trail.log_model_change(
        model_name,
        str(object_id),
        action,
        user,
        changes or {}
    )


def log_api_usage(api_name: str, endpoint: str = ''):
    """
    Decorator for logging API usage.
    
    Args:
        api_name: Name of the API being used
        endpoint: Specific endpoint being accessed
    
    Usage:
        @log_api_usage('user_api', '/api/users/')
        def user_api_view(request):
            # Your API logic here
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(request: HttpRequest, *args, **kwargs):
            user = getattr(request, 'user', None)
            username = user.username if user and user.is_authenticated else 'anonymous'
            ip_address = _get_client_ip(request)
            
            security_logger.log_security_event(
                'API_USAGE',
                'INFO',
                f'API access: {api_name}',
                username,
                ip_address,
                {
                    'api_name': api_name,
                    'endpoint': endpoint or request.path,
                    'method': request.method,
                    'view_function': func.__name__
                }
            )
            
            return func(request, *args, **kwargs)
        
        return wrapper
    return decorator


def get_security_events_summary(hours: int = 24) -> Dict[str, Any]:
    """
    Get a summary of security events from the last N hours.
    
    Note: This is a placeholder function. In a real implementation,
    you would parse the log files or query a database.
    
    Args:
        hours: Number of hours to look back
    
    Returns:
        Dictionary with security event summary
    """
    # This is a simplified implementation
    # In a real scenario, you'd parse the security log files
    return {
        'period_hours': hours,
        'total_events': 0,
        'critical_events': 0,
        'warning_events': 0,
        'info_events': 0,
        'top_event_types': [],
        'top_users': [],
        'top_ips': [],
        'note': 'This is a placeholder implementation. Parse actual log files for real data.'
    }


def _get_client_ip(request: HttpRequest) -> str:
    """Get client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR', '')
    return ip.strip()


# Convenience functions for common logging tasks
def log_login_attempt(username: str, ip_address: str, success: bool, reason: str = ''):
    """Convenience function for logging login attempts."""
    if success:
        security_logger.log_login_success(username, ip_address)
    else:
        security_logger.log_login_failure(username, ip_address, reason)


def log_password_change_attempt(username: str, ip_address: str, success: bool):
    """Convenience function for logging password change attempts."""
    if success:
        security_logger.log_password_change(username, ip_address)
    else:
        security_logger.log_security_event(
            'PASSWORD_CHANGE_FAILURE',
            'WARNING',
            f'Failed password change attempt for user {username}',
            username,
            ip_address
        )


def log_unauthorized_access(username: str, resource: str, ip_address: str):
    """Convenience function for logging unauthorized access attempts."""
    security_logger.log_access_denied(username, resource, ip_address)


def log_lab_access(lab_name: str, username: str, ip_address: str):
    """Convenience function for logging lab access in the security training platform."""
    security_logger.log_security_event(
        'LAB_ACCESS',
        'INFO',
        f'User accessed security lab: {lab_name}',
        username,
        ip_address,
        {'lab_name': lab_name, 'training_session': True}
    )


def log_vulnerability_discovery(vulnerability_type: str, username: str, ip_address: str, 
                              lab_name: str = '', payload: str = ''):
    """Convenience function for logging when users discover vulnerabilities in labs."""
    security_logger.log_security_event(
        'VULNERABILITY_DISCOVERY',
        'INFO',
        f'User discovered vulnerability: {vulnerability_type}',
        username,
        ip_address,
        {
            'vulnerability_type': vulnerability_type,
            'lab_name': lab_name,
            'payload': payload,
            'learning_event': True
        }
    )