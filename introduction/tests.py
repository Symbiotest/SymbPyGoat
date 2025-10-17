from django.test import TestCase, Client, RequestFactory
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from unittest.mock import patch, MagicMock
from datetime import timedelta
import json
import time
import logging
import io

from .models import VulnUser, VulnSession, VulnPasswordReset
from .views.vulnerabilities.auth_service import VulnerableAuthService
from .views.vulnerabilities.logging_service import (
    SecurityLogger, LogSanitizer, security_logger, audit_trail,
    set_request_context, clear_request_context, SecurityLogLevel
)
from .middleware import SecurityLoggingMiddleware, RequestCorrelationMiddleware, SecurityHeadersMiddleware
from .logging_utils import (
    log_authentication, log_data_access, log_vulnerability_test,
    log_admin_action, log_operation_time, SecurityEventCollector,
    create_audit_entry, log_api_usage
)


class VulnerableAuthServiceTestCase(TestCase):
    """
    Comprehensive test suite for the Vulnerable Authentication Service.
    These tests validate that the educational vulnerabilities work as intended.
    """
    
    def setUp(self):
        """Set up test data for all authentication vulnerability tests."""
        self.client = Client()
        self.auth_service = VulnerableAuthService()
        
        # Create test users with different vulnerability scenarios
        self.test_user1 = VulnUser.objects.create(
            username="testuser1",
            password="plaintext123",  # Intentionally plain text
            email="testuser1@example.com",
            role="user"
        )
        
        self.test_user2 = VulnUser.objects.create(
            username="admin",
            password="admin123",  # Weak admin password
            email="admin@example.com",
            role="admin"
        )
        
        self.test_user3 = VulnUser.objects.create(
            username="sqltest",
            password="password",
            email="sqltest@example.com",
            role="user"
        )
    
    def tearDown(self):
        """Clean up after each test."""
        VulnUser.objects.all().delete()
        VulnSession.objects.all().delete()
        VulnPasswordReset.objects.all().delete()


class Lab1PlainTextPasswordTests(VulnerableAuthServiceTestCase):
    """Test Lab 1: Plain Text Password Storage Vulnerability"""
    
    def test_plain_text_password_storage(self):
        """Test that passwords are stored in plain text (vulnerability demonstration)."""
        user = VulnUser.objects.get(username="testuser1")
        # Verify password is stored as plain text
        self.assertEqual(user.password, "plaintext123")
        
    def test_plain_text_authentication_success(self):
        """Test successful authentication with plain text passwords."""
        result = self.auth_service.authenticate_plaintext("testuser1", "plaintext123")
        self.assertTrue(result['success'])
        self.assertEqual(result['user'].username, "testuser1")
        self.assertIn("Plain text password storage", result['vulnerability'])
    
    def test_plain_text_authentication_failure(self):
        """Test failed authentication with incorrect password."""
        result = self.auth_service.authenticate_plaintext("testuser1", "wrongpassword")
        self.assertFalse(result['success'])
        self.assertIn("Invalid credentials", result['error'])
    
    def test_lab1_registration_view(self):
        """Test Lab 1 registration functionality."""
        response = self.client.post(reverse('lab1_plaintext_passwords'), {
            'action': 'register',
            'username': 'newuser',
            'password': 'newpassword',
            'email': 'newuser@example.com'
        })
        
        # Check that user was created
        new_user = VulnUser.objects.get(username='newuser')
        self.assertEqual(new_user.password, 'newpassword')  # Verify plain text storage
        
    def test_lab1_login_view(self):
        """Test Lab 1 login functionality."""
        response = self.client.post(reverse('lab1_plaintext_passwords'), {
            'action': 'login',
            'username': 'testuser1',
            'password': 'plaintext123'
        })
        
        # Check that login was successful and session was created
        self.assertEqual(response.status_code, 200)
        self.assertIn('vuln_user_id', self.client.session)


class Lab2SessionFixationTests(VulnerableAuthServiceTestCase):
    """Test Lab 2: Session Fixation Attack Vulnerability"""
    
    def test_session_fixation_vulnerability(self):
        """Test that sessions can be fixed by external input."""
        fixed_session_id = "attacker_controlled_session_123"
        
        result = self.auth_service.create_vulnerable_session(
            self.test_user1, 
            fixed_session_id=fixed_session_id
        )
        
        self.assertEqual(result['session_id'], fixed_session_id)
        self.assertIn("Session fixation possible", result['vulnerability'])
    
    def test_predictable_session_generation(self):
        """Test that session IDs are generated predictably."""
        result1 = self.auth_service.create_vulnerable_session(self.test_user1)
        result2 = self.auth_service.create_vulnerable_session(self.test_user2)
        
        # Session IDs should follow predictable pattern
        self.assertIn(str(self.test_user1.user_id), result1['session_id'])
        self.assertIn(str(self.test_user2.user_id), result2['session_id'])
    
    def test_lab2_session_fixation_view(self):
        """Test Lab 2 session fixation view."""
        response = self.client.post(reverse('lab2_session_fixation'), {
            'username': 'testuser1',
            'password': 'plaintext123',
            'session_id': 'fixed_session_by_attacker'
        })
        
        self.assertEqual(response.status_code, 200)
        # Check that the fixed session ID was used
        self.assertEqual(
            self.client.session.get('vuln_session_id'), 
            'fixed_session_by_attacker'
        )


class Lab3SQLInjectionTests(VulnerableAuthServiceTestCase):
    """Test Lab 3: SQL Injection Authentication Bypass"""
    
    def test_sql_injection_bypass_basic(self):
        """Test basic SQL injection bypass with OR 1=1."""
        result = self.auth_service.authenticate_sql_injection(
            "admin", 
            "' OR '1'='1"
        )
        
        self.assertTrue(result['success'])
        self.assertIn("SQL injection bypass possible", result['vulnerability'])
        self.assertIn("OR '1'='1'", result['query'])
    
    def test_sql_injection_comment_bypass(self):
        """Test SQL injection bypass using comment syntax."""
        result = self.auth_service.authenticate_sql_injection(
            "admin'--", 
            "anything"
        )
        
        # This should succeed because the comment ignores the password check
        self.assertIn("SQL injection", result['vulnerability'])
        self.assertIn("admin'--", result['query'])
    
    def test_sql_injection_union_attack(self):
        """Test SQL injection with UNION SELECT."""
        result = self.auth_service.authenticate_sql_injection(
            "' UNION SELECT 1,'admin','secret','admin@example.com','admin'--", 
            "anything"
        )
        
        self.assertIn("UNION SELECT", result['query'])
        self.assertIn("SQL injection", result['vulnerability'])
    
    def test_lab3_sql_injection_view(self):
        """Test Lab 3 SQL injection view."""
        response = self.client.post(reverse('lab3_sql_injection'), {
            'username': "admin",
            'password': "' OR '1'='1"
        })
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "SQL Injection Attack")


class Lab4PredictableTokenTests(VulnerableAuthServiceTestCase):
    """Test Lab 4: Predictable Password Reset Tokens"""
    
    def test_predictable_token_generation(self):
        """Test that reset tokens are generated predictably."""
        result = self.auth_service.generate_reset_token("testuser1@example.com")
        
        self.assertTrue(result['success'])
        self.assertIn("Predictable token generation", result['vulnerability'])
        
        # Token should follow predictable pattern
        token = result['token']
        self.assertIn(str(self.test_user1.user_id), token)
    
    def test_multiple_token_pattern_analysis(self):
        """Test that multiple tokens follow predictable patterns."""
        result1 = self.auth_service.generate_reset_token("testuser1@example.com")
        time.sleep(1)  # Ensure different timestamp
        result2 = self.auth_service.generate_reset_token("admin@example.com")
        
        token1 = result1['token']
        token2 = result2['token']
        
        # Both tokens should start with 'reset_'
        self.assertTrue(token1.startswith('reset_'))
        self.assertTrue(token2.startswith('reset_'))
        
        # Should contain user IDs
        self.assertIn(str(self.test_user1.user_id), token1)
        self.assertIn(str(self.test_user2.user_id), token2)
    
    def test_token_information_disclosure(self):
        """Test that token generation reveals account existence."""
        # Valid email
        result_valid = self.auth_service.generate_reset_token("testuser1@example.com")
        self.assertTrue(result_valid['success'])
        
        # Invalid email
        result_invalid = self.auth_service.generate_reset_token("nonexistent@example.com")
        self.assertFalse(result_invalid['success'])
        self.assertIn("not found", result_invalid['error'])
    
    def test_lab4_reset_token_view(self):
        """Test Lab 4 reset token generation view."""
        response = self.client.post(reverse('lab4_reset_tokens'), {
            'action': 'request_reset',
            'email': 'testuser1@example.com'
        })
        
        self.assertEqual(response.status_code, 200)
        # Check that a reset token was created
        reset_token = VulnPasswordReset.objects.filter(
            user_email='testuser1@example.com'
        ).first()
        self.assertIsNotNone(reset_token)
    
    def test_lab4_password_reset_functionality(self):
        """Test Lab 4 password reset functionality."""
        # First generate a token
        result = self.auth_service.generate_reset_token("testuser1@example.com")
        token = result['token']
        
        # Then use it to reset password
        response = self.client.post(reverse('lab4_reset_tokens'), {
            'action': 'reset_password',
            'token': token,
            'new_password': 'newpassword123'
        })
        
        # Check that password was updated
        updated_user = VulnUser.objects.get(email='testuser1@example.com')
        self.assertEqual(updated_user.password, 'newpassword123')


class Lab5UsernameEnumerationTests(VulnerableAuthServiceTestCase):
    """Test Lab 5: Username Enumeration Vulnerability"""
    
    def test_username_enumeration_timing_attack(self):
        """Test timing differences for valid vs invalid usernames."""
        # Valid username (should take longer due to password processing)
        start_time = time.time()
        result_valid = self.auth_service.authenticate_with_timing(
            "testuser1", "wrongpassword"
        )
        valid_time = result_valid['response_time']
        
        # Invalid username (should be faster)
        start_time = time.time()
        result_invalid = self.auth_service.authenticate_with_timing(
            "nonexistentuser", "wrongpassword"
        )
        invalid_time = result_invalid['response_time']
        
        # Valid username should take longer
        self.assertGreater(valid_time, invalid_time)
        self.assertIn("Timing attack possible", result_valid['vulnerability'])
        self.assertIn("Username enumeration possible", result_invalid['vulnerability'])
    
    def test_username_enumeration_error_messages(self):
        """Test different error messages for valid vs invalid usernames."""
        # Valid username, wrong password
        result_valid = self.auth_service.authenticate_with_timing(
            "testuser1", "wrongpassword"
        )
        self.assertIn("Invalid password", result_valid['error'])
        
        # Invalid username
        result_invalid = self.auth_service.authenticate_with_timing(
            "nonexistentuser", "anypassword"
        )
        self.assertIn("Username not found", result_invalid['error'])
    
    def test_successful_authentication_timing(self):
        """Test timing for successful authentication."""
        result = self.auth_service.authenticate_with_timing(
            "testuser1", "plaintext123"
        )
        
        self.assertTrue(result['success'])
        self.assertIn("Timing attack possible", result['vulnerability'])
    
    def test_lab5_username_enumeration_view(self):
        """Test Lab 5 username enumeration view."""
        # Test with valid username
        response = self.client.post(reverse('lab5_username_enumeration'), {
            'username': 'testuser1',
            'password': 'wrongpassword'
        })
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Username Enumeration Attack Results")
        
        # Test with invalid username
        response = self.client.post(reverse('lab5_username_enumeration'), {
            'username': 'nonexistent',
            'password': 'anypassword'
        })
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Username Enumeration Attack Results")


class AuthServiceAPITests(VulnerableAuthServiceTestCase):
    """Test Authentication Service API Endpoints"""
    
    def test_api_authenticate_plaintext(self):
        """Test API authentication with plaintext method."""
        response = self.client.post(reverse('api_authenticate'), {
            'username': 'testuser1',
            'password': 'plaintext123',
            'auth_type': 'plaintext'
        })
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data['success'])
        self.assertIn('Plain text password storage', data['vulnerability'])
    
    def test_api_authenticate_sql_injection(self):
        """Test API authentication with SQL injection method."""
        response = self.client.post(reverse('api_authenticate'), {
            'username': 'admin',
            'password': "' OR '1'='1",
            'auth_type': 'sql_injection'
        })
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn('SQL injection', data['vulnerability'])
    
    def test_api_authenticate_timing(self):
        """Test API authentication with timing method."""
        response = self.client.post(reverse('api_authenticate'), {
            'username': 'testuser1',
            'password': 'wrongpassword',
            'auth_type': 'timing'
        })
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn('response_time', data)
        self.assertIn('Timing attack possible', data['vulnerability'])
    
    def test_api_reset_token(self):
        """Test API reset token generation."""
        response = self.client.post(reverse('api_reset_token'), {
            'email': 'testuser1@example.com'
        })
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data['success'])
        self.assertIn('token', data)
        self.assertIn('Predictable token generation', data['vulnerability'])
    
    def test_api_session_info(self):
        """Test API session information endpoint."""
        # Create a session first
        session_result = self.auth_service.create_vulnerable_session(self.test_user1)
        session_id = session_result['session_id']
        
        response = self.client.get(reverse('api_session_info'), {
            'session_id': session_id
        })
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['session_id'], session_id)
        self.assertEqual(data['username'], 'testuser1')


class AuthServiceIntegrationTests(VulnerableAuthServiceTestCase):
    """Integration tests for the complete authentication service"""
    
    def test_main_auth_service_page(self):
        """Test the main authentication service homepage."""
        response = self.client.get(reverse('auth_service_home'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Vulnerable Authentication Service")
        self.assertContains(response, "OWASP Top 10")
    
    def test_all_lab_pages_accessible(self):
        """Test that all lab pages are accessible."""
        lab_urls = [
            'lab1_plaintext_passwords',
            'lab2_session_fixation',
            'lab3_sql_injection',
            'lab4_reset_tokens',
            'lab5_username_enumeration'
        ]
        
        for url_name in lab_urls:
            response = self.client.get(reverse(url_name))
            self.assertEqual(response.status_code, 200, f"Failed to access {url_name}")
    
    def test_end_to_end_attack_scenario(self):
        """Test a complete attack scenario across multiple labs."""
        # Step 1: Register a user in Lab 1
        self.client.post(reverse('lab1_plaintext_passwords'), {
            'action': 'register',
            'username': 'victim',
            'password': 'secret123',
            'email': 'victim@example.com'
        })
        
        # Step 2: Enumerate username in Lab 5
        response = self.client.post(reverse('lab5_username_enumeration'), {
            'username': 'victim',
            'password': 'wrongpassword'
        })
        self.assertContains(response, "Invalid password")
        
        # Step 3: Generate reset token in Lab 4
        response = self.client.post(reverse('lab4_reset_tokens'), {
            'action': 'request_reset',
            'email': 'victim@example.com'
        })
        
        # Step 4: Use SQL injection in Lab 3
        response = self.client.post(reverse('lab3_sql_injection'), {
            'username': "victim",
            'password': "' OR '1'='1"
        })
        self.assertContains(response, "SQL Injection Attack")
    
    def test_vulnerability_persistence(self):
        """Test that vulnerabilities persist across requests."""
        # Create data in one request
        self.client.post(reverse('lab1_plaintext_passwords'), {
            'action': 'register',
            'username': 'persistent_user',
            'password': 'persistent_pass',
            'email': 'persistent@example.com'
        })
        
        # Verify vulnerability persists in another request
        user = VulnUser.objects.get(username='persistent_user')
        self.assertEqual(user.password, 'persistent_pass')  # Still plain text
        
        # Test authentication with persistent data
        result = self.auth_service.authenticate_plaintext(
            'persistent_user', 'persistent_pass'
        )
        self.assertTrue(result['success'])


class AuthServiceSecurityTests(VulnerableAuthServiceTestCase):
    """Tests to ensure the educational vulnerabilities don't affect framework security"""
    
    def test_framework_csrf_protection(self):
        """Ensure framework CSRF protection is maintained where appropriate."""
        # Test that non-educational endpoints still have CSRF protection
        response = self.client.post('/admin/', {'username': 'test'})
        # Should get CSRF error or redirect, not a 500 error
        self.assertIn(response.status_code, [403, 302, 404])
    
    def test_educational_vulnerability_isolation(self):
        """Ensure educational vulnerabilities don't affect other parts of the system."""
        # Create a vulnerable user
        vuln_user = VulnUser.objects.create(
            username='isolated_test',
            password='plain_text',
            email='isolated@example.com'
        )
        
        # Ensure this doesn't affect Django's built-in User model or auth
        from django.contrib.auth.models import User
        django_user = User.objects.create_user(
            username='django_user',
            password='secure_password',
            email='django@example.com'
        )
        
        # Django user should have hashed password
        self.assertNotEqual(django_user.password, 'secure_password')
        self.assertTrue(django_user.password.startswith('pbkdf2_'))
    
    def test_database_isolation(self):
        """Test that vulnerable data is isolated to specific tables."""
        # Create vulnerable data
        VulnUser.objects.create(
            username='test_isolation',
            password='plain_password',
            email='test@example.com'
        )
        
        # Ensure it doesn't interfere with Django's auth tables
        from django.contrib.auth.models import User
        initial_count = User.objects.count()
        
        # Creating vulnerable users shouldn't affect Django user count
        VulnUser.objects.create(
            username='another_vuln_user',
            password='another_password',
            email='another@example.com'
        )
        
        self.assertEqual(User.objects.count(), initial_count)


class LogSanitizerTests(TestCase):
    """Test the LogSanitizer functionality."""
    
    def test_password_sanitization(self):
        """Test that passwords are properly sanitized from logs."""
        text = "password=secret123 and token=abc123"
        sanitized = LogSanitizer.sanitize(text)
        
        self.assertIn('password="[REDACTED]"', sanitized)
        self.assertIn('token="[REDACTED]"', sanitized)
        self.assertNotIn('secret123', sanitized)
        self.assertNotIn('abc123', sanitized)
    
    def test_dict_sanitization(self):
        """Test that dictionaries are properly sanitized."""
        data = {
            'username': 'john',
            'password': 'secret123',
            'token': 'bearer_token',
            'public_info': 'this is safe'
        }
        
        sanitized = LogSanitizer.sanitize_dict(data)
        
        self.assertEqual(sanitized['username'], 'john')
        self.assertEqual(sanitized['password'], '[REDACTED]')
        self.assertEqual(sanitized['token'], '[REDACTED]')
        self.assertEqual(sanitized['public_info'], 'this is safe')
    
    def test_nested_dict_sanitization(self):
        """Test sanitization of nested dictionaries."""
        data = {
            'user': {
                'name': 'john',
                'password': 'secret123'
            },
            'auth': {
                'token': 'bearer_abc',
                'expires': '2024-01-01'
            }
        }
        
        sanitized = LogSanitizer.sanitize_dict(data)
        
        self.assertEqual(sanitized['user']['name'], 'john')
        self.assertEqual(sanitized['user']['password'], '[REDACTED]')
        self.assertEqual(sanitized['auth']['token'], '[REDACTED]')
        self.assertEqual(sanitized['auth']['expires'], '2024-01-01')
    
    def test_list_sanitization(self):
        """Test sanitization of lists containing dictionaries."""
        data = {
            'users': [
                {'name': 'john', 'password': 'secret1'},
                {'name': 'jane', 'password': 'secret2'}
            ]
        }
        
        sanitized = LogSanitizer.sanitize_dict(data)
        
        self.assertEqual(sanitized['users'][0]['name'], 'john')
        self.assertEqual(sanitized['users'][0]['password'], '[REDACTED]')
        self.assertEqual(sanitized['users'][1]['name'], 'jane')
        self.assertEqual(sanitized['users'][1]['password'], '[REDACTED]')
    
    def test_email_sanitization(self):
        """Test that email addresses are properly sanitized."""
        text = "User email=test@example.com logged in"
        sanitized = LogSanitizer.sanitize(text)
        
        self.assertIn('email="[REDACTED]"', sanitized)
        self.assertNotIn('test@example.com', sanitized)
    
    def test_ssn_sanitization(self):
        """Test that SSNs are properly sanitized."""
        text = "SSN: 123-45-6789 for user"
        sanitized = LogSanitizer.sanitize(text)
        
        self.assertIn('ssn="[REDACTED]"', sanitized)
        self.assertNotIn('123-45-6789', sanitized)
    
    def test_credit_card_sanitization(self):
        """Test that credit card numbers are sanitized."""
        text = "Credit card: 4532-1234-5678-9012"
        sanitized = LogSanitizer.sanitize(text)
        
        self.assertIn('credit_card="[REDACTED]"', sanitized)
        self.assertNotIn('4532-1234-5678-9012', sanitized)


class SecurityLoggerTests(TestCase):
    """Test the SecurityLogger functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.logger = SecurityLogger('test_security')
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass',
            email='test@example.com'
        )
        
        # Capture log output
        self.log_stream = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log_stream)
        self.logger.logger.addHandler(self.log_handler)
        self.logger.logger.setLevel(logging.DEBUG)
    
    def tearDown(self):
        """Clean up after tests."""
        self.logger.logger.removeHandler(self.log_handler)
        clear_request_context()
    
    def test_login_success_logging(self):
        """Test successful login logging."""
        self.logger.log_login_success('testuser', '192.168.1.1')
        
        log_output = self.log_stream.getvalue()
        log_data = json.loads(log_output.strip())
        
        self.assertEqual(log_data['event_type'], 'LOGIN_SUCCESS')
        self.assertEqual(log_data['level'], 'SECURITY_INFO')
        self.assertIn('testuser', log_data['message'])
        self.assertEqual(log_data['data']['username'], 'testuser')
        self.assertEqual(log_data['data']['ip_address'], '192.168.1.1')
    
    def test_login_failure_logging(self):
        """Test failed login logging."""
        self.logger.log_login_failure('testuser', '192.168.1.1', 'Invalid password')
        
        log_output = self.log_stream.getvalue()
        log_data = json.loads(log_output.strip())
        
        self.assertEqual(log_data['event_type'], 'LOGIN_FAILURE')
        self.assertEqual(log_data['level'], 'SECURITY_WARNING')
        self.assertIn('Failed login attempt', log_data['message'])
        self.assertEqual(log_data['data']['reason'], 'Invalid password')
    
    def test_access_denied_logging(self):
        """Test access denied logging."""
        self.logger.log_access_denied('testuser', '/admin/users/', '192.168.1.1')
        
        log_output = self.log_stream.getvalue()
        log_data = json.loads(log_output.strip())
        
        self.assertEqual(log_data['event_type'], 'ACCESS_DENIED')
        self.assertEqual(log_data['level'], 'SECURITY_WARNING')
        self.assertIn('Access denied', log_data['message'])
        self.assertEqual(log_data['data']['resource'], '/admin/users/')
    
    def test_vulnerability_exploitation_logging(self):
        """Test vulnerability exploitation logging."""
        self.logger.log_vulnerability_exploitation(
            'SQL_INJECTION',
            'testuser',
            '192.168.1.1',
            "'; DROP TABLE users; --"
        )
        
        log_output = self.log_stream.getvalue()
        log_data = json.loads(log_output.strip())
        
        self.assertEqual(log_data['event_type'], 'VULNERABILITY_EXPLOITATION')
        self.assertEqual(log_data['level'], 'SECURITY_CRITICAL')
        self.assertEqual(log_data['data']['vulnerability_type'], 'SQL_INJECTION')
        # Payload should be sanitized
        self.assertNotIn('DROP TABLE', log_data['data']['payload'])
    
    def test_request_context_logging(self):
        """Test that request context is properly included in logs."""
        factory = RequestFactory()
        request = factory.get('/test/')
        request.user = self.user
        
        set_request_context(request)
        
        self.logger.log_login_success('testuser', '192.168.1.1')
        
        log_output = self.log_stream.getvalue()
        log_data = json.loads(log_output.strip())
        
        self.assertIn('context', log_data)
        self.assertIn('correlation_id', log_data['context'])
        self.assertEqual(log_data['context']['username'], 'testuser')
        self.assertEqual(log_data['context']['request_path'], '/test/')
    
    def test_password_sanitization_in_logs(self):
        """Test that passwords are sanitized in security logs."""
        self.logger.log_security_event(
            'TEST_EVENT',
            'INFO',
            'User login with password=secret123',
            'testuser',
            '192.168.1.1'
        )
        
        log_output = self.log_stream.getvalue()
        log_data = json.loads(log_output.strip())
        
        # Password should be redacted
        self.assertNotIn('secret123', log_data['message'])
        self.assertIn('[REDACTED]', log_data['message'])


class SecurityLoggingMiddlewareTests(TestCase):
    """Test the SecurityLoggingMiddleware functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.factory = RequestFactory()
        self.middleware = SecurityLoggingMiddleware(lambda r: HttpResponse('OK'))
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass'
        )
        
        # Capture log output
        self.log_stream = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log_stream)
        security_logger.logger.addHandler(self.log_handler)
        security_logger.logger.setLevel(logging.DEBUG)
    
    def tearDown(self):
        """Clean up after tests."""
        security_logger.logger.removeHandler(self.log_handler)
    
    def test_request_logging(self):
        """Test that requests are properly logged."""
        request = self.factory.get('/test/', {'param': 'value'})
        request.user = self.user
        
        response = self.middleware(request)
        
        log_output = self.log_stream.getvalue()
        self.assertIn('HTTP_REQUEST', log_output)
        self.assertIn('GET /test/', log_output)
    
    def test_response_logging(self):
        """Test that responses are properly logged."""
        request = self.factory.get('/test/')
        request.user = self.user
        
        response = self.middleware(request)
        
        log_output = self.log_stream.getvalue()
        self.assertIn('HTTP_RESPONSE', log_output)
        self.assertIn('Status: 200', log_output)
    
    def test_sensitive_path_detection(self):
        """Test that sensitive paths are detected and logged."""
        request = self.factory.post('/admin/users/', {'username': 'test'})
        request.user = self.user
        
        response = self.middleware(request)
        
        log_output = self.log_stream.getvalue()
        self.assertIn('SENSITIVE_PATH_ACCESS', log_output)
    
    def test_injection_detection(self):
        """Test that injection attempts are detected."""
        request = self.factory.get('/test/', {'q': "'; DROP TABLE users; --"})
        request.user = self.user
        
        response = self.middleware(request)
        
        log_output = self.log_stream.getvalue()
        self.assertIn('INJECTION_ATTEMPT', log_output)
    
    def test_xss_detection(self):
        """Test that XSS attempts are detected."""
        request = self.factory.get('/test/', {'input': '<script>alert("xss")</script>'})
        request.user = self.user
        
        response = self.middleware(request)
        
        log_output = self.log_stream.getvalue()
        self.assertIn('INJECTION_ATTEMPT', log_output)
    
    def test_rate_limiting_detection(self):
        """Test that rate limiting is properly detected."""
        request = self.factory.get('/test/')
        request.user = self.user
        request.META['REMOTE_ADDR'] = '192.168.1.100'
        
        # Simulate multiple requests from same IP
        for i in range(105):  # Exceed the default limit of 100
            self.middleware.request_counts['192.168.1.100'].append(
                timezone.now() - timedelta(seconds=i)
            )
        
        response = self.middleware(request)
        
        log_output = self.log_stream.getvalue()
        self.assertIn('RATE_LIMIT_EXCEEDED', log_output)
    
    def test_exception_logging(self):
        """Test that exceptions are properly logged."""
        def failing_view(request):
            raise ValueError("Test exception")
        
        middleware = SecurityLoggingMiddleware(failing_view)
        request = self.factory.get('/test/')
        request.user = self.user
        
        try:
            middleware(request)
        except ValueError:
            pass  # Expected
        
        log_output = self.log_stream.getvalue()
        self.assertIn('REQUEST_EXCEPTION', log_output)
        self.assertIn('Test exception', log_output)


class LoggingUtilsTests(TestCase):
    """Test the logging utilities and decorators."""
    
    def setUp(self):
        """Set up test data."""
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass'
        )
        
        # Capture log output
        self.log_stream = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log_stream)
        security_logger.logger.addHandler(self.log_handler)
        security_logger.logger.setLevel(logging.DEBUG)
    
    def tearDown(self):
        """Clean up after tests."""
        security_logger.logger.removeHandler(self.log_handler)
    
    def test_log_authentication_decorator(self):
        """Test the authentication logging decorator."""
        @log_authentication
        def mock_login_view(request):
            request.user = self.user
            return HttpResponse('Login successful')
        
        request = self.factory.post('/login/')
        response = mock_login_view(request)
        
        log_output = self.log_stream.getvalue()
        self.assertIn('LOGIN_SUCCESS', log_output)
    
    def test_log_data_access_decorator(self):
        """Test the data access logging decorator."""
        @log_data_access('user_profile', 'view')
        def mock_profile_view(request):
            return HttpResponse('Profile data')
        
        request = self.factory.get('/profile/')
        request.user = self.user
        response = mock_profile_view(request)
        
        log_output = self.log_stream.getvalue()
        self.assertIn('DATA_ACCESS', log_output)
        self.assertIn('user_profile', log_output)
    
    def test_log_vulnerability_test_decorator(self):
        """Test the vulnerability test logging decorator."""
        @log_vulnerability_test('SQL_INJECTION')
        def mock_lab_view(request):
            return HttpResponse('Lab completed')
        
        request = self.factory.get('/lab/sql/')
        request.user = self.user
        response = mock_lab_view(request)
        
        log_output = self.log_stream.getvalue()
        self.assertIn('VULNERABILITY_TEST', log_output)
        self.assertIn('SQL_INJECTION', log_output)
    
    def test_log_admin_action_decorator(self):
        """Test the admin action logging decorator."""
        @log_admin_action('user_creation')
        def mock_admin_view(request):
            return HttpResponse('User created')
        
        # Test with admin user
        admin_user = User.objects.create_user(
            username='admin',
            password='adminpass',
            is_staff=True
        )
        
        request = self.factory.post('/admin/create/')
        request.user = admin_user
        response = mock_admin_view(request)
        
        log_output = self.log_stream.getvalue()
        self.assertIn('ADMIN_ACTION', log_output)
        self.assertIn('user_creation', log_output)
    
    def test_log_admin_action_unauthorized(self):
        """Test admin action logging for unauthorized users."""
        @log_admin_action('user_deletion')
        def mock_admin_view(request):
            return HttpResponse('Unauthorized')
        
        request = self.factory.post('/admin/delete/')
        request.user = self.user  # Regular user, not admin
        response = mock_admin_view(request)
        
        log_output = self.log_stream.getvalue()
        self.assertIn('PRIVILEGE_ESCALATION', log_output)
    
    def test_security_event_collector(self):
        """Test the SecurityEventCollector utility."""
        collector = SecurityEventCollector('testuser', '192.168.1.1')
        
        collector.add_event('TEST_EVENT_1', 'INFO', 'First test event')
        collector.add_event('TEST_EVENT_2', 'WARNING', 'Second test event')
        
        collector.log_batch_event('Test Batch')
        
        log_output = self.log_stream.getvalue()
        self.assertIn('BATCH_SECURITY_EVENT', log_output)
        self.assertIn('Test Batch', log_output)
        self.assertIn('event_count', log_output)
    
    def test_log_operation_time_context_manager(self):
        """Test the operation timing context manager."""
        with log_operation_time('test_operation', 'testuser', '192.168.1.1'):
            time.sleep(1.1)  # Force a slow operation
        
        log_output = self.log_stream.getvalue()
        self.assertIn('SLOW_OPERATION', log_output)
        self.assertIn('test_operation', log_output)
    
    def test_create_audit_entry(self):
        """Test the audit entry creation utility."""
        # Capture audit log output
        audit_stream = io.StringIO()
        audit_handler = logging.StreamHandler(audit_stream)
        audit_trail.logger.addHandler(audit_handler)
        audit_trail.logger.setLevel(logging.DEBUG)
        
        try:
            create_audit_entry(
                self.user,
                'UPDATE',
                self.user,
                {'email': 'newemail@example.com'}
            )
            
            audit_output = audit_stream.getvalue()
            audit_data = json.loads(audit_output.strip())
            
            self.assertEqual(audit_data['model'], 'User')
            self.assertEqual(audit_data['action'], 'UPDATE')
            self.assertEqual(audit_data['username'], 'testuser')
            self.assertIn('changes', audit_data)
        finally:
            audit_trail.logger.removeHandler(audit_handler)
    
    def test_log_api_usage_decorator(self):
        """Test the API usage logging decorator."""
        @log_api_usage('test_api', '/api/test/')
        def mock_api_view(request):
            return HttpResponse('API response')
        
        request = self.factory.get('/api/test/')
        request.user = self.user
        response = mock_api_view(request)
        
        log_output = self.log_stream.getvalue()
        self.assertIn('API_USAGE', log_output)
        self.assertIn('test_api', log_output)


class SecurityHeadersMiddlewareTests(TestCase):
    """Test the SecurityHeadersMiddleware functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.factory = RequestFactory()
        self.middleware = SecurityHeadersMiddleware(lambda r: HttpResponse('OK'))
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass'
        )
    
    def test_security_headers_added(self):
        """Test that security headers are added to responses."""
        request = self.factory.get('/test/')
        request.user = self.user
        
        response = self.middleware(request)
        
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(response['X-Frame-Options'], 'DENY')
        self.assertEqual(response['X-XSS-Protection'], '1; mode=block')
        self.assertEqual(response['Referrer-Policy'], 'strict-origin-when-cross-origin')
    
    def test_headers_logging(self):
        """Test that security header addition is logged."""
        # Capture log output
        log_stream = io.StringIO()
        log_handler = logging.StreamHandler(log_stream)
        security_logger.logger.addHandler(log_handler)
        security_logger.logger.setLevel(logging.DEBUG)
        
        try:
            request = self.factory.get('/test/')
            request.user = self.user
            
            response = self.middleware(request)
            
            log_output = log_stream.getvalue()
            self.assertIn('SECURITY_HEADERS_ADDED', log_output)
        finally:
            security_logger.logger.removeHandler(log_handler)


class RequestCorrelationMiddlewareTests(TestCase):
    """Test the RequestCorrelationMiddleware functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.factory = RequestFactory()
        self.middleware = RequestCorrelationMiddleware(lambda r: HttpResponse('OK'))
    
    def test_correlation_id_added(self):
        """Test that correlation IDs are added to requests."""
        request = self.factory.get('/test/')
        
        response = self.middleware(request)
        
        self.assertTrue(hasattr(request, 'correlation_id'))
        self.assertIsInstance(request.correlation_id, str)
        self.assertTrue(len(request.correlation_id) > 0)


# Create your tests here.
