#!/usr/bin/env python3
"""
Authentication Service Test Runner

This script provides an easy way to run the comprehensive test suite
for the Vulnerable Authentication Service implementation.

Usage:
    python test_auth_service.py [test_class] [test_method]

Examples:
    python test_auth_service.py                           # Run all tests
    python test_auth_service.py Lab1PlainTextPasswordTests # Run specific test class
    python test_auth_service.py Lab1PlainTextPasswordTests test_plain_text_password_storage  # Run specific test
"""

import os
import sys
import django
from django.conf import settings
from django.core.management import execute_from_command_line


def setup_django():
    """Set up Django environment for testing."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pygoat.settings')
    django.setup()


def run_auth_service_tests(test_class=None, test_method=None):
    """Run authentication service tests with optional filtering."""
    
    # Base test command
    test_command = ['manage.py', 'test', 'introduction.tests']
    
    # Add specific test class if provided
    if test_class:
        test_command[-1] += f'.{test_class}'
        
        # Add specific test method if provided
        if test_method:
            test_command[-1] += f'.{test_method}'
    
    # Add verbose output
    test_command.extend(['-v', '2'])
    
    print(f\"Running: {' '.join(test_command)}\")\
    print(\"=\" * 60)
    
    # Execute the test command
    execute_from_command_line(test_command)


def print_available_tests():
    """Print available test classes and methods."""
    print(\"Available Test Classes:\")
    print(\"=\" * 30)
    print(\"- Lab1PlainTextPasswordTests\")
    print(\"- Lab2SessionFixationTests\")
    print(\"- Lab3SQLInjectionTests\")
    print(\"- Lab4PredictableTokenTests\")
    print(\"- Lab5UsernameEnumerationTests\")
    print(\"- AuthServiceAPITests\")
    print(\"- AuthServiceIntegrationTests\")
    print(\"- AuthServiceSecurityTests\")
    print(\"\\nExample test methods:\")
    print(\"- test_plain_text_password_storage\")
    print(\"- test_session_fixation_vulnerability\")
    print(\"- test_sql_injection_bypass_basic\")
    print(\"- test_predictable_token_generation\")
    print(\"- test_username_enumeration_timing_attack\")


def main():
    \"\"\"Main test runner function.\"\"\"
    
    # Parse command line arguments
    args = sys.argv[1:]
    
    if '--help' in args or '-h' in args:
        print(__doc__)
        print_available_tests()
        return
    
    # Set up Django
    setup_django()
    
    # Determine what tests to run
    test_class = args[0] if len(args) > 0 else None
    test_method = args[1] if len(args) > 1 else None
    
    try:
        run_auth_service_tests(test_class, test_method)
    except Exception as e:
        print(f\"Error running tests: {e}\")
        print(\"\nTip: Make sure you're in the project root directory and Django is properly configured.\")
        sys.exit(1)


if __name__ == '__main__':
    main()