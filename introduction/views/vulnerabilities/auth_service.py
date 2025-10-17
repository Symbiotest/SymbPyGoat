"""
Vulnerable Authentication Service - Educational Security Module

This module implements multiple authentication vulnerabilities for educational purposes
as part of the SymbPyGoat security learning platform. It demonstrates common authentication
failures based on OWASP Top 10 - A07:2021 Identification and Authentication Failures.

WARNING: This code contains intentional security vulnerabilities and should NEVER be used
in production environments. It is designed solely for cybersecurity education.
"""

import time
import hashlib
import random
import string
from datetime import datetime, timedelta
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db import connection
from django.utils import timezone
from ..models import VulnUser, VulnSession, VulnPasswordReset


class VulnerableAuthService:
    """
    Vulnerable Authentication Service demonstrating multiple security flaws
    """
    
    def __init__(self):
        self.failed_attempts = {}  # In-memory storage (vulnerable to restart bypass)
    
    # Lab 1: Plain Text Password Storage
    def authenticate_plaintext(self, username, password):
        """
        VULNERABILITY: Plain text password storage and comparison
        Demonstrates the risks of storing passwords without hashing
        """
        try:
            # Direct plaintext password comparison
            user = VulnUser.objects.get(username=username, password=password)
            return {"success": True, "user": user, "vulnerability": "Plain text password storage"}
        except VulnUser.DoesNotExist:
            return {"success": False, "error": "Invalid credentials"}
    
    # Lab 2: Session Fixation Attack
    def create_vulnerable_session(self, user, fixed_session_id=None):
        """
        VULNERABILITY: Session fixation - accepts pre-defined session IDs
        Demonstrates session management security flaws
        """
        if fixed_session_id:
            # Session fixation vulnerability - accepting external session ID
            session_id = fixed_session_id
        else:
            # Predictable session generation
            session_id = f"sess_{user.user_id}_{int(time.time())}"
        
        # Create or update session without proper regeneration
        session, created = VulnSession.objects.get_or_create(
            session_id=session_id,
            defaults={
                'user_reference': user,
                'session_data': f'user_role:{user.role};user_id:{user.user_id}'
            }
        )
        
        return {
            "session_id": session_id,
            "created": created,
            "vulnerability": "Session fixation possible"
        }
    
    # Lab 3: SQL Injection Authentication Bypass
    def authenticate_sql_injection(self, username, password):
        """
        VULNERABILITY: SQL injection in authentication query
        Demonstrates injection vulnerabilities in login systems
        """
        try:
            # Deliberately vulnerable SQL query construction
            query = f"SELECT * FROM introduction_vulnuser WHERE username = '{username}' AND password = '{password}'"
            
            with connection.cursor() as cursor:
                cursor.execute(query)
                row = cursor.fetchone()
                
                if row:
                    # Extract user data from raw SQL result
                    user_data = {
                        "user_id": row[0],
                        "username": row[1],
                        "password": row[2],
                        "email": row[3],
                        "role": row[4]
                    }
                    return {
                        "success": True, 
                        "user": user_data, 
                        "vulnerability": "SQL injection bypass possible",
                        "query": query
                    }
                else:
                    return {"success": False, "error": "Invalid credentials", "query": query}
        except Exception as e:
            return {"success": False, "error": str(e), "vulnerability": "SQL injection error"}
    
    # Lab 4: Predictable Password Reset Tokens
    def generate_reset_token(self, email):
        """
        VULNERABILITY: Predictable password reset token generation
        Demonstrates weak token generation algorithms
        """
        try:
            user = VulnUser.objects.get(email=email)
            
            # Predictable token generation using weak algorithms
            timestamp = str(int(time.time()))
            user_id = str(user.user_id)
            
            # Multiple vulnerable token generation methods
            token_methods = [
                f"reset_{user_id}_{timestamp}",  # Sequential pattern
                hashlib.md5(f"{email}{timestamp}".encode()).hexdigest()[:16],  # Weak hash
                f"{user_id}{timestamp[-4:]}",  # Partial timestamp
                str(random.randint(100000, 999999))  # Weak random
            ]
            
            # Use the first method (most predictable)
            reset_token = token_methods[0]
            
            # Store reset token with extended expiry
            expiry_time = timezone.now() + timedelta(hours=24)  # Too long
            
            VulnPasswordReset.objects.create(
                user_email=email,
                reset_token=reset_token,
                expiry_time=expiry_time
            )
            
            return {
                "success": True,
                "token": reset_token,
                "vulnerability": "Predictable token generation",
                "expiry": expiry_time
            }
        except VulnUser.DoesNotExist:
            # Information disclosure - revealing non-existent emails
            return {"success": False, "error": "Email address not found in system"}
    
    # Lab 5: Username Enumeration
    def authenticate_with_timing(self, username, password):
        """
        VULNERABILITY: Username enumeration through timing attacks and error messages
        Demonstrates information disclosure through authentication responses
        """
        start_time = time.time()
        
        try:
            # Check if username exists (information disclosure)
            user = VulnUser.objects.get(username=username)
            
            # Simulate password processing delay for valid users
            time.sleep(0.1)  # 100ms delay for valid username
            
            if user.password == password:
                end_time = time.time()
                return {
                    "success": True,
                    "user": user,
                    "response_time": end_time - start_time,
                    "vulnerability": "Timing attack possible"
                }
            else:
                end_time = time.time()
                return {
                    "success": False,
                    "error": "Invalid password for user",  # Information disclosure
                    "response_time": end_time - start_time,
                    "vulnerability": "Password enumeration possible"
                }
        except VulnUser.DoesNotExist:
            # Quick response for non-existent users
            end_time = time.time()
            return {
                "success": False,
                "error": "Username not found",  # Information disclosure
                "response_time": end_time - start_time,
                "vulnerability": "Username enumeration possible"
            }
    
    # Additional Vulnerability: Brute Force Attack (No Rate Limiting)
    def authenticate_no_rate_limit(self, username, password, request_ip):
        """
        VULNERABILITY: No rate limiting or account lockout
        Demonstrates brute force attack vulnerability
        """
        # Track attempts but don't enforce limits
        if request_ip not in self.failed_attempts:
            self.failed_attempts[request_ip] = []
        
        try:
            user = VulnUser.objects.get(username=username, password=password)
            # Clear failed attempts on successful login
            self.failed_attempts[request_ip] = []
            return {
                "success": True,
                "user": user,
                "vulnerability": "No brute force protection"
            }
        except VulnUser.DoesNotExist:
            # Record failed attempt but don't block
            self.failed_attempts[request_ip].append(datetime.now())
            return {
                "success": False,
                "error": "Invalid credentials",
                "failed_attempts": len(self.failed_attempts[request_ip]),
                "vulnerability": "Unlimited brute force attempts allowed"
            }
    
    # Authorization Bypass
    def check_authorization(self, session_id, required_role="user"):
        """
        VULNERABILITY: Weak authorization checking
        Demonstrates privilege escalation possibilities
        """
        try:
            session = VulnSession.objects.get(session_id=session_id)
            user = session.user_reference
            
            # Weak role checking - can be bypassed with parameter manipulation
            if "admin" in session.session_data or user.role == required_role:
                return {
                    "authorized": True,
                    "user": user,
                    "vulnerability": "Authorization bypass possible"
                }
            else:
                return {"authorized": False, "error": "Insufficient privileges"}
        except VulnSession.DoesNotExist:
            return {"authorized": False, "error": "Invalid session"}


# Global instance for demonstration
auth_service = VulnerableAuthService()


# View Functions for Laboratory Exercises

def auth_service_home(request):
    """Main authentication service laboratory homepage"""
    return render(request, 'Lab/AUTH/auth_service_home.html')


# Lab 1: Plain Text Password Storage
@require_http_methods(['GET', 'POST'])
def lab1_plaintext_passwords(request):
    """Lab 1: Demonstrates plain text password storage vulnerability"""
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'register':
            username = request.POST.get('username')
            password = request.POST.get('password')
            email = request.POST.get('email')
            
            if username and password and email:
                # Deliberately store password in plain text
                try:
                    user = VulnUser.objects.create(
                        username=username,
                        password=password,  # Plain text storage!
                        email=email
                    )
                    messages.success(request, f'User {username} registered successfully!')
                    return redirect('lab1_plaintext_passwords')
                except Exception as e:
                    messages.error(request, f'Registration failed: {str(e)}')
        
        elif action == 'login':
            username = request.POST.get('username')
            password = request.POST.get('password')
            
            result = auth_service.authenticate_plaintext(username, password)
            if result['success']:
                request.session['vuln_user_id'] = result['user'].user_id
                request.session['vuln_username'] = result['user'].username
                messages.success(request, f'Login successful! Welcome {username}')
                return render(request, 'Lab/AUTH/lab1_success.html', {'user': result['user']})
            else:
                messages.error(request, result['error'])
    
    # Show all users with their plain text passwords for educational purposes
    users = VulnUser.objects.all()
    return render(request, 'Lab/AUTH/lab1_plaintext.html', {'users': users})


# Lab 2: Session Fixation Attack
@require_http_methods(['GET', 'POST'])
def lab2_session_fixation(request):
    """Lab 2: Demonstrates session fixation vulnerability"""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        fixed_session = request.POST.get('session_id')  # Attacker-provided session ID
        
        result = auth_service.authenticate_plaintext(username, password)
        if result['success']:
            # Create session with potential fixation
            session_result = auth_service.create_vulnerable_session(
                result['user'], 
                fixed_session_id=fixed_session
            )
            
            request.session['vuln_session_id'] = session_result['session_id']
            request.session['vuln_user_id'] = result['user'].user_id
            
            return render(request, 'Lab/AUTH/lab2_success.html', {
                'user': result['user'],
                'session': session_result
            })
        else:
            messages.error(request, result['error'])
    
    return render(request, 'Lab/AUTH/lab2_session_fixation.html')


# Lab 3: SQL Injection Authentication Bypass
@require_http_methods(['GET', 'POST'])
@csrf_exempt
def lab3_sql_injection(request):
    """Lab 3: Demonstrates SQL injection in authentication"""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        result = auth_service.authenticate_sql_injection(username, password)
        
        return render(request, 'Lab/AUTH/lab3_sql_result.html', {
            'result': result,
            'username': username,
            'password': password
        })
    
    return render(request, 'Lab/AUTH/lab3_sql_injection.html')


# Lab 4: Predictable Password Reset Tokens
@require_http_methods(['GET', 'POST'])
def lab4_reset_tokens(request):
    """Lab 4: Demonstrates predictable password reset tokens"""
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'request_reset':
            email = request.POST.get('email')
            result = auth_service.generate_reset_token(email)
            return render(request, 'Lab/AUTH/lab4_reset_result.html', {'result': result})
        
        elif action == 'reset_password':
            token = request.POST.get('token')
            new_password = request.POST.get('new_password')
            
            try:
                reset_request = VulnPasswordReset.objects.get(
                    reset_token=token,
                    used_status=False
                )
                
                if reset_request.expiry_time > timezone.now():
                    user = VulnUser.objects.get(email=reset_request.user_email)
                    user.password = new_password  # Plain text storage again!
                    user.save()
                    
                    reset_request.used_status = True
                    reset_request.save()
                    
                    messages.success(request, 'Password reset successfully!')
                else:
                    messages.error(request, 'Reset token expired')
            except VulnPasswordReset.DoesNotExist:
                messages.error(request, 'Invalid reset token')
    
    # Show all active reset tokens for educational purposes
    active_tokens = VulnPasswordReset.objects.filter(used_status=False)
    return render(request, 'Lab/AUTH/lab4_reset_tokens.html', {'tokens': active_tokens})


# Lab 5: Username Enumeration
@require_http_methods(['GET', 'POST'])
def lab5_username_enumeration(request):
    """Lab 5: Demonstrates username enumeration through timing and error messages"""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        result = auth_service.authenticate_with_timing(username, password)
        
        return render(request, 'Lab/AUTH/lab5_timing_result.html', {
            'result': result,
            'username': username
        })
    
    return render(request, 'Lab/AUTH/lab5_username_enum.html')


# API Endpoints for Advanced Testing
@csrf_exempt
def api_authenticate(request):
    """API endpoint for authentication testing"""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        auth_type = request.POST.get('auth_type', 'plaintext')
        
        if auth_type == 'plaintext':
            result = auth_service.authenticate_plaintext(username, password)
        elif auth_type == 'sql_injection':
            result = auth_service.authenticate_sql_injection(username, password)
        elif auth_type == 'timing':
            result = auth_service.authenticate_with_timing(username, password)
        else:
            result = {"success": False, "error": "Invalid auth type"}
        
        return JsonResponse(result)
    
    return JsonResponse({"error": "POST method required"})


@csrf_exempt
def api_reset_token(request):
    """API endpoint for password reset token generation"""
    if request.method == 'POST':
        email = request.POST.get('email')
        result = auth_service.generate_reset_token(email)
        return JsonResponse(result)
    
    return JsonResponse({"error": "POST method required"})


def api_session_info(request):
    """API endpoint to view session information"""
    session_id = request.GET.get('session_id')
    if session_id:
        try:
            session = VulnSession.objects.get(session_id=session_id)
            return JsonResponse({
                "session_id": session.session_id,
                "username": session.user_reference.username,
                "role": session.user_reference.role,
                "session_data": session.session_data,
                "created": session.creation_time.isoformat(),
                "last_activity": session.last_activity.isoformat()
            })
        except VulnSession.DoesNotExist:
            return JsonResponse({"error": "Session not found"})
    
    return JsonResponse({"error": "session_id parameter required"})