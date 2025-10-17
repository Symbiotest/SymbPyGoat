import datetime
import re
import subprocess
from hashlib import md5
import ast
import ipaddress

import jwt
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password

from .models import CSRF_user_tbl
from .views import authentication_decorator

# import os

## Mitre top1 | CWE:787

# target zone
FLAG = "NOT_SUPPOSED_TO_BE_ACCESSED"

# target zone end


@authentication_decorator
def mitre_top1(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top1.html')

@authentication_decorator
def mitre_top2(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top2.html')

@authentication_decorator
def mitre_top3(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top3.html')
        
@authentication_decorator
def mitre_top4(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top4.html')
        
@authentication_decorator
def mitre_top5(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top5.html')
        
@authentication_decorator
def mitre_top6(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top6.html')
        
@authentication_decorator
def mitre_top7(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top7.html')
        
@authentication_decorator
def mitre_top8(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top8.html')
        
@authentication_decorator
def mitre_top9(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top9.html')
        
@authentication_decorator
def mitre_top10(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top10.html')
        
@authentication_decorator
def mitre_top11(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top11.html')
        
@authentication_decorator
def mitre_top12(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top12.html')
        
@authentication_decorator
def mitre_top13(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top13.html')
        
@authentication_decorator
def mitre_top14(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top14.html')

@authentication_decorator
def mitre_top15(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top15.html')

@authentication_decorator
def mitre_top16(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top16.html')

@authentication_decorator
def mitre_top17(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top17.html')

@authentication_decorator
def mitre_top18(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top18.html')

@authentication_decorator
def mitre_top19(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top19.html')


@authentication_decorator
def mitre_top20(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top20.html')


@authentication_decorator
def mitre_top21(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top21.html')


@authentication_decorator
def mitre_top22(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top22.html')


@authentication_decorator
def mitre_top23(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top23.html')


@authentication_decorator
def mitre_top24(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top24.html')

@authentication_decorator
def mitre_top25(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top25.html')

@authentication_decorator
def csrf_lab_login(request):
    if request.method == 'GET':
        return render(request, 'mitre/csrf_lab_login.html')
    elif request.method == 'POST':
        password_input = request.POST.get('password')
        username = request.POST.get('username')
        users = CSRF_user_tbl.objects.filter(username=username)
        if users:
            user = users[0]
            stored_password = user.password or ''
            is_authenticated = False
            # If password is in Django hasher format, use check_password
            if stored_password.startswith(('pbkdf2_', 'argon2', 'bcrypt_sha256$', 'bcrypt$')):
                is_authenticated = check_password(password_input, stored_password)
            else:
                # Legacy MD5 path
                legacy_hash = md5(password_input.encode()).hexdigest()
                if stored_password == legacy_hash:
                    is_authenticated = True
                    # Upgrade to Django hasher on successful legacy auth
                    user.password = make_password(password_input)
                    user.save(update_fields=['password'])
            if is_authenticated:
                payload ={
                    'username': username,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=300),
                    'iat': datetime.datetime.utcnow()
                }
                cookie = jwt.encode(payload, settings.SECRET_COOKIE_KEY, algorithm='HS256')
                response = redirect("/mitre/9/lab/transaction")
                response.set_cookie('auth_cookiee', cookie, httponly=True, samesite='Lax', secure=not settings.DEBUG)
                return response
        return redirect('/mitre/9/lab/login')

@authentication_decorator
@csrf_exempt
def csrf_transfer_monei(request):
    if request.method == 'GET':
        try:
            cookie = request.COOKIES['auth_cookiee']
            payload = jwt.decode(cookie, settings.SECRET_COOKIE_KEY, algorithms=['HS256'])
            username = payload['username']
            User = CSRF_user_tbl.objects.filter(username=username)
            if not User:
                redirect('/mitre/9/lab/login')
            return render(request, 'mitre/csrf_dashboard.html', {'balance': User[0].balance})
        except:
            return redirect('/mitre/9/lab/login')

def csrf_transfer_monei_api(request,recipent,amount):
    if request.method == "GET":
        cookie = request.COOKIES['auth_cookiee']
        payload = jwt.decode(cookie, settings.SECRET_COOKIE_KEY, algorithms=['HS256'])
        username = payload['username']
        User = CSRF_user_tbl.objects.filter(username=username)
        if not User:
            return redirect('/mitre/9/lab/login')
        if int(amount) > 0:
            if int(amount) <= User[0].balance:
                recipent = CSRF_user_tbl.objects.filter(username=recipent)
                if recipent:
                    recipent = recipent[0]
                    recipent.balance = recipent.balance + int(amount)
                    recipent.save()
                    User[0].balance = User[0].balance - int(amount)
                    User[0].save()
        return redirect('/mitre/9/lab/transaction') 
    else:
        return redirect ('/mitre/9/lab/transaction')


# @authentication_decorator
@csrf_exempt
def mitre_lab_25_api(request):
    if request.method == "POST":
        expression = request.POST.get('expression')
        try:
            result = _safe_eval_arithmetic(expression)
        except Exception:
            return HttpResponseBadRequest('Invalid expression')
        return JsonResponse({'result': result})
    else:
        return redirect('/mitre/25/lab/')


def _safe_eval_arithmetic(expression: str):
    """Safely evaluate a simple arithmetic expression using AST validation.
    Allowed: integers/floats, + - * / % ** //, unary +/-, and parentheses.
    """
    if expression is None:
        raise ValueError('Empty expression')
    node = ast.parse(expression, mode='eval')

    allowed_binops = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow, ast.FloorDiv)
    allowed_unary = (ast.UAdd, ast.USub)

    def _validate(n):
        if isinstance(n, ast.Expression):
            _validate(n.body)
        elif isinstance(n, ast.BinOp):
            if not isinstance(n.op, allowed_binops):
                raise ValueError('Operator not allowed')
            _validate(n.left)
            _validate(n.right)
        elif isinstance(n, ast.UnaryOp):
            if not isinstance(n.op, allowed_unary):
                raise ValueError('Unary operator not allowed')
            _validate(n.operand)
        elif isinstance(n, ast.Num):  # Py<3.8
            return
        elif isinstance(n, ast.Constant):  # Py>=3.8
            if not isinstance(n.value, (int, float)):
                raise ValueError('Only numbers allowed')
            return
        else:
            raise ValueError('Disallowed expression')

    _validate(node)

    def _compute(n):
        if isinstance(n, ast.Expression):
            return _compute(n.body)
        if isinstance(n, ast.Constant):
            return n.value
        if isinstance(n, ast.Num):
            return n.n
        if isinstance(n, ast.UnaryOp):
            operand = _compute(n.operand)
            if isinstance(n.op, ast.UAdd):
                return +operand
            if isinstance(n.op, ast.USub):
                return -operand
        if isinstance(n, ast.BinOp):
            left = _compute(n.left)
            right = _compute(n.right)
            if isinstance(n.op, ast.Add):
                return left + right
            if isinstance(n.op, ast.Sub):
                return left - right
            if isinstance(n.op, ast.Mult):
                return left * right
            if isinstance(n.op, ast.Div):
                return left / right
            if isinstance(n.op, ast.Mod):
                return left % right
            if isinstance(n.op, ast.Pow):
                return left ** right
            if isinstance(n.op, ast.FloorDiv):
                return left // right
        raise ValueError('Evaluation error')

    return _compute(node)


@authentication_decorator
def mitre_lab_25(request):
    return render(request, 'mitre/mitre_lab_25.html')

@authentication_decorator
def mitre_lab_17(request):
    return render(request, 'mitre/mitre_lab_17.html')

def command_out(args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout, result.stderr
    

@csrf_exempt
def mitre_lab_17_api(request):
    if request.method == "POST":
        ip = (request.POST.get('ip') or '').strip()
        try:
            # Validate IP address (IPv4/IPv6)
            ipaddress.ip_address(ip)
        except ValueError:
            return HttpResponseBadRequest('Invalid IP address')
        command = ["nmap", ip]
        res, err = command_out(command)
        pattern = "STATE SERVICE.*\\n\\n"
        ports = re.findall(pattern, res,re.DOTALL)[0][14:-2].split('\n')
        return JsonResponse({'raw_res': str(res), 'raw_err': str(err), 'ports': ports})