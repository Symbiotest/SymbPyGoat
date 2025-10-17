from django.conf import settings
from django.core.validators import MaxValueValidator
from django.db import models

# Create your models here.

class FAANG (models.Model):
    id = models.AutoField(primary_key=True)
    company=models.CharField(max_length=200);
    def __str__(self):
        return self.company;

class info(models.Model):
    id = models.AutoField(primary_key=True)
    faang=models.ForeignKey(to=FAANG,on_delete=models.CASCADE)

    ceo=models.CharField(max_length=200)
    about=models.CharField(max_length=200)

class login(models.Model):
    id = models.AutoField(primary_key=True)
    user=models.CharField(max_length=200)
    password=models.CharField(max_length=300)

class comments(models.Model):
    id = models.AutoField(primary_key=True)
    name=models.CharField(max_length=200)
    comment=models.CharField(max_length=600)

class authLogin(models.Model):
    username=models.CharField(max_length=200, unique = True)
    name=models.CharField(max_length=200)
    password=models.CharField(max_length=200)
    userid = models.AutoField(primary_key=True)

class otp(models.Model):
    id = models.AutoField(primary_key=True)
    email=models.CharField(max_length=200)
    otp=models.IntegerField(validators=[MaxValueValidator(300)])

class tickits(models.Model):
    id = models.AutoField(primary_key=True)
    user=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE)
    tickit=models.CharField(max_length=40, unique = True)

    def __str__(self):
        return self.tickit+ " " + self.user.username; 

class sql_lab_table(models.Model):
    id = models.CharField(primary_key = True, max_length=200)
    password = models.CharField(max_length=200)

class Blogs(models.Model):
    id = models.AutoField(primary_key=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE)
    blog_id = models.CharField(max_length=15, unique=True)
    def __str__(self):
        return self.blog_id

class CF_user(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=200)
    password = models.CharField(max_length=200)
    password2 = models.CharField(max_length=64)
    def __str__(self):
        return self.username

class AF_admin(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=200)
    password = models.CharField(max_length=200)
    session_id = models.CharField(max_length=200)
    last_login = models.DateTimeField(blank= True, null = True)
    logged_in = models.BooleanField(default=False)
    is_locked = models.BooleanField(default=False)
    failattempt = models.IntegerField(default=0)
    lockout_cooldown = models.DateTimeField(blank= True, null = True)

    def __str__(self):
        return self.username

class AF_session_id(models.Model):
    id = models.AutoField(primary_key=True)
    session_id = models.CharField(max_length=200)
    user = models.CharField(max_length=200)
    def __str__(self):
        return self.user

class CSRF_user_tbl(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=200)
    password = models.CharField(max_length=200)
    balance = models.IntegerField(default=0)
    is_loggedin = models.BooleanField(default=False)
    
    def __str__(self):
        return self.username

# Vulnerable Authentication Service Models
class VulnUser(models.Model):
    user_id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=50)
    password = models.CharField(max_length=100)  # Deliberately storing plain text passwords
    email = models.EmailField()
    role = models.CharField(max_length=20, default='user')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(blank=True, null=True)
    
    def __str__(self):
        return self.username

class VulnSession(models.Model):
    session_id = models.CharField(max_length=100, primary_key=True)
    user_reference = models.ForeignKey(VulnUser, on_delete=models.CASCADE)
    creation_time = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    session_data = models.TextField(blank=True)
    
    def __str__(self):
        return f"Session {self.session_id} for {self.user_reference.username}"

class VulnPasswordReset(models.Model):
    token_id = models.AutoField(primary_key=True)
    user_email = models.EmailField()
    reset_token = models.CharField(max_length=100)  # Predictable token generation
    expiry_time = models.DateTimeField()
    used_status = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Reset token for {self.user_email}"