from djongo import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

class UserManager(BaseUserManager):
    def create_user(self, email, role, password=None):
        if not email or not password or not role:
            raise ValueError("Missing required fields")
        user = self.model(email=self.normalize_email(email), role=role)
        user.set_password(password)
        user.save()
        return user

class User(AbstractBaseUser):
    ROLE_CHOICES = (('ops', 'Ops'), ('client', 'Client'))
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    is_active = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['role']

    objects = UserManager()

class File(models.Model):
    uploader = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to='uploads/')
    filename = models.CharField(max_length=255)
    upload_ts = models.DateTimeField(auto_now_add=True)
