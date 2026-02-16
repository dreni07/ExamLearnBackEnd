from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin 
from django.utils.text import slugify


class CustomUserManager(BaseUserManager):
    def create_user(self,email,password=None,**extra_fields):
        if not email:
            raise ValueError('Email is required')

        email = self.normalize_email(email)
        user = self.model(email=email,**extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self,email,password=None,**extra_fields):
        extra_fields.setdefault("is_staff",True)
        extra_fields.setdefault("is_superuser",True)
        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True")
        return self.create_user(email,password,**extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)  # add this line


    objects = CustomUserManager()

    USERNAME_FIELD = "email"

    REQUIRED_FIELDS = []

    class Meta:
        db_table = "users_user"
    
    def __str__(self):
        return self.email


class ExamType(models.Model):
    name = models.CharField(max_length=100,unique=True)
    slug = models.SlugField(unique=True)
    order = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "users_exam_type"
        ordering = ["order","name"]
        verbose_name = "Exam Type"
        verbose_name_plural = "Exam Types"
    
    def __str__(self):
        return self.name

    def save(self,*args,**kwargs):
        if not self.slug and self.name:
            self.slug = slugify(self.name)
        super().save(*args,**kwargs)


class UserProfile(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="profile"
    )
    exam_type = models.ForeignKey(
        ExamType,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="profiles"
    )

    full_name = models.CharField(max_length=100,blank=True)
    exam_year = models.PositiveIntegerField(null=True,blank=True)
    phone = models.CharField(max_length=20,blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "users_user_profile"
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"

    def __str__(self):
        return f"Profile of{self.user.email}"


class EmailVerificationCode(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="verification_codes"
    )

    code = models.CharField(max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "users_email_verification_code"
        verbose_name = "Email Verification Code"
        verbose_name_plural = "Email Verification Codes"
        ordering = ["-created_at"]
    
    def __str__(self):
        return f"Code for {self.user.email}"