from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.conf import settings

from .models import (
    ExamType,
    UserProfile,
    UserExam
)

from .services import  (
    create_verification_code,
    verify_code,
    create_password_change_code,
    verify_and_apply_password_change
)

from .email import send_verification_email, send_password_change_code_email

User = get_user_model()


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if not email or not password:
            raise serializers.ValidationError("Email and password are required")

        user = User.objects.filter(email__iexact=email).first()

        if not user or not user.check_password(password):
            raise serializers.ValidationError("Invalid credentials")

        attrs['user'] = user
        attrs['requires_verification'] = not user.is_active
        return attrs


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True, min_length=8, style={"input_type": "password"})

    full_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    exam_year = serializers.IntegerField(required=False, allow_null=True, min_value=2000, max_value=2100)
    phone = serializers.CharField(max_length=20, required=False, allow_blank=True)

    def validate_email(self, value):
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("A user with this email already exists")
        return value.lower()

    def validate(self, attrs):
        return attrs

    def create(self, validated_data):
        password = validated_data.pop("password")
        full_name = validated_data.get("full_name", "")
        exam_year = validated_data.pop("exam_year", None)
        phone = validated_data.pop("phone", "")

        # User stays inactive until they pick exam and verify email
        user = User.objects.create_user(
            email=validated_data["email"],
            password=password,
            is_active=False,
        )
        UserProfile.objects.create(
            user=user,
            exam_type=None,
            full_name=full_name,
            exam_year=exam_year,
            phone=phone,
        )
        return user


class PickExamSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True, required=False, allow_blank=True)
    exam_type_id = serializers.PrimaryKeyRelatedField(
        queryset=ExamType.objects.filter(is_active=True),
        required=True,
    )

    def validate(self, attrs):
        request = self.context.get("request")
        email = attrs.get("email")
        if request and request.user.is_authenticated:
            attrs["user"] = request.user
            attrs["is_authenticated"] = True
        else:
            if not email:
                raise serializers.ValidationError({"email": "Email is required when not authenticated."})

            user = User.objects.filter(email__iexact=email).first()

            if not user:
                raise serializers.ValidationError({"email": "No account found with this email."})
            if user.is_active:
                raise serializers.ValidationError({"email": "This account is already verified."})

            attrs["user"] = user  
            attrs["is_authenticated"] = False
        return attrs

    def save(self, **kwargs):
        user = self.validated_data["user"]
        exam_type = self.validated_data["exam_type_id"]
        is_authenticated = self.validated_data["is_authenticated"]

        profile = user.profile
        profile.exam_type = exam_type
        profile.save(update_fields=["exam_type"])

        UserExam.objects.update_or_create(
            user=user,
            defaults={"exam_type": exam_type},
        )

        if not is_authenticated:
            code = create_verification_code(user)
            send_verification_email(user.email, code)

        return user


class VerifyEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)
    code = serializers.CharField(write_only=True, min_length=4, max_length=10)

    def validate_email(self, value):
        user = User.objects.filter(email__iexact=value).first()
        if not user:
            raise serializers.ValidationError("No account found with this email.")
        if user.is_active:
            raise serializers.ValidationError("This account is already verified.")
        return value.lower()

    def validate(self, attrs):
        email = attrs['email']
        code = attrs['code']
        user = User.objects.get(email__iexact=email)

        success, error_msg = verify_code(user, code)
        if not success:
            raise serializers.ValidationError({"code": error_msg})

        attrs['user'] = user
        return attrs


class ResendCodeSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)

    def validate_email(self, value):
        user = User.objects.filter(email__iexact=value).first()
        if not user:
            raise serializers.ValidationError("No account found with this email.")
        if user.is_active:
            raise serializers.ValidationError("This account is already verified. You can log in.")
        return value.lower()

    def save(self, **kwargs):
        user = User.objects.get(email__iexact=self.validated_data['email'])
        code = create_verification_code(user)
        send_verification_email(user.email, code)
        return user


class ExamTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExamType
        fields = "__all__"


class GoogleAuthSerializer(serializers.Serializer):
    id_token = serializers.CharField(write_only=True)

    def validate(self, attrs):
        from google.oauth2 import id_token
        from google.auth.transport import requests as google_requests

        id_token_str = attrs.get('id_token')
        if not id_token_str:
            raise serializers.ValidationError("id_token is required")

        client_id = getattr(settings, 'GOOGLE_OAUTH2_CLIENT_ID', None)
        if not client_id:
            raise serializers.ValidationError("Google OAuth is not configured")

        try:
            payload = id_token.verify_oauth2_token(
                id_token_str,
                google_requests.Request(),
                client_id
            )
        except ValueError:
            raise serializers.ValidationError("Invalid or expired Google Token")

        email = (payload.get("email") or "").lower().strip()
        if not email:
            raise serializers.ValidationError("Invalid Google Token: No email found")
        name = (payload.get("name") or "").strip()

        user, created = User.objects.get_or_create(
            email=email,
            defaults={"email": email}
        )

        if created:
            user.set_unusable_password()
            user.save()
            UserProfile.objects.get_or_create(
                user=user,
                defaults={"full_name": name}
            )

        if not user.is_active:
            raise serializers.ValidationError("User is not active")

        attrs["user"] = user
        return attrs


class RequestPasswordChangeSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)

    def validate_email(self, value):
        user = User.objects.filter(email__iexact=value).first()
        if not user:
            raise serializers.ValidationError("No account found with this email.")
        return value.lower()

    def save(self, **kwargs):
        user = User.objects.get(email__iexact=self.validated_data["email"])
        code = create_password_change_code(user)
        send_password_change_code_email(user.email, code)
        return user


class ConfirmPasswordChangeSerializer(serializers.Serializer):
    user_id = serializers.IntegerField(write_only=True)
    code = serializers.CharField(write_only=True, min_length=4, max_length=10)
    new_password = serializers.CharField(
        write_only=True, min_length=8, style={"input_type": "password"}
    )

    def validate(self, attrs):
        user_id = attrs["user_id"]
        code = attrs["code"]
        new_password = attrs["new_password"]

        success, error_msg = verify_and_apply_password_change(
            user_id, code, new_password
        )
        if not success:
            raise serializers.ValidationError({"code": error_msg})

        return attrs