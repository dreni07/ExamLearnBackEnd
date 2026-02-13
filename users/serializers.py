from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import ExamType,UserProfile

User = get_user_model()

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True)

    def validate(self,attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if not email or not password:
            raise serializers.ValidationError("Email and password are required")

        user = User.objects.filter(email=email).first()

        if not user or not user.check_password(password):
            raise serializers.ValidationError("Invalid credentials")

        if not user.is_active:
            raise serializers.ValidationError("User is not active")

        attrs['user'] = user
        
        return attrs

class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True,min_length=8,style={"input_type":"password"})

    full_name = serializers.CharField(max_length=255,required=False,allow_blank=True)
    exam_type_id = serializers.PrimaryKeyRelatedField(
        queryset=ExamType.objects.filter(is_active=True),
        required=True,
    )

    exam_year = serializers.IntegerField(required=False, allow_null=True, min_value=2000, max_value=2100)
    phone = serializers.CharField(max_length=20, required=False, allow_blank=True)

    def validate_email(self,value):
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("A user with this email already exists")
        return value.lower()

    def validate(self, attrs):
        return attrs

    def create(self, validated_data):
        password = validated_data.pop("password")
        exam_type = validated_data.pop("exam_type_id")
        full_name = validated_data.get("full_name", "")
        exam_year = validated_data.pop("exam_year", None)
        phone = validated_data.pop("phone", "")

        user = User.objects.create_user(
            email=validated_data["email"],
            password=password,
        )
        UserProfile.objects.create(
            user=user,
            exam_type=exam_type,
            full_name=full_name,
            exam_year=exam_year,
            phone=phone,
        )
        return user