from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.generics import ListAPIView

from .models import ExamType
from .serializers import (
    ExamTypeSerializer,
    LoginSerializer,
    RegisterSerializer,
    PickExamSerializer,
    GoogleAuthSerializer,
    VerifyEmailSerializer,
    ResendCodeSerializer,
)


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token)
    }


class LoginView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        requires_verification = serializer.validated_data.get('requires_verification',False)

        if requires_verification:
            has_exam = hasattr(user, 'profile') and user.profile.exam_type_id is not None
            return Response(
                {
                    "email_verified": False,
                    "requires_verification": True,
                    "email": user.email,
                    "next_step": "verify_email" if has_exam else "pick_exam",
                    "detail": "Please verify your email to continue. Check your inbox for the verification code."
                    if has_exam
                    else "Please pick your exam type first, then verify your email.",
                },
                status=status.HTTP_403_FORBIDDEN
            )

        tokens = get_tokens_for_user(user)
        
        return Response({
            'access': tokens['access'],
            'refresh': tokens['refresh'],
            'user': {
                'id': user.id,
                'email': user.email,
            },
            'email_verified': True,
            'requires_verification': False,
        }, status=status.HTTP_200_OK)


class LogoutView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        try:
            refresh = request.data.get('refresh')
            if not refresh:
                return Response(
                    {"detail": "Refresh token is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            token = RefreshToken(refresh)
            token.blacklist()
            return Response(
                {"detail": "Successfully logged out"},
                status=status.HTTP_200_OK
            )
        except Exception:
            return Response(
                {"detail": "Error logging out"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RegisterView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(
            {
                "message": "Account created. Please pick your exam type to continue.",
                "email_verified": False,
                "requires_verification": True,
                "next_step": "pick_exam",
                "email": user.email,
            },
            status=status.HTTP_201_CREATED,
        )


class PickExamView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        serializer = PickExamSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(
            {
                "message": "Verification code sent. Please check your email and enter the code.",
                "email_verified": False,
                "requires_verification": True,
                "next_step": "verify_email",
                "email": user.email,
            },
            status=status.HTTP_200_OK,
        )


class VerifyEmailView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        serializer = VerifyEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        tokens = get_tokens_for_user(user)
        return Response(
            {
                "access": tokens["access"],
                "refresh": tokens["refresh"],
                "user": {
                    "id": user.id,
                    "email": user.email,
                },
                "email_verified": True,
                "requires_verification": False,
            },
            status=status.HTTP_200_OK,
        )


class ResendCodeView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        serializer = ResendCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"message": "A new verification code has been sent to your email."},
            status=status.HTTP_200_OK,
        )


class GoogleAuthView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        serializer = GoogleAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        tokens = get_tokens_for_user(user)
        return Response(
            {
                "access": tokens["access"],
                "refresh": tokens["refresh"],
                "user": {
                    "id": user.id,
                    "email": user.email
                }
            },
            status=status.HTTP_200_OK
        )


class ExamTypeListView(ListAPIView):
    queryset = ExamType.objects.filter(is_active=True).order_by("order", "name")
    serializer_class = ExamTypeSerializer
    permission_classes = []
    authentication_classes = []