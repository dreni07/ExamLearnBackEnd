from django.shortcuts import render
from django.http import JsonResponse
from rest_framework import status
from rest_framework.response import Response 
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from .serializers import LoginSerializer,RegisterSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from .models import ExamType
from rest_framework.generics import ListAPIView
from .serializers import ExamTypeSerializer, LoginSerializer, RegisterSerializer


# Create your views here.

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token)
    }

class LoginView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self,request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        tokens = get_tokens_for_user(user)
        return Response({
            'access': tokens['access'],
            'refresh': tokens['refresh']
        }, status=status.HTTP_200_OK)

class LogoutView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self,request):
        try:
            refresh = request.data.get('refresh')
            if not refresh:
                return Response(
                    {
                        "detail": "Refresh token is required"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            token = RefreshToken(refresh)
            token.blacklist()

            return Response(
                {
                    "detail": "Successfully logged out"
                },
                status=status.HTTP_200_OK
            )

        except Exception:
            return Response(
                {
                    "detail": "Error logging out"
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class RegisterView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        tokens = get_tokens_for_user(user)
        return Response(
            {
                "access": tokens["access"],
                "refresh": tokens["refresh"],
                "user": {
                    "id": user.id,
                    "email": user.email,
                },
            },
            status=status.HTTP_201_CREATED,
        )

class ExamTypeListView(ListAPIView):
    queryset = ExamType.objects.filter(is_active=True).order_by("order","name")
    serializer_class = ExamTypeSerializer
    permission_classes = []
    authentication_classes = []
