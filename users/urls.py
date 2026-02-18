from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

urlpatterns = [
    path('auth/register/', views.RegisterView.as_view()),
    path('auth/pick-exam/', views.PickExamView.as_view()),
    path('auth/verify-email/', views.VerifyEmailView.as_view()),
    path('auth/resend-code/', views.ResendCodeView.as_view()),
    path('auth/login/', views.LoginView.as_view()),
    path('auth/refresh/', TokenRefreshView.as_view()),
    path('auth/logout/', views.LogoutView.as_view()),
    path('auth/google/', views.GoogleAuthView.as_view()),
    path('exam-types/', views.ExamTypeListView.as_view()),
    path('exam-types/<int:pk>/', views.ExamTypeDetailView.as_view()),
    path('user-exam/update-target-date/',views.UpdateUserExamTargetDateView.as_view()),

    path('auth/request-password-change/', views.RequestPasswordChangeView.as_view()),
    path('auth/confirm-password-change/', views.ConfirmPasswordChangeView.as_view()),
]