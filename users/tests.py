from unittest.mock import patch
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from .models import ExamType, UserProfile, EmailVerificationCode

User = get_user_model()


@patch("users.serializers.send_verification_email")
@patch("users.email.send_mail")
class RegisterEndpointTests(APITestCase):
    def setUp(self):
        self.url = "/users/auth/register/"
        ExamType.objects.create(name="12th Grade", slug="12th-grade", is_active=True)

    def test_register_success_returns_201_no_tokens(self, mock_send_mail, mock_send_verification):
        payload = {
            "email": "newuser@example.com",
            "password": "securepass123",
        }
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotIn("access", response.data)
        self.assertNotIn("refresh", response.data)
        self.assertIn("email", response.data)
        self.assertEqual(response.data["email"], "newuser@example.com")
        self.assertIn("next_step", response.data)
        self.assertEqual(response.data["next_step"], "pick_exam")
        self.assertIn("requires_verification", response.data)
        self.assertTrue(response.data["requires_verification"])
        self.assertFalse(response.data["email_verified"])
        self.assertTrue(User.objects.filter(email="newuser@example.com").exists())
        user = User.objects.get(email="newuser@example.com")
        self.assertFalse(user.is_active)
        self.assertTrue(UserProfile.objects.filter(user=user).exists())
        self.assertIsNone(user.profile.exam_type_id)

    def test_register_with_optional_fields(self, mock_send_mail, mock_send_verification):
        payload = {
            "email": "full@example.com",
            "password": "securepass123",
            "full_name": "Test User",
            "exam_year": 2026,
            "phone": "+1234567890",
        }
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user = User.objects.get(email="full@example.com")
        self.assertEqual(user.profile.full_name, "Test User")
        self.assertEqual(user.profile.exam_year, 2026)
        self.assertEqual(user.profile.phone, "+1234567890")
        self.assertFalse(user.is_active)

    def test_register_duplicate_email_returns_400(self, mock_send_mail, mock_send_verification):
        User.objects.create_user(email="taken@example.com", password="otherpass")
        payload = {
            "email": "taken@example.com",
            "password": "securepass123",
        }
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_missing_email_returns_400(self, mock_send_mail, mock_send_verification):
        payload = {"password": "securepass123"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_missing_password_returns_400(self, mock_send_mail, mock_send_verification):
        payload = {"email": "nopass@example.com"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class LoginEndpointTests(APITestCase):
    def setUp(self):
        self.url = "/users/auth/login/"
        self.user = User.objects.create_user(
            email="testuser@example.com", password="securepass123", is_active=True
        )

    def test_login_success_returns_200_and_tokens(self):
        payload = {"email": "testuser@example.com", "password": "securepass123"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)
        self.assertIn("user", response.data)
        self.assertTrue(response.data["email_verified"])
        self.assertFalse(response.data["requires_verification"])

    def test_login_unverified_user_returns_403_with_next_step(self):
        inactive_user = User.objects.create_user(
            email="unverified@example.com", password="pass123", is_active=False
        )
        UserProfile.objects.create(user=inactive_user, exam_type=None)
        payload = {"email": "unverified@example.com", "password": "pass123"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(response.data["email_verified"])
        self.assertTrue(response.data["requires_verification"])
        self.assertEqual(response.data["next_step"], "pick_exam")
        self.assertEqual(response.data["email"], "unverified@example.com")
        self.assertNotIn("access", response.data)

    def test_login_unverified_user_with_exam_returns_403_next_step_verify(self):
        exam = ExamType.objects.create(name="12th", slug="12th", is_active=True)
        inactive_user = User.objects.create_user(
            email="has_exam@example.com", password="pass123", is_active=False
        )
        UserProfile.objects.create(user=inactive_user, exam_type=exam)
        payload = {"email": "has_exam@example.com", "password": "pass123"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["next_step"], "verify_email")

    def test_login_wrong_password_returns_400(self):
        User.objects.create_user(email="login@example.com", password="correctpass")
        payload = {"email": "login@example.com", "password": "wrongpass"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_nonexistent_email_returns_400(self):
        payload = {"email": "nobody@example.com", "password": "anypass"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


@patch("users.serializers.send_verification_email")
@patch("users.email.send_mail")
class PickExamEndpointTests(APITestCase):
    def setUp(self):
        self.url = "/users/auth/pick-exam/"
        self.exam_type = ExamType.objects.create(
            name="12th Grade", slug="12th-grade", is_active=True
        )
        self.user = User.objects.create_user(
            email="pickexam@example.com", password="pass123", is_active=False
        )
        UserProfile.objects.create(user=self.user, exam_type=None)

    def test_pick_exam_success(self, mock_send_mail, mock_send_verification):
        payload = {
            "email": "pickexam@example.com",
            "exam_type_id": self.exam_type.id,
        }
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["next_step"], "verify_email")
        self.assertFalse(response.data["email_verified"])
        self.assertTrue(response.data["requires_verification"])
        self.assertEqual(response.data["email"], "pickexam@example.com")
        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.profile.exam_type_id, self.exam_type.id)
        self.assertTrue(EmailVerificationCode.objects.filter(user=self.user).exists())
        mock_send_verification.assert_called_once()

    def test_pick_exam_nonexistent_user_returns_400(self, mock_send_mail, mock_send_verification):
        payload = {"email": "nobody@example.com", "exam_type_id": self.exam_type.id}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_pick_exam_already_verified_returns_400(self, mock_send_mail, mock_send_verification):
        self.user.is_active = True
        self.user.save()
        payload = {"email": "pickexam@example.com", "exam_type_id": self.exam_type.id}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_pick_exam_invalid_exam_type_returns_400(self, mock_send_mail, mock_send_verification):
        payload = {"email": "pickexam@example.com", "exam_type_id": 99999}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class VerifyEmailEndpointTests(APITestCase):
    def setUp(self):
        self.url = "/users/auth/verify-email/"
        self.user = User.objects.create_user(
            email="verify@example.com", password="pass123", is_active=False
        )
        UserProfile.objects.create(user=self.user, exam_type=None)
        self.code = EmailVerificationCode.objects.create(user=self.user, code="123456")

    def test_verify_email_success(self):
        payload = {"email": "verify@example.com", "code": "123456"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)
        self.assertIn("user", response.data)
        self.assertTrue(response.data["email_verified"])
        self.assertFalse(response.data["requires_verification"])
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)
        self.assertFalse(EmailVerificationCode.objects.filter(user=self.user).exists())

    def test_verify_email_wrong_code_returns_400(self):
        payload = {"email": "verify@example.com", "code": "000000"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("code", response.data)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)

    def test_verify_email_nonexistent_user_returns_400(self):
        payload = {"email": "nobody@example.com", "code": "123456"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_email_already_verified_returns_400(self):
        self.user.is_active = True
        self.user.save()
        payload = {"email": "verify@example.com", "code": "123456"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


@patch("users.serializers.send_verification_email")
@patch("users.email.send_mail")
class ResendCodeEndpointTests(APITestCase):
    def setUp(self):
        self.url = "/users/auth/resend-code/"
        self.user = User.objects.create_user(
            email="resend@example.com", password="pass123", is_active=False
        )
        UserProfile.objects.create(user=self.user, exam_type=None)
        self.old_code = EmailVerificationCode.objects.create(
            user=self.user, code="111111"
        )

    def test_resend_code_success(self, mock_send_mail, mock_send_verification):
        payload = {"email": "resend@example.com"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("message", response.data)
        mock_send_verification.assert_called_once()
        self.assertEqual(EmailVerificationCode.objects.filter(user=self.user).count(), 1)
        new_code = EmailVerificationCode.objects.get(user=self.user)
        self.assertNotEqual(new_code.code, "111111")

    def test_resend_code_nonexistent_user_returns_400(
        self, mock_send_mail, mock_send_verification
    ):
        payload = {"email": "nobody@example.com"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        mock_send_verification.assert_not_called()

    def test_resend_code_already_verified_returns_400(
        self, mock_send_mail, mock_send_verification
    ):
        self.user.is_active = True
        self.user.save()
        payload = {"email": "resend@example.com"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        mock_send_verification.assert_not_called()


class LogoutEndpointTests(APITestCase):
    def setUp(self):
        self.url = "/users/auth/logout/"
        self.user = User.objects.create_user(
            email="logout@example.com",
            password="pass123",
        )

    def test_logout_success_returns_200(self):
        refresh = RefreshToken.for_user(self.user)
        payload = {"refresh": str(refresh)}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("detail"), "Successfully logged out")

    def test_logout_missing_refresh_returns_400(self):
        response = self.client.post(self.url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("detail", response.data)


class ExamTypeListEndpointTests(APITestCase):
    def setUp(self):
        self.url = "/users/exam-types/"

    def test_list_returns_200_and_exam_types(self):
        ExamType.objects.create(name="9th Grade", slug="9th-grade", order=1, is_active=True)
        ExamType.objects.create(name="12th Grade", slug="12th-grade", order=2, is_active=True)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data, list)
        self.assertEqual(len(response.data), 2)
        by_name = {item["name"]: item for item in response.data}
        self.assertIn("9th Grade", by_name)
        self.assertIn("12th Grade", by_name)

    def test_list_returns_only_active_exam_types(self):
        ExamType.objects.create(name="Active", slug="active", order=1, is_active=True)
        ExamType.objects.create(name="Inactive", slug="inactive", order=2, is_active=False)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["name"], "Active")

class ExamTypeDetailEndpointTests(APITestCase):
    def setUp(self):
        self.exam_type = ExamType.objects.create(
            name="12th Grade",
            slug="12th-grade",
            order=1,
            is_active=True
        )
        self.url = f"/users/exam-types/{self.exam_type.id}/"

    def test_detail_returns_200_and_exam_type(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["name"], "12th Grade")
        self.assertEqual(response.data["slug"], "12th-grade")
        self.assertEqual(response.data["order"], 1)
        self.assertEqual(response.data["is_active"], True)

    
    def test_detail_nonexistent_id_returns_404(self):
        response = self.client.get("/users/exam-types/99999/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_detail_inactive_exam_type_returns_404(self):
        inactive = ExamType.objects.create(
            name="Inactive Exam",
            slug="inactive-exam",
            order=2,
            is_active=False
        )
        response = self.client.get(f"/users/exam-types/{inactive.id}/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)