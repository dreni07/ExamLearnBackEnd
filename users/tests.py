from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from .models import ExamType,UserProfile

User = get_user_model()

class RegisterEndpointTests(APITestCase):
    def setUp(self):
        self.url = "/users/auth/register/"
        self.exam_type = ExamType.objects.create(name="12th Grade",slug="12th-grade",is_active=True)

    def test_register_success_returns_201_and_tokens(self):
        payload = {
            "email": "newuser@example.com",
            "password": "securepass123",
            "exam_type_id": self.exam_type.id
        }

        response = self.client.post(self.url,payload,format="json")

        self.assertEqual(response.status_code,status.HTTP_201_CREATED)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)
        self.assertIn("user", response.data)
        self.assertEqual(response.data["user"]["email"], "newuser@example.com")
        self.assertTrue(User.objects.filter(email="newuser@example.com").exists())
        user = User.objects.get(email="newuser@example.com")
        self.assertTrue(UserProfile.objects.filter(user=user).exists())
        self.assertEqual(user.profile.exam_type_id, self.exam_type.id)

    def test_register_with_optional_fields(self):
        payload = {
            "email": "full@example.com",
            "password": "securepass123",
            "exam_type_id": self.exam_type.id,
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

    def test_register_duplicate_email_returns_400(self):
        User.objects.create_user(email="taken@example.com", password="otherpass")
        payload = {
            "email": "taken@example.com",
            "password": "securepass123",
            "exam_type_id": self.exam_type.id,
        }
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    
    def test_register_missing_exam_type_id_returns_400(self):
        payload = {
            "email": "noname@example.com",
            "password": "securepass123",
        }
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_invalid_exam_type_id_returns_400(self):
        payload = {
            "email": "bad@example.com",
            "password": "securepass123",
            "exam_type_id": 99999,
        }
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class LoginEndpointTests(APITestCase):
    def setUp(self):
        self.url = "/users/auth/login/"
        self.user = User.objects.create_user(email="testuser@example.com", password="securepass123")

    def test_login_success_returns_200_and_tokens(self):
        payload = {"email": "testuser@example.com", "password": "securepass123"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_login_wrong_password_returns_400(self):
        payload = {"email": "login@example.com", "password": "wrongpass"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_nonexistent_email_returns_400(self):
        payload = {"email": "nobody@example.com", "password": "anypass"}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


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
        for item in response.data:
            self.assertIn("id", item)
            self.assertIn("name", item)
            self.assertIn("slug", item)
            self.assertIn("order", item)
        self.assertEqual(by_name["9th Grade"]["slug"], "9th-grade")
        self.assertEqual(by_name["9th Grade"]["order"], 1)
        self.assertEqual(by_name["12th Grade"]["slug"], "12th-grade")
        self.assertEqual(by_name["12th Grade"]["order"], 2)

    
    def test_list_returns_only_active_exam_types(self):
        ExamType.objects.create(name="Active", slug="active", order=1, is_active=True)
        ExamType.objects.create(name="Inactive", slug="inactive", order=2, is_active=False)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["name"], "Active")