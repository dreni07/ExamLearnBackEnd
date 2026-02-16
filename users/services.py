import random
from django.utils import timezone
from datetime import timedelta

from .models import User, EmailVerificationCode

CODE_EXPIRY_MINUTES = 15

CODE_LENGTH = 6


def generate_verification_code():
    return ''.join([str(random.randint(0, 9)) for _ in range(CODE_LENGTH)])

def create_verification_code(user):
    EmailVerificationCode.objects.filter(user=user).delete()

    code  = generate_verification_code()
    EmailVerificationCode.objects.create(user=user,code=code)

    return code

def verify_code(user, user_provided_code):
    expiry_cutoff = timezone.now() - timedelta(minutes=CODE_EXPIRY_MINUTES)

    verification = (
        EmailVerificationCode.objects
        .filter(user=user,created_at__gte=expiry_cutoff)
        .order_by('-created_at')
        .first()
    )

    if not verification:
        return False, "Verification code has expired. Please request a new one"

    if verification.code != user_provided_code.strip():
        return False, "Invalid verification code"

    verification.delete()
    user.is_active = True
    user.save(update_fields=['is_active'])

    return True, None

    