
from django.core.mail import send_mail
from django.conf import settings


def send_verification_email(email, code):
    subject = "Verify your email - ExamLearn"
    message = f"""
            Hello,

            Your verification code is: {code}

            This code will expire in 15 minutes.

            If you did not request this, please ignore this email.

            —
            ExamLearn
    """
    from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@examlearn.com')
    recipient_list = [email]
    fail_silently = not settings.DEBUG  

    send_mail(
        subject=subject.strip(),
        message=message.strip(),
        from_email=from_email,
        recipient_list=recipient_list,
        fail_silently=fail_silently,
    )

def send_password_change_code_email(email,code):
    subject = "Change your password - ExamLearn"
    message = f"""
        Hello,

        Your password change code is: {code}

        This code will expire in 15 minutes.

        If you did not request this, please ignore this email and ensure your account is secure.

        —
        ExamLearn
        """

    from_email = getattr(settings,'DEFAULT_FROM_EMAIL','noreply@examlearn.com')
    recipient_list = [email]
    fail_silently = not settings.DEBUG  

    send_mail(
        subject=subject.strip(),
        message=message.strip(),
        from_email=from_email,
        recipient_list=recipient_list,
        fail_silently=fail_silently,
    )