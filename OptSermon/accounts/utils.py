# création et génération des otp (code de verification) d'email
import random
from django.conf import settings

from django.core.mail import EmailMessage

from .models import UserCustom, OneTimePassword



def generateOtp():
    otp = ""
    for i in range(6):
        otp += str(random.randint(1, 9))
    return otp


def send_code_to_user(email, curent_site=None):
    subject = "One Time passcode for Email"
    otp_code = generateOtp()
    print(otp_code)
    user = UserCustom.objects.get(email=email)
    current_site = curent_site
    email_body = f"{current_site} \n {user.first_name} {user.last_name} pour vérifier votre adresse électronique, entrez ce code {otp_code}"
    from_email = settings.EMAIL_HOST_USER
    OneTimePassword.objects.create(user=user,code=otp_code)
    d_email = EmailMessage(subject=subject,body=email_body,from_email=from_email,to=[email])
    d_email.send(fail_silently=True)


def send_normal_email(data):
    email = EmailMessage(
        subject=data['email_subject'],
        body=data['email_body'],
        from_email=settings.EMAIL_HOST_USER,
        to=[data['to_email']]
    )
    email.send()