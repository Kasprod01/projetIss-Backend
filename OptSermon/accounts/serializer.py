from abc import ABC

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import authenticate
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import smart_str, smart_bytes, force_str, force_bytes

from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework.fields import empty
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .models import UserCustom
from .utils import send_normal_email


class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=60, min_length=6, write_only=True)
    password2 = serializers.CharField(max_length=60, min_length=6, write_only=True)

    class Meta:
        model = UserCustom
        fields = ("email", "first_name", "last_name", "password", "password2")

    def validate(self, attrs):
        password = attrs.get('password', ' ')
        password2 = attrs.get('password2', ' ')

        if password != password2:
            raise ValidationError(_("Passwords do not much"))
        return attrs

    def create(self, validated_data):
        user = UserCustom.objects.create_user(
            email=validated_data['email'],
            first_name=validated_data.get('first_name'),
            last_name=validated_data.get('last_name'),
            password=validated_data.get('password'),
        )
        return user


class LoginUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=7, required=True)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    full_name = serializers.CharField(max_length=255, read_only=True)
    access_token = serializers.CharField(max_length=255, read_only=True)
    refresh_token = serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = UserCustom
        fields = ('email', 'password', 'full_name', 'access_token', 'refresh_token')

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        request = self.context.get('request_user')
        user = authenticate(request, email=email, password=password)

        if not user:
            raise AuthenticationFailed("Mot de passe ou Nom d'utilisateur invalide")
        if not user.is_verified:
            raise AuthenticationFailed("Veuillez vérifier votre adresse email")
        user_tokens = user.tokens()
        return {
            'email': user.email,
            'full_name': user.get_full_name,
            'access_token': str(user_tokens.get('access')),
            'refresh_token': str(user_tokens.get('refresh')),
        }


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')

        if UserCustom.objects.filter(email=email).exists():
            user = UserCustom.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))  # encodage de l'identifiant
            token = PasswordResetTokenGenerator().make_token(user)
            request = self.context.get('request')
            site_domain = request.META.get('HTTP_ORIGIN')
            relative_link = f"/set-password.html?uidb64={uidb64}&token={token}"
            print(uidb64)
            print(token)
            abs_link = f"{site_domain}{relative_link}"
            email_body = f"Salut utilise le lien  en dessous pour  le changement de votre mot de passe \n {abs_link}"
            print(abs_link)
            data = {
                'email': email_body,
                'email_subject': "Changement de mot de passe",
                'email_body': email_body,
                'to_email': user.email,
            }
            # send_normal_email(data)
        return super().validate(attrs)


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=100, min_length=6, write_only=True)
    confirm_password = serializers.CharField(max_length=100, min_length=6, write_only=True)
    uidb64 = serializers.CharField(max_length=255, write_only=True)
    token = serializers.CharField(max_length=255, write_only=True)

    class Meta:
        fields = ["password", "confirm_password", "uidb64", "token"]

    def validate(self, attrs):
        try:
            uidb64 = attrs.get('uidb64')
            token = attrs.get('token')
            password = attrs.get('password')
            confirm_password = attrs.get('confirm_password')
            user_id = int(force_str(urlsafe_base64_decode(uidb64)))
            user = UserCustom.objects.get(id=user_id)
            print(user)

            if user:

                if not PasswordResetTokenGenerator().check_token(user, token):
                    raise AuthenticationFailed('Le lien a expiré ou invalid')
                if password != confirm_password:
                    raise AuthenticationFailed('Les deux mots de passe ne sont pas les mêmes')
                user.set_password(password)
                user.save()


        except Exception as e:
            print(e)
        return super().validate(attrs)


class LogoutUserSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(max_length=255)

    default_error_messages = {
        'bad_token': 'Le jeton de rafraishement est invalide ou a expiré'
    }

    def validate(self, attrs):
        self.token = attrs.get('refresh_token')
        return attrs

    def save(self, **kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()
        except TokenError:
            return self.fail('bad_token')


class VerifyUserSerializer(serializers.Serializer):
    otp_code = serializers.CharField(max_length=255)

    class Meta:
        fields = ('otp_code',)


class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()
