from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import DjangoUnicodeDecodeError
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.utils.encoding import smart_str, smart_bytes, force_str, force_bytes
from django.utils.http import urlsafe_base64_decode
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .models import OneTimePassword, UserCustom
from .serializer import UserRegisterSerializer, LoginUserSerializer, PasswordResetRequestSerializer, \
    SetNewPasswordSerializer, LogoutUserSerializer, VerifyUserSerializer, RefreshTokenSerializer
from .utils import send_code_to_user


class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer

    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        current_site = request.META.get('HTTP_HOST', ' ')

        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user = serializer.data
            # send a email function
            send_code_to_user(user['email'], current_site)
            return Response({
                "data": user,
                "message": f"Bonjour {user.get('last_name')} Merci de vous avoir fait inscrit"
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyUserEmail(GenericAPIView):
    serializer_class = VerifyUserSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            otp_code = serializer.validated_data['otp_code']
            print(otp_code)
            try:
                user_code = OneTimePassword.objects.get(code=otp_code)
                user = user_code.user
                if not user.is_verified:
                    user.is_verified = True
                    user.save()
                    return Response({
                        'message': 'Le compte email a été vérifié avec succès'
                    }, status=status.HTTP_200_OK)
                return Response({
                    'message': 'Le compte email a déjà été vérifié'
                }, status=status.HTTP_400_BAD_REQUEST)
            except OneTimePassword.DoesNotExist:
                return Response({
                    'message': 'Veuillez entrer un code valide'
                }, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RefreshTokenView(GenericAPIView):
    serializer_class = RefreshTokenSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            refresh_token = serializer.validated_data['refresh']
            try:
                # Create a new refresh token object
                token = RefreshToken(refresh_token)
                # Generate new access token
                new_access_token = str(token.access_token)
                return Response({
                    'access': new_access_token
                }, status=status.HTTP_200_OK)
            except TokenError as e:
                return Response({
                    'message': f'Invalid token: {str(e)}'
                }, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginUserView(GenericAPIView):
    serializer_class = LoginUserSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data, context={'request_user': request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response({'message': '"Un lien a été envoyé à ton adresse email pour changer le mot de passe'},
                        status=status.HTTP_200_OK)


class PasswordResetConfirm(GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = UserCustom.objects.get(id=user_id)

            # on véerifie si le jeton de resetpassword appartient à l'utilisateur
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'mesage': 'Le ticket est invalid ou a expiré'})
            return Response(
                {
                    'success': True,
                    'message': True,
                    'uidb64': uidb64,
                    'token': token
                }, status=status.HTTP_200_OK
            )
        except DjangoUnicodeDecodeError:
            return Response({'message': 'le ticket de validation est invalid ou a expiré'},
                            status=status.HTTP_401_UNAUTHORIZED)


class SetNewPassword(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Votre mot de passe a été modifé avec succès'}, status=status.HTTP_200_OK)


class LogoutUserView(GenericAPIView):
    serializer_class = LogoutUserSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Déconnexion réussie.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
