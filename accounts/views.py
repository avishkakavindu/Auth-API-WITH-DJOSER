from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import *
from rest_framework.response import Response
from rest_framework import status
import requests

from django.utils.encoding import smart_bytes, force_str, smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode


class UserActivationView(APIView):

    def get(self, request, uid, token, format=None):
        payload = {
            'uid': uid,
            'token': token
        }

        url = 'http://localhost:8000/auth/users/activation/'
        response = requests.post(url, data=payload)

        if response.status_code == 204:
            return Response({'detail': 'Account activated successfully!'}, status=status.HTTP_204_NO_CONTENT)
        else:
            return Response(response.json(), status=status.HTTP_400_BAD_REQUEST)


class UserPasswordResetConfirmView(APIView):
    """ Verify Email Address"""

    def get(self, request, uid, token, format=None):
        payload = {
            'token': '{}/{}'.format(uid, token)
        }

        url = 'http://localhost:8000/password/reset/confirmed/{}/'.format(smart_str(urlsafe_base64_decode(uid)))
        response = requests.put(url, data=payload)

        if response.status_code == 204:
            return Response(
                {'Detail': 'Verified Successfully! please reset your password via Smartapp'})
        else:
            return Response({'Error': 'Verification failed! Token may be expired!'}, status=status.HTTP_401_UNAUTHORIZED)


class UserPasswordResetView(APIView):

    def get_object(self, pk):
        try:
            return UserAccount.objects.get(pk=pk)
        except UserAccount.DoesNotExist:
            raise Response(status=status.HTTP_404_NOT_FOUND)

    def put(self, request, pk):
        user = self.get_object(pk)
        payload = {
            "password_reset_token": request.data["token"]
        }

        serializer = UserAccountPasswordResetConfirmationSerializer(user, data=payload)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_204_NO_CONTENT)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetView(APIView):

    def post(self, request):
        try:
            user = UserAccount.objects.get(email=request.data['email'])

            # print("User=", user.password)
            # print(request.data['new_password'])
        except UserAccount.DoesNotExist:
            context = {
                'Error': 'Please confirm your email'
            }
            return Response(context, status=status.HTTP_401_UNAUTHORIZED)

        uid_token = user.password_reset_token.split('/')
        payload = {
            'uid': uid_token[0],
            'token': uid_token[1],
            'new_password': request.data['new_password'],
            're_new_password': request.data['re_new_password']
        }

        url = 'http://localhost:8000/auth/users/reset_password_confirm/'
        response = requests.post(url, data=payload)

        if response.status_code == 204:
            return Response({'Detail': 'Password Reset Successfully'}, status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({'Error': 'Please verify your email'}, status=status.HTTP_401_UNAUTHORIZED)
