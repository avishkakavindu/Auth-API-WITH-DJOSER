from django.shortcuts import render
from django.utils.encoding import smart_str
from django.utils.http import urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, viewsets, permissions, generics
from rest_framework_simplejwt.authentication import JWTTokenUserAuthentication
from django.http import Http404
from .serializers import *
from .permissions import IsOwner
from .util import Util
from .tasks import update_request_status
import requests
from random import randint


class PayhereDetailViewSet(viewsets.ModelViewSet):
    authentication_classes = [JWTTokenUserAuthentication]
    permission_classes = [permissions.IsAuthenticated, IsOwner]

    queryset = PayhereDetails.objects.all()
    serializer_class = PayhereDetailsSerializer

    def perform_create(self, serializer):
        # when a product is saved, its saved how it is the owner
        if serializer.is_valid():
            serializer.save(user_id=self.request.user.id)
            return Response({'Detail': 'Transaction Completed'}, status=status.HTTP_201_CREATED)
        return Response({'Error': 'Transaction Failed'}, status=status.HTTP_400_BAD_REQUEST)

    def get_queryset(self):
        # after get all products on DB it will be filtered by its owner and return the queryset
        owner_queryset = self.queryset.filter(user_id=self.request.user.id)

        return owner_queryset


class RFIDDetailListAPIView(APIView):
    authentication_classes = [JWTTokenUserAuthentication]
    permission_classes = [permissions.IsAuthenticated, IsOwner]

    # get rfdi records of the user
    def get(self, request):
        rfid_detail = RFIDDetail.objects.filter(user=self.request.user.id)
        serializer = RFIDDetailSerializer(rfid_detail, many=True)

        return Response(serializer.data)

    # create rfdi record
    def post(self, request):
        serializer = RFIDDetailSerializer(data=request.data)

        if serializer.is_valid():
            if RFIDDetail.objects.filter(vehicle_no=self.request.data['vehicle_no']).exists():
                return Response({'Error': 'RFID tag already assigned for the vehicle!'}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                serializer.save(user_id=self.request.user.id)
                context = {
                    'Detail': 'RFID Application saved! Please wait for conformation email.',
                    'Data': serializer.data
                }
                return Response(context, status=status.HTTP_201_CREATED)

        return Response({'Error': 'Request Failed'}, status=status.HTTP_400_BAD_REQUEST)


class RFIDDetailAPIView(APIView):
    authentication_classes = [JWTTokenUserAuthentication]
    permission_classes = [permissions.IsAuthenticated, IsOwner]

    # get individual record
    def get_object(self, request, pk):
        try:
            return RFIDDetail.objects.get(pk=pk, user=request.user.id)
        except RFIDDetail.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        record = self.get_object(request, pk)
        serializer = RFIDDetailSerializer(record)

        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPoolAPIView(generics.CreateAPIView):
    authentication_classes = [JWTTokenUserAuthentication]
    permission_classes = [permissions.IsAuthenticated, IsOwner]

    def get_rfid(self, vehicle_no):
        rfid = RFIDDetail.objects.get(vehicle_no=vehicle_no)

        return rfid

    def post(self, request):
        serializer = RequestPoolSerializer(data=request.data)

        if serializer.is_valid():
            rfid = RFIDDetail.objects.get(vehicle_no=request.data['vehicle_no']).rf_id

            rec = serializer.save(rfid=rfid)
            # shedule bakgroundtask
            # update_request_status(rec.id)

            context = {
                'Success': 'Purchase Request created!'
            }

            return Response(context, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_403_FORBIDDEN)


class OtpView(APIView):
    """ Handles the OTP """

    def get_object(self, email):
        try:
            return UserAccount.objects.get(email=email)
        except UserAccount.DoesNotExist:
            raise Response(status=status.HTTP_404_NOT_FOUND)

    def generateOTP(self):
        return randint(100000, 999999)

    def put(self, request):
        user = self.get_object(request.data['email'])

        otp = self.generateOTP()

        payload = {
            "otp": otp,
            "otp_verified": False
        }

        serializer = OtpSerializer(user, data=payload, partial=True)

        email_body = "Hi " + user.name + "\nPlease use following OTP to verify your email\n {}".format(otp)

        data = {
            'receiver': user.email,
            'email_body': email_body,
            'email_subject': 'Verify your Email',
        }

        if serializer.is_valid():
            serializer.save()
            Util.send_email(data)
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):

    def get_object(self, email):
        try:
            return UserAccount.objects.get(email=email)
        except UserAccount.DoesNotExist:
            raise Response(status=status.HTTP_404_NOT_FOUND)

    # otp verification
    def post(self, request):
        user = self.get_object(request.data['email'])

        if request.data['otp'] == user.otp and request.data['otp'] != '0':
            payload = {
                # 'is_active': True,
                'otp': '0',
                'otp_verified': True
            }

            context = {'detail': 'OTP verified!'}

            serializer = UserActivationSerialier(user, data=payload)

            if serializer.is_valid():
                serializer.save()
                return Response(context, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)
        return Response({'error': 'Failed to verify'}, status=status.HTTP_401_UNAUTHORIZED)

    # user activation
    def put(self, request):
        user = self.get_object(request.data['email'])

        if request.data['otp'] == user.otp and request.data['otp'] != '0':
            payload = {
                'is_active': True,
                'otp': '0'
            }

            serializer = UserActivationSerialier(user, data=payload)

            email_body = "Hi " + user.name + "\nYour user account activated successfully!\n"

            data = {
                'receiver': user.email,
                'email_body': email_body,
                'email_subject': 'Verify your Email',
            }

            if serializer.is_valid():
                serializer.save()
                Util.send_email(data)
                return Response({'detail': 'Account Activated!'}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)

        return Response({'error': 'Failed to activate'}, status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get_object(self, email):
        try:
            return UserAccount.objects.get(email=email)
        except UserAccount.DoesNotExist:
            raise Response(status=status.HTTP_404_NOT_FOUND)

    def patch(self, request):
        user = self.get_object(request.data['email'])

        if user.otp_verified:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            context = {
                'success': True,
                'msg': 'Password Reset Success!'
            }

            payload = {
                'email': request.data['email'],
            }

            current_site = get_current_site(request=request).domain
            url = 'http://' + current_site + '/auth/otp_initial_state'
            response = requests.put(url, data=payload)
            return Response(context, status=status.HTTP_200_OK)

        context = {
            'success': False,
            'msg': 'Verification failed!'
        }
        return Response(context, status=status.HTTP_401_UNAUTHORIZED)


class OtpInitialAPIView(APIView):

    def get_object(self, email):
        try:
            return UserAccount.objects.get(email=email)
        except UserAccount.DoesNotExist:
            raise Response(status=status.HTTP_404_NOT_FOUND)

    def put(self, request):
        user = self.get_object(request.data['email'])

        payload = {
            "otp": '0',
            "otp_verified": False
        }

        serializer = OtpSerializer(user, data=payload, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_204_NO_CONTENT)

















# class UserActivationView(APIView):
#
#     def get(self, request, uid, token, format=None):
#         payload = {
#             'uid': uid,
#             'token': token
#         }
#
#         url = 'http://localhost:8000/auth/users/activation/'
#         response = requests.post(url, data=payload)
#
#         if response.status_code == 204:
#             return Response({'detail': 'Account activated successfully!'}, status=status.HTTP_204_NO_CONTENT)
#         else:
#             return Response(response.json(), status=status.HTTP_400_BAD_REQUEST)
#
#
# class UserPasswordResetConfirmView(APIView):
#     """ Verify Email Address"""
#     def get_object(self, pk):
#         try:
#             return UserAccount.objects.get(pk=pk)
#         except UserAccount.DoesNotExist:
#             raise Response(status=status.HTTP_404_NOT_FOUND)
#
#     def get(self, request, uid, token, format=None):
#         user = self.get_object(smart_str(urlsafe_base64_decode(uid)))
#         if user.otp_verified:
#             payload = {
#                 'token': '{}/{}'.format(uid, token)
#             }
#
#             url = 'http://localhost:8000/password/reset/confirmed/{}/'.format(smart_str(urlsafe_base64_decode(uid)))
#             response = requests.put(url, data=payload)
#
#             if response.status_code == 204:
#                 return Response(
#                     {'Detail': 'Verified Successfully! please reset your password via Smartapp'}, status=status.HTTP_204_NO_CONTENT)
#             else:
#                 return Response({'Error': 'Verification failed! Token may be expired!'}, status=status.HTTP_400_BAD_REQUEST)
#         return Response({'error': 'OTP verification failed!'}, status=status.HTTP_401_UNAUTHORIZED)
#
#
# class UserPasswordResetView(APIView):
#
#     def get_object(self, pk):
#         try:
#             return UserAccount.objects.get(pk=pk)
#         except UserAccount.DoesNotExist:
#             raise Response(status=status.HTTP_404_NOT_FOUND)
#
#     def put(self, request, pk):
#         user = self.get_object(pk)
#         payload = {
#             "password_reset_token": request.data["token"]
#         }
#
#         serializer = UserAccountPasswordResetConfirmationSerializer(user, data=payload)
#
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_204_NO_CONTENT)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#
#
# class PasswordResetView(APIView):
#
#     def post(self, request):
#         try:
#             user = UserAccount.objects.get(email=request.data['email'])
#
#             # print("User=", user.password)
#             # print(request.data['new_password'])
#         except UserAccount.DoesNotExist:
#             context = {
#                 'Error': 'Please confirm your email'
#             }
#             return Response(context, status=status.HTTP_401_UNAUTHORIZED)
#
#         uid_token = user.password_reset_token.split('/')
#         payload = {
#             'uid': uid_token[0],
#             'token': uid_token[1],
#             'new_password': request.data['new_password'],
#             're_new_password': request.data['re_new_password']
#         }
#
#         url = 'http://localhost:8000/auth/users/reset_password_confirm/'
#         response = requests.post(url, data=payload)
#
#         if response.status_code == 204:
#             return Response({'Detail': 'Password Reset Successfully'}, status=status.HTTP_204_NO_CONTENT)
#         else:
#             return Response({'Error': 'Please verify your email'}, status=status.HTTP_401_UNAUTHORIZED)
