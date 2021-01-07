from djoser.serializers import UserCreateSerializer
from django.contrib.auth import get_user_model
from rest_framework import serializers, status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from .models import UserAccount, PayhereDetails, RFIDDetail, RFID, RequestPool
from django.utils import timezone

User = get_user_model()


class UserCreateSerializer(UserCreateSerializer):
    class Meta(UserCreateSerializer.Meta):
        model = User
        fields = ['id', 'email', 'name', 'password']


# class UserAccountPasswordResetConfirmationSerializer(serializers.ModelSerializer):
#
#     class Meta:
#         model = UserAccount
#         fields = ['password_reset_token',]


class PayhereDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = PayhereDetails
        fields = '__all__'


class OtpSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAccount
        fields = ['otp', 'otp_verified']


class UserActivationSerialier(serializers.ModelSerializer):
    class Meta:
        model = UserAccount
        fields = ['is_active', 'otp', 'otp_verified']


class SetNewPasswordSerializer(serializers.Serializer):
    """Serializer for Setting of New Password"""
    email = serializers.EmailField()
    password1 = serializers.CharField(max_length=20, min_length=4, write_only=True)
    password2 = serializers.CharField(max_length=20, min_length=4, write_only=True)

    class Meta:
        fields = ['email', 'password1', 'password2']

    def validate(self, attrs):
        try:
            pass1 = attrs.get('password1')
            pass2 = attrs.get('password2')

            if pass1 != pass2:
                raise AuthenticationFailed("Passwords didn't matched!", 401)

            user = UserAccount.objects.get(email=attrs.get('email'))

            if user.otp_verified:
                user.set_password(pass1)
                user.save()

            return user

        except Exception as e:
            raise AuthenticationFailed(e, 401)


class RFIDDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = RFIDDetail
        exclude = ['rf_id', 'user']


class RequestPoolSerializer(serializers.ModelSerializer):
    """ Serializer to get fuel payment request """
    EXP_TIME = 180  # in seconds

    class Meta:
        model = RequestPool
        fields = ['vehicle_no', 'merchant_id', 'amount']

    def validate(self, data):
        # RFID validation by vehicle_no
        try:
            latest_request_time = RequestPool.objects.filter(vehicle_no=data['vehicle_no']).latest('request_date').request_date
        except:
            latest_request_time = None
        # time stamp validation
        if latest_request_time is not None:
            if (timezone.now() - latest_request_time).total_seconds() < self.EXP_TIME:
                raise serializers.ValidationError({'Error': 'Please wait 3 minutes to place another request'})

        # Is vehicle registered
        if not RFIDDetail.objects.filter(vehicle_no=data['vehicle_no']).exists():
            raise AuthenticationFailed({'Error':'Failed to verify the RFID, Please register your vehicle!'})

        return data



