from djoser.serializers import UserCreateSerializer
from django.contrib.auth import get_user_model
from rest_framework import serializers, status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from .models import UserAccount, PayhereDetails, RFIDDetail, RFID
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


class RFIDDetailSerializer(serializers.ModelSerializer):

    class Meta:
        model = RFIDDetail
        exclude = ['rf_id', 'user']


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
