from djoser.serializers import UserCreateSerializer
from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import UserAccount, PayhereDetails
User = get_user_model()


class UserCreateSerializer(UserCreateSerializer):
    class Meta(UserCreateSerializer.Meta):
        model = User
        fields = ['id', 'email', 'name', 'password']


class UserAccountPasswordResetConfirmationSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserAccount
        fields = ['password_reset_token',]


class PayhereDetailsSerializer(serializers.ModelSerializer):

    class Meta:
        model = PayhereDetails
        fields = '__all__'
