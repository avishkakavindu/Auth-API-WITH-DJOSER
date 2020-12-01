from djoser.serializers import UserCreateSerializer
from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import UserAccount
User = get_user_model()


class UserCreateSerializer(UserCreateSerializer):
    class Meta(UserCreateSerializer.Meta):
        model = User
        fields = ['id', 'email', 'name', 'password']


class UserAccountPasswordResetConfirmationSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserAccount
        fields = ['password_reset_token',]



