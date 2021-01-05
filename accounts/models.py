from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager, UserManager
from rest_framework.response import Response
from rest_framework import status
from django.utils.html import format_html


class UserAccountManager(BaseUserManager):
    def create_user(self, name, email, password=None):
        if name is None:
            raise TypeError('User need to have username!')
        if email is None:
            raise TypeError('User need to have Email!')

        user = self.model(name=name, email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, name, email, password):
        if password is None:
            raise TypeError("Password shouldn't be None!")

        user = self.create_user(name, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()

        # activate super-user
        s_user = UserAccount.objects.get(email=email)
        s_user.is_active = True
        s_user.save()

        return user


class UserAccount(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    password_reset_token = models.CharField(max_length=255, default="")
    otp = models.CharField(max_length=6, default=0)
    otp_verified = models.BooleanField(default=False)

    objects = UserAccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    def get_full_name(self):
        return self.name

    def get_short_name(self):
        return self.name

    def __str__(self):
        return self.email


class PayhereDetails(models.Model):
    merchant_id = models.CharField(max_length=20)  # PayHere Merchant ID of the merchant
    order_id = models.CharField(max_length=20)  # Order ID sent by Merchant to Checkout page
    payhere_amount = models.DecimalField(max_digits=10, decimal_places=2)  # Total Amount of the payment
    date = models.DateTimeField(auto_now_add=True)
    card_holder_name = models.CharField(max_length=255, default="")  # Card Holder Name
    card_no = models.CharField(max_length=19, default="")  # Card number
    card_expiry = models.CharField(max_length=5, default="")  # Card expiry in format MMYY (Ex: 0122)
    user = models.ForeignKey(UserAccount, on_delete=models.CASCADE)

    def __str__(self):
        return '{} - {}'.format(self.order_id, self.user)


class RFID(models.Model):
    rf_id = models.CharField(max_length=255)

    def __str__(self):
        return 'id_{} -RFID_{}'.format(self.id, self.rf_id)


class RFIDDetail(models.Model):
    rf_id = models.OneToOneField(RFID, on_delete=models.CASCADE, null=True, blank=True)
    vehicle_no = models.CharField(max_length=10)
    engine_no = models.CharField(max_length=255)
    fuel_type = models.CharField(max_length=20)
    phone = models.CharField(max_length=12)
    address = models.TextField()
    user = models.ForeignKey(UserAccount, on_delete=models.CASCADE)
    is_assigned = models.BooleanField(default=False)

    def get_rf_id(self):
        if self.rf_id is None:
            return format_html(
                '<span style="color:#FF0000;">*** RFID NOT ASSIGNED ***</span>'
            )
        return 'id_{} -RFID_{}-user_{}'.format(self.id, self.rf_id, self.user)
    # def __str__(self):
    #     return 'id_{} -RFID_{}-user_{}'.format(self.id, self.rf_id, self.user)
