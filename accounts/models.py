from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager


class UserAccountManager(BaseUserManager):
    def create_user(self, email, name, password=None):
        if not email:
            raise ValueError('Users must have an email address')
        
        email = self.normalize_email(email)
        user = self.model(email=email, name=name)

        user.set_password(password)
        user.save()

        return user


class UserAccount(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    password_reset_token = models.CharField(max_length=255, default="")

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

    merchant_id = models.CharField(max_length=20)           # PayHere Merchant ID of the merchant
    order_id = models.CharField(max_length=20)              # Order ID sent by Merchant to Checkout page
    payhere_amount = models.DecimalField(max_digits=10, decimal_places=2)  # Total Amount of the payment
    card_holder_name = models.CharField(max_length=255, default="")   # Card Holder Name
    card_no = models.CharField(max_length=19, default="")    # Card number
    card_expiry = models.CharField(max_length=5, default="")    # Card expiry in format MMYY (Ex: 0122)
    user = models.ForeignKey(UserAccount, on_delete=models.CASCADE)

    def __str__(self):
        return '{} - {}'.format(self.order_id, self.user)
