from django.urls import path, include, re_path
from django.views.generic import TemplateView
from django.contrib import admin
from accounts.views import *
from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register('user/payhere-detail', PayhereDetailViewSet)
# router.register('user/rfid-detail', RFIDDetailViewSet)


urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('djoser.urls')),
    path('auth/', include('djoser.urls.jwt')),
    path('auth/', include('djoser.urls.authtoken')),
    # path('activate/<str:uid>/<str:token>/', UserActivationView.as_view()),
    # path('password/reset/confirm/<str:uid>/<str:token>/', UserPasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    # path('password/reset/confirmed/<str:pk>/', UserPasswordResetView.as_view()),
    # path('auth/password/reset', PasswordResetView.as_view()),
    path('auth/send_otp', OtpView.as_view()),
    path('auth/user_verification', VerifyOTPView.as_view()),
    path('auth/set_new_password', SetNewPasswordAPIView.as_view()),
    path('auth/otp_initial_state', OtpInitialAPIView.as_view()),
    path('', include(router.urls)),
    path('user/rfid-detail', RFIDDetailListAPIView.as_view()),
    path('user/rfid-detail/<int:pk>', RFIDDetailAPIView.as_view()),
]
