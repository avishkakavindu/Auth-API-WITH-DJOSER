from django.urls import path, include, re_path
from django.views.generic import TemplateView
from accounts.views import UserActivationView
from accounts.views import *
from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register('user/payhere-detail', PayhereDetailViewSet)

urlpatterns = [
    path('auth/', include('djoser.urls')),
    path('auth/', include('djoser.urls.jwt')),
    path('auth/', include('djoser.urls.authtoken')),
    path('activate/<str:uid>/<str:token>/', UserActivationView.as_view()),
    path('password/reset/confirm/<str:uid>/<str:token>/', UserPasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('password/reset/confirmed/<str:pk>/', UserPasswordResetView.as_view()),
    path('auth/password/reset', PasswordResetView.as_view()),
    path('', include(router.urls))
]

