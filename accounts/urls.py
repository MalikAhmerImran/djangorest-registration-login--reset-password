from django.contrib import admin
from django.urls import path,include
from accounts. views import UserRegistrationView,UserLoginView,UserPasswordResetView,UserPasswordResetUpdateView,UserVerifyEmailView,ResendOtpView
urlpatterns = [
    path('register/',UserRegistrationView.as_view(),name='register'),
    path('login/',UserLoginView.as_view(),name='login'),
    path('reset/',UserPasswordResetView.as_view(),name='reset'),
    path('verify/',UserVerifyEmailView.as_view(),name='verify'),
    path('otpresend/',ResendOtpView.as_view(),name='otpresend'),
    path('resetpasswordupdate/',UserPasswordResetUpdateView.as_view(),name='password update'),
]
