from django.contrib import admin
from django.urls import path,include
from accounts. views import  ChangePasswordView,UserRegistrationView,UserLoginView,UserPasswordResetView,UserPasswordResetUpdateView,UserVerifyEmailView,ResendOtpView,InformationView
urlpatterns = [
    path('register/',UserRegistrationView.as_view(),name='register'),
    path('login/',UserLoginView.as_view(),name='login'),
    path('reset/',UserPasswordResetView.as_view(),name='reset'),
    path('verify/',UserVerifyEmailView.as_view(),name='verify'),
    path('otpresend/',ResendOtpView.as_view(),name='otpresend'),
    path('changepassword/',ChangePasswordView.as_view(),name='change password'),
    path('resetpasswordupdate/',UserPasswordResetUpdateView.as_view(),name='password update'),
    path('information/',InformationView.as_view(),name='information'),
]
