from django.contrib import admin
from django.urls import path,include
from accounts. views import  (ChangePasswordView,
                              UserRegistrationView,
                              UserLoginView,
                              UserPasswordResetView,
                              UserPasswordResetUpdateView,
                              UserVerifyEmailView,
                              ResendOtpView,
                              ProductListView,
                              ProductDetailView,
                              ProductListCreateMixinView,
                              ProductDetailMixinView
                              )
urlpatterns = [
    path('register/',UserRegistrationView.as_view(),name='register'),
    path('login/',UserLoginView.as_view(),name='login'),
    path('reset/',UserPasswordResetView.as_view(),name='reset'),
    path('verify/',UserVerifyEmailView.as_view(),name='verify'),
    path('otpresend/',ResendOtpView.as_view(),name='otpresend'),
    path('changepassword/',ChangePasswordView.as_view(),name='change password'),
    path('resetpasswordupdate/',UserPasswordResetUpdateView.as_view(),name='password update'),
    path('product/',ProductListView.as_view(),name='product'),
    path('product/<int:pk>/',ProductDetailView.as_view(),name='product details'),
    path('product/mixin/',ProductListCreateMixinView.as_view(),name='mixin view'),
     path('product/mixin/<int:pk>/',ProductDetailMixinView.as_view(),name='mixin detail view'),

]
