from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from accounts.serializers import ChangePasswordSerializer,ResendOtpSerializer,UserRegistrationSerializer,UserLoginSerializer,UserPasswordResetSerailizer,UserPasswordResetUpdateserializer,UserVerifyEmailSerializer,InformationSerializer
from django.contrib.auth import authenticate
import logging
from accounts.models import Information
from accounts.utils import *
from accounts.tokens import get_tokens_for_user
from django.contrib.auth.password_validation  import validate_password
from django.core.exceptions  import ValidationError
# Create your views here.


class UserRegistrationView(APIView):
    def post(self,request,format=None):
        serializer=UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user=serializer.save()
            email_otp_verifcation(user.email)
            return Response({'msg':'registration sucessul','is_verified':user.is_verified},status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    

class UserLoginView(APIView):
    def post(self, request, format=None):
        data=request.data
        serializer = UserLoginSerializer(data=data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')
            user = authenticate(request, email=email, password=password)
            if not user: 
                 return Response({"msg":'user does not exits '},status=status.HTTP_404_NOT_FOUND)
            tokens=get_tokens_for_user(user)
            if user is not None:
                return Response({'refresh_token':tokens['refresh'],'access_token':tokens['access'],'msg': 'Login successfully','uid':user.id,'username':user.username,'email':user.email}, status=status.HTTP_200_OK)
            else:
                return Response({
                    'errors': {'non_field_errors': ["Email or password is not valid"]},
                }, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        

class UserPasswordResetView(APIView):
    def post(self,request,fromat=None):
        serializer=UserPasswordResetSerailizer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email=serializer.validated_data['email']
            user=User.objects.filter(email=email).first()
            if user:
                password_reset_otp(user.email)
                return Response({'msg':'Please check your email otp is send to password reset'},status=status.HTTP_200_OK)
            return Response({'msg':'user is not exits'},status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.error,status=status.HTTP_400_BAD_REQUEST)


class UserPasswordResetUpdateView(APIView):
    def post(self,request):
        serializer=UserPasswordResetUpdateserializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            password=serializer.validated_data['password']
            password2=serializer.validated_data['password2']
            otp=serializer.validated_data['otp']
            user=User.objects.filter(otp=otp).first()
            if not user:
                 return Response({"msg":"User does not exits"},status=status.HTTP_404_NOT_FOUND)
            try:
                 validate_password(password=password)
                 if password!=password2:
                            return Response({'msg':'Password and Confirm password did not match'},status=status.HTTP_404_NOT_FOUND)
            except ValidationError as err:
                 return Response(ValidationError({'password':err.messages})) 
            if user.otp!=otp:
                    return Response({'msg':'you have entered the wrong otp'},status=status.HTTP_404_NOT_FOUND)
            print(user.set_password(password))
            user.save()
            print(user.password)
            return Response({'msg':'password reset successfully'},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    

class UserVerifyEmailView(APIView):
    def post(self, request):
        serializer = UserVerifyEmailSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            user = User.objects.filter(email=email).first()
            if not user:
                return Response({
                    'msg': 'something went wrong',
                    'data': 'invalid email'
                }, status=status.HTTP_400_BAD_REQUEST)
            if user.otp != otp:
                return Response({
                    'msg': 'something went wrong',
                    'data': 'wrong otp'
                }, status=status.HTTP_400_BAD_REQUEST)
            user.is_verified = True
            user.save()
            return Response({
                'msg': 'email verified'
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class ResendOtpView(APIView):
    def post(self, request):
        serializer = ResendOtpSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.filter(email=email).first()
            if user :
                if not user.is_verified:   
                        email_otp_verifcation(user.email)
                        return Response({'msg': 'OTP resent, please check your email.'}, status=status.HTTP_200_OK)
                else:
                        return Response({'msg': 'Email already verified'}, status=status.HTTP_200_OK)
            else:
                 return Response({'msg': 'User not found with the provided email'}, status=status.HTTP_404_NOT_FOUND) 
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class ChangePasswordView(APIView):
     def post(self,request):
         serializer=ChangePasswordSerializer(data=request.data)
         if serializer.is_valid():
              email=serializer.validated_data['email']

              old_password=serializer.validated_data['old_password']
              print(old_password)
              new_password=serializer.validated_data['new_password']
              print("user=",User.objects.filter(password=old_password).first())
              user=User.objects.filter(email=email).first()
              if user is None:
                   return Response({'msg':'old password is incorrect'},status=status.HTTP_404_NOT_FOUND)
               
              print(user.set_password(new_password))
              user.save()
              print(user.password)
              return Response({'msg':'password change successfully'},status=status.HTTP_200_OK)
         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
     
     
class InformationView(APIView):
    def post(self, request):
        serializer = InformationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.filter(email=email).first()
            print(user)

            if not user:
                return Response({'msg': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

            user_information = Information.objects.filter(user_key=user)
            print(user_information)

            if not user_information.exists():
                return Response({'msg': 'Information not found for this user'}, status=status.HTTP_404_NOT_FOUND)

            
            information_list = []
            for info in user_information:
                print(info)
                information_list.append({
                    'is_owner': info.is_owner,
                    'is_staff': info.is_staff,
                    'store': info.Store_key.name,
                     'user':info.user_key.username
                })

            return Response({'msg': 'Information retrieved successfully', 'data': information_list}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



          