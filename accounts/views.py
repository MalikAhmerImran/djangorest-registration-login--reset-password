from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from accounts.serializers import ResendOtpSerializer,UserRegistrationSerializer,UserLoginSerializer,UserPasswordResetSerailizer,UserPasswordResetUpdate,UserVerifyEmailSerializer
from django.contrib.auth import authenticate
import logging
from accounts.utils import *
from accounts.tokens import get_tokens_for_user
logger = logging.getLogger(__name__)
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
        print(serializer)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')
            
            logger.info(f"Attempting to authenticate user: {email}")
            
            user = authenticate(request, email=email, password=password)
            
            tokens=get_tokens_for_user(user)
            

            
            if user is not None:
                logger.info(f"User {email} authenticated successfully")
                return Response({'refresh_token':tokens['refresh'],'access_token':tokens['access'],'msg': 'Login successfully','uid':user.id,'username':user.username,'email':user.email}, status=status.HTTP_200_OK)
            else:
                logger.warning(f"Authentication failed for user: {email}")
                return Response({
                    'errors': {'non_field_errors': ["Email or password is not valid"]},
                }, status=status.HTTP_401_UNAUTHORIZED)
        else:
            logger.error(f"Invalid serializer data: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class UserProfileView(APIView):
#     def get(self,request,format=None):
#         serializer=UserProfileViewSerializer(request.user)
#         if serializer.is_valid():
#             return Response(serializer.data,status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
    def post(self,request,fromat=None):
        serializer=UserPasswordResetSerailizer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':"password Reset link sent to your email please check your email"},status=status.HTTP_200_OK)
        return Response(serializer.error,status=status.HTTP_400_BAD_REQUEST)
    
class UserPasswordResetUpdateView(APIView):
    def post(self,request,uid,token,format=None):
        serializer=UserPasswordResetUpdate(data=request.data,context={'uid':uid,'token':token})
        if serializer.is_valid(raise_exception=True):
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
                logger.error(f"Invalid email: {email}")
                return Response({
                    'msg': 'something went wrong',
                    'data': 'invalid email'
                }, status=status.HTTP_400_BAD_REQUEST)

            if user.otp != otp:
                logger.error(f"Wrong OTP for email: {email}")
                return Response({
                    'msg': 'something went wrong',
                    'data': 'wrong otp'
                }, status=status.HTTP_400_BAD_REQUEST)

            user.is_verified = True
            user.save()
            logger.info(f"User verified: {user.email}, is_verified: {user.is_verified}")

            return Response({
                'msg': 'email verified'
            }, status=status.HTTP_200_OK)
        
        logger.error(f"Invalid serializer data: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

import logging

logger = logging.getLogger(__name__)

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

