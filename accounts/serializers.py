from rest_framework import serializers
from rest_framework.response import Response 
from accounts.models import User,Store,Information
from django.contrib.auth.password_validation  import validate_password
from django.core.exceptions import ValidationError
from accounts.utils import Util
class UserRegistrationSerializer(serializers.ModelSerializer):
    password2=serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model=User
        fields='__all__'
        extra_kwargs={
            'password':{'write_only':True}
        }
    def validate(self, attrs):
        password=attrs.get('password')
        password2=attrs.get('password2')
        
        if password!= password2:
            raise serializers.ValidationError("Password and confirm password didnot match   ")
        return attrs    
    def create(self, validated_data):
        try:
            validate_password(password=validated_data['password'])
        except ValidationError as err:
            raise serializers.ValidationError({"password":err.messages})    
        return User.objects.create_user(**validated_data)
class UserLoginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=50)
    class Meta:
        model=User
        fields=['password','email']
class UserPasswordResetSerailizer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=50)
    class Meta:
        model=User
        fields=['email']
class UserPasswordResetUpdateserializer(serializers.Serializer):
      password=serializers.CharField(max_length=50,style={'input_type':'password'},write_only=True)
      password2=serializers.CharField(max_length=50,style={'input_type':'password'},write_only=True)
      otp=serializers.CharField()
      class Meta:
        model=User
        fields=['otp','password','password2']
class   UserVerifyEmailSerializer(serializers.Serializer):
    email=serializers.CharField()
    otp=serializers.CharField()   
class  ResendOtpSerializer(serializers.Serializer):
    email=serializers.CharField()
    
class ChangePasswordSerializer(serializers.Serializer):
        email=serializers.CharField()
        old_password=serializers.CharField(max_length=50,style={'input_type':'password'},write_only=True)
        new_password=serializers.CharField(max_length=50,style={'input_type':'password'},write_only=True)

class InformationSerializer(serializers.Serializer):
    email=serializers.CharField()
    class  Meta:
        model=Information
        fields="__all__"
