from rest_framework import serializers
from rest_framework.response import Response 
from accounts.models import User,Product
from django.contrib.auth.password_validation  import validate_password
from django.core.exceptions import ValidationError
from accounts.utils import Util
class UserRegistrationSerializer(serializers.ModelSerializer):
    products=serializers.PrimaryKeyRelatedField(many=True,queryset=Product.objects.all())

    password2=serializers.CharField(style={'input_type':'password'},write_only=True)
    is_owner=serializers.BooleanField()
    class Meta:
        model=User
        fields=['username','email','password','is_owner','password2','products']
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
        print(validated_data)
        try:
            validate_password(password=validated_data['password'])
        except ValidationError as err:
            raise serializers.ValidationError({"password":err.messages})    
        username=validated_data['username']
        email=validated_data['email']
        password=validated_data['password']
        is_owner=validated_data['is_owner']
        return User.objects.create_user(username=username,email=email,password=password,is_owner=is_owner)
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

class ProductSerializer(serializers.ModelSerializer):
           user = serializers.ReadOnlyField(source='user.username')
           

           class Meta:
                model=Product
                fields=['id','product_name','product_price','user']
