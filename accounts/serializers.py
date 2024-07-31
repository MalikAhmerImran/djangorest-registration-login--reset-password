from rest_framework import serializers
from accounts.models import User
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
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
        return User.objects.create_user(**validated_data)
    
class UserLoginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=50)
    class Meta:
        model=User
        fields=['password','email']

# class UserProfileViewSerializer(serializers.ModelSerializer):
#     class Meta:
#         model=User
#         fields=['username','email']        

class UserPasswordResetSerailizer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=50)
    class Meta:
        model=User
        fields=['email']

    def validate(self, attrs):
        email=attrs.get('email')
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            uid=urlsafe_base64_encode(force_bytes(user.id))
            print("encoded user id",uid)
            token=PasswordResetTokenGenerator().make_token(user)
            print('token',token)
            link='http//localhost:8000/api/user/register/'+uid+'/'+token
            print("password reset link",link)
            body="click the following link to reset password" + link
            data={
                "subject":'reset your password',
                "body":body,
                "to_email":user.email
                
            }
            Util.send_email(data)
            return attrs
        else:
            raise ValidationError("You are not the registered user")
        
class UserPasswordResetUpdate(serializers.ModelSerializer):
      password=serializers.CharField(max_length=50,style={'input_type':'password'},write_only=True)
      password2=serializers.CharField(max_length=50,style={'input_type':'password'},write_only=True)

      class Meta:
        model=User
        
        fields=['password','password2']
      
      def validate(self, attrs):
        try:
            password=attrs.get('password')
            password2=attrs.get('password2')
            uid=self.context.get('uid')
            token=self.context.get('token')
            
            if password!= password2:
                raise serializers.ValidationError("Password and confirm password didnot match   ")
            id=smart_str(urlsafe_base64_decode(uid))
            user=User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise ValidationError("Token is npt valid or expired")
            user.set_password(password)
            user.save()
            return attrs  
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator(user,token)
            raise ValidationError("Token is npt valid or expired")
        
class   UserVerifyEmailSerializer(serializers.Serializer):
    email=serializers.CharField()
    otp=serializers.CharField()   

class  ResendOtpSerializer(serializers.Serializer):
    email=serializers.CharField()
     

   
