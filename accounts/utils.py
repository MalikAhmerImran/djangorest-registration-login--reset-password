from django.core.mail import  EmailMessage,send_mail
import os
import random
from accounts.models import User
class Util:
    @staticmethod
    def send_email(data):
        email=EmailMessage(
            subject=data['subject'],
            body=data['body'],
            from_email='malikracco1234@gmail.com',
            to=[data['to_email']]
        )
        email.send()
def  email_otp_verifcation(email):
        subject='OTP For  Email Verification'
        otp=random.randint(1,100)
        message=f'your otp is {otp}'
        email_from='malikracco1234@gmail.com'
        send_mail(subject,message,email_from,[email])
        user_obj=User.objects.get(email=email)
        user_obj.otp=otp
        user_obj.save()
def  password_reset_otp(email):
        subject='OTP For  Password Reset'
        otp=random.randint(100000,999999)
        message=f'your otp is {otp}'
        email_from='malikracco1234@gmail.com'
        send_mail(subject,message,email_from,[email])
        user_obj=User.objects.get(email=email)
        user_obj.otp=otp
        user_obj.save()
        
       