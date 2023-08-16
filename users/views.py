from django.utils.datetime_safe import datetime
from rest_framework.generics import CreateAPIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.views import APIView
from rest_framework.generics import UpdateAPIView
from rest_framework import permissions
from rest_framework.decorators import permission_classes
from rest_framework.exceptions import ValidationError, NotFound
from rest_framework.response import Response
from .serializers import ChangeUserInformation, ChangeUserPhotoSerializer, ForgotPasswordSerializer, LoginSerializer, LoginRefreshSerializer, LogoutSerializer, ResetPasswordSerializer

from shared.utility import check_email_or_phone, send_email

from .models import CODE_VERIFIED, DONE, NEW, VIA_EMAIL, VIA_PHONE, User
from .serializers import SignUpSerializer


class CreateUserView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignUpSerializer
    permission_classes = (permissions.AllowAny, )


class VerifyAPIView(APIView):
    permission_classes = (permissions.IsAuthenticated, )

    def post(self, request, *args, **kwargs):
        user = self.request.user
        code = self.request.data.get('code')

        self.check_verify(user, code)
        return Response(
            data={
                "success":True,
                "auth_status":user.auth_status,
                "access":user.token()['access'],
                "refresh":user.token()['refresh_token'],
            }
        )

    @staticmethod
    def check_verify(user, code):
        verifies = user.verify_codes.filter(expire_time__gte=datetime.now(), code=code, is_confirmed=False)
        if not verifies.exists():
            data = {
                "message":"Tasdiqlash kodingiz xato yoki eskirgan." 
            }
            raise ValidationError(data)
        else:
            verifies.update(is_confirmed=True)
        if user.auth_status == NEW:
            user.auth_status = CODE_VERIFIED
            user.save()
        return True
    
# Tasdiqlash kodini qayta jo'natish
class GetNewVerification(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self,request, *args, **kwargs):
        user = self.request.user
        self.check_verification(user)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_email(user.phone_number, code)
        else:
            data = {
                "message": "Email yoki telefon raqami noto'g'ri"
            }
            raise ValidationError(data)
        return Response({
            "success": True,
            "message": "Tasdiqlash kodingiz qaytadan jo'natildi."
        })


    @staticmethod
    def check_verification(user):
        verifies = user.verify_codes.filter(expire_time__gte=datetime.now(), is_confirmed=False)
        if verifies.exists():
            data = {
                "message": "Kodingiz hali ishlatish uchun yaroqli. Biroz kutib turing"
            }
            raise ValidationError(data)
        
# User data change View

class ChangeUserInformationView(UpdateAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = ChangeUserInformation
    http_method_names = ['patch', 'put']

    # User datasini ID bilan emas oddiy request.user bilan change qilish uchun
    def get_object(self):
        return self.request.user
    
    # update() va patch() - ozimiz istagan holatda Response qaytarish uchun
    def update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).update(request, *args, **kwargs)
        data = {
            "success":True,
            "message":"User updated successfully!",
            "auth_status": self.request.user.auth_status,
        }
        return Response(data, status=200)
    
    def partial_update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).partial_update(request, *args, **kwargs)
        data = {
            "success":True,
            "message":"User updated successfully!",
            "auth_status": self.request.user.auth_status,
        }
        return Response(data, status=200)
    
# Change user data - VIEW
class ChangeUserPhotoView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    
    def put(self, request, *args, **kwargs):
        serializer = ChangeUserPhotoSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            # update(instance) - instanceni serializerdagi validatsiya qilingan data yordamida yangilab, return qilsih
            serializer.update(user, serializer.validated_data)
            return Response({
                "success":True,
                "message":"User photo has been changed successfully!"
            }, status=200)
        
# LOGIN VIEW
class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer

class LoginRefreshView(TokenRefreshView):
    serializer_class = LoginRefreshSerializer

class LogOutView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        try:
            refresh_token = self.request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            data = {
                "success": True,
                "message": "You are logged out!"
            }
            return Response(data, status=205)
        except TokenError:
            return Response(status=400)
        
# Forgot Password View
class ForgotPasswordView(APIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = ForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        email_or_phone = serializer.validated_data.get('email_or_phone')
        user = serializer.validated_data.get('user')
        if check_email_or_phone(email_or_phone) == 'phone':
            code = user.create_verify_code(VIA_PHONE)
            send_email(email_or_phone, code)
        elif check_email_or_phone(email_or_phone) == 'email':
            code = user.create_verify_code(VIA_EMAIL)
            send_email(email_or_phone, code)
        return Response({
            "success": True,
            "message": "Tasdiqlash kodi muvaffaqiyatli yuborildi!",
            "access": user.token()['access'],
            "refresh": user.token()['refresh_token'],
            "user_status": user.auth_status, 
        }, status=200)
    
# Reset Password
class ResetPasswordView(UpdateAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = (permissions.IsAuthenticated, )
    http_method_names = ['patch', 'put']

    def get_object(self):
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        response = super(ResetPasswordView, self).update(request, *args, **kwargs)
        try:
            user = User.objects.get(id=response.data.get('id'))
        except ObjectDoesNotExist as e:
            raise NotFound(detail="User Not Found")
        return Response({
            "success": True,
            "message": "Parolingiz muvaffaqiyatli o'zgartirildi!",
            "access": user.token()['access'],
            "refresh": user.token()['refresh_token'],
        })