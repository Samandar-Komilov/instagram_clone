from django.contrib.auth.models import AbstractUser
from rest_framework_simplejwt.tokens import RefreshToken
from django.db import models
from shared.models import BaseModel
from django.core.validators import FileExtensionValidator
from datetime import datetime, timedelta
import random
import uuid

# CONSTANTS

ORDINARY_USER, MANAGER, ADMIN = ("ordinary_user","manager","admin")
VIA_EMAIL, VIA_PHONE = ("via_email","via_phone")
NEW, CODE_VERIFIED, DONE, PHOTO_DONE = ("new","code_verified","done","photo_done")



# USER MODEL

class User(AbstractUser, BaseModel):
    USER_ROLES = (
        (ORDINARY_USER,ORDINARY_USER),
        (MANAGER,MANAGER),
        (ADMIN,ADMIN)
    )
    AUTH_TYPE_CHOICES = (
        (VIA_EMAIL,VIA_EMAIL),
        (VIA_PHONE,VIA_PHONE)
    )
    AUTH_STATUS_CHOICES = (
        (NEW,NEW),
        (CODE_VERIFIED,CODE_VERIFIED),
        (DONE,DONE),
        (PHOTO_DONE, PHOTO_DONE)
    )

    user_roles = models.CharField(max_length=31, choices=USER_ROLES, default=ORDINARY_USER)
    auth_type = models.CharField(max_length=31,choices=AUTH_TYPE_CHOICES)
    auth_status = models.CharField(max_length=31, choices=AUTH_STATUS_CHOICES, default=NEW)

    email = models.EmailField(null=True, blank=True, unique=True)
    phone_number = models.CharField(max_length=13, blank=True, null=True)
    photo = models.ImageField(upload_to='user_photos/',null=True, blank=True,
                              # Upload uchun allowed fayllar, masalan rasm orniga video yuklamaslik uchun
                              validators=[FileExtensionValidator(allowed_extensions=['jpg','jpeg','png'])])
    #created_time, updated_time, uuid - all of them are in Shared model!

    def __str__(self):
        return self.username
    
    # Read-Only property - to read the fullname of the user
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    def create_verify_code(self, verify_type):
        # Generating a new 4-digit code using list comprehension
        code = "".join([str(random.randint(0,100) % 10) for _ in range(4)])

        UserConfirmation.objects.create(
            user_id = self.id,
            verify_type = verify_type,
            code = code
        )
        return code
    
    def check_username(self):
        if not self.username:
            # temp_username = "instagram-35d3d873712d" kabi
            temp_username = f"instagram-{uuid.uuid4().__str__().split('-')[-1]}"
            while User.objects.filter(username=temp_username):
                temp_username = f"{temp_username}{random.randint(0,9)}" 
            self.username = temp_username

    def check_email(self):
        if self.email:
            normalize_email = self.email.lower() # eMaIl@gmail.com -> email@gmail.com
            self.email = normalize_email

    def check_pass(self):
        if not self.password:
            temp_password = f"password-{uuid.uuid4().__str__().split('-')[-1]}"
            self.password = temp_password

    # Hashing the password using Django's default hashing function
    def hashing_password(self):
        if not self.password.startswith("pbkdf2_sha256"):
            self.set_password(self.password)

    def token(self):
        refresh = RefreshToken.for_user(self)
        return {
            "access": str(refresh.access_token),
            "refresh_token": str(refresh)
        }
    
    def clean(self):
        self.check_email()
        self.check_username()
        self.check_pass()
        self.hashing_password()

    def save(self, *args, **kwargs):
        self.clean()
        super(User, self).save(*args, **kwargs)




# USER CONFIRMATION MODEL
    
PHONE_EXPIRE = 2
EMAIL_EXPIRE = 4

class UserConfirmation(BaseModel):
    TYPE_CHOICES = (
        (VIA_PHONE,VIA_PHONE),
        (VIA_EMAIL,VIA_EMAIL)
    )
    code = models.CharField(max_length=4)
    verify_type = models.CharField(max_length=31, choices=TYPE_CHOICES)
    user = models.ForeignKey('users.User', models.CASCADE, related_name='verify_codes') # related_name - teskari reference
    expire_time = models.DateTimeField(null=True)
    is_confirmed = models.BooleanField(default=False)

    def __str__(self):
        return str(self.user.__str__())
    
    def save(self, *args, **kwargs):
        if self.verify_type == VIA_EMAIL:  # 30-mart 11-33 + 5minutes
            self.expire_time = datetime.now() + timedelta(minutes=EMAIL_EXPIRE)
        else:
            self.expire_time = datetime.now() + timedelta(minutes=PHONE_EXPIRE)
        super(UserConfirmation, self).save(*args, **kwargs)