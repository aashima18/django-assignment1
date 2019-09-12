from django.db import models
from django.contrib.auth.models import UserManager
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from .validators import validate_file_extension


def validate_image(image):     
    file_size = image.file.size
    limit_mb = 2
    if file_size >limit_mb * 1024 * 1024:
       raise ValidationError("Max size of file is %s MB" % limit_mb)


class User(AbstractUser):
    email = models.EmailField(max_length=254)
    username = models.CharField(max_length=254,unique=True)
    first_name = models.CharField(max_length=15)
    last_name = models.CharField(max_length=15)
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,10}$', message="Phone number must be entered in the format: '+999999999'. Up to 10 digits allowed.")
    phone = models.CharField(validators=[phone_regex],max_length=10)
    organization=models.CharField(max_length=254)
    address = models.TextField()
    Image = models.ImageField(upload_to='images/',validators=[validate_file_extension,validate_image])
   


   
  

    

