from django import forms
from django.core.validators import RegexValidator
from django.forms import ModelForm
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from django.contrib.auth.admin import UserAdmin
from .models import User
from django.contrib.auth import get_user_model
User = get_user_model()




class SignUpForm(forms.ModelForm):
    first_name = forms.CharField(max_length=30, required=True)
    last_name = forms.CharField(max_length=30, required=True)
    email = forms.EmailField(max_length=254, required=True)
    # check = forms.BooleanField(required = True,label='Terms and conditions')
   
    class Meta:
        model = User
        fields = ('first_name', 'last_name','username','email','phone')
        

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email and User.objects.filter(email=email).count() > 0:
            raise forms.ValidationError('This email address is already registered.')
        return email

    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        if phone and User.objects.filter(phone=phone).count() > 0:
            raise forms.ValidationError('This phone number is already registered.')
        return phone

class PasswordForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput())
    confirm_password = forms.CharField(widget=forms.PasswordInput())
    class Meta:
        model = User
        fields = ('password', 'confirm_password')
    def clean(self):
        cleaned_data = super(PasswordForm, self).clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        min_length = 8
        if len(password) < min_length:
            msg = 'Password must be at least %s characters long.' %(str(min_length))
            self.add_error('password', msg)

        # check for digit
        if sum(c.isdigit() for c in password) < 1:
            msg = 'Password must contain at least 1 number.'
            self.add_error('password', msg)

        # check for uppercase letter
        if not any(c.isupper() for c in password):
            msg = 'Password must contain at least 1 uppercase letter.'
            self.add_error('password', msg)

        # check for lowercase letter
        if not any(c.islower() for c in password):
            msg = 'Password must contain at least 1 lowercase letter.'
            self.add_error('password', msg)

        if password != confirm_password:
            raise forms.ValidationError(
                "password and confirm_password does not match"
            )


class LoginForm(forms.ModelForm):
    
    class Meta:
        model = User
        fields = ('username', 'password')


class UpdateProfile(forms.ModelForm):
    username = forms.CharField(required=True, widget=forms.TextInput(attrs={'readonly':'readonly'}))
    first_name = forms.CharField(required=False)
    last_name = forms.CharField(required=False)
    email = forms.EmailField(required=True ,widget=forms.TextInput(attrs={'readonly':'readonly'}))
    Image = forms.ImageField(required=False)
    organization = forms.CharField(required=False)
    address = forms.CharField(required=False)

    class Meta:
        model = User
        fields = ('username','first_name', 'last_name','phone','email','Image','organization','address')