from django.shortcuts import render,redirect,reverse
from django.contrib.auth import authenticate,login as dj_login
from django.core.mail import send_mail, BadHeaderError
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from .models import User
from django.template import RequestContext
# from django.contrib.auth.forms import CustomUserLoginForm
from .forms import SignUpForm,PasswordForm, LoginForm,UpdateProfile
from django.contrib.auth.forms import PasswordChangeForm
# from .templates import  ValidCaptcha
import json
from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.views import generic
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from core.tokens import account_activation_token
from django.contrib.auth.models import User
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth import get_user_model
User = get_user_model()


def indexx(request):
     return render(request, 'layout.html')     



# class SignUp(generic.CreateView):
#      form_class =SignUpForm
#      success_url = reverse_lazy('indexx')
#      template_name = 'registration/signup.html'



def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            # if Captcha.is_valid():
                user= form.save(commit=False)
                user.phone_number = form.cleaned_data.get('phone_number')
                user.is_active = False
                user.save()
                current_site = get_current_site(request)
                mail_subject = 'Activate your blog account.'
                message = render_to_string('acc_active_email.html', {
                    'user': user,
                    'domain': current_site.domain,
                    'uid':urlsafe_base64_encode(force_bytes(user.pk)) ,
                    'token':account_activation_token.make_token(user),
                })
                to_email = form.cleaned_data.get('email')
            
                email = EmailMessage(mail_subject, message, to=[to_email])
                email.send()
                return HttpResponse('Please confirm your email address to complete the registration')
    else:
        form = SignUpForm()
        
    return render(request, 'registration/signup.html', {'form': form})



def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        dj_login(request, user)
        return HttpResponseRedirect(reverse('pass', args=(uid,)))
        # return redirect('pass')
    else:
        return HttpResponse('Activation link is invalid!')

def password(request,uid):
    if request.method == 'POST':
        form = PasswordForm(request.POST)
        if form.is_valid():
            user = User.objects.get(pk=uid)
            password= request.POST.get('password')
            password= form.cleaned_data['password']
            user.set_password(password)
            user.save()
            dj_login(request,user)
            return redirect('login')
    else:
         form = PasswordForm()    
    return render(request, "gen_pas.html", {'form': form})


# def login(request):
#     if request.method == 'POST':
#           form = LoginForm(request.POST)
#           username = request.POST['username']
#           password = request.POST['password']
#           user = authenticate(username=username, password=password)
      
#           if user is not None:
#                   print("sjh")
#                   dj_login(request, user)
#                   print("dbb")
#                   # Redirect to index page.
#                   return redirect('profile')   
#     else:
#         form = PasswordForm()    
        
#     return render(request, "registration/login.html", {'form': form})




@login_required
def get_user_profile(request):
    user=request.user
    users = User.objects.all()
    return render(request, 'profile.html', {"users":users})

    
@login_required
def update_profile(request):
    if request.method == 'POST':
        user_form = UpdateProfile(request.POST, request.FILES , instance=request.user)
        
        if (user_form.is_valid()):
           
            user_form.save()            
            return HttpResponseRedirect(reverse('profile'))
        
    else:
        user_form = UpdateProfile(instance=request.user)
    return render(request, 'registration/update_profile.html', {
        'user_form': user_form
    })



def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            # messages.success(request, 'Your password was successfully updated!')
            return redirect('profile')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'change_password.html', {
        'form': form
    })