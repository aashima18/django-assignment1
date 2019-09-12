from django.urls import path
from django.conf.urls import url
from .import views
from .views import indexx,signup,get_user_profile,update_profile

urlpatterns=[
    path('',views.indexx,name='indexx'),
    path('pass/<int:uid>',views.password,name='pass'),
    # path('login1/',views.login,name='login1'),
    # path('signup/', views.SignUp.as_view(), name='signup'),
    path('signup/', views.signup, name='signup'),
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.activate, name='activate'),
    path('profile',views.get_user_profile,name='profile'),
    path('editprofile',views.update_profile,name='editprofile'), 
    url(r'^password/$', views.change_password, name='change_password'),
   
]