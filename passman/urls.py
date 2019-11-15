from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path("register/", views.register, name="register"),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('home/', views.home, name='home'),
  #  path('generate/',views.generate, name='generate'),
    path('pass/', views.passwd, name='pass')

]
