from django.urls import path
from . import views

urlpatterns = [
    path('signin/', views.prest_signin),
    path('signup/', views.prest_signup)
]