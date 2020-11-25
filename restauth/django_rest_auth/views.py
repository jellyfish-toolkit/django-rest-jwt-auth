import jwt
from django.conf import settings
# JWT_SECRET, JWT_ALGORITHM, JWT_ROLE
from django.contrib.auth import authenticate


def prest_signin(request):
    username = request.POST['username']
    password = request.POST['password']
    user = authenticate(request, username=username, password=password)
    if user is not None:
        pass


def prest_signup(request):
    pass
