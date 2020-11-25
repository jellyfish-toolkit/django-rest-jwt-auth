import jwt
from django.conf import settings
# JWT_SECRET, JWT_ALGORITHM, JWT_ROLE
from django.contrib.auth import authenticate
from django.http.response import HttpResponse
from http import HTTPStatus
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
import json


def _create_jwt(user):
    if user:
        resp = json.dumps({'token': jwt.encode({
            'role': settings.JWT_ROLE,
            'userid': str(user.id)
        }, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM).decode('utf-8')})
    else:
        resp = {'token': None}  # TODO maybe return jwt for anon user
    return json.dumps(resp)


def prest_signin(request):
    if request.methpd == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)  # return user model if it exists
        if user is not None:
            return HttpResponse(_create_jwt(user))
        else:
            return HttpResponse(_create_jwt(user), status=HTTPStatus.UNAUTHORIZED)
    return HttpResponse('', status=HTTPStatus.METHOD_NOT_ALLOWED)


def prest_signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if not user:
            user = User(username=username, password=make_password(password))
            user.save()
        else:
            user = None
        return HttpResponse(_create_jwt(user))
    return HttpResponse('', status=HTTPStatus.METHOD_NOT_ALLOWED)
