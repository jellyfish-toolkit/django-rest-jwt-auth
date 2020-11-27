import jwt
import json

from http import HTTPStatus
from django.conf import settings
from django.http.response import JsonResponse, HttpResponse
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password


def _create_jwt(user):
    token = jwt.encode({
        'role': settings.JWT_ROLE,
        'userid': str(user.id)
    }, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM).decode('utf-8')
    return {'token': token}


def prest_signin(request):
    if request.method == 'POST':
        try:
            request_body = json.loads(request.body)
        except:
            return HttpResponse('Data not correctly', status=HTTPStatus.BAD_REQUEST)

        username = request_body.get('username')
        email = request_body.get('email')
        password = request_body.get('password')

        if not (username or email) or not password:
            return HttpResponse('\'username\' and \'password\' fields are required', 
                                status=HTTPStatus.BAD_REQUEST)

        user = authenticate(username=username or email, password=password)
        if user is not None:
            return JsonResponse(_create_jwt(user), status=HTTPStatus.OK)
        else:
            return HttpResponse('', status=HTTPStatus.UNAUTHORIZED)

    return HttpResponse('', status=HTTPStatus.METHOD_NOT_ALLOWED)


def prest_signup(request):
    if request.method == 'POST':
        try:
            request_body = json.loads(request.body)
        except:
            return HttpResponse('Data not correctly', status=HTTPStatus.BAD_REQUEST)

        username = request_body.get('username')
        email = request_body.get('email')
        password = request_body.get('password')

        if not (username or email) or not password:
            return HttpResponse(f"{'username' if username else 'email'} and 'password' fields are required",
                                status=HTTPStatus.BAD_REQUEST)

        if User.objects.filter(username=username or email).exists():
            return HttpResponse(f'User {"username" if username else "email"} already exists',
                                status=HTTPStatus.BAD_REQUEST)
        else:
            user = User(username=username or email, password=make_password(password))
            user.save()
            return HttpResponse('', status=HTTPStatus.CREATED)

    return HttpResponse('', status=HTTPStatus.METHOD_NOT_ALLOWED)
