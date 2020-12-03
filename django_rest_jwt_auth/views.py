import jwt
import json

from http import HTTPStatus
from django.conf import settings
from django.http.response import JsonResponse
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password

from django.views.decorators.csrf import csrf_exempt


def create_jwt(user):
    token = jwt.encode({
        'role': settings.JWT_ROLE,
        'userid': str(user.id)
    }, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM).decode('utf-8')
    return {'token': token}


def prepare_response(status: int, token=None, error=None, user=None):
    resp = {'status': status}
    if error:
        resp['data'] = {'error': {'message': error}}
    elif user:
        user_info = user.__dict__
        del user_info['_state']
        del user_info['password']
        resp['data'] = {'user': user_info}
    elif token:
        if isinstance(token, dict):
            resp['data'] = token
        elif isinstance(token, str):
            resp['data'] = {'token': token}
    resp['data']['status'] = status
    return resp


@csrf_exempt
def signin(request):
    if request.method == 'POST':
        try:
            request_body = json.loads(request.body)
        except:
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST,
                                                   error='Incorrect data format, JSON expected'))

        username = request_body.get('username')
        email = request_body.get('email')
        password = request_body.get('password')

        if not (username or email) or not password:
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST,
                                                   error="'username'/'email' and 'password' fields are required"))

        user = authenticate(username=username or email, password=password)
        if user is not None:
            return JsonResponse(**prepare_response(status=HTTPStatus.OK, token=create_jwt(user)))
        else:
            return JsonResponse(**prepare_response(status=HTTPStatus.NOT_FOUND,
                                                   error='User not found'))

    return JsonResponse(**prepare_response(status=HTTPStatus.METHOD_NOT_ALLOWED,
                                           error='Only POST method, only JSON data'))


@csrf_exempt
def signup(request):
    if request.method == 'POST':
        try:
            request_body = json.loads(request.body)
        except:
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST,
                                                   error='Incorrect data format, JSON expected'))

        username = request_body.get('username')
        email = request_body.get('email')
        password = request_body.get('password')

        if not (username or email) or not password:
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST,
                                                   error="'username'/'email' and 'password' fields are required"))

        if User.objects.filter(username=username or email).exists():
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST,
                                                   error=f"User {'username' if username else 'email'} already exists"))
        else:
            user = User(username=username or email, password=make_password(password))
            user.save()
            return JsonResponse(**prepare_response(status=HTTPStatus.CREATED, user=user))

    return JsonResponse(**prepare_response(status=HTTPStatus.METHOD_NOT_ALLOWED,
                                           error='Only POST method, only JSON data'))
