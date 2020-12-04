import jwt
import json

from http import HTTPStatus
from django.conf import settings
from django.http.response import JsonResponse
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password

from django.views.decorators.csrf import csrf_exempt

from datetime import datetime, timedelta

from django.core.validators import validate_email
from django.core.exceptions import ValidationError


def create_jwt(user):
    token = jwt.encode({
        'role': settings.JWT_ROLE,
        'userid': str(user.id),
        'exp': (datetime.now() + timedelta(minutes=1)).timestamp(),
    }, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM).decode('utf-8')
    return {'token': token}

def refresh_jwt(token):
    try:
        # TODO find out the way to refresh token (now does not check if the token has expired)
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM], verify=False)
        user = User.objects.get(id=payload['userid'])
        if not user:
            return None
        return create_jwt(user)
    except jwt.ExpiredSignatureError:
        return None

def restore_password(email):
    pass

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

def get_error(code):
    errors = {
        'wd': 'Incorrect data format, JSON expected',
        'wt': 'Wrong token',
        'we': 'Invalid email',

        'fr': "'username' and 'password' fields are required",
        'fr_r': "'email' and 'password' fields are required",
        'fr_r_c': "'username' or 'email_as_name' field is required. If both - 'username' is prior",

        'ue':'User with such username already exists',
        'ee': 'User with such email already exists',
        'unf': 'User not found',

        'pj': 'Only POST method, only JSON data',
        'nat': 'No Autherization token'
    }
    return errors[code]

@csrf_exempt
def signin(request):
    if request.method == 'POST':
        try:
            request_body = json.loads(request.body)
        except:
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST, error=get_error('wd')))

        username = request_body.get('username')
        password = request_body.get('password')

        if not username or not password:
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST, error=get_error('fr')))

        user = authenticate(username=username, password=password)
        if user is not None:
            return JsonResponse(**prepare_response(status=HTTPStatus.OK, token=create_jwt(user)))
        else:
            return JsonResponse(**prepare_response(status=HTTPStatus.NOT_FOUND, error=get_error('unf')))
    return JsonResponse(**prepare_response(status=HTTPStatus.METHOD_NOT_ALLOWED, error=get_error('pj')))


@csrf_exempt
def signup(request):
    if request.method == 'POST':
        try:
            request_body = json.loads(request.body)
        except:
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST, error=get_error('wd')))

        # TODO mb make new function for getting data and validating if need
        username = request_body.get('username')
        email = request_body.get('email')
        password = request_body.get('password')
        email_as_username = request_body.get('email_as_name')

        if not email or not password:
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST, error=get_error('fr_r')))

        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=get_error('we')))

        if (not username and not email_as_username):  # TODO fix needings in 'email_as_username'
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST, error=get_error('fr_r_c')))
        if (not username and email_as_username):
            username = email

        if User.objects.filter(username=username).exists():
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST,  error=get_error('ue')))
        elif User.objects.filter(email=email).exists():
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST, error=get_error('ee')))
        else:
            user = User(username=username, password=make_password(password), email=email)
            user.save()
            return JsonResponse(**prepare_response(status=HTTPStatus.CREATED, user=user))
    return JsonResponse(**prepare_response(status=HTTPStatus.METHOD_NOT_ALLOWED, error=get_error('pj')))


@csrf_exempt
def refresh(request):
    if request.method == 'POST':
        auth_header = request.headers.get('Authorization')
        if auth_header:
            token = refresh_jwt(auth_header.replace('Bearer ', ''))
            if token:
                return JsonResponse(**prepare_response(status=HTTPStatus.OK, token=token))
            else:
                return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=get_error('wt')))
        return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error= get_error('nat')))
    return JsonResponse(**prepare_response(status=HTTPStatus.METHOD_NOT_ALLOWED, error=get_error('pj')))


@csrf_exempt
def restore(request):
    pass
