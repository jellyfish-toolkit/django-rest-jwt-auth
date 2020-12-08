import jwt
import json
from json import JSONDecodeError

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

from django.core.mail import send_mail
from smtplib import SMTPException as SMTPExc
from cryptography.fernet import Fernet

from django.urls import reverse


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


def encrypt_token():
    data = json.dumps({'expired_time': (datetime.now() + timedelta(minutes=1)).timestamp()}).encode()
    fernet_encr = Fernet(settings.EMAIL_ENCRYPT_KEY)
    return fernet_encr.encrypt(data).decode('utf-8')

def decrypt_token(encr_data):
    fernet_decr = Fernet(settings.EMAIL_ENCRYPT_KEY)
    try:
        decrypted = fernet_decr.decrypt(encr_data.encode())
    except JSONDecodeError:
        return FalseFalse
    return decrypted

def restore_password(email, restore_url):
    sms = {
        'subject': 'Restoring password',
        'message': restore_url,
        'from_email': settings.FROM_EMAIL,
        'recipient_list': [].append(email)
    }
    try:
        result = send_mail(**sms)
    except SMTPExc:
        result = None

    return result


def prepare_response(status: int, token=None, error=None, user=None, message=None):
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
    elif message:
        resp['data'] = {'message': message}
    resp['data']['status'] = status
    return resp

def get_error(code):
    errors = {
        'wd': 'Incorrect data format, JSON expected',
        'wt': 'Invalid token',
        'we': 'Invalid email',
        'wd_f': 'Incorrect data fields',

        'fr': "'username' and 'password' fields are required",
        'fr_r': "'email' and 'password' fields are required",
        'fr_r_c': "'username' or 'email_as_name' field is required. If both - 'username' is prior",

        'ue':'User with such username already exists',
        'ee': 'User with such email already exists',
        'unf': 'User not found',

        'pj': 'Only POST method, only JSON data',
        'nat': 'No Autherization token',

        'ens': 'Email wasnt sent',
        'te': 'Token expired'
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

        if (not username and not email_as_username):
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
            token = refresh_jwt(auth_header.replace('Bearer ', ''))  # TODO mb not neccesary
            if token:
                return JsonResponse(**prepare_response(status=HTTPStatus.OK, token=token))
            else:
                return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=get_error('wt')))
        return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error= get_error('nat')))
    return JsonResponse(**prepare_response(status=HTTPStatus.METHOD_NOT_ALLOWED, error=get_error('pj')))


@csrf_exempt
def restore(request):
    if request.method == 'POST':
        restoring_data = json.loads(request.body)

        restoring_email = restoring_data.get('restoring_email')
        restoring_token = restoring_data.get('restoring_token')
        restoring_password = restoring_data.get('restoring_password')

        if restoring_email and not (restoring_token or restoring_password):
            user = User.objects.get(email=restoring_email)
            if user:
                restoring_token = encrypt_token()
                # TODO create a field in User model for restoring token
                # user.restoring_token = restoring_token
                restoring_url = request.build_absolute_uri() + f'?restoring={restoring_token}'
                # restoring_status = restore_password(restoring_email, restoring_url)  # TODO check email sending
                restoring_status = True
                if restoring_status:
                    return JsonResponse(**prepare_response(status=HTTPStatus.OK,
                                                           message=f'Email has sent. The address is {restoring_email}'))
                else:
                    return JsonResponse(**prepare_response(status=HTTPStatus.NOT_IMPLEMENTED, error=get_error('ens')))
            else:
                return JsonResponse(**prepare_response(status=HTTPStatus.NOT_FOUND, error=get_error('unf')))
        elif not restoring_email and (restoring_token and restoring_password):
            decrypted = decrypt_token(restoring_token)
            if decrypted:
                if (decrypted['expired_time'] - datetime.now().timestamp()) > 0:
                    # user = User.objects.get(restoring_token=restoring_token)  # TODO check
                    user = True  # TODO drop
                    if user:
                        user.password = make_password(restoring_password)
                        # user.restoring_token = None
                        return JsonResponse(**prepare_response(status=HTTPStatus.OK, message='Password changed'))
                else:
                    return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=get_error('te')))
            else:
                return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=get_error('wt')))
        else:
            return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=get_error('wd_f')))
    else:
        return JsonResponse(**prepare_response(status=HTTPStatus.METHOD_NOT_ALLOWED, error=get_error('pj')))
