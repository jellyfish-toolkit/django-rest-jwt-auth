import jwt
import json
from json import JSONDecodeError

from http import HTTPStatus
from django.conf import settings
from django.http.response import JsonResponse
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.hashers import make_password

from datetime import datetime, timedelta

from django.core.validators import validate_email
from django.core.exceptions import ValidationError, ObjectDoesNotExist

from django.core.mail import send_mail
from smtplib import SMTPException as SMTPExc
from cryptography.fernet import Fernet, InvalidToken


def create_jwt(user):
    token = jwt.encode({
        'role': settings.JWT_ROLE,
        'userid': str(user.id),
        'exp': (datetime.now() + timedelta(minutes=settings.JWT_EXP if settings.JWT_EXP else 1440)).timestamp(),
    }, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return {'token': token}


def refresh_jwt(token):
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM],
                             options={'verify_exp': False})
        user = get_user_model().objects.get(id=payload['userid'])
        return create_jwt(user)
    except ObjectDoesNotExist:
        return None


def encrypt_token():
    data = json.dumps({'expired_time': (datetime.now() + timedelta(
        minutes=settings.EMAIL_TOKEN_EXP if settings.EMAIL_TOKEN_EXP else 1440)).timestamp()}).encode('utf-8')
    fernet_encr = Fernet(settings.EMAIL_ENCRYPT_KEY)
    return fernet_encr.encrypt(data).decode('utf-8')


def decrypt_token(encr_data):
    fernet_decr = Fernet(settings.EMAIL_ENCRYPT_KEY)
    try:
        decrypted = fernet_decr.decrypt(encr_data.encode()).decode('utf-8')
    except InvalidToken:
        return False
    return decrypted


def restore_password(email, restore_url):
    from django.core import mail
    connection = mail.get_connection()
    connection.open()
    try:
        result = send_mail('Restoring password', restore_url, settings.FROM_EMAIL, [email], connection=connection)
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
        del user_info['restoring_token']
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


class AuthError:
    WRONG_DATA_FORMAT = 'Incorrect data format, JSON expected'
    WRONG_TOKEN = 'Invalid token'
    WRONG_EMAIL = 'Invalid email'
    WRONG_DATA_FIELDS = 'Incorrect data fields'

    FIELDS_REQUIRED = "'username' and 'password' fields are required"
    FIELDS_REQUIRED_REGISTR = "'email' and 'password' fields are required"
    FIELDS_REQUIRED_REGISTR_CHOICE = "'username' or 'email_as_name' field is required. If both - 'username' is prior"

    USER_EXISTS = 'User with such username already exists'
    EMAIL_EXISTS = 'User with such email already exists'
    USER_NOT_FOUND = 'User not found'

    POST_JSON = 'Only POST method, only JSON data'
    NO_AUTH_TOKEN = 'No Autherization token'

    EMAIL_WASNT_SENT = 'Email wasnt sent'
    TOKEN_EXPIRED = 'Token expired'


def signin(request):
    if request.method == 'POST':
        try:
            request_body = json.loads(request.body)
        except JSONDecodeError:
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST, error=AuthError.WRONG_DATA_FORMAT))

        if not all(map(lambda x: x in request_body.keys(), ['username', 'password'])):
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST, error=AuthError.FIELDS_REQUIRED))

        username = request_body['username']
        password = request_body['password']

        user = authenticate(username=username, password=password)
        if user:
            return JsonResponse(**prepare_response(status=HTTPStatus.OK, token=create_jwt(user)))
        else:
            return JsonResponse(**prepare_response(status=HTTPStatus.NOT_FOUND, error=AuthError.USER_NOT_FOUND))
    return JsonResponse(**prepare_response(status=HTTPStatus.METHOD_NOT_ALLOWED, error=AuthError.POST_JSON))


def signup(request):
    if request.method == 'POST':
        try:
            request_body = json.loads(request.body)
        except JSONDecodeError:
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST, error=AuthError.WRONG_DATA_FORMAT))

        username = request_body.get('username')
        email = request_body.get('email')
        password = request_body.get('password')
        email_as_username = request_body.get('email_as_name')

        if not email or not password:
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST, error=AuthError.FIELDS_REQUIRED_REGISTR))

        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.WRONG_EMAIL))

        if not username and not email_as_username:
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST,
                                                   error=AuthError.FIELDS_REQUIRED_REGISTR_CHOICE))
        if not username and email_as_username:
            username = email

        if get_user_model().objects.filter(username=username).exists():
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST,  error=AuthError.USER_EXISTS))
        elif get_user_model().objects.filter(email=email).exists():
            return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST, error=AuthError.EMAIL_EXISTS))
        else:
            user = get_user_model()(username=username, password=make_password(password), email=email)
            user.save()
            return JsonResponse(**prepare_response(status=HTTPStatus.CREATED, user=user))
    return JsonResponse(**prepare_response(status=HTTPStatus.METHOD_NOT_ALLOWED, error=AuthError.POST_JSON))


def refresh(request):
    if request.method == 'POST':
        auth_header = request.headers.get('Authorization')
        if auth_header:
            token = refresh_jwt(auth_header.replace('Bearer ', ''))
            if token:
                return JsonResponse(**prepare_response(status=HTTPStatus.OK, token=token))
            else:
                return JsonResponse(**prepare_response(status=HTTPStatus.NOT_FOUND, error=AuthError.USER_NOT_FOUND))
        return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.NO_AUTH_TOKEN))
    return JsonResponse(**prepare_response(status=HTTPStatus.METHOD_NOT_ALLOWED, error=AuthError.POST_JSON))


def validation(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
        except JSONDecodeError:
            return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.WRONG_DATA_FORMAT))
        token = data.get('token')
        if token:
            try:
                payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
                exp_data = payload.get('exp')
                return JsonResponse(**prepare_response(status=HTTPStatus.OK,
                                                       message=f'Token will expire {datetime.fromtimestamp(exp_data)}'))
            except jwt.ExpiredSignatureError:
                return JsonResponse(**prepare_response(status=HTTPStatus.OK, error=AuthError.TOKEN_EXPIRED))
            except jwt.InvalidTokenError:
                return JsonResponse(**prepare_response(status=HTTPStatus.UNAUTHORIZED, error=AuthError.WRONG_TOKEN))
        else:
            return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.WRONG_DATA_FIELDS))
    else:
        return JsonResponse(**prepare_response(status=HTTPStatus.METHOD_NOT_ALLOWED, error=AuthError.POST_JSON))


def restore(request):
    if request.method == 'POST':
        restoring_data = json.loads(request.body)

        restoring_email = restoring_data.get('email')
        restoring_token = restoring_data.get('token')
        restoring_password = restoring_data.get('new_password')

        if restoring_email and not (restoring_token or restoring_password):
            try:
                user = get_user_model().objects.get(email=restoring_email)
            except ObjectDoesNotExist:
                return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.USER_NOT_FOUND))
            restoring_token = encrypt_token()
            user.restoring_token = restoring_token
            user.save()
            restoring_url = request.build_absolute_uri() + f'?restoring={restoring_token}'
            restoring_status = restore_password(restoring_email, restoring_url)
            if restoring_status:
                return JsonResponse(**prepare_response(status=HTTPStatus.OK,
                                                       message=f'Email has sent. The address is {restoring_email}'))
            else:
                return JsonResponse(**prepare_response(status=HTTPStatus.NOT_IMPLEMENTED,
                                                       error=AuthError.EMAIL_WASNT_SENT))
        elif not restoring_email and (restoring_token and restoring_password):
            decrypted = decrypt_token(restoring_token)
            if not decrypted:
                return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.WRONG_TOKEN))
            try:
                user = get_user_model().objects.get(restoring_token=restoring_token)
            except ObjectDoesNotExist:
                return JsonResponse(**prepare_response(status=HTTPStatus.NOT_FOUND, error=AuthError.USER_NOT_FOUND))
            user.restoring_token = None
            decrypted = json.loads(decrypted)
            if (decrypted['expired_time'] - datetime.now().timestamp()) > 0:
                user.password = make_password(restoring_password)
                user.save()
                return JsonResponse(**prepare_response(status=HTTPStatus.OK, message='Password changed'))
            else:
                user.save()
                return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST,
                                                       error=AuthError.TOKEN_EXPIRED))
        else:
            return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.WRONG_DATA_FIELDS))
    else:
        return JsonResponse(**prepare_response(status=HTTPStatus.METHOD_NOT_ALLOWED, error=AuthError.POST_JSON))


def get_user_by_jwt(request):
    if request.method == 'POST':
        token = json.loads(request.body).get('token')
        if not token:
            return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.NO_AUTH_TOKEN))
        try:
            token = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
            user = get_user_model().objects.get(id=token["userid"])
            return JsonResponse(**prepare_response(status=HTTPStatus.OK, user=user))
        except ObjectDoesNotExist:
            return JsonResponse(**prepare_response(status=HTTPStatus.NOT_FOUND, error=AuthError.USER_NOT_FOUND))
        except jwt.ExpiredSignatureError:
            return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.TOKEN_EXPIRED))
        except jwt.InvalidTokenError:
            return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.WRONG_TOKEN))
    return JsonResponse(**prepare_response(status=HTTPStatus.METHOD_NOT_ALLOWED, error=AuthError.POST_JSON))
