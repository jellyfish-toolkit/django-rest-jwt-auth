import json
from datetime import datetime, timedelta
from http import HTTPStatus
from smtplib import SMTPException as SMTPExc

import jwt
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.http.response import JsonResponse

from .response_errors import AuthError


def create_jwt(user):
    token = jwt.encode({
        'role': settings.JWT_ROLE,
        'userid': str(user.id),
        'exp': int((datetime.now() + timedelta(minutes=settings.JWT_EXP if settings.JWT_EXP else 1440)).timestamp()),
    }, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return {'token': token}


def refresh_jwt(token):
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM],
                             options={'verify_exp': False})
        user = get_user_model().objects.get(id=payload['userid'])
        return create_jwt(user)
    except get_user_model().ObjectDoesNotExist:
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


def restore_password(email, restoring_token):
    from django.core import mail
    connection = mail.get_connection()
    connection.open()
    domain_path = settings.PATH_TO_RESTORE
    if not domain_path.endswith('/'):
        domain_path = domain_path + '/'
    restoring_url = domain_path + f'?restoring={restoring_token}'
    try:
        result = send_mail('Restoring password', restoring_url, settings.FROM_EMAIL, [email], connection=connection)
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


def restoring_with_email(restoring_email):
    try:
        user = get_user_model().objects.get(email=restoring_email)
    except get_user_model().ObjectDoesNotExist:
        return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.USER_NOT_FOUND))
    restoring_token = encrypt_token()
    user.restoring_token = restoring_token
    user.save(update_fields=('restoring_token',))
    restoring_status = restore_password(restoring_email, restoring_token)
    if restoring_status:
        return JsonResponse(**prepare_response(status=HTTPStatus.OK,
                                               message=f'Email has sent. The address is {restoring_email}'))
    else:
        return JsonResponse(**prepare_response(status=HTTPStatus.NOT_IMPLEMENTED,
                                               error=AuthError.EMAIL_WASNT_SENT))


def restoring_with_token_and_password(restoring_token, restoring_password):
    decrypted = decrypt_token(restoring_token)
    if not decrypted:
        return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.WRONG_TOKEN))
    try:
        user = get_user_model().objects.get(restoring_token=restoring_token)
    except get_user_model().ObjectDoesNotExist:
        return JsonResponse(**prepare_response(status=HTTPStatus.NOT_FOUND, error=AuthError.USER_NOT_FOUND))
    user.restoring_token = None
    decrypted = json.loads(decrypted)
    if (decrypted['expired_time'] - datetime.now().timestamp()) > 0:
        user.password = make_password(restoring_password)
        user.save(update_fields=('restoring_token', 'password'))
        return JsonResponse(**prepare_response(status=HTTPStatus.OK, message='Password changed'))
    else:
        user.save(update_fields=('restoring_token',))
        return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST,
                                               error=AuthError.TOKEN_EXPIRED))
