import json
from datetime import datetime
from http import HTTPStatus
from json import JSONDecodeError

import jwt
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.http.response import JsonResponse
from django.views.decorators.http import require_POST

from .response_errors import AuthError
from .utils import (create_jwt, prepare_response, refresh_jwt,
                    restoring_with_email, restoring_with_token_and_password)


@require_POST
def signin(request):
    try:
        request_body = json.loads(request.body)
    except JSONDecodeError:
        return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST, error=AuthError.WRONG_DATA_FORMAT))

    if not all(i in request_body.keys() for i in ['username', 'password']):
        return JsonResponse(**prepare_response(HTTPStatus.BAD_REQUEST, error=AuthError.FIELDS_REQUIRED))

    username = request_body['username']
    password = request_body['password']

    user = authenticate(username=username, password=password)
    if user:
        return JsonResponse(**prepare_response(status=HTTPStatus.OK, token=create_jwt(user)))
    else:
        return JsonResponse(**prepare_response(status=HTTPStatus.NOT_FOUND, error=AuthError.USER_NOT_FOUND))


@require_POST
def signup(request):
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
        user = get_user_model().objects.create(username=username, password=make_password(password), email=email)
        return JsonResponse(**prepare_response(status=HTTPStatus.CREATED, user=user))


@require_POST
def refresh(request):
    auth_header = request.headers.get('Authorization')
    if auth_header:
        token = refresh_jwt(auth_header.replace('Bearer ', ''))
        if token:
            return JsonResponse(**prepare_response(status=HTTPStatus.OK, token=token))
        else:
            return JsonResponse(**prepare_response(status=HTTPStatus.NOT_FOUND, error=AuthError.USER_NOT_FOUND))
    return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.NO_AUTH_TOKEN))


@require_POST
def validation(request):
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


@require_POST
def restore(request):
    restoring_data = json.loads(request.body)

    restoring_email = restoring_data.get('email')
    restoring_token = restoring_data.get('token')
    restoring_password = restoring_data.get('new_password')

    if restoring_email and not (restoring_token or restoring_password):
        return restoring_with_email(restoring_email)
    elif not restoring_email and (restoring_token and restoring_password):
        return restoring_with_token_and_password(restoring_token, restoring_password)
    else:
        return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.WRONG_DATA_FIELDS))


@require_POST
def get_user_by_jwt(request):
    token = json.loads(request.body).get('token')
    if not token:
        return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.NO_AUTH_TOKEN))
    try:
        token = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        user = get_user_model().objects.get(id=token["userid"])
        return JsonResponse(**prepare_response(status=HTTPStatus.OK, user=user))
    except get_user_model().ObjectDoesNotExist:
        return JsonResponse(**prepare_response(status=HTTPStatus.NOT_FOUND, error=AuthError.USER_NOT_FOUND))
    except jwt.ExpiredSignatureError:
        return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.TOKEN_EXPIRED))
    except jwt.InvalidTokenError:
        return JsonResponse(**prepare_response(status=HTTPStatus.BAD_REQUEST, error=AuthError.WRONG_TOKEN))
