django-rest-jwt-auth
====================

1. Add app to your INSTALLED_APPS setting like this::

```python
INSTALLED_APPS = [
    ...
    'django_rest_jwt_auth',
]
```
Make migration for app
```python
python manage.py makemigrations django_rest_jwt_auth
```

2. Include the polls URLconf in your project urls.py like this::

```python
path('<path>/', include('django_rest_jwt_auth.urls'))
```

Paths are:

`/signin`
`/signup`
`/restore`
`/validation`
`/refresh`
`get_user/`


3. In settings.py:

*For JWT*
```python
JWT_SECRET = 'super-secret-key'
JWT_ALGORITHM = 'HS256'
JWT_ROLE = DATABASES['default']['USER']
JWT_EXP = <amount in minutes>
```
*Restoring password*
```python
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
FROM_EMAIL - from who is email
EMAIL_ENCRYPT_KEY - key for encrypting link for restoring password. key must be 32 url-safe base64-encoded bytes.
EMAIL_HOST_USER - username for SMTP
EMAIL_HOST_PASSWORD - password for SMTP
EMAIL_HOST - host for SMTP
EMAIL_PORT - port for SMTP
EMAIL_USE_TLS - if TLS use
EMAIL_USE_SSL - if SSL use
EMAIL_TOKEN_EXP = <amount in minutes>
PATH_TO_RESTORE = '<schema>://<domain>/<path>' [frontend path]
```

```python
Set up User model
Package provide an AbstractUser for inheritance.
You should either inherit Your user from it or create your own user model,
provides *restoring_token* charfield with 145 characters lenght.
You can get it in the next way::
    from django_rest_jwt_auth import AuthAbstractUser
    
!Don't forget set up new setting'!
AUTH_USER_MODEL = '<app>.<User model name>'
```
4. Request examples
Signup:

url - `/signup`

```js
{ 
    "email": "...", // if email_as_name is set up
    "password": "...", // required
    "username": "..." // or you can use boolean field email_as_name
}

"Either email or username must exists, not both"
```
Signin:

url - `/signin`

```js
{ 
    "password": "...", // required
    "username": "..." // if you used email_as_username put an email in that field
}
```

Refresh:

url - `/refresh`

```
Authorization: Bearer <token>
```

Restore:

url `/restore`

Send email:

```js
{
    "email": ""
}
```

Restoring:
Restoring token will be given as query param in URL in email msg.
```js
{
    "token": "",
    "new_password": ""
}
```

Validation:

```js
{
    "token": "..."
}
```

Get User model:
```js
{
    "token": "..."
}
```



5. Response examples

`/signup`

JSON with created user object [except password]

```js
{
    "user": {<user data>}, 
    "status": 200
}
```

`/signin`
```js
{
    "token":"<token>", 
    "status": 200
}
```
`/refresh`
```js
{
    "token":"<token>", 
    "status": 200
}
```
`/restore`

*If was or not email sent*
```js
{
    "message": "", 
    "status": 200
}
```

`/validation`
```js
{
    "message": "Token will expired ...", 
    "status": 200
}
```

6. Error example

```js
{
    "status": <your error HTTP code>,
    "error": {
        "message": "Error explanation"
    }
}
```
