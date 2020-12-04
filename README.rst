====================
django-rest-jwt-auth
====================

1. Add app to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = [
        ...
        'django_rest_jwt_auth',
    ]

2. Include the polls URLconf in your project urls.py like this::

    path('<path>/', include('django_rest_jwt_auth.urls'))
        pathes::
            /signin
            /signup
            /refresh


3. In settings.py::
    For JWT::

        JWT_SECRET = 'super-secret-key'
        JWT_ALGORITHM = 'HS256'
        JWT_ROLE = DATABASES['default']['USER']

    For Restoring password::

        FROM_EMAIL - from who is email
        EMAIL_ENCRYPT_KEY - key for encrypting link for restoring password. key must be 32 url-safe base64-encoded bytes.
        EMAIL_HOST_USER - username for SMTP
        EMAIL_HOST_PASSWORD - password for SMTP
        EMAIL_HOST - host for SMTP
        EMAIL_PORT - port for SMTP
        EMAIL_USE_TLS - if TLS use
        EMAIL_USE_SSL - if SSL use

4. JSON data that sends, should include next fields::
    For signup::

        email - required
        password - required
        username or you can use boolean field email_as_name

    For signin::

        username - required (independent if email was used as username)
        password - required

    For refresh::

        Just have header Autherization with token


5. Data that retrievs::
    From */signup*::

        JSON with created user object [except password]
        {"user": {<user data>}, "status": 200}

    From */signin*::

        JWT. {"token":"<token>", "status": 200}

    From */refresh*::

        New JWT. {"token":"<token>", "status": 200}

6. Error cases::

    {
    "status": <your error HTTP code>,
     "error": {
        "message": "Error explanation"
        }
    }
