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
    JWT_SECRET = 'super-secret-key'

    JWT_ALGORITHM = 'HS256'

    JWT_ROLE = DATABASES['default']['USER']

3. JSON data that sends, should include next fields::
    username or email (as Login)

    password (as Password)

4. From */signin* you will retrieve JWT, that will be used to have access

   From */signup* you will retrieve JSON with created user object [except password]

   From */refresh* you will retrieve new JWT