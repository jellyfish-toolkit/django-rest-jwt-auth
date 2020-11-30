=============
pREST API app
=============

1. Add app to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = [
        ...
        'django_rest_auth',
    ]

2. Include the polls URLconf in your project urls.py like this::

    path('path/', include('django_rest_auth.urls'))


3. In settings.py::
    JWT_SECRET = 'super-secret-key'

    JWT_ALGORITHM = 'HS256'

    JWT_ROLE = DATABASES['default']['USER']

3. Data that sends should include next fields::
    username or email (as Login)

    password (as Password)

4. From *signin* you will retrieve JWT, that will be used to have access for pREST service