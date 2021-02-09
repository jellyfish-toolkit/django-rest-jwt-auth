from setuptools import setup

setup(
    name='django-rest-jwt-auth',
    install_requires=[
        'PyJWT>=2.0.0',
        'Django>=2.0',
        'cryptography>=3.2.1',
        'psycopg2-binary>=2.8.6'
    ]
)
