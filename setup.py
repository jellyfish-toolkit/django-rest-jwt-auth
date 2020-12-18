from setuptools import setup

setup(
    name='django-rest-jwt-auth',
    install_requires=[
        'PyJWT==1.7.1',
        'Django>=2.0',
        'cryptography==3.2.1'
    ]
)
