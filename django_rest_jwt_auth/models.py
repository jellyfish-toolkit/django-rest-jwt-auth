from django.contrib.auth.models import AbstractUser
from django.db import models


class AuthAbstractUser(AbstractUser):
    restoring_token = models.CharField(max_length=145, null=True, blank=True, default=None)

    class Meta:
        abstract = True
