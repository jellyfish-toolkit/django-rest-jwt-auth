from django.db import models
from django.conf import settings

class UserProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    restoring_token = models.CharField(max_length=145, null=True, blank=True, default=None)
