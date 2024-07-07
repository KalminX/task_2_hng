from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db import models
import uuid


class User(AbstractUser):
    userId = models.UUIDField(default=uuid.uuid4, editable=False)
    firstName = models.CharField(max_length=255, blank=False)
    lastName = models.CharField(max_length=255, blank=False)
    password = models.CharField(max_length=100, null=False)
    email = models.EmailField(unique=True)
    username = models.CharField(
        max_length=150, unique=True, null=True)
    phone = models.CharField(max_length=255, null=True, blank=True)
    REQUIRED_FIELDS = ['email']


    def __str__(self):
        return f"{self.firstName} {self.lastName}--{self.email} {self.userId}"


class Organisation(models.Model):
    orgId = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    name = models.CharField(max_length=255, null=False)
    description = models.TextField(blank=True, null=True)
    users = models.ManyToManyField('User', related_name='organisations')

    def __str__(self):
        return f"{self.name}"