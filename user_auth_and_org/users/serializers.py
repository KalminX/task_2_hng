from .models import User
from rest_framework import serializers
from .models import User, Organisation


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['userId', 'firstName', 'lastName', 'email', 'password', 'phone']
        extra_kwargs = {
            'password': {'write_only': True},
        }


class OrganisationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organisation
        fields = ['orgId', 'name', 'description']


# serializers.py


class AddUserToOrganizationSerializer(serializers.Serializer):
    userId = serializers.CharField(max_length=100)
