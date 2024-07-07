from .serializers import OrganisationSerializer
from .models import Organisation
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from .serializers import UserSerializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.contrib.auth.hashers import make_password
from .models import User, Organisation
from .serializers import (
    UserSerializer, OrganisationSerializer, AddUserToOrganizationSerializer)
from django.db import IntegrityError
import bcrypt
from django.shortcuts import get_object_or_404


@api_view(['POST'])
def register_user(request):
    serializer = UserSerializer(data=request.data)

    if serializer.is_valid():
        try:
            raw_password = serializer.validated_data['password']
            hashed_password = bcrypt.hashpw(
                raw_password.encode('utf-8'), bcrypt.gensalt())
            serializer.validated_data['password'] = hashed_password.decode(
                'utf-8')

            user = serializer.save()

            organisation_name = f"{user.firstName}'s Organisation"
            organisation = Organisation.objects.create(name=organisation_name)
            user.organisations.add(organisation)

            # Generate JWT token
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            return Response({
                "status": "success",
                "message": "Registration successful",
                "data": {
                    "accessToken": access_token,
                    "user": serializer.data
                }
            }, status=status.HTTP_201_CREATED)
        except IntegrityError as e:
            # Here we handle the IntegrityError specifically
            return Response({
                "status": "Bad request",
                "message": "Registration unsuccessful: Duplicate email or username",
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "status": "Bad request",
                "message": "An unexpected error occurred",
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)
    else:
        errors = []
        for field, messages in serializer.errors.items():
            for message in messages:
                errors.append({
                    "field": field,
                    "message": message
                })
        return Response({
            "errors": errors
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def login_user(request):
    email = request.data.get('email')
    password = request.data.get('password')

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        user = None

    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        # Passwords match, proceed with authentication
        # Generate JWT token
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # Serialize user data
        serializer = UserSerializer(user)

        return Response({
            "status": "success",
            "message": "Login successful",
            "data": {
                "accessToken": access_token,
                "user": serializer.data
            }
        })
    else:
        # Authentication failed
        return Response({
            "status": "Bad request",
            "message": "Authentication failed",
            "statusCode": 401
        }, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user(request, pk):
    try:
        user = get_object_or_404(User, userId=pk)
        # Check if the user is accessing their own record or record in organisations they belong to or created
        if user:
            serializer = UserSerializer(user)
            return Response({
                "status": "success",
                "message": "User details retrieved successfully",
                "data": serializer.data
            })
        else:
            return Response({
                "status": "error",
                "message": "You do not have permission to access this user's details"
            }, status=status.HTTP_403_FORBIDDEN)
    except User.DoesNotExist:
        return Response({
            "status": "error",
            "message": "User not found"
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_organisation(request, pk):
    try:
        user = request.user
        # Assuming the organization exists and the user has access to it
        organisation = Organisation.objects.get(orgId=pk, users=user)
        serializer = OrganisationSerializer(organisation)
        return Response({
            "status": "success",
            "message": "Organisation retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({
            "status": "Bad Request",
            "message": "Organisation not found or you do not have access to this organisation",
            "statusCode": 400
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST', 'GET'])
@permission_classes([IsAuthenticated])
def organisation_view(request, pk=None):
    if request.method == 'POST':
        try:
            # Validate request data
            serializer = OrganisationSerializer(data=request.data)
            if serializer.is_valid():
                # Create the organisation
                new_organisation = serializer.save()

                # Prepare response data
                response_data = {
                    "status": "success",
                    "message": "Organisation created successfully",
                    "data": {
                        "orgId": new_organisation.orgId,
                        "name": new_organisation.name,
                        "description": new_organisation.description
                    }
                }
                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                # Return validation errors if serializer is not valid
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            # Handle any unexpected errors
            return Response({
                "status": "Bad Request",
                "message": str(e),
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'GET':
        user = request.user
        organisations = Organisation.objects.filter(users=user)
        serializer = OrganisationSerializer(organisations, many=True)
        return Response({
            "status": "success",
            "message": "Organisations retrieved successfully",
            "data": {
                "organisations": serializer.data
            }
        }, status=200)


@api_view(['POST'])
def add_user_to_organisation(request, pk):
    if request.method == 'POST':
        serializer = AddUserToOrganizationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user_id = serializer.validated_data['userId']
                user = get_object_or_404(User, userId=user_id)
                organization = Organisation.objects.get(orgId=pk)
                organization.users.add(user)
                return Response({
                    "status": "success",
                    "message": "User added to organization successfully",
                }, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"message": "User not found."}, status=status.HTTP_404_NOT_FOUND)
            except Organisation.DoesNotExist:
                return Response({"message": "Organization not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
