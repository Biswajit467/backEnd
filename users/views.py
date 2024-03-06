from django.shortcuts import render
from django.http import HttpResponse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.contrib.auth.hashers import make_password
import json
from .models import Users
from django.db import connection
from django.contrib.auth.hashers import check_password
import jwt
from rest_framework.decorators import api_view
from .serializers import UserUpdateSerializer, AdminUpdateSerializer, PostsSerializer , NotificationSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics
from datetime import datetime, timedelta
from django.utils import timezone
import logging
from rest_framework.response import Response
from rest_framework import status
from .models import Posts
from django.shortcuts import get_object_or_404


# Create your views here.

logger = logging.getLogger(__name__)


def index(request):
    return HttpResponse('<h1> Hey welcome </h1>')


def admins(request):
    return HttpResponse('<h2>hello this is now admin apis</h2>')


def check_db_connection(request):
    try:
        # Attempt to execute a simple query to check the database connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            if result[0] == 1:
                return JsonResponse({'status': 'Database connection successful'}, status=200)
            else:
                return JsonResponse({'status': 'Database connection failed'}, status=500)
    except Exception as e:
        # If an exception occurs, return an error response
        return JsonResponse({'status': 'Database connection failed', 'error': str(e)}, status=500)


@api_view(['POST'])
@csrf_exempt
def create_admin(request):
    print("request body of create user", request.body)
    try:
        data = json.loads(request.body.decode('utf-8'))
        student_id = data.get('student_id')
        email = data.get('email')
        password = data.get('password')
        name = data.get('name')
        sem = data.get('sem')
        admin = data.get('admin', True)

        print(student_id, email, password, name, sem, admin)

        if not all([student_id, email, password, name, sem]):
            return JsonResponse({'error': 'Missing required fields'}, status=400)

        if Users.objects.filter(student_id=student_id).exists() or Users.objects.filter(email=email).exists():
            return JsonResponse({'error': 'User already exists!'}, status=409)

        user = Users(student_id=student_id, email=email,
                     password=make_password(password), name=name, sem=sem, admin=admin)
        user.save()

        return JsonResponse({'message': 'User has been created.'}, status=200)

    except Exception as e:
        logger.exception("Error creating user: %s", e)
        return JsonResponse({'error': 'Internal Server Error'}, status=500)


@api_view(['POST'])
@csrf_exempt
def create_user(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        student_id = data.get('student_id')
        email = data.get('email')
        password = data.get('password')
        name = data.get('name')
        sem = data.get('sem')
        admin = data.get('admin', False)
        registration_number = data.get('registration_number', '0000000000')  # Default value added
        branch = data.get('branch', 'cse')  # Default value added
        
        # Adding current datetime for created_at field
        created_at = datetime.now()

        if not all([student_id, email, password, name, sem]):  
            return JsonResponse({'error': 'Missing required fields'}, status=400)

        if Users.objects.filter(student_id=student_id).exists() or Users.objects.filter(email=email).exists():
            return JsonResponse({'error': 'User already exists!'}, status=409)

        user = Users(student_id=student_id, email=email,
                     password=make_password(password), name=name, sem=sem, admin=admin,
                     registration_number=registration_number, branch=branch, created_at=created_at)  
        user.save()

        return JsonResponse({'message': 'User has been created.'}, status=200)

    except Exception as e:
        logger.exception("Error creating user: %s", e)
        return JsonResponse({'error': 'Internal Server Error'}, status=500)


@api_view(['POST'])
def login(request):
    print("inside login function")
    print("this is user request data", request)
    student_id = request.POST.get('student_id')
    password = request.POST.get('password')
    print("this is login request data", student_id, password)
    try:
        # Check if the user exists
        user = Users.objects.get(student_id=student_id)
        print("is_banned" , user.ban)
    except Users.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    # Check if the password is correct
    if not check_password(password, user.password):
        return JsonResponse({'error': 'Wrong user name or password'}, status=400)

    # Generate JWT token
    token = jwt.encode({'id': user.id}, 'jwtkey', algorithm='HS256')
    print("this is my jwt token", token)

    return JsonResponse({'student_id_token': token, 'user': {'id': user.id, 'student_id': user.student_id},  'message': 'user logged in successfully'}, status=200)

    #  # Add the token to the response as a cookie
    # response = JsonResponse({'user': {'id': user.id, 'student_id': user.student_id, 'name': user.name, 'sem': user.sem,
    #                         'img': user.img, 'email': user.email}, 'message': 'user logged in successfully'}, status=200)

    # response.set_cookie('student_id_token', token)
    # # response['Authorization'] = f'Bearer {token}'

    # return response


@api_view(['POST'])
# @csrf_protect
@csrf_exempt
def logout(request):
    print("reuest data", request)
    response = JsonResponse({"message": "User has been logged out."})
    print(response)
    response.delete_cookie("access_token", samesite="None", secure=True)

    print("cookie has been cleared")
    return response


@csrf_exempt
@api_view(['PATCH'])
def update_personal_info(request, pk):
    try:
        user = Users.objects.get(pk=pk)
    except Users.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PATCH':
        # Make a copy of request data to avoid modifying the original data
        data = request.data.copy()
        password = data.get('password')
        if password:
            data['password'] = make_password(password)  # Encrypt the password
        serializer = UserUpdateSerializer(user, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'Only PATCH method is allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


@csrf_exempt
@api_view(['PATCH'])
def update_student_info(request, pk):
    print('inside update student info')
    try:
        user = Users.objects.get(pk=pk)
    except Users.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PATCH':
        try:
            data = json.loads(request.body.decode('utf-8'))
            password = data.get('password')
            if password:
                data['password'] = make_password(password)  # Encrypt the password
            serializer = AdminUpdateSerializer(user, data=data, partial=True)
            if serializer.is_valid():
                print('inside serializer valid')
                # Update created_at field
                serializer.validated_data['created_at'] = datetime.now()
                serializer.save()
                return Response({'message': 'User info has been updated.'}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception("Error updating user info: %s", e)
            return Response({'error': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        return Response({'error': 'Only PATCH method is allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@api_view(['DELETE'])
@csrf_exempt
def delete_user(request, student_id):
    try:
        # Check if the user exists
        user = Users.objects.get(student_id=student_id)
    except Users.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    # Delete the user
    user.delete()

    return Response({'message': 'User has been deleted'}, status=status.HTTP_204_NO_CONTENT)

@api_view(['DELETE'])
@csrf_exempt
def delete_old_users(request):
    try:
        # Calculate the date 8 years ago
        eight_years_ago = timezone.now() - timedelta(days=8*365)

        # Query for users whose creation time is 8 years older than the current date
        old_users = Users.objects.filter(created_at__lte=eight_years_ago)

        # Delete the retrieved users from the database
        old_users.delete()

        return Response({'message': 'Old users have been deleted'}, status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        return Response({'error': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def create_notification(request):
    print("inside create notification")
    serializer = NotificationSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
   

    # post apis


@api_view(['POST'])
def add_post(request):
    # print('This is req.body',request.body)
    # print('This is req.data',request.data)
    print("request headers", request.headers)
    token = request.headers.get('Authorization')

    print("This is token ", token)

    if not token:
        return Response({"error": "Not authenticated!"}, status=status.HTTP_401_UNAUTHORIZED)


    try:
        decoded_token = jwt.decode(token, 'jwtkey', algorithms=['HS256'])
        print("This is decoded-token", decoded_token)
        user_instance = get_object_or_404(Users, id=decoded_token['id'])
        print("This is user instance", user_instance)

    except jwt.ExpiredSignatureError:
        return Response({"error": "Token is expired!"}, status=status.HTTP_403_FORBIDDEN)
    except jwt.InvalidTokenError:
        return Response({"error": "Token is not valid!"}, status=status.HTTP_403_FORBIDDEN)

    serializer = PostsSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(uid=user_instance)  # Assign uid from decoded token
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
