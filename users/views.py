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
from .serializers import UserUpdateSerializer , AdminUpdateSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics
import logging


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
    print("request body of create user",request.body)
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
    # print("request body of create user",request.body)
    try:
        data = json.loads(request.body.decode('utf-8'))
        student_id = data.get('student_id')
        email = data.get('email')
        password = data.get('password')
        name = data.get('name')
        sem = data.get('sem')
        admin = data.get('admin', False)

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
def login(request):
    print("inside login function")
    print("this is user request data",request)
    student_id = request.POST.get('student_id')
    password = request.POST.get('password')
    print("this is login request data",student_id, password)
    try:
        # Check if the user exists
        user = Users.objects.get(student_id=student_id)
    except Users.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    # Check if the password is correct
    if not check_password(password, user.password):
        return JsonResponse({'error': 'Wrong user name or password'}, status=400)

    # Generate JWT token
    token = jwt.encode({'id': user.id}, 'jwtkey', algorithm='HS256')
    print("this is my jwt token", token)
    
    # return JsonResponse({'token': token, 'user': {'id': user.id, 'student_id': user.student_id},  'message': 'user logged in successfully'}, status=200)
    
    
    #  # Add the token to the response as a cookie
    response = JsonResponse({'user': {'id': user.id, 'student_id': user.student_id,'name': user.name,'sem': user.sem, 'img':user.img,'email':user.email}, 'message': 'user logged in successfully'}, status=200)

    response.set_cookie('student_id_token', token, httponly=True)

    return response
    



@api_view(['POST'])
# @csrf_protect
@csrf_exempt
def logout(request):
    print("reuest data",request)
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
        data = request.data.copy()  # Make a copy of request data to avoid modifying the original data
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
        data = request.data.copy()  # Make a copy of request data to avoid modifying the original data
        password = data.get('password')
        if password:
            data['password'] = make_password(password)  # Encrypt the password
        serializer = AdminUpdateSerializer(user, data=data, partial=True)
        if serializer.is_valid():
            print('inside serielizer valid')
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'Only PATCH method is allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)