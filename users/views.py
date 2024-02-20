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

# Create your views here.


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
def register(request):
    data = json.loads(request.body)
    user_name = data.get('user_name')
    email = data.get('email')
    password = data.get('password')

    print(user_name, email, password)
    # Check if the user already exists
    if Users.objects.filter(user_name=user_name).exists() or Users.objects.filter(email=email).exists():
        return JsonResponse({'error': 'User already exists!'}, status=409)

        # Create a new user
    user = Users(user_name=user_name, email=email,
                 password=make_password(password))
    user.save()

    return JsonResponse({'message': 'User has been created.'}, status=200)


@api_view(['POST'])
def login(request):
    user_name = request.POST.get('user_name')
    password = request.POST.get('password')
    print(user_name, password)
    try:
        # Check if the user exists
        user = Users.objects.get(user_name=user_name)
    except Users.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    # Check if the password is correct
    if not check_password(password, user.password):
        return JsonResponse({'error': 'Wrong user name or password'}, status=400)

    # Generate JWT token
    token = jwt.encode({'id': user.id}, 'jwtkey', algorithm='HS256')
    print("this is my jwt token", token)

    return JsonResponse({'token': token, 'user': {'id': user.id, 'user_name': user.user_name},  'message': 'user logged in successfully'}, status=200)


@api_view(['POST'])
@csrf_protect
def logout(request):
    response = JsonResponse({"message": "User has been logged out."})
    response.delete_cookie("access_token", samesite="None", secure=True)

    print("cookie has been cleared")
    return response
