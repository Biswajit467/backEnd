from django.shortcuts import render
from django.http import HttpResponse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.contrib.auth.hashers import make_password
import json
from .models import Users , Posts , Notification , Scores
from django.db import connection
from django.contrib.auth.hashers import check_password
import jwt
from rest_framework.decorators import api_view
from .serializers import UserUpdateSerializer, AdminUpdateSerializer, PostsSerializer, NotificationSerializer
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
from django.conf import settings
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger


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
        registration_number = data.get(
            'registration_number', '0000000000')  # Default value added
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
        print("is_banned", user.ban)
    except Users.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    # Check if the password is correct
    if not check_password(password, user.password):
        return JsonResponse({'error': 'Wrong user name or password'}, status=400)

    # Generate JWT token
    token = jwt.encode({'id': user.id}, 'jwtkey', algorithm='HS256')
    print("this is my jwt token", token)

    return JsonResponse({'student_id_token': token, 'user': {'id': user.id, 'student_id': user.student_id , 'is_admin':user.admin ,'is_banned' : user.ban},  'message': 'user logged in successfully'}, status=200)

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
                data['password'] = make_password(
                    password)  # Encrypt the password
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


@api_view(['GET'])
def get_all_notifications(request):
    notifications = Notification.objects.all()
    serialized_data = []

    for notification in notifications:
        user_id = notification.user_id.id  # Assuming user_id is the foreign key to Users table
        try:
            user = Users.objects.get(id=user_id)
            user_name = user.name
        except Users.DoesNotExist:
            user_name = "Unknown"

        # Serialize notification data along with user name
        serialized_notification = {
            'id': notification.id,
            'notification': notification.notification,
            'created_at': notification.created_at,
            'user_id': user_id,
            'user_name': user_name
        }
        serialized_data.append(serialized_notification)

    return Response(serialized_data, status=status.HTTP_200_OK)

@api_view(['POST'])
def create_notification(request):
    print("inside create notification")
    token = request.headers.get('Authorization')

    print("This is token ", token)

    if not token:
        return Response({"error": "Not authenticated!"}, status=status.HTTP_401_UNAUTHORIZED)
    try:
        decoded_token = jwt.decode(token, 'jwtkey', algorithms=['HS256'])
        user_instance = get_object_or_404(Users, id=decoded_token['id'])
        print( "decode token" , decoded_token , 'user_instance' ,user_instance)
    except jwt.ExpiredSignatureError:
        return Response({"error": "Token is expired!"}, status=status.HTTP_403_FORBIDDEN)
    except jwt.InvalidTokenError:
        return Response({"error": "Token is not valid!"}, status=status.HTTP_403_FORBIDDEN)
    serializer = NotificationSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(user_id=user_instance)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT'])
def update_notification(request, pk):
    try:
        notification_instance = Notification.objects.get(pk=pk)
    except Notification.DoesNotExist:
        return Response({"error": "Notification not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = NotificationSerializer(notification_instance, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

   




@api_view(['POST'])
def add_post(request):
    print("This is add_post api")
    print("This is headers: ", request.headers)
    token = request.headers.get('Authorization')
    if not token:
        return Response({"error": "Not authenticated!"}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        decoded_token = jwt.decode(token, 'jwtkey', algorithms=['HS256'])
        user_instance = get_object_or_404(Users, id=decoded_token['id'])
    except jwt.ExpiredSignatureError:
        return Response({"error": "Token is expired!"}, status=status.HTTP_403_FORBIDDEN)
    except jwt.InvalidTokenError:
        return Response({"error": "Token is not valid!"}, status=status.HTTP_403_FORBIDDEN)

    serializer = PostsSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(uid=user_instance)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def get_images(request):
    page_number = request.query_params.get('page', 1)
    try:
        page_number = int(page_number)
    except ValueError:
        page_number = 1

    paginator = Paginator(Posts.objects.all().order_by('-date'), 10)

    try:
        result_page = paginator.page(page_number)
    except PageNotAnInteger:
        result_page = paginator.page(1)
    except EmptyPage:
        result_page = paginator.page(paginator.num_pages)

    serializer = PostsSerializer(result_page, many=True)
    return Response({
        'data': serializer.data,
        'total_pages': paginator.num_pages
    })


@api_view(['GET'])
def get_post_details(request, post_id):
    print("Inside the get_post_details method :")
    try:
        post = Posts.objects.get(id=post_id)
        print('This is post id : ', post)
        serializer = PostsSerializer(post)
        print("this is serializer : ", serializer)
        return Response(serializer.data)
    except Posts.DoesNotExist:
        return Response(status=404)


@api_view(['PUT'])
def update_post(request, post_id):
    print("This is update_post api")
    token = request.headers.get('Authorization')

    if not token:
        return Response({"error": "Not authenticated!"}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        decoded_token = jwt.decode(token, 'jwtkey', algorithms=['HS256'])
        user_instance = get_object_or_404(Users, id=decoded_token['id'])

    except jwt.ExpiredSignatureError:
        return Response({"error": "Token is expired!"}, status=status.HTTP_403_FORBIDDEN)
    except jwt.InvalidTokenError:
        return Response({"error": "Token is not valid!"}, status=status.HTTP_403_FORBIDDEN)

    post = get_object_or_404(Posts, id=post_id)

    if post.uid != user_instance:
        return Response({"error": "You do not have permission to update this post"}, status=status.HTTP_403_FORBIDDEN)

    title = request.data.get('title')
    desc = request.data.get('desc')
    category = request.data.get('category')

    if not title:
        request.data['title'] = post.title
    if not desc:
        request.data['desc'] = post.desc
    if not category:
        request.data['category'] = post.category

    serializer = PostsSerializer(post, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
def delete_post(request, post_id):
    print("This is delete_post api")
    print("This is headers: ", request.headers)
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

    post = get_object_or_404(Posts, id=post_id)
    print("thisi is post var: ", post)

    if post.uid != user_instance:
        return Response({"error": "You do not have permission to delete this post"}, status=status.HTTP_403_FORBIDDEN)

    post.delete()
    return Response({"message": "Post deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

@api_view(['POST'])
def update_scores(request):
    student_id = request.data.get('student_id')
    semester = request.data.get('semester')
    tech = request.data.get('tech', 0)
    etc = request.data.get('etc', 0)
    art = request.data.get('art', 0)
    sports = request.data.get('sports', 0)
    academic = request.data.get('academic', 0)

    if not student_id or not semester:
        return Response({'error': 'student_id and semester are required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = Users.objects.get(id=student_id)
        scores_instances = Scores.objects.filter(student=user, sem__gte=semester)
    except Users.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    if not scores_instances.exists():
        return Response({'error': 'Scores instances not found for the provided semester'}, status=status.HTTP_404_NOT_FOUND)

    # Update score values for all relevant instances
    for score_instance in scores_instances:
        score_instance.tech += tech
        score_instance.etc += etc
        score_instance.art += art
        score_instance.sports += sports
        score_instance.academic += academic

        # Calculate overall score
        overall = tech + etc + art + sports + academic
        score_instance.overall = overall
        score_instance.save()

    return Response({'message': 'Scores updated successfully'}, status=status.HTTP_200_OK)


def get_user_data(request, user_id):
    print('inside get_user_data')
    try:
        user = Users.objects.get(id=user_id)
        user_data = {
            'id': user.id,
            'student_id': user.student_id,
            'email': user.email,
            'name': user.name,
            'sem': user.sem,
            'img': user.img,
            'admin': user.admin,
            'registration_number': user.registration_number,
            'branch': user.branch,
        }
        return JsonResponse({'user': user_data})
    except Users.DoesNotExist:
        return JsonResponse({'error': 'User does not exist'}, status=404)

