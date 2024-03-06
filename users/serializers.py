# serializers.py
from rest_framework import serializers
from .models import Users
from .models import Posts


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['name', 'email', 'password','img' ] 
class AdminUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['student_id','name', 'email', 'password', 'img' ] 


class PostsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Posts
        fields = ['id', 'title', 'img', 'desc', 'date', 'uid', 'category']