# serializers.py
from rest_framework import serializers
from .models import Users

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['name', 'email', 'password','img' ] 
class AdminUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['student_id','name', 'email', 'password', 'img' , 'branch' , 'registration_number' , 'ban' ] 