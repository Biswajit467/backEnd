# serializers.py
from rest_framework import serializers
from .models import Users
from .models import Posts

from .models import Notification

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['name', 'email', 'password','img' ] 
class AdminUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['student_id','name', 'email', 'password', 'img' , 'branch' , 'registration_number' , 'ban' ] 
class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'notification', 'created_at', 'user_id']
    def update(self, instance, validated_data):
        # Update notification fields
        instance.notification = validated_data.get('notification', instance.notification)
        instance.save()
        return instance


class PostsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Posts
        fields = ['id', 'title', 'img', 'desc', 'date', 'uid', 'category']