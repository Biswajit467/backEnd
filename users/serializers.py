# serializers.py
from rest_framework import serializers
from .models import Users
from .models import Posts
from .models import Scores

from .models import Notification


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['name', 'email', 'password', 'img']


class AdminUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['student_id', 'name', 'email', 'password',
                  'img', 'branch', 'registration_number', 'ban']


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'notification', 'created_at', 'user_id']
    def update(self, instance, validated_data):
        # Update notification fields
        instance.notification = validated_data.get('notification', instance.notification)
        instance.save()
        return instance


# class PostsSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Posts
#         fields = ['id', 'title', 'img', 'desc', 'date', 'uid', 'category']

class PostsSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField()

    class Meta:
        model = Posts
        fields = ['id', 'title', 'img', 'desc',
                  'date', 'uid', 'category', 'url']

    def get_url(self, obj):
        return obj.img.url

        fields = ['id', 'title', 'img', 'desc', 'date', 'uid', 'category']

class ScoresSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scores
        fields = '__all__'

class UsersSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['name', 'sem', 'img', 'registration_number', 'branch']

class UsersSerializerforAdmin(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = '__all__'

class TopScoresSerializer(serializers.ModelSerializer):
    student_details = UsersSerializer(source='student', read_only=True)

    class Meta:
        model = Scores
        fields = '__all__'
        extra_fields = ['student_details']