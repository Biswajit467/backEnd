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


# class AdminUpdateSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Users
#         fields = ['student_id', 'name', 'email', 'password',
#                   'img', 'branch', 'registration_number', 'ban']
        

class AdminUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['id', 'student_id', 'password', 'email', 'name', 'sem', 'img', 'admin', 'registration_number', 'branch', 'ban']
        
    def to_internal_value(self, data):
        updated_data = {}
        for key, value in data.items():
            # If the value is not empty, include it in the updated data
            if value != "":
                updated_data[key] = value
        return updated_data


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'notification', 'created_at', 'user_id']

    def update(self, instance, validated_data):
        # Update notification fields
        instance.notification = validated_data.get(
            'notification', instance.notification)
        instance.save()
        return instance


class PostsSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField()
    uid = serializers.SerializerMethodField()

    class Meta:
        model = Posts
        fields = ['id', 'title', 'img', 'desc',
                  'date', 'uid', 'category', 'url']

    def get_url(self, obj):
        return obj.img.url

    def get_uid(self, obj):
        user = obj.uid
        return {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'sem': user.sem,
            'admin': user.admin,
            'branch': user.branch
        }

        fields = ['id', 'title', 'img', 'desc', 'date', 'uid', 'category']

class ScoresSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scores
        fields = '__all__'

class UsersSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['name', 'sem', 'img', 'registration_number', 'branch','ban']

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