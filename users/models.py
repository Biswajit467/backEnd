from django.db import models

# Create your models here.

class Users(models.Model):
    id = models.AutoField(primary_key=True)
    user_name = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    email = models.EmailField(unique=True)

    class Meta:
        db_table = 'users'  # Specify the table name explicitly
class Posts(models.Model):
    id = models.AutoField(primary_key=True)
    
    class Meta:
        db_table = 'posts'