from django.db import models
from datetime import datetime
# Create your models here.

class Users(models.Model):
    id = models.AutoField(primary_key=True)
    student_id = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=200) 
    sem = models.IntegerField() 
    img = models.CharField(max_length=1000 , null=True) 
    admin = models.BooleanField(default=False) 

    class Meta:
        db_table = 'users'  # Specify the table name explicitly
class Posts(models.Model):
    id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=255 , default='title')
    img = models.CharField(max_length=255 , default ='img')
    desc = models.CharField(max_length=10000 , default = 'desc')
    date = models.DateField(auto_now_add=True )
    uid = models.ForeignKey(Users, on_delete=models.CASCADE)
    category = models.CharField(max_length=45 , default=None , null=True)
    
    class Meta:
        db_table = 'posts'
