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
    img = models.CharField(max_length=1000, null=True) 
    admin = models.BooleanField(default=False) 
    registration_number = models.CharField(max_length=255 , default='0000000000')  
    branch = models.CharField(max_length=255 , default='cse')  
    ban = models.BooleanField(default=False)  
    created_at = models.DateTimeField(auto_now_add=True)  # New field for creation date

    class Meta:
        db_table = 'users'
        
class Posts(models.Model):
    id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=255 , default='title')
    img = models.CharField(max_length=255 , default ='img')
    desc = models.CharField(max_length=10000 , default = 'desc')
    date = models.DateField(auto_now_add=True )
    uid = models.ForeignKey("Users", on_delete=models.CASCADE)  # Foreign key to Users model with related name "posts"
    category = models.CharField(max_length=45 , default=None , null=True)
    
    class Meta:
        db_table = 'posts'
