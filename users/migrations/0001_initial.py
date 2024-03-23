# Generated by Django 5.0.2 on 2024-03-03 18:46

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Users',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('student_id', models.CharField(max_length=255, unique=True)),
                ('password', models.CharField(max_length=255)),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('name', models.CharField(max_length=200)),
                ('sem', models.IntegerField()),
                ('img', models.CharField(max_length=1000, null=True)),
                ('admin', models.BooleanField(default=False)),
                ('registration_number', models.CharField(default='0000000000', max_length=255)),
                ('branch', models.CharField(default='cse', max_length=255)),
                ('ban', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('registration_number', models.CharField(default='0000000000', max_length=255)),
                ('branch', models.CharField(default='cse', max_length=255)),
                ('ban', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'users',
            },
        ),
        migrations.CreateModel(
            name='Posts',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('title', models.CharField(default='title', max_length=255)),
                ('img', models.CharField(default='img', max_length=255)),
                ('desc', models.CharField(default='desc', max_length=10000)),
                ('date', models.DateField(auto_now_add=True)),
                ('category', models.CharField(default=None, max_length=45, null=True)),
                ('uid', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='users.users')),
            ],
            options={
                'db_table': 'posts',
            },
        ),
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('notification', models.CharField(max_length=10000)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='users.users')),
            ],
            options={
                'db_table': 'notification',
            },
        ),
    ]
