from django.urls import path
from . import views

user_api = [
    path('index/', views.index, name='index')
]
admin_api = [
    path('admins/', views.admins, name='admins')
]

auth_api = [
    path('create-admin/', views.create_admin, name='create_admin'),
    path('create-user/', views.create_user, name='create_user'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('check-db-connection/', views.check_db_connection,
         name='check_db_connection'),
]

urlpatterns = user_api + admin_api + auth_api
