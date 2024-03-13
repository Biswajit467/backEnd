from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

user_api = [
    path('index/', views.index, name='index')
]
admin_api = [
    path('admins/', views.admins, name='admins')
]

auth_api = [
    path('create-admin/', views.create_admin, name='create_admin'),
    path('create-user/', views.create_user, name='create_user'),
    path('delete-user/<str:student_id>/',
         views.delete_user, name='delete_user'),
    path('delete-old-users/', views.delete_old_users, name='delete-old-users'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('check-db-connection/', views.check_db_connection,
         name='check_db_connection'),
]
post_api = [

    path('add-post/', views.add_post, name='add_post'),
    path('view-posts/', views.get_images, name='get_images')

]

updation_api = [
    path('user/update-personal-info/<int:pk>/',
         views.update_personal_info, name='update_personal_info'),
    path('admins/update-student-info/<int:pk>/',
         views.update_student_info, name='update_student_info')
]

notfication_api = [
    path('create-notification/', views.create_notification,
         name='create-notification'),

]

urlpatterns = user_api + admin_api + auth_api + \
    post_api + updation_api + notfication_api

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
