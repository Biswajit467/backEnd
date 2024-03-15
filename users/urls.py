from django.urls import path
from . import views

user_api = [
       path('user/get-user-data/<int:user_id>/', views.get_user_data, name='get_user_data'),

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
    path('add-post/', views.add_post, name='add_post')
]

updation_api = [
    path('user/update-personal-info/<int:pk>/',
         views.update_personal_info, name='update_personal_info'),
    path('admins/update-student-info/<int:pk>/',
         views.update_student_info, name='update_student_info')
]

notfication_api = [
    path('get-notifications/', views.get_all_notifications,
         name='get_all_notifications'),

    path('create-notification/', views.create_notification,
         name='create_notification'),
    path('update-notification/<int:pk>/',
         views.update_notification, name='update_notification'),
]

scores_api = [
    path('update-scores/', views.update_scores, name='update_scores'),
]

urlpatterns = user_api + admin_api + auth_api + \
    scores_api + updation_api + notfication_api
