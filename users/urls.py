from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

user_api = [
       path('user/get-user-data/<int:user_id>/', views.get_user_data, name='get_user_data'),

]
admin_api = [
    path('admins/', views.admins, name='admins'),
    path('admins/user-stats/', views.user_stats, name='user_stats'),
    path('admins/users-by-branch/<str:branch>/<int:semester>/', views.users_by_branch_and_semester, name='users_by_branch_and_semester'),
]

auth_api = [
    path('create-admin/', views.create_admin, name='create_admin'),
    path('admins/create-user/', views.create_user, name='create_user'),
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
    path('view-posts/', views.view_posts, name='view_posts'),
    path('delete-post/<int:post_id>', views.delete_post, name='delete_post'),
    path('update-post/<int:post_id>', views.update_post, name='update_post'),
    path('post-details/<int:post_id>',
         views.get_post_details, name='get_post_details')


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

    path('admins/create-notification/', views.create_notification,
         name='create_notification'),
    path('admins/update-notification/<int:pk>/',
         views.update_notification, name='update_notification'),
]

scores_api = [
    path('admins/update-scores/', views.update_scores, name='update_scores'),
    path('user/get-user-scores/<int:user_id>/<int:semester>/', views.get_user_scores, name='get_user_scores'),
    path('top-scores/', views.top_scores, name='top_scores'),
    path('student-scores/<str:student_id>/', views.student_scores, name='student-scores'),
    path('get-leader-board/<str:student_id>/', views.get_leader_board, name='get_leader_board'),

]

mongo_apis =[
        path('insert-semester-marks/', views.insert_semester_marks, name='insert_semester_marks'),
        path('get-subject-marks/', views.get_subject_marks, name='get_subject_marks'),
        path('get-records-by-student-id/', views.get_records_by_student_id, name='get_records_by_student_id'),

]


urlpatterns = user_api + admin_api + auth_api + \
    post_api + \
    scores_api + updation_api + notfication_api + mongo_apis

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
