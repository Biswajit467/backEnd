from django.apps import AppConfig


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'
    
    def ready(self):
        from . import signals
        from django.core.management import call_command
        call_command('delete_old_notifications')
