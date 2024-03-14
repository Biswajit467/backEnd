from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Users, Scores

@receiver(post_save, sender=Users)
def create_scores(sender, instance, created, **kwargs):
    if created:
        for sem in range(1, 9):
            Scores.objects.create(student=instance, sem=sem)

# from django.apps import apps
# from django.db.models.signals import post_migrate
# from django.dispatch import receiver
# from django.core.management import call_command

# @receiver(post_migrate)
# def delete_old_notifications(sender, **kwargs):
#     print("inside funciton after post migration")
#     if sender.name == apps.get_app_config('users').name:
#         call_command('delete_old_notifications')