from django.core.management.base import BaseCommand
from django.utils import timezone
from users.models import Notification

class Command(BaseCommand):
    help = 'Deletes notifications older than 15 days'
    print('inside command file ')

    def handle(self, *args, **kwargs):
        print("inside handle function")
        fifteen_days_ago = timezone.now() - timezone.timedelta(days=15)
        
        # Delete notifications older than 15 days
        deleted_count, _ = Notification.objects.filter(created_at__lt=fifteen_days_ago).delete()
        
        self.stdout.write(self.style.SUCCESS(f'Deleted {deleted_count} old notifications'))
