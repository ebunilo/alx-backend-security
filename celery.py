import os
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ip_tracking.settings')

app = Celery('ip_tracking')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

# Celery Beat Schedule for periodic tasks
app.conf.beat_schedule = {
    'detect-anomalies-hourly': {
        'task': 'ip_tracking.tasks.detect_anomalies',
        'schedule': crontab(minute=0),  # Run every hour
    },
    'cleanup-old-logs-daily': {
        'task': 'ip_tracking.tasks.cleanup_old_logs',
        'schedule': crontab(hour=2, minute=0),  # Run daily at 2 AM
    },
}