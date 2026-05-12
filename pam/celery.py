import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pam.settings')

app = Celery('pam')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
