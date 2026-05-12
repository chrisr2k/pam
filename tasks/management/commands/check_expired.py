from django.core.management.base import BaseCommand
from django.utils import timezone
from access_requests.models import AccessRequest
from tasks.provisioning import deprovision_access_sync


class Command(BaseCommand):
    help = 'Check for and deprovision any expired access sessions'

    def handle(self, *args, **options):
        now = timezone.now()
        expired_requests = AccessRequest.objects.filter(
            status__in=[AccessRequest.Status.PROVISIONED, AccessRequest.Status.ACTIVE],
            expires_at__lte=now,
        )

        count = expired_requests.count()
        if count == 0:
            self.stdout.write(self.style.SUCCESS('No expired sessions found.'))
            return

        self.stdout.write(f'Found {count} expired session(s), deprovisioning...')
        for req in expired_requests:
            self.stdout.write(f'  Deprovisioning request #{req.id} ({req.requester.username} -> {req.role.name})...')
            try:
                deprovision_access_sync(req.id)
                self.stdout.write(self.style.SUCCESS(f'  Done.'))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'  Failed: {e}'))

        self.stdout.write(self.style.SUCCESS(f'Deprovisioned {count} expired session(s).'))
