"""
Management command to seed the database with demo data.
Creates an admin user and sample roles for demonstration purposes.

Usage: python manage.py seed_demo
       python manage.py seed_demo --admin-password MySecurePass1
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from roles.models import PrivilegedRole

User = get_user_model()


class Command(BaseCommand):
    help = 'Seed the database with demo data (admin user + sample roles)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--admin-password',
            default='admin123',
            help='Password for the admin user (default: admin123)',
        )

    def handle(self, *args, **options):
        admin_password = options['admin_password']

        # Create admin user if not exists
        admin_user, created = User.objects.get_or_create(
            username='admin',
            defaults={
                'email': 'admin@example.com',
                'role': User.Role.ADMIN,
                'is_staff': True,
                'is_superuser': True,
            },
        )
        admin_user.set_password(admin_password)
        admin_user.save()
        if created:
            self.stdout.write(self.style.SUCCESS(f'Created admin user (password: {admin_password})'))
        else:
            self.stdout.write(self.style.SUCCESS(f'Reset admin user password (password: {admin_password})'))

        # Create sample approver
        approver, created = User.objects.get_or_create(
            username='approver',
            defaults={
                'email': 'approver@example.com',
                'role': User.Role.APPROVER,
                'is_staff': True,
            },
        )
        approver.set_password('approver123')
        approver.save()
        if created:
            self.stdout.write(self.style.SUCCESS('Created approver user (password: approver123)'))
        else:
            self.stdout.write(self.style.SUCCESS('Reset approver user password (password: approver123)'))

        # Create sample requester
        requester, created = User.objects.get_or_create(
            username='requester',
            defaults={
                'email': 'requester@example.com',
                'role': User.Role.REQUESTER,
            },
        )
        requester.set_password('requester123')
        requester.save()
        if created:
            self.stdout.write(self.style.SUCCESS('Created requester user (password: requester123)'))
        else:
            self.stdout.write(self.style.SUCCESS('Reset requester user password (password: requester123)'))

        # Create sample AWS role
        aws_role, created = PrivilegedRole.objects.get_or_create(
            name='AWS-Admin-Access',
            defaults={
                'description': 'Full administrative access to AWS production account',
                'provider': 'AWS',
                'aws_account_id': '123456789012',
                'aws_permission_set_arn': 'arn:aws:sso:::permissionSet/ssoins-123/ps-admin',
                'max_duration_minutes': 480,
                'requires_approval': True,
            },
        )
        if created:
            aws_role.approvers.add(approver)
            self.stdout.write(self.style.SUCCESS('Created AWS-Admin-Access role'))
        else:
            self.stdout.write(self.style.WARNING('AWS-Admin-Access role already exists'))

        # Create sample Entra role
        # Use try/except because the model's clean() method validates uniqueness
        # and get_or_create calls save() which calls clean()
        try:
            entra_role, created = PrivilegedRole.objects.get_or_create(
                name='Entra-Global-Admin',
                defaults={
                    'description': 'Global Administrator role in Entra ID',
                    'provider': 'ENTRA',
                    'entra_role_id': '62e90394-69f5-4237-9190-012177145e10',
                    'entra_role_name': 'Global Administrator',
                    'max_duration_minutes': 240,
                    'requires_approval': True,
                },
            )
            if created:
                entra_role.approvers.add(approver)
                self.stdout.write(self.style.SUCCESS('Created Entra-Global-Admin role'))
            else:
                self.stdout.write(self.style.WARNING('Entra-Global-Admin role already exists'))
        except Exception:
            # Role may already exist with a different name but same entra_role_id
            entra_role = PrivilegedRole.objects.filter(
                provider='ENTRA',
                entra_role_id='62e90394-69f5-4237-9190-012177145e10',
            ).first()
            if entra_role:
                self.stdout.write(self.style.WARNING('Entra-Global-Admin role already exists (found by role ID)'))

        # Create a no-approval-needed role for quick testing
        quick_role, created = PrivilegedRole.objects.get_or_create(
            name='AWS-ReadOnly',
            defaults={
                'description': 'Read-only access to AWS (no approval needed)',
                'provider': 'AWS',
                'aws_account_id': '123456789012',
                'aws_permission_set_arn': 'arn:aws:sso:::permissionSet/ssoins-123/ps-readonly',
                'max_duration_minutes': 120,
                'requires_approval': False,
            },
        )
        if created:
            self.stdout.write(self.style.SUCCESS('Created AWS-ReadOnly role (no approval needed)'))
        else:
            self.stdout.write(self.style.WARNING('AWS-ReadOnly role already exists'))

        self.stdout.write(self.style.SUCCESS('\nDemo data seeded successfully!'))
        self.stdout.write('')
        self.stdout.write('Demo accounts:')
        self.stdout.write(f'  Admin:     admin / {admin_password}')
        self.stdout.write('  Approver:  approver / approver123')
        self.stdout.write('  Requester: requester / requester123')
