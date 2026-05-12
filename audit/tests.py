"""Tests for the audit app - models, middleware, and views."""

from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.contrib.messages.storage.fallback import FallbackStorage

from .models import AuditLog
from .middleware import AuditMiddleware

User = get_user_model()


class AuditLogModelTests(TestCase):
    """Test the AuditLog model."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser', password='testpass',
        )
        self.log = AuditLog.objects.create(
            actor=self.user,
            action='REQUEST_CREATED',
            target_type='AccessRequest',
            target_id='1',
            details={'request_id': 1},
        )

    def test_log_creation(self):
        """Test basic log creation."""
        self.assertEqual(self.log.actor, self.user)
        self.assertEqual(self.log.action, 'REQUEST_CREATED')
        self.assertEqual(self.log.target_type, 'AccessRequest')

    def test_log_str(self):
        """Test string representation."""
        self.assertIn('Access Request Created', str(self.log))
        self.assertIn('testuser', str(self.log))

    def test_auto_timestamp(self):
        """Test that timestamp is set."""
        self.assertIsNotNone(self.log.timestamp)

    def test_ordering(self):
        """Test default ordering is newest first."""
        AuditLog.objects.create(
            actor=self.user,
            action='REQUEST_APPROVED',
            target_type='AccessRequest',
            target_id='2',
        )
        logs = list(AuditLog.objects.all())
        self.assertEqual(logs[0].action, 'REQUEST_APPROVED')
        self.assertEqual(logs[1].action, 'REQUEST_CREATED')

    def test_details_json_field(self):
        """Test that details stores JSON."""
        self.assertEqual(self.log.details, {'request_id': 1})


class AuditLogListViewTests(TestCase):
    """Test the audit log list view."""

    def setUp(self):
        self.list_url = reverse('audit:log')
        # Create an admin user with the ADMIN role
        self.admin = User.objects.create_user(
            username='admin', password='adminpass',
            role=User.Role.ADMIN,
        )
        self.user = User.objects.create_user(username='user', password='testpass')

    def test_log_requires_login(self):
        """Test that log requires authentication."""
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 302)

    def test_log_requires_auditor_or_admin(self):
        """Test that log requires auditor or admin."""
        self.client.force_login(self.user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 403)

    def test_log_loads_for_admin(self):
        """Test that log loads for admin."""
        self.client.force_login(self.admin)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/audit_log.html')

    def test_log_loads_for_auditor(self):
        """Test that log loads for auditor."""
        auditor = User.objects.create_user(
            username='auditor', password='auditorpass',
            role=User.Role.AUDITOR,
        )
        self.client.force_login(auditor)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 200)

    def test_log_pagination(self):
        """Test that log is paginated."""
        self.client.force_login(self.admin)
        for i in range(55):
            AuditLog.objects.create(
                actor=self.admin,
                action=f'ACTION_{i}',
                target_type='Test',
                target_id=str(i),
            )
        response = self.client.get(self.list_url)
        self.assertEqual(len(response.context['logs']), 50)

    def test_log_filter_by_action(self):
        """Test filtering by action."""
        self.client.force_login(self.admin)
        AuditLog.objects.create(
            actor=self.admin,
            action='SPECIFIC_ACTION',
            target_type='Test',
            target_id='1',
        )
        AuditLog.objects.create(
            actor=self.admin,
            action='OTHER_ACTION',
            target_type='Test',
            target_id='2',
        )
        response = self.client.get(self.list_url, {'action': 'SPECIFIC_ACTION'})
        self.assertEqual(len(response.context['logs']), 1)
