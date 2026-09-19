"""Tests for the vault app: crypto, models/signals, provider, checkout flow."""

from datetime import timedelta
from unittest.mock import patch

import pyotp
from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from access_requests.models import AccessRequest
from audit.models import AuditLog
from roles.models import PrivilegedRole
from .crypto import (
    decrypt_value,
    encrypt_value,
    generate_rotation_value,
    hash_previous_value,
)
from .models import VaultEntry, VaultRotationEvent
from .provider import VaultProvider
from .services import execute_reveal

User = get_user_model()

OTP_SECRET = 'JBSWY3DPEHPK3PXP'


def enroll(user):
    """Enroll a user in MFA with the test-vector secret."""
    user.set_otp_secret(OTP_SECRET)
    user.mfa_enrolled_at = timezone.now()
    user.save()


def make_entry(**kwargs):
    """Create a VaultEntry with a plaintext value (auto-encrypted on save)."""
    defaults = dict(
        name='Prod-DB',
        secret_type='PASSWORD',
        encrypted_value='initial-password',
    )
    defaults.update(kwargs)
    return VaultEntry.objects.create(**defaults)


class VaultCryptoTests(TestCase):
    """Test the crypto helpers."""

    def test_encrypt_decrypt_roundtrip(self):
        """Plaintext round-trips through encryption."""
        token = encrypt_value('s3cret-value')
        self.assertEqual(decrypt_value(token), 's3cret-value')

    def test_ciphertext_hides_plaintext_and_is_nondeterministic(self):
        """Ciphertext contains no plaintext and differs between encryptions."""
        token1 = encrypt_value('s3cret-value')
        token2 = encrypt_value('s3cret-value')
        self.assertNotIn('s3cret-value', token1)
        self.assertNotEqual(token1, token2)

    def test_generate_rotation_value_has_all_char_classes(self):
        """Generated values are 24 chars with every character class."""
        import string
        value = generate_rotation_value()
        self.assertEqual(len(value), 24)
        self.assertTrue(any(c.isupper() for c in value))
        self.assertTrue(any(c.islower() for c in value))
        self.assertTrue(any(c.isdigit() for c in value))
        self.assertTrue(any(c in string.punctuation for c in value))

    def test_hash_previous_value_is_keyed_and_stable(self):
        """The reuse hash is deterministic and keyed (not plain SHA256)."""
        import hashlib
        digest = hash_previous_value('value')
        self.assertEqual(digest, hash_previous_value('value'))
        self.assertNotEqual(digest, hashlib.sha256(b'value').hexdigest())


class VaultEntryModelTests(TestCase):
    """Test VaultEntry encryption and shim-role signals."""

    def test_save_encrypts_plaintext(self):
        """Plaintext assigned to encrypted_value is encrypted on save."""
        entry = make_entry()
        self.assertTrue(entry.encrypted_value.startswith('gAAAA'))
        self.assertNotEqual(entry.encrypted_value, 'initial-password')
        self.assertEqual(entry.get_secret_value(), 'initial-password')

    def test_shim_auto_created_on_save(self):
        """Saving an entry creates a mirrored VAULT shim role."""
        entry = make_entry(description='DB password', max_checkout_minutes=45)
        shim = PrivilegedRole.objects.get(provider='VAULT', vault_entry=entry)
        self.assertEqual(shim.name, 'Vault: Prod-DB')
        self.assertEqual(shim.description, 'DB password')
        self.assertEqual(shim.requires_approval, True)
        self.assertEqual(shim.max_duration_minutes, 45)

    def test_shim_synced_on_update_no_duplicate(self):
        """Updating the entry syncs the existing shim; no duplicate created."""
        entry = make_entry()
        entry.name = 'Prod-DB-New'
        entry.requires_approval = False
        entry.save()
        shims = PrivilegedRole.objects.filter(provider='VAULT', vault_entry=entry)
        self.assertEqual(shims.count(), 1)
        self.assertEqual(shims.first().name, 'Vault: Prod-DB-New')
        self.assertFalse(shims.first().requires_approval)

    def test_entry_delete_deactivates_shim_and_audits(self):
        """Deleting an entry deactivates (not deletes) the shim and audits."""
        entry = make_entry()
        shim = entry.shim_role
        entry.delete()
        shim.refresh_from_db()
        self.assertFalse(shim.is_active)
        self.assertIsNone(shim.vault_entry)  # SET_NULL keeps history
        self.assertTrue(AuditLog.objects.filter(
            action='VAULT_ENTRY_DELETED',
            target_type='VaultEntry').exists())


class VaultProviderTests(TestCase):
    """Test the VaultProvider implementation."""

    def setUp(self):
        self.provider = VaultProvider()
        self.entry = make_entry()

    def test_provision_success(self):
        """Provisioning returns a vault: reference id."""
        result = self.provider.provision_access(
            'ignored-oid', {'entry_id': self.entry.pk}, 60)
        self.assertTrue(result['success'])
        self.assertEqual(result['reference_id'], f'vault:{self.entry.pk}')

    def test_provision_missing_or_inactive_entry_fails(self):
        """Missing/inactive entries fail with an error."""
        result = self.provider.provision_access('oid', {'entry_id': 99999}, 60)
        self.assertFalse(result['success'])
        self.assertIn('error', result)
        self.entry.is_active = False
        self.entry.save()
        result = self.provider.provision_access('oid', {'entry_id': self.entry.pk}, 60)
        self.assertFalse(result['success'])
        self.assertIn('error', result)

    def test_deprovision_no_rotate_is_noop(self):
        """Without auto_rotate, deprovision is a no-op success."""
        original = self.entry.encrypted_value
        self.assertTrue(self.provider.deprovision_access(f'vault:{self.entry.pk}'))
        self.entry.refresh_from_db()
        self.assertEqual(self.entry.encrypted_value, original)
        self.assertEqual(self.entry.rotation_events.count(), 0)

    def test_deprovision_auto_rotates(self):
        """Auto-rotate entries get a new value + event + audit on deprovision."""
        entry = make_entry(auto_rotate=True)
        old_value = entry.get_secret_value()
        self.assertTrue(self.provider.deprovision_access(f'vault:{entry.pk}'))
        entry.refresh_from_db()
        self.assertNotEqual(entry.get_secret_value(), old_value)
        self.assertIsNotNone(entry.last_rotated_at)
        event = entry.rotation_events.get()
        self.assertEqual(event.reason, VaultRotationEvent.Reason.AUTO_CHECKIN)
        self.assertIsNone(event.rotated_by)
        self.assertEqual(event.previous_value_hash, hash_previous_value(old_value))
        self.assertEqual(event.plugin, 'vault_only')
        self.assertFalse(event.synced_to_system)
        audit = AuditLog.objects.filter(action='VAULT_SECRET_ROTATED').first()
        self.assertIsNotNone(audit)
        self.assertIsNone(audit.actor)
        self.assertNotIn(old_value, audit.details.values())

    def test_deprovision_deleted_entry_returns_true(self):
        """Deprovisioning a deleted entry is a safe no-op success."""
        self.assertTrue(self.provider.deprovision_access('vault:99999'))

    def test_check_access_status_and_list_roles(self):
        """Status is entry-based; roles list is empty."""
        self.assertEqual(
            self.provider.check_access_status(f'vault:{self.entry.pk}'), 'active')
        self.entry.is_active = False
        self.entry.save()
        self.assertEqual(
            self.provider.check_access_status(f'vault:{self.entry.pk}'), 'expired')
        self.assertEqual(self.provider.check_access_status('vault:99999'), 'not_found')
        self.assertEqual(self.provider.list_available_roles(), [])


class VaultCheckoutFlowTests(TestCase):
    """End-to-end checkout via the AccessRequest flow."""

    def setUp(self):
        self.requester = User.objects.create_user(
            username='requester', password='testpass',
            entra_object_id=None,  # vault checkout must not require Entra OID
        )
        self.approver = User.objects.create_user(
            username='approver', password='testpass', role=User.Role.APPROVER)
        enroll(self.approver)
        self.entry = make_entry(auto_rotate=True)
        self.entry.shim_role.approvers.add(self.approver)
        self.shim = self.entry.shim_role

    def _create_pending_request(self):
        with patch('tasks.provisioning.provision_access_sync'), \
             patch('access_requests.services.send_notification'):
            from access_requests.services import execute_create
            access_request, form = execute_create(self.requester, {
                'role': str(self.shim.pk),
                'justification': 'Need DB password',
                'requested_duration_minutes': '30',
            })
        self.assertIsNone(form)
        return access_request

    def _approve_via_challenge(self, access_request):
        with patch('tasks.provisioning.provision_access_sync'):
            self.client.force_login(self.approver)
            url = reverse('requests:approve', kwargs={'pk': access_request.pk})
            response = self.client.post(url, {'comment': 'Approved'})
            self.assertEqual(response.status_code, 200)
            ticket = self.client.session['mfa_ticket']
            return self.client.post(reverse('accounts:mfa_challenge'), {
                'code': pyotp.TOTP(OTP_SECRET).now(),
                'comment': 'Approved',
                'ticket': ticket,
                'target_id': str(access_request.pk),
            })

    def test_full_checkout_reveal_rotate_flow(self):
        """Submit → approve → provision → reveal → deprovision rotates."""
        access_request = self._create_pending_request()
        self._approve_via_challenge(access_request)

        from tasks.provisioning import provision_access_sync, deprovision_access_sync
        provision_access_sync(access_request.pk)
        access_request.refresh_from_db()
        self.assertEqual(access_request.status, AccessRequest.Status.PROVISIONED)
        self.assertEqual(access_request.provider_reference_id, f'vault:{self.entry.pk}')

        secret, err = execute_reveal(self.requester, self.entry.pk)
        self.assertIsNone(err)
        self.assertEqual(secret, 'initial-password')
        audit = AuditLog.objects.filter(action='VAULT_SECRET_REVEALED').first()
        self.assertIsNotNone(audit)
        self.assertNotIn(secret, audit.details.values())

        old_value = self.entry.get_secret_value()
        deprovision_access_sync(access_request.pk, trigger='revoked')
        access_request.refresh_from_db()
        self.assertEqual(access_request.status, AccessRequest.Status.EXPIRED)
        self.entry.refresh_from_db()
        self.assertNotEqual(self.entry.get_secret_value(), old_value)

    def test_reveal_denied_without_checkout(self):
        """No checkout means no reveal."""
        secret, err = execute_reveal(self.requester, self.entry.pk)
        self.assertIsNone(secret)
        self.assertIn('no active checkout', err)

    def test_reveal_denied_expired_or_other_users_checkout(self):
        """Expired checkouts and other users' checkouts don't grant reveal."""
        access_request = AccessRequest.objects.create(
            requester=self.requester, role=self.shim, justification='Test',
            status=AccessRequest.Status.PROVISIONED,
            provider_reference_id=f'vault:{self.entry.pk}',
            provisioned_at=timezone.now(),
            expires_at=timezone.now() - timedelta(minutes=1),
        )
        secret, err = execute_reveal(self.requester, self.entry.pk)
        self.assertIsNone(secret)
        other = User.objects.create_user(username='other', password='testpass')
        AccessRequest.objects.create(
            requester=other, role=self.shim, justification='Test',
            status=AccessRequest.Status.PROVISIONED,
            provider_reference_id=f'vault:{self.entry.pk}',
            provisioned_at=timezone.now(),
            expires_at=timezone.now() + timedelta(hours=1),
        )
        secret, err = execute_reveal(self.requester, self.entry.pk)
        self.assertIsNone(secret)
        self.assertIsNotNone(access_request)

    def test_auto_approve_entry_checks_out_instantly(self):
        """requires_approval=False entries provision without an approval step."""
        self.entry.requires_approval = False
        self.entry.save()
        from access_requests.services import execute_create
        with patch('tasks.provisioning.provision_access_sync'):
            access_request, form = execute_create(self.requester, {
                'role': str(self.shim.pk),
                'justification': 'Need DB password',
                'requested_duration_minutes': '30',
            })
        self.assertEqual(access_request.status, AccessRequest.Status.APPROVED)
        from tasks.provisioning import provision_access_sync
        provision_access_sync(access_request.pk)
        access_request.refresh_from_db()
        self.assertEqual(access_request.status, AccessRequest.Status.PROVISIONED)

    def test_user_without_entra_oid_can_checkout(self):
        """The entra_oid guard is relaxed for VAULT roles."""
        access_request = AccessRequest.objects.create(
            requester=self.requester, role=self.shim, justification='Test',
            status=AccessRequest.Status.APPROVED,
            requested_duration_minutes=30,
        )
        from tasks.provisioning import provision_access_sync
        provision_access_sync(access_request.pk)
        access_request.refresh_from_db()
        self.assertEqual(access_request.status, AccessRequest.Status.PROVISIONED)


class VaultRevealViewTests(TestCase):
    """Test the reveal view and its MFA challenge."""

    def setUp(self):
        self.user = User.objects.create_user(username='user', password='testpass')
        self.entry = make_entry()
        self.checkout = AccessRequest.objects.create(
            requester=self.user, role=self.entry.shim_role, justification='Test',
            status=AccessRequest.Status.PROVISIONED,
            provider_reference_id=f'vault:{self.entry.pk}',
            provisioned_at=timezone.now(),
            expires_at=timezone.now() + timedelta(hours=1),
        )

    def test_reveal_via_mfa_challenge(self):
        """An enrolled user reveals through the MFA challenge."""
        enroll(self.user)
        self.client.force_login(self.user)
        response = self.client.post(
            reverse('vault:reveal', kwargs={'pk': self.entry.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/mfa_challenge.html')
        # Regression: the form must POST to the challenge endpoint, not back
        # to the reveal URL it rendered from.
        self.assertContains(response, 'action="/accounts/mfa/challenge/"')
        ticket = self.client.session['mfa_ticket']
        response = self.client.post(reverse('accounts:mfa_challenge'), {
            'code': pyotp.TOTP(OTP_SECRET).now(),
            'ticket': ticket,
            'target_id': str(self.entry.pk),
        })
        self.assertRedirects(
            response, reverse('vault:detail', kwargs={'pk': self.entry.pk}))
        messages = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any('initial-password' in m for m in messages))

    def test_reveal_precheck_denied_without_checkout_no_ticket(self):
        """No active checkout → error, no challenge ticket issued."""
        self.checkout.expires_at = timezone.now() - timedelta(minutes=1)
        self.checkout.save()
        self.client.force_login(self.user)
        response = self.client.post(
            reverse('vault:reveal', kwargs={'pk': self.entry.pk}))
        self.assertRedirects(
            response, reverse('vault:detail', kwargs={'pk': self.entry.pk}))
        self.assertNotIn('mfa_ticket', self.client.session)


class VaultStaffViewTests(TestCase):
    """Test staff-only entry management."""

    def setUp(self):
        self.staff = User.objects.create_user(
            username='staff', password='testpass', is_staff=True)
        self.requester = User.objects.create_user(
            username='requester', password='testpass')

    def test_staff_only_list_create_rotate(self):
        """List/create/rotate are staff-only; detail requires login."""
        self.client.force_login(self.requester)
        self.assertEqual(self.client.get(reverse('vault:list')).status_code, 403)
        self.assertEqual(self.client.get(reverse('vault:create')).status_code, 403)
        entry = make_entry()
        self.assertEqual(
            self.client.post(
                reverse('vault:rotate', kwargs={'pk': entry.pk}),
                {'new_value': 'x'}).status_code, 403)
        self.client.force_login(self.staff)
        self.assertEqual(self.client.get(reverse('vault:list')).status_code, 200)
        self.assertEqual(
            self.client.get(reverse('vault:detail', kwargs={'pk': entry.pk}))
            .status_code, 200)

    def test_create_view_encrypts_and_creates_shim(self):
        """Staff create stores ciphertext, creates the shim, and audits."""
        self.client.force_login(self.staff)
        response = self.client.post(reverse('vault:create'), {
            'name': 'New-Entry',
            'description': 'Test',
            'secret_type': 'PASSWORD',
            'value': 'new-secret',
            'auto_rotate': 'on',
            'requires_approval': 'on',
            'max_checkout_minutes': '60',
        })
        self.assertRedirects(response, reverse('vault:list'))
        entry = VaultEntry.objects.get(name='New-Entry')
        self.assertTrue(entry.encrypted_value.startswith('gAAAA'))
        self.assertEqual(entry.get_secret_value(), 'new-secret')
        self.assertTrue(PrivilegedRole.objects.filter(
            provider='VAULT', vault_entry=entry).exists())
        self.assertTrue(AuditLog.objects.filter(
            action='VAULT_ENTRY_CREATED').exists())

    def test_manual_rotate_success_and_audit(self):
        """Staff rotation changes the value and is audited."""
        entry = make_entry()
        self.client.force_login(self.staff)
        response = self.client.post(
            reverse('vault:rotate', kwargs={'pk': entry.pk}),
            {'new_value': 'rotated-value'})
        self.assertRedirects(
            response, reverse('vault:detail', kwargs={'pk': entry.pk}))
        entry.refresh_from_db()
        self.assertEqual(entry.get_secret_value(), 'rotated-value')
        event = entry.rotation_events.get()
        self.assertEqual(event.reason, VaultRotationEvent.Reason.MANUAL)
        self.assertEqual(event.rotated_by, self.staff)

    def test_manual_rotate_rejects_same_value_and_reuse(self):
        """Same-value and previously-used values are rejected."""
        entry = make_entry()
        self.client.force_login(self.staff)
        rotate_url = reverse('vault:rotate', kwargs={'pk': entry.pk})
        # Same as current
        self.client.post(rotate_url, {'new_value': 'initial-password'})
        entry.refresh_from_db()
        self.assertEqual(entry.get_secret_value(), 'initial-password')
        # Rotate once, then try to reuse the original
        self.client.post(rotate_url, {'new_value': 'second-value'})
        response = self.client.post(rotate_url, {'new_value': 'initial-password'})
        entry.refresh_from_db()
        self.assertEqual(entry.get_secret_value(), 'second-value')
        messages = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any('previously used' in m for m in messages))


class VaultAdminRegistrationTests(TestCase):
    """Regression: the lazy admin-site proxy must not shadow custom admins."""

    def test_registered_admin_is_custom_class(self):
        """The replay must register VaultEntryAdmin, not a plain ModelAdmin."""
        from pam.admin_site import get_admin_site
        from vault.admin import VaultEntryAdmin
        site = get_admin_site()
        admin_instance = site._registry.get(VaultEntry)
        self.assertIsNotNone(admin_instance)
        self.assertIs(admin_instance.__class__, VaultEntryAdmin)

    def test_admin_form_includes_structured_config_fields(self):
        """The admin change form exposes the structured plugin config fields."""
        from django.test import RequestFactory
        from pam.admin_site import get_admin_site
        site = get_admin_site()
        admin_instance = site._registry.get(VaultEntry)
        request = RequestFactory().get('/x/')
        request.user = User.objects.create_user(
            username='adminform', password='x', is_staff=True, role='ADMIN')
        entry = make_entry()
        form = admin_instance.get_form(request, entry)
        self.assertIn('host', form.base_fields)
        self.assertIn('rotation_plugin', form.base_fields)
        self.assertIn('secret_value', form.base_fields)

    def test_admin_form_secret_value_encrypts_on_save(self):
        """The admin create form accepts a secret and encrypts it at rest."""
        from vault.forms import VaultEntryAdminForm
        form = VaultEntryAdminForm(data={
            'name': 'New-Secret', 'secret_type': 'PASSWORD',
            'max_checkout_minutes': '60',
            'encrypted_value': 'placeholder',
            'secret_value': 'hunter2',
        })
        self.assertTrue(form.is_valid(), form.errors)
        entry = form.save()
        self.assertEqual(entry.get_secret_value(), 'hunter2')
        self.assertTrue(entry.encrypted_value.startswith('gAAAA'))

    def test_admin_form_blank_secret_keeps_existing_on_edit(self):
        """Editing with a blank secret value keeps the stored secret."""
        from vault.forms import VaultEntryAdminForm
        entry = make_entry()
        form = VaultEntryAdminForm(data={
            'name': entry.name, 'description': '',
            'secret_type': 'PASSWORD', 'max_checkout_minutes': '60',
            'is_active': 'on', 'rotation_plugin': '',
            'encrypted_value': entry.encrypted_value,
        }, instance=entry)
        self.assertTrue(form.is_valid(), form.errors)
        saved = form.save()
        self.assertEqual(saved.get_secret_value(), 'initial-password')
