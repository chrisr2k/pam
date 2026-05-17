import logging
from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


def provision_access_sync(request_id: int):
    """
    Synchronous version of provision_access for when Celery is not available.
    Schedules deprovisioning via Celery ETA for reliability.
    """
    from access_requests.models import AccessRequest
    from providers.aws_identity_center import AWSIdentityCenterProvider
    from providers.entra_pim import EntraPIMProvider

    try:
        access_request = AccessRequest.objects.select_related('requester', 'role').get(id=request_id)
    except AccessRequest.DoesNotExist:
        logger.error(f'AccessRequest {request_id} not found')
        return

    if access_request.status != AccessRequest.Status.APPROVED:
        logger.warning(f'Request {request_id} is not in APPROVED state (current: {access_request.status})')
        return

    # Update status to provisioning
    access_request.status = AccessRequest.Status.PROVISIONING
    access_request.save(update_fields=['status'])

    role = access_request.role
    user = access_request.requester
    entra_oid = user.entra_object_id

    if not entra_oid:
        logger.error(f'User {user.id} has no Entra ID object ID')
        access_request.mark_failed()
        return

    try:
        if role.provider == 'AWS':
            provider = AWSIdentityCenterProvider()
            role_config = {
                'permission_set_arn': role.aws_permission_set_arn,
                'account_id': role.aws_account_id,
            }
        elif role.provider == 'ENTRA':
            provider = EntraPIMProvider()
            role_config = {
                'role_id': role.entra_role_id,
                'justification': access_request.justification,
            }
        else:
            logger.error(f'Unknown provider: {role.provider}')
            access_request.mark_failed()
            return

        result = provider.provision_access(
            user_entra_oid=entra_oid,
            role_config=role_config,
            duration_minutes=access_request.requested_duration_minutes,
        )

        if result.get('success'):
            access_request.mark_provisioned(provider_ref=result.get('reference_id', ''))
            logger.info(f'Successfully provisioned access for request {request_id}')

            # Send notification
            from notifications.services import send_notification
            send_notification(
                access_request,
                'access_provisioned',
                recipients=[access_request.requester.email],
            )

            # Schedule deprovisioning via Celery ETA for reliability.
            # Falls back to the periodic check_expired_sessions task if Celery is down.
            expires_at = access_request.expires_at
            if expires_at:
                try:
                    schedule_deprovision.apply_async(
                        args=[request_id],
                        eta=expires_at,
                    )
                    logger.info(f'Scheduled deprovisioning for request {request_id} at {expires_at}')
                except Exception:
                    logger.exception(
                        f'Failed to schedule Celery deprovision for request {request_id}, '
                        f'will rely on periodic check_expired_sessions task'
                    )
        else:
            logger.error(f'Provisioning failed for request {request_id}: {result.get("error")}')
            access_request.mark_failed()

    except Exception as e:
        logger.exception(f'Unexpected error provisioning request {request_id}: {e}')
        access_request.mark_failed()



def deprovision_access_sync(request_id: int):
    """
    Synchronous version of deprovision_access for when Celery is not available.
    """
    from access_requests.models import AccessRequest
    from providers.aws_identity_center import AWSIdentityCenterProvider
    from providers.entra_pim import EntraPIMProvider

    try:
        access_request = AccessRequest.objects.select_related('role').get(id=request_id)
    except AccessRequest.DoesNotExist:
        logger.error(f'AccessRequest {request_id} not found')
        return

    if access_request.status not in (AccessRequest.Status.PROVISIONED, AccessRequest.Status.ACTIVE):
        logger.warning(f'Request {request_id} is not provisioned/active (current: {access_request.status})')
        return

    role = access_request.role
    reference_id = access_request.provider_reference_id

    if not reference_id:
        logger.warning(f'No provider reference ID for request {request_id}')
        access_request.mark_expired()
        return

    try:
        if role.provider == 'AWS':
            provider = AWSIdentityCenterProvider()
        elif role.provider == 'ENTRA':
            provider = EntraPIMProvider()
        else:
            logger.error(f'Unknown provider: {role.provider}')
            return

        success = provider.deprovision_access(reference_id)
        if success:
            access_request.mark_expired()
            logger.info(f'Successfully deprovisioned access for request {request_id}')
        else:
            logger.error(f'Deprovisioning failed for request {request_id}')

    except Exception as e:
        logger.exception(f'Unexpected error deprovisioning request {request_id}: {e}')



@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def provision_access(self, request_id: int):
    """
    Provision privileged access for an approved request.
    This task is called after an approver approves a request.
    """
    from access_requests.models import AccessRequest
    from providers.aws_identity_center import AWSIdentityCenterProvider
    from providers.entra_pim import EntraPIMProvider

    try:
        access_request = AccessRequest.objects.select_related('requester', 'role').get(id=request_id)
    except AccessRequest.DoesNotExist:
        logger.error(f'AccessRequest {request_id} not found')
        return

    if access_request.status != AccessRequest.Status.APPROVED:
        logger.warning(f'Request {request_id} is not in APPROVED state (current: {access_request.status})')
        return

    # Update status to provisioning
    access_request.status = AccessRequest.Status.PROVISIONING
    access_request.save(update_fields=['status'])

    role = access_request.role
    user = access_request.requester
    entra_oid = user.entra_object_id

    if not entra_oid:
        logger.error(f'User {user.id} has no Entra ID object ID')
        access_request.mark_failed()
        return

    try:
        if role.provider == 'AWS':
            provider = AWSIdentityCenterProvider()
            role_config = {
                'permission_set_arn': role.aws_permission_set_arn,
                'account_id': role.aws_account_id,
            }
        elif role.provider == 'ENTRA':
            provider = EntraPIMProvider()
            role_config = {
                'role_id': role.entra_role_id,
                'justification': access_request.justification,
            }
        else:
            logger.error(f'Unknown provider: {role.provider}')
            access_request.mark_failed()
            return

        result = provider.provision_access(
            user_entra_oid=entra_oid,
            role_config=role_config,
            duration_minutes=access_request.requested_duration_minutes,
        )

        if result.get('success'):
            access_request.mark_provisioned(provider_ref=result.get('reference_id', ''))
            logger.info(f'Successfully provisioned access for request {request_id}')

            # Schedule deprovisioning
            schedule_deprovision.apply_async(
                args=[request_id],
                eta=access_request.expires_at,
            )
        else:
            logger.error(f'Provisioning failed for request {request_id}: {result.get("error")}')
            access_request.mark_failed()

    except Exception as e:
        logger.exception(f'Unexpected error provisioning request {request_id}: {e}')
        access_request.mark_failed()


@shared_task
def deprovision_access(request_id: int):
    """
    Deprovision privileged access for an expired/revoked request.
    """
    from access_requests.models import AccessRequest
    from providers.aws_identity_center import AWSIdentityCenterProvider
    from providers.entra_pim import EntraPIMProvider

    try:
        access_request = AccessRequest.objects.select_related('role').get(id=request_id)
    except AccessRequest.DoesNotExist:
        logger.error(f'AccessRequest {request_id} not found')
        return

    if access_request.status not in (AccessRequest.Status.PROVISIONED, AccessRequest.Status.ACTIVE):
        logger.warning(f'Request {request_id} is not provisioned/active (current: {access_request.status})')
        return

    role = access_request.role
    reference_id = access_request.provider_reference_id

    if not reference_id:
        logger.warning(f'No provider reference ID for request {request_id}')
        access_request.mark_expired()
        return

    try:
        if role.provider == 'AWS':
            provider = AWSIdentityCenterProvider()
        elif role.provider == 'ENTRA':
            provider = EntraPIMProvider()
        else:
            logger.error(f'Unknown provider: {role.provider}')
            return

        success = provider.deprovision_access(reference_id)
        if success:
            access_request.mark_expired()
            logger.info(f'Successfully deprovisioned access for request {request_id}')
        else:
            logger.error(f'Deprovisioning failed for request {request_id}')

    except Exception as e:
        logger.exception(f'Unexpected error deprovisioning request {request_id}: {e}')


@shared_task
def schedule_deprovision(request_id: int):
    """
    Scheduled task to deprovision access when it expires.
    This is called by the ETA-based scheduling from provision_access.
    """
    deprovision_access.delay(request_id)


@shared_task
def check_expired_sessions():
    """
    Periodic task to check for and deprovision any expired sessions.
    Runs via celery beat every 5 minutes.
    """
    from access_requests.models import AccessRequest

    now = timezone.now()
    expired_requests = AccessRequest.objects.filter(
        status__in=[AccessRequest.Status.PROVISIONED, AccessRequest.Status.ACTIVE],
        expires_at__lte=now,
    )

    for req in expired_requests:
        logger.info(f'Found expired request {req.id}, deprovisioning...')
        deprovision_access.delay(req.id)
