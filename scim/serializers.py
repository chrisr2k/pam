"""SCIM v2 JSON serialization for users."""

USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User'
LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse'


def user_to_scim(user) -> dict:
    """Serialize a PAM user into a SCIM v2 User resource."""
    full_name = user.get_full_name() or user.username
    emails = []
    if user.email:
        emails.append({'value': user.email, 'primary': True})
    return {
        'schemas': [USER_SCHEMA],
        'id': str(user.pk),
        'externalId': user.entra_object_id,
        'userName': user.username,
        'name': {
            'formatted': full_name,
            'givenName': user.first_name,
            'familyName': user.last_name,
        },
        'displayName': full_name,
        'emails': emails,
        'active': user.is_active,
        'meta': {
            'resourceType': 'User',
            'created': user.date_joined.isoformat(),
        },
    }
