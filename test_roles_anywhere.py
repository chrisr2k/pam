"""Test script to verify Roles Anywhere connection."""
import os
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pam.settings')

import django
django.setup()

from providers.aws_identity_center import AWSIdentityCenterProvider

provider = AWSIdentityCenterProvider()

session = provider._get_roles_anywhere_session('us-east-1')

if session:
    sts = session.client('sts')
    identity = sts.get_caller_identity()
    print(f'Success! Identity: {identity["Arn"]}')
else:
    print('Failed to get session')
    sys.exit(1)
