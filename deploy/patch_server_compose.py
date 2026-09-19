#!/usr/bin/env python3
"""Idempotent patcher for the deployed PAM docker-compose.yml (OCI server).

Replaces the celery_beat command with a wait-for-migrations loop so beat no
longer races the web container's `migrate` on stack restarts (it previously
crashed with "relation django_celery_beat_crontabschedule does not exist").

The server compose has local customizations (port 8090, AWS Roles Anywhere
cert mounts) that must be preserved, so this patches one line surgically
instead of overwriting the file. Safe to run repeatedly.

Usage (run on the server, from /opt/pam):
    sudo python3 - < deploy/patch_server_compose.py
"""

import shutil
import sys
import time
from pathlib import Path

COMPOSE_PATH = Path('/opt/pam/docker-compose.yml')

OLD_COMMAND = (
    'command: celery -A pam beat -l info '
    '--scheduler django_celery_beat.schedulers:DatabaseScheduler'
)
NEW_COMMAND = (
    'command: sh -c "until python manage.py migrate --check; '
    "do echo 'waiting for migrations...'; sleep 5; done && "
    'celery -A pam beat -l info '
    '--scheduler django_celery_beat.schedulers:DatabaseScheduler"'
)


def main():
    text = COMPOSE_PATH.read_text(encoding='utf-8')
    count = text.count(OLD_COMMAND)
    if count == 0:
        print('Already patched (old command not found) - nothing to do.')
        return 0
    if count > 1:
        print(f'ERROR: found {count} occurrences of the old command; aborting.', file=sys.stderr)
        return 1

    backup = COMPOSE_PATH.with_name(
        f'docker-compose.yml.bak-beatfix-{time.strftime("%Y%m%d%H%M%S")}')
    shutil.copy2(COMPOSE_PATH, backup)
    print(f'Backup written to {backup.name}')

    text = text.replace(OLD_COMMAND, NEW_COMMAND)
    COMPOSE_PATH.write_text(text, encoding='utf-8')
    print('Patched celery_beat command:')
    for line in text.splitlines():
        if 'command:' in line and 'beat' in line or 'migrate --check' in line:
            print(f'  {line.strip()}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
