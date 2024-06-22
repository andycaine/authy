import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def check_authz(event, session):
    if 'Admins' in session.groups:
        return True, {}

    http = event['requestContext']['http']
    path = http['path']

    if 'BlogAdmins' in session.groups:
        if path.startswith('/blog/'):
            return True, {}

    logger.info('No rules matched, access denied')
    return False, {}
