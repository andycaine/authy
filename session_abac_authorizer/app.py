import logging
import os
import re

import sessions

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def denyall_authz(*_):
    return False, {}


_authoriser = denyall_authz

try:
    import pdp
    _authoriser = pdp.check_authz
except ImportError:
    logger.info('pdp module not found - all requests will be unauthorised')

origin_key = os.environ.get('CUSTOM_ORIGIN_KEY', None)
inactivity_timeout_mins = int(os.environ['SESSION_INACTIVITY_TIMEOUT_MINS'])
session_timeout = int(os.environ['SESSION_TIMEOUT_MINS'])
sessionsdb = sessions.Database(os.environ['SESSIONS_TABLE_NAME'])


def get_session_id(event):
    cookie_strings = event.get('cookies', [])
    cookies = {k: v for k, v in (s.split('=') for s in cookie_strings)}
    return cookies.get('__Host-authy_session_id', None)


def get_origin_key_header(event):
    return event.get('headers', {}).get('x-custom-origin-key', '')


def raise_401():
    raise Exception('Unauthorized')  # Return a 401 Unauthorized response


def handler(event, _):
    response = {
        'isAuthorized': False,
        'context': {}
    }

    origin_key_value = get_origin_key_header(event)
    if not origin_key:
        logger.warning('No Origin Key configured - unable to enforce access '
                       'via CloudFront')
    elif origin_key_value != origin_key:
        logger.info(f'Invalid Origin Key - unauthorised: <{origin_key_value}>')
        return response

    session_id = get_session_id(event)
    if not session_id:
        logger.info('No session cookie - unauthorised (401)')
        raise_401()

    if not re.match(r'^[a-f0-9]{64}+$', session_id):
        logger.info('Invalid session ID - unauthorised (401)')
        raise_401()

    session = sessionsdb.get_session(session_id)
    if not session:
        logger.info('No session - unauthorised (401)')
        raise_401()

    if session.expired():
        logger.info('Session expired - unauthorised (401)')
        raise_401()

    sessionsdb.extend_session(session,
                              by_mins=inactivity_timeout_mins,
                              up_to_mins=session_timeout)

    logger.info('Active session found')

    is_authz, _ = _authoriser(event, session)
    logger.info(f'Authorisation check returned {is_authz}')

    response.update({
        'isAuthorized': is_authz,
        'context': dict(
            email=session.email,
            groups=session.groups,
            name=session.name
        )
    })
    return response
