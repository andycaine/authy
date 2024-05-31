import os
import logging

import jwt

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
region = os.environ['REGION']
user_pool_id = os.environ['USER_POOL_ID']
client_id = os.environ['USER_POOL_CLIENT_ID']
keys_url = f'https://cognito-idp.{region}.amazonaws.com/{user_pool_id}' \
            '/.well-known/jwks.json'
jwks_client = jwt.PyJWKClient(keys_url)


def get_id_token(event):
    cookie_strings = event.get('cookies', [])
    cookies = {k: v for k, v in (s.split('=') for s in cookie_strings)}
    return cookies.get('authy_id_token', None)


def get_origin_key_header(event):
    return event.get('headers', {}).get('x-custom-origin-key', '')


def handler(event, context):
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

    id_token = get_id_token(event)
    if not id_token:
        logger.info('No ID token - unauthorised (401)')
        raise Exception('Unauthorized')  # Return a 401 Unauthorized response

    signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    claims = jwt.decode(id_token, signing_key.key, audience=client_id,
                        algorithms=["RS256"])

    # now we can use the claims
    logger.info(f'JWT validated with the following claims: {claims}')

    id_attrs = dict(
        user=claims['email'],
        groups=claims.get('cognito:groups', []),
        name=claims.get('name', ''),
    )
    is_authz, _ = _authoriser(event, id_attrs)

    response.update({
        'isAuthorized': is_authz,
        'context': id_attrs
    })
    return response
