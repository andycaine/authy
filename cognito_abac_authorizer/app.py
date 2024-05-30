import os
import json
import time
import urllib.request
import logging

from jose import jwk, jwt
from jose.utils import base64url_decode

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

# instead of re-downloading the public keys every time
# we download them only on cold start
# https://aws.amazon.com/blogs/compute/container-reuse-in-lambda/
with urllib.request.urlopen(keys_url) as f:
    response = f.read()
keys = json.loads(response.decode('utf-8'))['keys']


def get_id_token(event):
    cookie_strings = event.get('cookies', [])
    cookies = {k: v for k, v in (s.split('=') for s in cookie_strings)}
    return cookies.get('bd_auth_id_token', None)


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

    # get the kid from the headers prior to verification
    headers = jwt.get_unverified_headers(id_token)
    kid = headers['kid']

    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        logger.info('Public key not found in jwks.json - unauthorised (401)')
        raise Exception('Unauthorized')  # Return a 401 Unauthorized response

    # construct the public key
    public_key = jwk.construct(keys[key_index])

    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(id_token).rsplit('.', 1)

    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        logger.info('Signature verification failed - unauthorised (401)')
        raise Exception('Unauthorized')  # Return a 401 Unauthorized response

    logger.info('Signature successfully verified')

    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(id_token)

    # additionally we can verify the token expiration
    if time.time() > claims['exp']:
        logger.info('Token is expired - unauthorised (401)')
        raise Exception('Unauthorized')  # Return a 401 Unauthorized response
    # and the Audience  (use claims['client_id'] if verifying an access token)
    if claims['aud'] != client_id:
        logger.info('Token was not issued for this audience - unauthorised')
        return response

    # now we can use the claims
    logger.info(f'JWT validated with the following claims: {claims}')

    logger.info(f"Validated ID token for {claims['email']}")

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
