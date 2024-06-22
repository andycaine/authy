import os
from http.cookies import SimpleCookie
import requests
import logging
import urllib.parse

import jwt

import sessions


logger = logging.getLogger()
logger.setLevel(logging.INFO)

client_id = os.environ.get('CLIENT_ID')
cf_domain = os.environ.get('CF_DOMAIN')
auth_domain = os.environ.get('AUTH_DOMAIN')
oidc_callback_path = os.environ.get('OIDC_CALLBACK_PATH')
inactivity_timeout_mins = int(os.environ.get('SESSION_INACTIVITY_TIMEOUT_MINS'))
session_timeout = int(os.environ.get('SESSION_TIMEOUT_MINS'))
region = os.environ.get('REGION')
user_pool_id = os.environ.get('USER_POOL_ID')

keys_url = f'https://cognito-idp.{region}.amazonaws.com/{user_pool_id}' \
            '/.well-known/jwks.json'
jwks_client = jwt.PyJWKClient(keys_url)
sessiondb = sessions.Database(os.environ.get('SESSIONS_TABLE_NAME'))


def build_url(domain, path):
    return f"https://{domain}{path}"


oidc_callback_url = build_url(cf_domain, oidc_callback_path),
oidc_endpoint = build_url(auth_domain, '')


def parse_cookies(cookie_strings):
    result = {}
    for cookie_string in cookie_strings:
        cookie = SimpleCookie()
        cookie.load(cookie_string)
        result.update({key: cookie[key].value for key in cookie})
    return result


def bad_request():
    return {
        'statusCode': 400,
        'body': 'Bad Request'
    }


def http_401():
    return {
        'statusCode': 401,
        'body': ''
    }


def handler(event, context):
    code = event.get('queryStringParameters', {}).get('code')
    state = event.get('queryStringParameters', {}).get('state')

    if not code or not state:
        logger.info("CIS_AUTH_FAIL: Missing code or state parameters")
        return bad_request()

    if 'cookies' not in event:
        logger.info("CIS_AUTH_FAIL: Missing cookie header")
        return bad_request()

    cookies = parse_cookies(event['cookies'])
    if 'state' not in cookies or 'code_verifier' not in cookies:
        logger.info("CIS_AUTH_FAIL: Missing state or code_verifier cookie")
        return bad_request()

    if state != cookies['state']:
        logger.info(f"CIS_AUTH_FAIL: State mismatch: {state} vs "
                    f"{cookies['state']}")
        return bad_request()

    code_verifier = cookies['code_verifier']
    if not code_verifier:
        logger.info("CIS_AUTH_FAIL: Missing code verifier")
        return bad_request()

    next_path = urllib.parse.unquote_plus(cookies.get('authy_next_path', '/'))
    if urllib.parse.urlparse(next_path).netloc:
        # all redirects should be relative here
        logger.info('CIS_OPEN_REDIRECT_ATTEMPT_BLOCKED: '
                    f'attempt to redirect to {next_path}')
        return bad_request()

    data = {
        'grant_type': 'authorization_code',
        'client_id': client_id,
        'redirect_uri': oidc_callback_url,
        'code': code,
        'state': state,
        'code_verifier': cookies['code_verifier']
    }

    response = requests.post(f"{oidc_endpoint}/oauth2/token", data=data)

    response.raise_for_status()
    auth_token = response.json()

    id_token = auth_token['id_token']
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    try:
        claims = jwt.decode(id_token, signing_key.key, audience=client_id,
                            algorithms=["RS256"])
    except Exception as e:
        logger.info(f'Failed to decode JWT: {str(e)} - '
                    'returning unauthorised (401)')
        return http_401()

    # now we can use the claims
    logger.info(f'JWT validated with the following claims: {claims}')

    http = event['requestContext']['http']
    ip = http['sourceIp']
    ua = http['userAgent']

    session_cookie = '__Host-authy_session_id'
    session = session_cookie in cookies and \
        sessiondb.get_session(cookies[session_cookie])

    if session and not session.expired():
        logger.info('Found active session')
        sessiondb.mark_reauthenticated_and_extend(
            session,
            by_mins=inactivity_timeout_mins,
            up_to_mins=session_timeout
        )
    else:
        logger.info('No active session found - creating a new one')
        session = sessiondb.create_session(
            email=claims['email'],
            groups=claims.get('cognito:groups', []),
            name=claims.get('name', ''),
            ip=ip,
            user_agent=ua,
            duration_in_mins=inactivity_timeout_mins
        )

    return {
        'statusCode': 302,
        'headers': {
            'Location': next_path,
            'Cache-Control': ('max-age=0, no-cache, no-store, '
                              'must-revalidate, private')

        },
        'cookies': [
            f"__Host-authy_session_id={session.session_id}; Path=/; "
            "HttpOnly; Secure"
        ],
        'body': ''
    }
