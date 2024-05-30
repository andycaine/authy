import os
from http.cookies import SimpleCookie
import requests
import logging
import urllib.parse

logger = logging.getLogger()
logger.setLevel(logging.INFO)

client_id = os.environ.get('CLIENT_ID')
cf_domain = os.environ.get('CF_DOMAIN')
auth_domain = os.environ.get('AUTH_DOMAIN')
oidc_callback_path = os.environ.get('OIDC_CALLBACK_PATH')


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
        logger.info("CIS_AUTH_FAIL: Missing state or codeVerifier cookie")
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

    return {
        'statusCode': 302,
        'headers': {
            'Location': next_path,
            'Cache-Control': ('max-age=0, no-cache, no-store, '
                              'must-revalidate, private')

        },
        'cookies': [
            f"authy_id_token={auth_token['id_token']}; "
            "Path=/; HttpOnly; Secure",
            f"authy_refresh_token={auth_token['refresh_token']}; "
            "Path=/; HttpOnly; Secure",
        ],
        'body': ''
    }
