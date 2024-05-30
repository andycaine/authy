import os
from secrets import token_hex
import json
import requests
import logging
import urllib.parse

import pkce


logger = logging.getLogger()
logger.setLevel(logging.INFO)

client_id = os.environ.get('CLIENT_ID')
cf_domain = os.environ.get('CF_DOMAIN')
auth_domain = os.environ.get('AUTH_DOMAIN')
oidc_callback_path = os.environ.get('OIDC_CALLBACK_PATH')


def build_url(domain, path):
    return f"https://{domain}{path}"


oidc_callback_url = build_url(cf_domain, oidc_callback_path)
oidcEndpoint = build_url(auth_domain, '')


def generate_random_string(length):
    return token_hex(length // 2)


def parse_cookie_strings(cookie_strings):
    cookies = {}
    for pair in cookie_strings:
        key, value = pair.split('=')
        cookies[key.strip()] = value
    return cookies


def handler(event, context):
    logger.info('Event: %s', event)
    next_path = urllib.parse.unquote_plus(
        event.get('queryStringParameters', {}).get('next', '/')
    )
    # Firstly, try to get a new id_token using the refresh token
    cookie_strings = event.get('cookies', [])
    if cookie_strings:
        logger.info('Cookie found - attempting to use refresh token')
        cookies = parse_cookie_strings(cookie_strings)
        refresh_token = cookies.get('authy_refresh_token')
        if refresh_token:
            data = {
                'grant_type': 'refresh_token',
                'client_id': client_id,
                'refresh_token': refresh_token
            }
            try:
                response = requests.post(f"{oidcEndpoint}/oauth2/token",
                                         data=data)
                response.raise_for_status()
                auth_token = response.json()

                if 'id_token' not in auth_token:
                    raise ValueError("Error refreshing session - "
                                     f"no id_token: {json.dumps(auth_token)}")

                logger.info("Refreshed session silently")
                return {
                    'statusCode': 302,
                    'headers': {
                        'Location': next_path
                    },
                    'cookies': [
                        f"authy_id_token={auth_token['id_token']}; Path=/; "
                        "HttpOnly; Secure",
                    ],
                    'body': ''
                }
            except Exception as e:
                logger.error("Error refreshing session", exc_info=e)

    logger.info("No cookie found - unable to refresh session with refresh "
                "token")

    # Send a redirect to the IdP's login page, after storing state and the
    # code verifier in cookies so that they can be used to validate the
    # callback
    state = generate_random_string(32)
    code_verifier, code_challenge = pkce.generate_pkce_pair()

    redirect_url = (
        f"{oidcEndpoint}/login?client_id={client_id}"
        f"&response_type=code&state={state}&code_challenge_method=S256"
        f"&code_challenge={code_challenge}&redirect_uri={oidc_callback_url}"
    )

    return {
        'statusCode': 302,
        'headers': {
            'Location': redirect_url,
            'Cache-Control': ('max-age=0, no-cache, no-store, '
                              'must-revalidate, private')
        },
        'cookies': [
            f"state={state}; HttpOnly; Secure",
            f"code_verifier={code_verifier}; HttpOnly; Secure",
            f"authy_next_path={next_path}; HttpOnly; Secure",
        ],
        'body': ''
    }
