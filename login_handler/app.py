import os
import secrets
import logging
import urllib.parse

import pkce


logger = logging.getLogger()
logger.setLevel(logging.INFO)

client_id = os.environ['CLIENT_ID']
cf_domain = os.environ['CF_DOMAIN']
auth_domain = os.environ['AUTH_DOMAIN']
oidc_callback_path = os.environ['OIDC_CALLBACK_PATH']


def build_url(domain, path):
    return f"https://{domain}{path}"


oidc_callback_url = urllib.parse.quote_plus(build_url(cf_domain,
                                                      oidc_callback_path))
oidcEndpoint = build_url(auth_domain, '')


def generate_random_string(length):
    return secrets.token_hex(length // 2)


def bad_request():
    return {
        'statusCode': 400,
        'body': 'Bad Request'
    }


def handler(event, context):
    next_path = urllib.parse.unquote_plus(
        event.get('queryStringParameters', {}).get('next', '/')
    )
    if urllib.parse.urlparse(next_path).netloc:
        # all redirects should be relative here
        logger.info('CIS_OPEN_REDIRECT_ATTEMPT_BLOCKED: '
                    f'attempt to redirect to {next_path}')
        return bad_request()

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
