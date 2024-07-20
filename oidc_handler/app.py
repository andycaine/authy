import hashlib
import os
from http.cookies import SimpleCookie
import requests
import re
import logging
import urllib.parse

import jwt

import sessions
import httplambda
import vocab


vocab.configure(context_fn=httplambda.logging_context)
logger = logging.getLogger('authy.oidc_handler')


client_id = os.environ.get('CLIENT_ID')
cf_domain = os.environ.get('CF_DOMAIN')
auth_domain = os.environ.get('AUTH_DOMAIN')
oidc_callback_path = os.environ.get('OIDC_CALLBACK_PATH')
inactivity_timeout_mins = int(os.environ.get(
    'SESSION_INACTIVITY_TIMEOUT_MINS'
))
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


#def parse_cookies(cookie_strings):
#    result = {}
#    for cookie_string in cookie_strings:
#        cookie = SimpleCookie()
#        cookie.load(cookie_string)
#        result.update({key: cookie[key].value for key in cookie})
#    return result


def _decode(token):
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    try:
        claims = jwt.decode(token, signing_key.key, audience=client_id,
                            algorithms=["RS256"],
                            options={'require': ['email']})
        return claims
    except jwt.exceptions.InvalidSignatureError:
        logger.authn_oidc_flow_invalid_signature()
    except jwt.exceptions.ExpiredSignatureError:
        logger.authn_oidc_flow_expired_signature()
    except jwt.exceptions.InvalidAudienceError:
        logger.authn_oidc_flow_invalid_audience()
    except jwt.exceptions.InvalidIssuerError:
        logger.authn_oidc_flow_invalid_issuer()
    except jwt.exceptions.InvalidIssuedAtError:
        logger.authn_oidc_flow_invalid_issued_at()
    except jwt.exceptions.ImmatureSignatureError:
        logger.authn_oidc_flow_immature_signature()
    except jwt.exceptions.MissingRequiredClaimError:
        logger.authn_oidc_flow_missing_required_claim()
    except jwt.exceptions.InvalidKeyError:
        logger.authn_oidc_flow_invalid_signing_key()
    except jwt.exceptions.DecodeError:
        logger.authn_oidc_flow_invalid_token()
    except jwt.exceptions.InvalidTokenError:
        logger.authn_oidc_flow_invalid_token()
    return None


@httplambda.route
def handler(request):
    state_param = request.args.get('state', '')

    if not re.match(r'^[0-9a-f]{64}$', state_param):
        logger.authn_oidc_flow_invalid_state('param', state_param)
        return httplambda.bad_request()

    cookies = request.cookies
    state_cookie = cookies.get('state', '')

    if not re.match(r'^[0-9a-f]{64}$', state_cookie):
        logger.authn_oidc_flow_invalid_state('cookie', state_param)
        return httplambda.bad_request()

    if hashlib.sha256(bytes.fromhex(state_cookie)).hexdigest() != state_param:
        logger.authn_oidc_flow_incorrect_state(state_param)
        return httplambda.bad_request()

    code_param = request.args.get('code', '')
    if not code_param:
        logger.authn_oidc_flow_missing_code_param()
        return httplambda.bad_request()

    code_verifier = cookies.get('code_verifier')
    if not code_verifier:
        logger.authn_oidc_flow_missing_code_verifer_cookie()
        return httplambda.bad_request()

    next_path = urllib.parse.unquote_plus(cookies.get('authy_next_path', '/'))
    if urllib.parse.urlparse(next_path).netloc:
        # all redirects should be relative here
        logger.malicious_redirect_attempt('anonymous', next_path)
        return httplambda.bad_request()

    data = {
        'grant_type': 'authorization_code',
        'client_id': client_id,
        'redirect_uri': oidc_callback_url,
        'code': code_param,
        'state': state_param,
        'code_verifier': cookies['code_verifier']
    }

    response = requests.post(f"{oidc_endpoint}/oauth2/token", data=data)

    response.raise_for_status()
    auth_token = response.json()

    id_token = auth_token['id_token']
    claims = _decode(id_token)

    if not claims:  # unable to parse token, return unauthorised
        return httplambda.http_401()

    username = claims['email']  # we checked email exists when we decoded

    session_cookie = '__Host-authy_session_id'
    session = session_cookie in cookies and \
        sessiondb.get_session(cookies[session_cookie])

    if session and not session.expired():
        # Step up auth scenario - user already authenticated but we want them
        # to re-authenticate before performing a sensitive operation.
        logger.authn_reauth_success(username)
        sessiondb.mark_reauthenticated_and_extend(
            session,
            by_mins=inactivity_timeout_mins,
            up_to_mins=session_timeout
        )
    else:
        logger.authn_login_success(username)
        session = sessiondb.create_session(
            username=username,
            groups=claims.get('cognito:groups', []),
            name=claims.get('name', ''),
            ip=request.remote_addr,
            user_agent=request.user_agent,
            duration_in_mins=inactivity_timeout_mins
        )
        logger.session_created(username)

    return httplambda.redirect(
        next_path,
        cookies=[httplambda.session_cookie('__Host-authy_session_id',
                                           session.session_id)],
        headers={
            'Cache-Control': ('max-age=0, no-cache, no-store, must-revalidate,'
                              ' private')
        }
    )
