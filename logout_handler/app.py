import os
import datetime
import logging
import urllib.parse
import re

import sessions

logger = logging.getLogger()

logout_path = os.environ.get('LOGOUT_PATH')
client_id = os.environ.get('CLIENT_ID')
cf_domain = os.environ.get('CF_DOMAIN')
auth_domain = os.environ.get('AUTH_DOMAIN')

sessiondb = sessions.Database(os.environ.get('SESSIONS_TABLE_NAME'))


def generate_delete_cookie(name):
    expiry_date = datetime.datetime(1970, 1, 1)
    expires_str = expiry_date.strftime('%a, %d %b %Y %H:%M:%S GMT')
    return f"{name}=deleted; Path=/; HttpOnly; Secure; expires={expires_str}"


def build_url(domain, path):
    return f"https://{domain}{path}"


logout_uri = urllib.parse.quote_plus(build_url(cf_domain, logout_path))
oidc_endpoint = build_url(auth_domain, '')


def get_session_id(event):
    cookie_strings = event.get('cookies', [])
    cookies = {k: v for k, v in (s.split('=') for s in cookie_strings)}
    session_id = cookies.get('__Host-authy_session_id', '')
    return re.match(r'^[a-f0-9]{64}+$', session_id) and session_id or None


def handler(event, context):
    session_id = get_session_id(event)
    if session_id:
        sessiondb.delete_session(session_id)

    redirect_url = (
        f"{oidc_endpoint}/logout?client_id={client_id}"
        f"&logout_uri={logout_uri}"
    )

    return {
        'statusCode': 302,
        'headers': {
            'Location': redirect_url
        },
        'cookies': [
            generate_delete_cookie('__Host-authy_session_id')
        ],
        'body': ''
    }
