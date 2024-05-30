import os
import datetime
import logging

logger = logging.getLogger()

logout_path = os.environ.get('LOGOUT_PATH')
client_id = os.environ.get('CLIENT_ID')
cf_domain = os.environ.get('CF_DOMAIN')
auth_domain = os.environ.get('AUTH_DOMAIN')


def generate_delete_cookie(name):
    expiry_date = datetime.datetime(1970, 1, 1)
    expires_str = expiry_date.strftime('%a, %d %b %Y %H:%M:%S GMT')
    return f"{name}=deleted; Path=/; HttpOnly; Secure; expires={expires_str}"


def build_url(domain, path):
    return f"https://{domain}{path}"


logout_uri = build_url(cf_domain, logout_path)
oidc_endpoint = build_url(auth_domain, '')


def handler(event, context):

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
            generate_delete_cookie('authy_id_token'),
            generate_delete_cookie('authy_refresh_token')
        ],
        'body': ''
    }
