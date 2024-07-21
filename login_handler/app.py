import os
import logging
import urllib.parse

import vocab
import httplambda
import s256

vocab.configure(context_fn=httplambda.logging_context)
logger = logging.getLogger('authy.login_handler')

client_id = os.environ['CLIENT_ID']
cf_domain = os.environ['CF_DOMAIN']
auth_domain = os.environ['AUTH_DOMAIN']
oidc_callback_path = os.environ['OIDC_CALLBACK_PATH']


def build_url(domain, path):
    return f"https://{domain}{path}"


oidc_callback_url = urllib.parse.quote_plus(build_url(cf_domain,
                                                      oidc_callback_path))
oidcEndpoint = build_url(auth_domain, '')


@httplambda.route
def handler(request):
    next_path = urllib.parse.unquote_plus(
        request.args.get('next', '/')
    )
    if urllib.parse.urlparse(next_path).netloc:
        # all redirects should be relative here
        logger.malicious_redirect_attempt('anonymous', next_path)
        return httplambda.bad_request()

    # Send a redirect to the IdP's login page, after storing state and the
    # code verifier in cookies so that they can be used to validate the
    # callback
    state, state_sha256 = s256.pair()
    code_verifier, code_challenge = s256.pair()

    redirect_url = (
        f"{oidcEndpoint}/login?client_id={client_id}"
        f"&response_type=code&state={state_sha256}&code_challenge_method=S256"
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
