import dataclasses
import urllib.parse

import pytest
import responses


auth_domain = 'auth.example.com'
app_domain = 'app.example.com'
oidc_callback_path = '/auth/oidc'


@pytest.fixture
def set_env(monkeypatch):
    monkeypatch.setenv('AUTH_DOMAIN', auth_domain)
    monkeypatch.setenv('CF_DOMAIN', app_domain)
    monkeypatch.setenv('OIDC_CALLBACK_PATH', oidc_callback_path)


@pytest.fixture
def app(set_env):
    from oidc_handler import app
    return app


@dataclasses.dataclass(frozen=True)
class RequestData:
    state_param: str = 'test_state'
    code_param: str = 'test_code'
    state_cookie: str = 'test_state'
    code_verifier_cookie: str = 'test_code_verifier'
    next_path_cookie: str = '/next/path'
    send_cookies: bool = True


@pytest.fixture
def valid_request():
    return RequestData()


@pytest.fixture(params=[
    RequestData(next_path_cookie='https://evil.com'),
    RequestData(state_param=''),
    RequestData(state_param=None),
    RequestData(code_param=''),
    RequestData(code_param=None),
    RequestData(state_param='foo', state_cookie='bar'),
    RequestData(send_cookies=False),
    RequestData(state_cookie=None),
    RequestData(code_verifier_cookie=None),
    RequestData(state_cookie=''),
    RequestData(code_verifier_cookie=''),
])
def invalid_request(request):
    return request.param


def create_event(request_data):
    qsp = {}
    if request_data.code_param is not None:
        qsp['code'] = request_data.code_param
    if request_data.state_param is not None:
        qsp['state'] = request_data.state_param

    result = {
        'queryStringParameters': qsp
    }
    if request_data.send_cookies:
        cookies = []
        if request_data.state_cookie is not None:
            cookies.append(f'state={request_data.state_cookie}')
        if request_data.code_verifier_cookie is not None:
            cookies.append(
                f'code_verifier={request_data.code_verifier_cookie}'
            )
        if request_data.next_path_cookie is not None:
            cookies.append(
                'authy_next_path='
                f'{urllib.parse.quote_plus(request_data.next_path_cookie)}'
            )
        result['cookies'] = cookies
    return result


@responses.activate
def test_handle_valid_request(app, valid_request):
    responses.add(
        responses.POST,
        f'https://{auth_domain}/oauth2/token',
        json={
            'id_token': 'test_id_token',
            'refresh_token': 'test_refresh_token',
        },
        status=200
    )
    response = app.handler(create_event(valid_request), {})
    assert response == {
        'statusCode': 302,
        'headers': {
            'Location': valid_request.next_path_cookie,
            'Cache-Control': 'max-age=0, no-cache, no-store, must-revalidate, private'
        },
        'cookies': [
            'bd_auth_id_token=test_id_token; Path=/; HttpOnly; Secure',
            'bd_auth_refresh_token=test_refresh_token; Path=/; HttpOnly; '
            'Secure',
        ],
        'body': ''
    }
    assert len(responses.calls) == 1
    request = responses.calls[0].request
    assert request.url == f'https://{auth_domain}/oauth2/token'
    redirect_uri = urllib.parse.quote_plus(
        f'https://{app_domain}{oidc_callback_path}'
    )
    assert request.body == 'grant_type=authorization_code' \
        f'&redirect_uri={redirect_uri}&code={valid_request.code_param}' \
        f'&state={valid_request.state_param}' \
        f'&code_verifier={valid_request.code_verifier_cookie}'


@responses.activate
def test_invalid_request(app, invalid_request):
    event = create_event(invalid_request)
    response = app.handler(event, {})
    assert response['statusCode'] == 400
    assert len(responses.calls) == 0
