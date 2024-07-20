import unittest
import urllib.parse

import pytest


@pytest.fixture
def envvars(monkeypatch, sessions_table_name):
    monkeypatch.setenv('CLIENT_ID', 'test_client_id')
    monkeypatch.setenv('CF_DOMAIN', 'admin.test.com')
    monkeypatch.setenv('AUTH_DOMAIN', 'auth.test.com')
    monkeypatch.setenv('OIDC_CALLBACK_PATH', '/auth/oidc')


@pytest.fixture
def app(envvars, sessiondb, mock_token_bytes):
    from login_handler import app
    yield app


@pytest.fixture
def request_with_active_session_id(active_session):
    return {
        'cookies': [f'__Host-authy_session_id={active_session.session_id}']
    }


@pytest.fixture
def request_with_no_cookies():
    return {}


@pytest.fixture
def request_with_invalid_session_id():
    return {
        'cookies': ['__Host-authy_session_id=xyz']
    }


@pytest.fixture
def mock_pkce():
    with unittest.mock.patch('pkce.generate_pkce_pair') as mock:
        mock.return_value = ('code_verifier', 'code_challenge')
        yield mock


@pytest.fixture
def state_bytes():
    return (b'I\xbdA\x9e\xea\x91\x94\xaaG]\x83\x18\xf5\xae\xee.\xd3\xdda\xc0'
            b'w\xe7\xc0\x82\xd4\xa6\x87\x1e\xc0p\xd2I')


@pytest.fixture
def state():
    return '49bd419eea9194aa475d8318f5aeee2ed3dd61c077e7c082d4a6871ec070d249'


@pytest.fixture
def state_hash():
    return '3fe24d16472fbb9893910479522a5a4eac0b593ae84c8e40b8afdee278039563'


@pytest.fixture
def mock_token_bytes(state_bytes):
    with unittest.mock.patch('secrets.token_bytes') as mock:
        mock.return_value = state_bytes
        yield mock


def assert_login_redirect(response, next_path, code_verifier, state,
                          code_challenge, state_hash):
    assert response == {
        'statusCode': 302,
        'headers': {
            'Location': (
                'https://auth.test.com/login?client_id=test_client_id'
                f'&response_type=code&state={state_hash}'
                '&code_challenge_method=S256'
                f'&code_challenge={code_challenge}'
                '&redirect_uri=https%3A%2F%2Fadmin.test.com%2Fauth%2Foidc'),
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


def test_login(app, mock_pkce, state, state_hash):
    code_verifier, code_challenge = mock_pkce()
    next_path = '/'
    response = app.handler({}, {})
    assert_login_redirect(response, next_path, code_verifier, state,
                          code_challenge, state_hash)


def test_login_with_next_path(app, mock_pkce, state, state_hash):
    code_verifier, code_challenge = mock_pkce()
    next_path = '/admin/'
    response = app.handler({
        'queryStringParameters': {'next': urllib.parse.quote_plus(next_path)}},
        {}
    )
    assert_login_redirect(response, next_path, code_verifier, state,
                          code_challenge, state_hash)


def test_login_with_evil_next_path(app):
    next_path = 'https://evil.com'
    response = app.handler({
        'queryStringParameters': {'next': urllib.parse.quote_plus(next_path)}},
        {}
    )
    assert response == {
        'statusCode': 400,
        'body': 'Bad Request'
    }
