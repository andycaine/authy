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
def app(envvars, sessiondb):
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
def mock_token_hex():
    with unittest.mock.patch('secrets.token_hex') as mock:
        mock.return_value = 'test_token_hex'
        yield mock


def assert_login_redirect(response, next_path, code_verifier, state,
                          code_challenge):
    assert response == {
        'statusCode': 302,
        'headers': {
            'Location': (
                'https://auth.test.com/login?client_id=test_client_id'
                f'&response_type=code&state={state}&code_challenge_method=S256'
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


def test_login(app, mock_pkce, mock_token_hex):
    state = mock_token_hex()
    code_verifier, code_challenge = mock_pkce()
    next_path = '/'
    response = app.handler({}, {})
    assert_login_redirect(response, next_path, code_verifier, state,
                          code_challenge)


def test_login_with_next_path(app, mock_pkce, mock_token_hex):
    state = mock_token_hex()
    code_verifier, code_challenge = mock_pkce()
    next_path = '/admin/'
    response = app.handler({
        'queryStringParameters': {'next': urllib.parse.quote_plus(next_path)}},
        {}
    )
    assert_login_redirect(response, next_path, code_verifier, state,
                          code_challenge)


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
