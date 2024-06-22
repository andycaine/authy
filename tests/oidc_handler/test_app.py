from unittest.mock import patch, MagicMock
import datetime
import contextlib
import os
import urllib.parse
import json

import pytest
import responses
import jwt


auth_domain = 'auth.example.com'
app_domain = 'app.example.com'
oidc_callback_path = '/auth/oidc'
session_inactivity_timeout_mins = '15'
region = 'eu-west-2'
user_pool_id = 'eu-west-2_2dIWFAizy'
client_id = '2vh0abc7eh343nq67v2alno0k7'


@pytest.fixture
def set_env(monkeypatch, sessions_table_name):
    monkeypatch.setenv('AUTH_DOMAIN', auth_domain)
    monkeypatch.setenv('CF_DOMAIN', app_domain)
    monkeypatch.setenv('OIDC_CALLBACK_PATH', oidc_callback_path)
    monkeypatch.setenv('SESSION_INACTIVITY_TIMEOUT_MINS',
                       session_inactivity_timeout_mins)
    monkeypatch.setenv('SESSION_TIMEOUT_MINS', '60')
    monkeypatch.setenv('REGION', region)
    monkeypatch.setenv('USER_POOL_ID', user_pool_id)
    monkeypatch.setenv('CLIENT_ID', client_id)
    monkeypatch.setenv('SESSIONS_TABLE_NAME', sessions_table_name)


@pytest.fixture
def token_responses(id_token):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.POST,
            f'https://{auth_domain}/oauth2/token',
            json={
                'id_token': id_token,
                'refresh_token': 'test_refresh_token',
            },
            status=200
        )
        yield rsps


@pytest.fixture
def app(set_env, mock_urlopen, sessiondb):
    from oidc_handler import app
    yield app


@pytest.fixture
def open_redirect():
    yield {
        'queryStringParameters': {
            'state': 'test_state',
            'code': 'test_code'
        },
        'cookies': [
            'state=test_state',
            'code_verifier=test_code_verifier',
            'authy_next_path=https%3A%2F%2Fevil.com'
        ]
    }


@pytest.fixture
def empty_state_param():
    yield {
        'queryStringParameters': {
            'state': '',
            'code': 'test_code'
        },
        'cookies': [
            'state=test_state',
            'code_verifier=test_code_verifier',
            'authy_next_path=%2Fnext%2Fpath'
        ]
    }


@pytest.fixture
def missing_state_param():
    yield {
        'queryStringParameters': {
            'code': 'test_code'
        },
        'cookies': [
            'state=test_state',
            'code_verifier=test_code_verifier',
            'authy_next_path=%2Fnext%2Fpath'
        ]
    }


@pytest.fixture
def valid_request_event():
    yield {
        'queryStringParameters': {
            'state': 'test_state',
            'code': 'test_code'
        },
        'cookies': [
            'state=test_state',
            'code_verifier=test_code_verifier',
            'authy_next_path=%2Fnext%2Fpath'
        ],
        'requestContext': {
            'http': {
                'sourceIp': '127.0.0.1',
                'userAgent': 'unittest',
                'method': 'GET',
                'path': '/test/path'
            }
        }
    }


@pytest.fixture
def valid_request_event_with_session(active_session):
    yield {
        'queryStringParameters': {
            'state': 'test_state',
            'code': 'test_code'
        },
        'cookies': [
            'state=test_state',
            'code_verifier=test_code_verifier',
            'authy_next_path=%2Fnext%2Fpath',
            f'__Host-authy_session_id={active_session.session_id}'
        ],
        'requestContext': {
            'http': {
                'sourceIp': '127.0.0.1',
                'userAgent': 'unittest',
                'method': 'GET',
                'path': '/test/path'
            }
        }
    }


@pytest.fixture
def valid_request_event_with_expired_session(expired_session):
    yield {
        'queryStringParameters': {
            'state': 'test_state',
            'code': 'test_code'
        },
        'cookies': [
            'state=test_state',
            'code_verifier=test_code_verifier',
            'authy_next_path=%2Fnext%2Fpath',
            f'__Host-authy_session_id={expired_session.session_id}'
        ],
        'requestContext': {
            'http': {
                'sourceIp': '127.0.0.1',
                'userAgent': 'unittest',
                'method': 'GET',
                'path': '/test/path'
            }
        }
    }


@pytest.fixture
def empty_code_param():
    yield {
        'queryStringParameters': {
            'state': 'test_state',
            'code': ''
        },
        'cookies': [
            'state=test_state',
            'code_verifier=test_code_verifier',
            'authy_next_path=%2Fnext%2Fpath'
        ]
    }


@pytest.fixture
def different_state_cookie_and_param():
    yield {
        'queryStringParameters': {
            'state': 'foo',
            'code': 'test_code'
        },
        'cookies': [
            'state=bar',
            'code_verifier=test_code_verifier',
            'authy_next_path=%2Fnext%2Fpath'
        ]
    }


@pytest.fixture
def missing_code_param():
    yield {
        'queryStringParameters': {
            'state': 'state'
        },
        'cookies': [
            'state=state',
            'code_verifier=test_code_verifier',
            'authy_next_path=%2Fnext%2Fpath'
        ]
    }


@pytest.fixture
def no_cookies():
    yield {
        'queryStringParameters': {
            'state': 'test_state',
            'code': 'test_code'
        },
        'cookies': []
    }


@pytest.fixture
def missing_state_cookie():
    yield {
        'queryStringParameters': {
            'state': 'test_state',
            'code': 'test_code'
        },
        'cookies': [
            'code_verifier=test_code_verifier',
            'authy_next_path=%2Fnext%2Fpath'
        ]
    }


@pytest.fixture
def missing_code_verifier_cookie():
    yield {
        'queryStringParameters': {
            'state': 'test_state',
            'code': 'test_code'
        },
        'cookies': [
            'state=test_state',
            'authy_next_path=%2Fnext%2Fpath'
        ]
    }


@pytest.fixture
def empty_state_cookie():
    yield {
        'queryStringParameters': {
            'state': 'test_state',
            'code': 'test_code'
        },
        'cookies': [
            'state=',
            'code_verifier=test_code_verifier',
            'authy_next_path=%2Fnext%2Fpath'
        ]
    }


@pytest.fixture
def empty_code_verifier_cookie():
    yield {
        'queryStringParameters': {
            'state': 'test_state',
            'code': 'test_code'
        },
        'cookies': [
            'state=test_state',
            'code_verifier=',
            'authy_next_path=%2Fnext%2Fpath'
        ]
    }


@contextlib.contextmanager
def readrel(filename):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(current_dir, filename), 'r') as f:
        yield f


@pytest.fixture
def id_token():
    with readrel('test_id_token.txt') as f:
        return f.read().strip()


@pytest.fixture
def private_key():
    with readrel('test_private_key.pem') as f:
        return f.read().strip()


def create_id_token(private_key, auth_time, key_id):
    claims = {
        'at_hash': 'c5xznp5DMm0DxkAg765i6w',
        'sub': '26c24244-c0a1-7086-6af4-4b1eaf153b89',
        'cognito:groups': ['Admins'],
        'iss': f'https://cognito-idp.eu-west-2.amazonaws.com/{user_pool_id}',
        'cognito:username': '26c24244-c0a1-7086-6af4-4b1eaf153b89',
        'origin_jti': 'e5559751-b7e2-430f-b845-ec92ec5a93db',
        'aud': client_id,
        'event_id': '17bd50ee-915f-481b-96c7-88ee18c5edda',
        'token_use': 'id',
        'auth_time': auth_time,
        'name': 'Foo Bar',
        'exp': auth_time + 60,
        'iat': auth_time,
        'jti': 'a30f2e59-0b04-469a-942f-1126e9a35bc2',
        'email': 'test@example.com'
    }
    algorithm = 'RS256'
    headers = dict(kid=key_id)
    return jwt.encode(claims, private_key, algorithm=algorithm,
                      headers=headers)


@pytest.fixture
def valid_id_token(private_key):
    auth_time = int(datetime.datetime.now().timestamp())
    yield create_id_token(private_key, auth_time, 'my-test-key')


@pytest.fixture
def expired_id_token(private_key):
    auth_time = int(datetime.datetime.now().timestamp()) - 600
    yield create_id_token(private_key, auth_time, 'my-test-key')


@pytest.fixture
def tampered_id_token(private_key):
    auth_time = int(datetime.datetime.now().timestamp())
    yield create_id_token(private_key, auth_time,
                          'Pp+/LoFQ+B11O5+AwuPGlx2OnwFO5McILaXXKZJEfAM=')


def token_response(id_token):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.POST,
            f'https://{auth_domain}/oauth2/token',
            json={
                'id_token': id_token,
                'refresh_token': 'test_refresh_token',
            },
            status=200
        )
        yield rsps


@pytest.fixture
def tampered_id_token_response(tampered_id_token):
    yield from token_response(tampered_id_token)


@pytest.fixture
def expired_id_token_response(expired_id_token):
    yield from token_response(expired_id_token)


@pytest.fixture
def valid_id_token_response(valid_id_token):
    yield from token_response(valid_id_token)


@pytest.fixture
def jwks():
    with readrel('test_jwks.json') as f:
        return json.load(f)


@pytest.fixture
def mock_token_hex():
    with patch('secrets.token_hex') as mock_token_hex:
        mock_token_hex.return_value = 'mock_token_hex'
        yield mock_token_hex


@pytest.fixture
def mock_urlopen(jwks):
    with patch('urllib.request.urlopen') as mock_urlopen:
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(jwks)
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = None
        mock_urlopen.return_value = mock_response
        yield mock_urlopen


def assert_authenticated_response(response, session_id):
    assert response == {
        'statusCode': 302,
        'headers': {
            'Location': '/next/path',
            'Cache-Control': ('max-age=0, no-cache, no-store, '
                              'must-revalidate, private')
        },
        'cookies': [
            f'__Host-authy_session_id={session_id}; Path=/; HttpOnly; '
            'Secure'
        ],
        'body': ''
    }


def assert_valid_token_request(token_response_mock):
    assert len(token_response_mock.calls) == 1
    request = token_response_mock.calls[0].request
    assert request.url == f'https://{auth_domain}/oauth2/token'
    redirect_uri = urllib.parse.quote_plus(
        f'https://{app_domain}{oidc_callback_path}'
    )
    assert request.body == 'grant_type=authorization_code' \
        '&client_id=2vh0abc7eh343nq67v2alno0k7' \
        f'&redirect_uri={redirect_uri}&code=test_code' \
        f'&state=test_state' \
        f'&code_verifier=test_code_verifier'


def test_handle_valid_request(app, valid_request_event, mock_token_hex,
                              valid_id_token_response, sessiondb):

    response = app.handler(valid_request_event, {})
    assert_authenticated_response(response, mock_token_hex())

    # no session id in request so a new one should have been created
    session = sessiondb.get_session(mock_token_hex())
    assert session.email == 'test@example.com'

    assert_valid_token_request(valid_id_token_response)


def test_handle_valid_request_with_existing_session(
    app, valid_request_event_with_session, valid_id_token_response,
    sessiondb, active_session, mock_token_hex
):
    response = app.handler(valid_request_event_with_session, {})

    # we had an active session, so that session should have been reused
    assert_authenticated_response(response, active_session.session_id)

    # check we didn't create a new session
    assert sessiondb.get_session(mock_token_hex()) is None

    # check that we marked the session as re-authenticated and extended it
    updated_session = sessiondb.get_session(active_session.session_id)
    assert updated_session.last_authenticated_at > \
        active_session.last_authenticated_at
    assert updated_session.expires_at > \
        active_session.expires_at

    assert_valid_token_request(valid_id_token_response)


def test_handle_valid_request_with_expired_session(
    app, valid_request_event_with_expired_session, sessiondb,
    mock_token_hex, valid_id_token_response
):
    response = app.handler(valid_request_event_with_expired_session, {})

    # session was expired so the response should have a new session
    assert_authenticated_response(response, mock_token_hex())
    assert sessiondb.get_session(mock_token_hex()).email == \
        'test@example.com'

    assert_valid_token_request(valid_id_token_response)


def test_handle_valid_request_expired_token(
        app, valid_request_event, sessiondb, expired_id_token_response
):
    response = app.handler(valid_request_event, {})
    assert response == {
        'statusCode': 401,
        'body': ''
    }
    session = sessiondb.get_session('mock_token_hex')
    assert session is None

    assert_valid_token_request(expired_id_token_response)


def test_handle_valid_request_tampered_token(
        app, valid_request_event, sessiondb, tampered_id_token_response
):
    response = app.handler(valid_request_event, {})
    assert response == {
        'statusCode': 401,
        'body': ''
    }
    session = sessiondb.get_session('mock_token_hex')
    assert session is None

    assert_valid_token_request(tampered_id_token_response)


@responses.activate
@pytest.mark.parametrize('request_fixture', [
    'open_redirect',
    'empty_state_param',
    'missing_state_param',
    'empty_code_param',
    'missing_code_param',
    'different_state_cookie_and_param',
    'no_cookies',
    'missing_state_cookie',
    'missing_code_verifier_cookie',
    'empty_state_cookie',
    'empty_code_verifier_cookie'
])
def test_invalid_request(request, app, request_fixture):
    fixture = request.getfixturevalue(request_fixture)
    response = app.handler(fixture, {})
    assert response['statusCode'] == 400
    assert len(responses.calls) == 0
