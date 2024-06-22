import unittest.mock
import secrets
import time

import moto
import pytest
import freezegun


inactivity_timeout_mins = 60
session_timeout_mins = 120
custom_origin_key = 'xyz'


@pytest.fixture
def mock_authorizer():
    mock = unittest.mock.Mock()
    mock.return_value = True, {}
    yield mock


@pytest.fixture
def app(monkeypatch, sessiondb, mock_authorizer, sessions_table_name):
    monkeypatch.setenv('SESSIONS_TABLE_NAME', sessions_table_name)
    monkeypatch.setenv('SESSION_INACTIVITY_TIMEOUT_MINS',
                       str(inactivity_timeout_mins))
    monkeypatch.setenv('SESSION_TIMEOUT_MINS', str(session_timeout_mins))
    monkeypatch.setenv('CUSTOM_ORIGIN_KEY', custom_origin_key)

    with moto.mock_aws():
        from session_abac_authorizer import app
        app._authoriser = mock_authorizer
        yield app


def session_cookie(session_id):
    return f'__Host-authy_session_id={session_id}'


def origin_key_header(key):
    return {
        'x-custom-origin-key': key
    }


def request_event(cookies=[], headers=origin_key_header(custom_origin_key)):
    return dict(
        cookies=cookies,
        headers=headers,
    )


@pytest.fixture
def request_for_active_session(active_session):
    return request_event(cookies=[session_cookie(active_session.session_id)])


@freezegun.freeze_time()
@pytest.mark.parametrize('authorized', [True, False])
def test_active_session(app, active_session, request_for_active_session,
                        sessiondb, mock_authorizer, authorized):
    mock_authorizer.return_value = authorized, {}

    response = app.handler(request_for_active_session, {})
    assert response == {
        'isAuthorized': authorized,
        'context': {
            'groups': active_session.groups,
            'name': active_session.name,
            'email': active_session.email
        }
    }
    expected_new_expires_at = int(time.time()) + inactivity_timeout_mins * 60
    session = sessiondb.get_session(active_session.session_id)
    assert session.expires_at == expected_new_expires_at
    active_session.expires_at = session.expires_at

    mock_authorizer.assert_called_once_with(request_for_active_session,
                                            active_session)


@pytest.fixture
def request_with_no_session_cookie():
    return request_event(cookies=[])


@pytest.mark.parametrize('fixture_name', [
    'request_with_no_session_cookie',
    'request_with_expired_session',
    'request_with_missing_session',
    'request_with_invalid_session_cookie'
])
def test_unauthenticated(request, app, fixture_name):
    fixture = request.getfixturevalue(fixture_name)
    # Exception('Unauthorized') triggers a 401 response so is used in all
    # situations where the client should be redirected to the authentication
    # endpoint
    with pytest.raises(Exception, match='Unauthorized'):
        app.handler(fixture, {})


@pytest.fixture
def request_with_expired_session(expired_session):
    return request_event(
        cookies=[session_cookie(expired_session.session_id)]
    )


@pytest.fixture
def request_with_missing_session():
    return request_event(
        cookies=[session_cookie(secrets.token_hex(32))]
    )


@pytest.fixture
def request_with_invalid_session_cookie():
    return request_event(
        cookies=[session_cookie('invalid')]
    )


@pytest.fixture
def request_with_invalid_origin_header():
    return request_event(headers=origin_key_header('invalid'))


@pytest.fixture
def request_with_no_origin_header():
    return request_event(headers={})


@pytest.mark.parametrize('fixture_name', [
    'request_with_no_origin_header',
    'request_with_invalid_origin_header'
])
def test_unauthorized_request(request, app, fixture_name):
    fixture = request.getfixturevalue(fixture_name)
    response = app.handler(fixture, {})
    assert response == {
        'isAuthorized': False,
        'context': {}
    }
