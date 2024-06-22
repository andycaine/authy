import pytest


@pytest.fixture
def envvars(monkeypatch, sessions_table_name):
    monkeypatch.setenv('LOGOUT_PATH', '/auth/login')
    monkeypatch.setenv('CLIENT_ID', 'test_client_id')
    monkeypatch.setenv('CF_DOMAIN', 'admin.test.com')
    monkeypatch.setenv('AUTH_DOMAIN', 'auth.test.com')
    monkeypatch.setenv('SESSIONS_TABLE_NAME', sessions_table_name)


@pytest.fixture
def app(envvars, sessiondb):
    from logout_handler import app
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


def assert_logout_redirect(response):
    assert response == {
        'statusCode': 302,
        'headers': {
            'Location': ('https://auth.test.com/logout?client_id='
                         'test_client_id&logout_uri='
                         'https%3A%2F%2Fadmin.test.com%2Fauth%2Flogin')
        },
        'cookies': [
            '__Host-authy_session_id=deleted; Path=/; HttpOnly; Secure; '
            'expires=Thu, 01 Jan 1970 00:00:00 GMT'],
        'body': ''
    }


def test_logout_active_session(app, request_with_active_session_id, sessiondb,
                               active_session):
    response = app.handler(request_with_active_session_id, {})
    assert sessiondb.get_session(active_session.session_id) is None
    assert_logout_redirect(response)


def test_logout_no_cookies(app, request_with_no_cookies):
    response = app.handler(request_with_no_cookies, {})
    assert_logout_redirect(response)


def test_logout_invalid_session_id(app, request_with_invalid_session_id):
    response = app.handler(request_with_invalid_session_id, {})
    assert_logout_redirect(response)
