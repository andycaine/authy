from unittest.mock import patch
import json
import io

from freezegun import freeze_time
import pytest


jwks = {
    "keys": [{
        "alg": "RS256",
        "e": "AQAB",
        "kid": "BMLq2Z9km8EjG3CfsnNk0DQW9rFD6AWQxPAmWAO75Hs=",
        "kty": "RSA",
        "n": "wQSDNYLf0jhK8H0QgtlGjTy9PoJekhe8hNhOMOazQlDQbUhQwFf3l1UYC4xko5ovCId27bOt0seUKiTHRZrXueyWBOfP-mewBOdAnyGF8-HPRRzFi4M8LAro0bqnHH6jcFvYVyyvT5_dQUS7SRHOMk95tyW-2qeqGanyYd7haeEWhMG5rQIqvoYK9HN2iENpVg7dd3-YoykixqcEOUMJGeaL5pIrnhQBSYeOEOzmZWMiDcIp8Fye5nYc0KDyqcmB0cDjwxWQNpw0yHE67sEuYEAydHCPvJqlD_LlrKjg-EXRnQz38YhYSgYA6yc4gDqt68yDJwNNYVVOzSzIbTfodQ",
        "use": "sig"
    }, {
        "alg": "RS256",
        "e": "AQAB",
        "kid": "Pp+/LoFQ+B11O5+AwuPGlx2OnwFO5McILaXXKZJEfAM=",
        "kty": "RSA",
        "n": "1JtflUft1bgb8gTeS0qhyJC-AxzyEo56aCCXzww4oxiyntIwe7THID5TnpmcC5CtsV5Fs-mZuJHjTTc8BWUr2urksajB3djgD3-gqQ0rgBATsR1CtrHEZOFDPV8G-FEt53DvLnGr7fxMjs_EBnlSw-6CAVbTKVBGB_8JtAmAMMrORG7IIdrQ2wmuoZ1e3btgEAZmlWBQFK8kNOOzkmOJNlxmgJjPtohWlNqRMbcDhb6omsD45yU9yYJYUB1q3KGw-nwl0K43Vj1iU3EtbR0DrLsPOEOWF70Q9M-M-okC0mKy8oNlxzRo46h1gXaEGKdx3wJ9AyKnh_Fk62rxHRc0-w",
        "use": "sig"
    }]
}


@pytest.fixture
def set_env(monkeypatch):
    monkeypatch.setenv('REGION', 'eu-west-2')
    monkeypatch.setenv('USER_POOL_ID', 'eu-west-2_2dIWFAizy')
    monkeypatch.setenv('USER_POOL_CLIENT_ID', '2vh0abc7eh343nq67v2alno0k7')


@pytest.fixture
def app(set_env):
    with patch('urllib.request.urlopen') as mock_urlopen:
        mock_response = io.BytesIO(json.dumps(jwks).encode('utf-8'))
        mock_urlopen.return_value = mock_response

        from cognito_abac_authorizer import app
        yield app


@freeze_time("2024-02-29 18:00:00")
def test_valid_jwt(app):
    def test_authoriser(*_):
        return True, {}

    app._authoriser = test_authoriser
    event = {
        'cookies': [
            'bd_auth_id_token=eyJraWQiOiJCTUxxMlo5a204RWpHM0Nmc25OazBEUVc5ckZENkFXUXhQQW1XQU83NUhzPSIsImFsZyI6IlJTMjU2In0.eyJhdF9oYXNoIjoiYzV4em5wNURNbTBEeGtBZzc2NWk2dyIsInN1YiI6IjI2YzI0MjQ0LWMwYTEtNzA4Ni02YWY0LTRiMWVhZjE1M2I4OSIsImNvZ25pdG86Z3JvdXBzIjpbIkFkbWlucyJdLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuZXUtd2VzdC0yLmFtYXpvbmF3cy5jb21cL2V1LXdlc3QtMl8yZElXRkFpenkiLCJjb2duaXRvOnVzZXJuYW1lIjoiMjZjMjQyNDQtYzBhMS03MDg2LTZhZjQtNGIxZWFmMTUzYjg5Iiwib3JpZ2luX2p0aSI6ImU1NTU5NzUxLWI3ZTItNDMwZi1iODQ1LWVjOTJlYzVhOTNkYiIsImF1ZCI6IjJ2aDBhYmM3ZWgzNDNucTY3djJhbG5vMGs3IiwiZXZlbnRfaWQiOiIxN2JkNTBlZS05MTVmLTQ4MWItOTZjNy04OGVlMThjNWVkZGEiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTcwOTIzMDEzNSwibmFtZSI6IkFuZHkgQ2FpbmUiLCJleHAiOjE3MDkyMzM3MzUsImlhdCI6MTcwOTIzMDEzNSwianRpIjoiYTMwZjJlNTktMGIwNC00NjlhLTk0MmYtMTEyNmU5YTM1YmMyIiwiZW1haWwiOiJhY2FpbmUwMEBnbWFpbC5jb20ifQ.kgMv88fCvndGxgxsWksM8p5Tk6MSzA__yU2JOx0GAPCAgcvZk75uzTjA4sy5tjgmxu05fr_Oxk-L8WVjLnI5AehWbiYM09YkBjONGExd05XBKkFxpibhyWcphH5fSlmEfqN98b3euflls-UsJcGEjcWBY4MvjA54v1kYNH-hNXpKLO5ENZ2yDPfURmHD8TomawTKHquecezu85GnKvJgwS9i4GVsFzhj-vwdbW_cDg813awLHuB2b7WRFaAY4uPCO4VkA-I89IPj0vpKoVg8M975Kt9WAQ9nOYI0UB1zY7l-WouoJkuzEHpAK53c63ohSZzkvNZEwEiR56oSWFQGIw'
        ],
        'requestContext': {
            'http': {
                'method': 'GET',
                'path': '/blog/posts'
            }
        }
    }
    response = app.handler(event, {})
    assert response == {
        'isAuthorized': True,
        'context': {
            'groups': ['Admins'],
            'name': 'Andy Caine',
            'user': 'acaine00@gmail.com'
        }
    }


@freeze_time("2024-02-29 20:00:00")
def test_expired_jwt(app):
    def test_authoriser(*_):
        return True, {}

    app._authoriser = test_authoriser
    event = {
        'cookies': [
            'bd_auth_id_token=eyJraWQiOiJCTUxxMlo5a204RWpHM0Nmc25OazBEUVc5ckZENkFXUXhQQW1XQU83NUhzPSIsImFsZyI6IlJTMjU2In0.eyJhdF9oYXNoIjoiYzV4em5wNURNbTBEeGtBZzc2NWk2dyIsInN1YiI6IjI2YzI0MjQ0LWMwYTEtNzA4Ni02YWY0LTRiMWVhZjE1M2I4OSIsImNvZ25pdG86Z3JvdXBzIjpbIkFkbWlucyJdLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuZXUtd2VzdC0yLmFtYXpvbmF3cy5jb21cL2V1LXdlc3QtMl8yZElXRkFpenkiLCJjb2duaXRvOnVzZXJuYW1lIjoiMjZjMjQyNDQtYzBhMS03MDg2LTZhZjQtNGIxZWFmMTUzYjg5Iiwib3JpZ2luX2p0aSI6ImU1NTU5NzUxLWI3ZTItNDMwZi1iODQ1LWVjOTJlYzVhOTNkYiIsImF1ZCI6IjJ2aDBhYmM3ZWgzNDNucTY3djJhbG5vMGs3IiwiZXZlbnRfaWQiOiIxN2JkNTBlZS05MTVmLTQ4MWItOTZjNy04OGVlMThjNWVkZGEiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTcwOTIzMDEzNSwibmFtZSI6IkFuZHkgQ2FpbmUiLCJleHAiOjE3MDkyMzM3MzUsImlhdCI6MTcwOTIzMDEzNSwianRpIjoiYTMwZjJlNTktMGIwNC00NjlhLTk0MmYtMTEyNmU5YTM1YmMyIiwiZW1haWwiOiJhY2FpbmUwMEBnbWFpbC5jb20ifQ.kgMv88fCvndGxgxsWksM8p5Tk6MSzA__yU2JOx0GAPCAgcvZk75uzTjA4sy5tjgmxu05fr_Oxk-L8WVjLnI5AehWbiYM09YkBjONGExd05XBKkFxpibhyWcphH5fSlmEfqN98b3euflls-UsJcGEjcWBY4MvjA54v1kYNH-hNXpKLO5ENZ2yDPfURmHD8TomawTKHquecezu85GnKvJgwS9i4GVsFzhj-vwdbW_cDg813awLHuB2b7WRFaAY4uPCO4VkA-I89IPj0vpKoVg8M975Kt9WAQ9nOYI0UB1zY7l-WouoJkuzEHpAK53c63ohSZzkvNZEwEiR56oSWFQGIw'
        ],
        'requestContext': {
            'http': {
                'method': 'GET',
                'path': '/blog/posts'
            }
        }
    }
    with pytest.raises(Exception):
        app.handler(event, {})
