import datetime
import sys
import logging

import pytest
import boto3
import moto
import freezegun

# Set up path in the same way as the lambda function would
LIB_PATH = 'lib'
if LIB_PATH not in sys.path:
    sys.path.insert(0, LIB_PATH)


@pytest.fixture(autouse=True)
def loginfo(caplog):
    caplog.set_level(logging.INFO)
    pass


@pytest.fixture(autouse=True)
def aws_creds(monkeypatch):
    # Make sure that no tests try to use real AWS creds
    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'testing')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'testing')
    monkeypatch.setenv('AWS_SECURITY_TOKEN', 'testing')
    monkeypatch.setenv('AWS_SESSION_TOKEN', 'testing')
    monkeypatch.setenv('AWS_DEFAULT_REGION', 'us-east-1')


@pytest.fixture
def sessions_table_name():
    return 'sessions'


@pytest.fixture
def sessiondb(aws_creds, sessions_table_name):
    # Importing sessions here, after the lambda layer has been added to the
    # path, means that equality assertions will work properly
    import sessions
    with moto.mock_aws():
        dynamodb = boto3.resource('dynamodb')
        dynamodb.create_table(
            TableName=sessions_table_name,
            KeySchema=[
                {
                    'AttributeName': 'pk',
                    'KeyType': 'HASH'
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'pk',
                    'AttributeType': 'S'
                }
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        yield sessions.Database(sessions_table_name)


@pytest.fixture
def session_factory(sessiondb):
    def create_session(duration_in_mins=5):
        return sessiondb.create_session(
            username='test@example.com',
            ip='192.168.1.1',
            user_agent='fake-ua',
            duration_in_mins=duration_in_mins,
            groups=['Admins'],
            name='Foo Bar'
        )
    yield create_session


@pytest.fixture
def active_session(session_factory):
    just_now = datetime.datetime.now(datetime.UTC)\
        - datetime.timedelta(minutes=1)
    with freezegun.freeze_time(just_now.isoformat()):
        session = session_factory()
    yield session


@pytest.fixture
def expired_session(session_factory):
    some_time_ago = datetime.datetime.now(datetime.UTC)\
        - datetime.timedelta(minutes=8)
    with freezegun.freeze_time(some_time_ago.isoformat()):
        session = session_factory()
    yield session
