import dataclasses
import secrets
import time

import boto3


class Database:

    def __init__(self, table_name):
        self.table = boto3.resource('dynamodb').Table(table_name)

    def get_session(self, session_id):
        result = self.table.get_item(Key={'pk': session_id})
        if 'Item' not in result:
            return None
        item = result['Item']
        return Session(
            session_id=item['session_id'],
            email=item['email'],
            name=item['name'],
            ip=item['ip'],
            user_agent=item['user_agent'],
            created_at=item['created_at'],
            expires_at=item['expires_at'],
            last_authenticated_at=item['last_authenticated_at'],
            groups=item['groups']
        )

    def extend_session(self, session, by_mins, up_to_mins):
        session.extend(by_mins, up_to_mins)
        self.table.update_item(
            Key={'pk': session.session_id},
            UpdateExpression='SET expires_at = :expires_at',
            ExpressionAttributeValues={
                ':expires_at': session.expires_at,
            }
        )

    def mark_reauthenticated_and_extend(self, session, by_mins, up_to_mins):
        session.extend(by_mins, up_to_mins)
        session.last_authenticated_at = int(time.time())
        self.table.update_item(
            Key={'pk': session.session_id},
            UpdateExpression=('SET last_authenticated_at = '
                              ':last_authenticated_at, '
                              'expires_at = :expires_at'),
            ExpressionAttributeValues={
                ':last_authenticated_at': session.last_authenticated_at,
                ':expires_at': session.expires_at,
            }
        )

    def create_session(self, email, ip, user_agent, duration_in_mins, groups,
                       name):
        session_id = secrets.token_hex(32)
        created_at = int(time.time())
        expires_at = int(created_at + duration_in_mins * 60)
        session = Session(
            session_id=session_id,
            email=email,
            ip=ip,
            name=name,
            groups=groups,
            user_agent=user_agent,
            created_at=created_at,
            last_authenticated_at=created_at,
            expires_at=expires_at
        )
        self.table.put_item(
            Item={
                'pk': session.session_id,
                'session_id': session.session_id,
                'email': session.email,
                'name': session.name,
                'ip': session.ip,
                'user_agent': session.user_agent,
                'created_at': session.created_at,
                'last_authenticated_at': session.last_authenticated_at,
                'expires_at': session.expires_at,
                'groups': session.groups
            }
        )
        return session

    def delete_session(self, session_id):
        self.table.delete_item(Key={'pk': session_id})


@dataclasses.dataclass
class Session:
    session_id: str
    email: str
    name: str
    ip: str
    user_agent: str
    created_at: int
    last_authenticated_at: int
    expires_at: int
    groups: list[str]

    def expired(self):
        return int(time.time()) > self.expires_at

    def extend(self, by_mins, up_to_mins):
        max_expires_at = self.created_at + up_to_mins * 60
        new_expires_at = int(time.time()) + by_mins * 60
        self.expires_at = int(min(new_expires_at, max_expires_at))
