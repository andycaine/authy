import datetime
import json
import logging
import sys


class JsonFormatter(logging.Formatter):

    def __init__(self, fields):
        super().__init__()
        self.__formatter = logging.Formatter('%(message)s')
        self.fields = fields

    def format(self, record):
        record.message = self.__formatter.format(record)
        event = {}
        for f in self.fields:
            if isinstance(f, str):
                if hasattr(record, f):
                    event[f] = getattr(record, f)
            else:
                record_name, output_name = f
                if hasattr(record, record_name):
                    value = getattr(record, record_name)
                    event[output_name] = value
        return json.dumps(event)


def _nothing():
    return {}


_context_fn = _nothing


class VocabularyLogger(logging.Logger):

    def __log_event(self, event_name, description, level=logging.INFO):
        extra = _context_fn()
        extra['event'] = event_name
        extra['datetime'] = datetime.datetime.now().astimezone()\
            .replace(microsecond=0).isoformat()
        self.log(level, description, extra=extra)

    def authn_oidc_flow_incorrect_state(self, state_param):
        self.__log_event(
            f'authn_oidc_flow_incorrect_state:{state_param}',
            f'State param <{state_param}> was incorrect during OIDC flow'
        )

    def authn_oidc_flow_invalid_signature(self):
        self.__log_event(
            'authn_oidc_flow_invalid_signature',
            'OIDC token endpoint returned a JWT with an invalid signature'
        )

    def authn_oidc_flow_expired_signature(self):
        self.__log_event(
            'authn_oidc_flow_expired_signature',
            'OIDC token endpoint returned a JWT with an expired signature'
        )

    def authn_oidc_flow_invalid_audience(self):
        self.__log_event(
            'authn_oidc_flow_invalid_audience',
            'OIDC token endpoint returned a JWT with an invalid audience'
        )

    def authn_oidc_flow_invalid_issuer(self):
        self.__log_event(
            'authn_oidc_flow_invalid_issuer',
            'OIDC token endpoint returned a JWT with an invalid issuer'
        )

    def authn_oidc_flow_invalid_issued_at(self):
        self.__log_event(
            'authn_oidc_flow_invalid_issued_at',
            'OIDC token endpoint returned a JWT with an iat in the future'
        )

    def authn_oidc_flow_immature_signature(self):
        self.__log_event(
            'authn_oidc_flow_immature_signature',
            'OIDC token endpoint returned a JWT with a nbf in the future'
        )

    def authn_oidc_flow_invalid_signing_key(self):
        self.__log_event(
            'authn_oidc_flow_invalid_signing_key',
            'OIDC token endpoint returned a JWT with an invalid key'
        )

    def authn_oidc_flow_invalid_token(self):
        self.__log_event(
            'authn_oidc_flow_invalid_token',
            'OIDC token endpoint returned an invalid JWT'
        )

    def authn_oidc_flow_missing_required_claim(self):
        self.__log_event(
            'authn_oidc_flow_missing_required_claim',
            'OIDC token endpoint returned a JWT missing a required claim'
        )

    def authn_login_success(self, username):
        self.__log_event(
            f'authn_login_success:{username}',
            f'User {username} logged in successfully'
        )

    def authn_reauth_success(self, username):
        self.__log_event(
            f'authn_reauth_success:{username}',
            f'User {username} re-authenticated successfully'
        )

    def authz_fail(self, username, resource):
        self.__log_event(
            f'authz_fail:{username},{resource}',
            f'User {username} attempted to access a resource without '
            'entitlement'
        )

    def input_validation_fail(self, field, username='anonymous'):
        self.__log_event(
            f'input_validation_fail:{field},{username}',
            f'User {username} submitted data that failed validation'
        )

    def session_created(self, username):
        self.__log_event(
            f'session_created:{username}',
            f'User {username} has started a new session'
        )

    def malicious_redirect_attempt(self, username, uri):
        self.__log_event(
            f'malicious_redirect_attempt:{username}:{uri}',
            f'User {username} attempted to redirect to {uri}'
        )

    def malicious_proxy_bypass(self):
        self.__log_event(
            'malicious_proxy_bypass',
            'An attempt was make to bypass the proxy and access the service '
            'directly'
        )


def configure(context_fn):
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter([
        'datetime',
        'name',
        'event',
        ('levelname', 'level'),
        'message',
        'useragent',
        'source_ip',
        'host_ip',
        'hostname',
        'protocol',
        'port',
        'request_uri',
        'request_method',
        'geo'
        'region',
    ]))

    logging.basicConfig(level=logging.INFO, handlers=[handler])
    global _context_fn
    _context_fn = context_fn
    logging.setLoggerClass(VocabularyLogger)
