import dataclasses
import http.cookies
import contextvars


@dataclasses.dataclass
class Request:
    args: dict
    method: str
    cookies: dict
    headers: dict
    remote_addr: str
    user_agent: str
    path: str
    host: str
    scheme: str


request = contextvars.ContextVar('request')


def logging_context():
    r = request.get()

    host = r.host
    port = ''
    if ':' in host:
        host, port = host.split(':')
    return {
        'useragent': r.user_agent,
        'source_ip': r.remote_addr,
        'host_ip': '',
        'hostname': host,
        'protocol': r.scheme,
        'port': port,
        'request_uri': r.path,
        'request_method': r.method,
        'region': '',
        'geo': {
            'city': r.headers.get('cloudfront-viewer-city', ''),
            'country': r.headers.get('cloudfront-viewer-country', '')
        }
    }


def _parse_cookies(event):
    result = {}
    for cookie_string in event.get('cookies', []):
        cookie = http.cookies.SimpleCookie()
        cookie.load(cookie_string)
        result.update({key: cookie[key].value for key in cookie})
    return result


def make_request(event):
    http = event.get('requestContext', {}).get('http', {})
    headers = event.get('headers', {})
    host = headers.get('host', '')
    port = headers.get('x-forwarded-port', '')
    if port:
        host = f'{host}:{port}'
    return Request(
        args=event.get('queryStringParameters', {}),
        cookies=_parse_cookies(event),
        method=http.get('method', ''),
        remote_addr=http.get('sourceIp'),
        user_agent=http.get('userAgent'),
        headers=headers,
        path=http.get('path', ''),
        host=host,
        scheme=headers.get('x-forwarded-proto', '')
    )


def route(fn):
    def inner(event, _):
        r = make_request(event)
        request.set(r)
        result = fn(r)
        return result
    return inner


def bad_request():
    return {
        'statusCode': 400,
        'body': 'Bad Request'
    }


def http_401():
    return {
        'statusCode': 401,
        'body': ''
    }


def session_cookie(name, session_id, path='/'):
    if not name.startswith('__Host-'):
        raise ValueError('Session cookies must start with "__Host-" prefix')
    return cookie(name, session_id, path=path)


def cookie(name, value, http_only=True, secure=True, path='/',
           same_site='Strict'):
    builder = [f'{name}={value}; Path={path}; SameSite={same_site}']
    if http_only:
        builder.append('; HttpOnly')
    if secure:
        builder.append('; Secure')
    return ''.join(builder)


def redirect(location, cookies=[], headers={}):
    headers['Location'] = location
    return response(302, '', cookies=cookies, headers=headers)


def response(status_code, body='', cookies=[], headers={}):
    return {
        'statusCode': status_code,
        'cookies': cookies,
        'headers': headers,
        'body': body
    }
