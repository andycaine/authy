import base64
import hashlib
import secrets


def _s256(s):
    h = hashlib.sha256(s.encode('ascii')).digest()
    return base64.urlsafe_b64encode(h).rstrip(b'=').decode('ascii')


def pair(nbytes=32):
    """Return a pair containing a random string and the corresponding SHA256
    hash.

    The random string has *nbytes* random bytes and is URL-safe text string,
    in Base64 encoding.

    The hash is the SHA256 of the ascii encoding of the random string, which
    is then also returned as a URL-safe text string in Base64 encoding.
    """
    s = secrets.token_urlsafe(nbytes)
    return s, _s256(s)


def match(s, s256):
    """Return True if the SHA256 hash of *s* matches *s256*."""
    return _s256(s) == s256
