"""
Authenticating Request Using Authorization Header by AWS Signature Version 4
"""
from hashlib import sha256
from urllib.parse import quote, urlparse
from datetime import datetime
import hmac
import socket


class SimpleTCPClient():
    def __init__(self, host: str, port: int):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._host = host
        self._port = port

    def _send(self, payload: bytes):
        self.client_socket.connect((self._host, self._port))

        self.client_socket.sendall(payload)

        parts = []
        while True:
            parts.append(self.client_socket.recv(1024<<10))
            if not parts[len(parts) - 1]:
                break
        self.client_socket.close()
        parts.pop()  # Consume a last empty part
        return b''.join(parts)

    def __call__(self, payload: bytes):
        return self._send(payload)


class SimpleRESTClient(SimpleTCPClient):
    def _send(self, payload: bytes):
        raise NotImplementedError()

    def __init__(self, url: str):
        parsed_url = urlparse(url)
        parsed_netloc = parsed_url.netloc.split(':')

        if len(parsed_netloc) == 2:
            port = parsed_netloc[1]
        elif parsed_url.scheme in ('http', '') :
            port = 80
        elif parsed_url.scheme == 'https':
            port = 443
        else:
            raise ValueError('Unrecognized scheme')

        host = parsed_netloc[0]
        self._uri = parsed_url.path if parsed_url.path else '/'
        if parsed_url.query:
            self._uri += '?' + parsed_url.query

        SimpleTCPClient.__init__(self, host, port)

    def __call__(self, method: str='GET', headers: dict=None, body: bytes=b''):
        payload = '\n'.join(
            [
                f'{method} {self._uri} HTTP/1.1',
                f'Host: {self._host}',
            ]
        )

        headers = {k.lower().title(): v for k, v in (headers.items()
                                                     if headers else {})}
        if 'Accept' not in headers:
            headers['Accept'] = '*/*'

        payload = (
            '\n'.join(
                [
                    payload,
                    '\n'.join(
                        [
                            f'{k}:{v}' for k, v in headers.items()
                        ]
                    ),
                    '', ''
                ]
            )
        ).encode('utf8') + body

        return self._send(payload)


class AuthorizationHeader():
    def __init__(self, http_verb: str, uri: str, algorithm: str, region: str,
                 secret_access_key: str, headers: dict = None,
                 query_strings: dict = None, has_trailer: bool = False):
        self._secret_access_key = secret_access_key
        self._region = region
        self._algorithm = algorithm
        self._has_trailer = has_trailer
        headers = headers if headers else {}
        query_strings = query_strings if query_strings else {}

        self._canonical_request = (
            '\n'.join(
                [
                    # HTTP Verb
                    http_verb,
                    # Canonical URI
                    quote(uri),
                    # Canonical Query String
                    '&'.join(
                        [f'{quote(k)}={quote(v)}'
                         for k, v in query_strings.items()]),
                    # Canonical Headers
                    '\n'.join(
                        [f'{k.lower()}:{v.strip()}'
                         for k, v in headers.items()]),
                    # Signed Headers
                    ';'.join([k.lower() for k in headers]),
                    # x-amz-content-sha256
                    self.x_amz_content_sha256]))

    @property
    def x_amz_content_sha256(self):
        return (f'STREAMING-{self._algorithm}-PAYLOAD' +
                '-TRAILER' if self._has_trailer else '')

    @property
    def timestamp(self):
        return datetime.now().isoformat()  # yyyymmddThhmmssZ

    @property
    def scope(self):
        return '/'.join(
            [
                datetime.now().strftime('%Y%m%d'),
                self._region,
                's3',
                'aws4_request'])

    @property
    def string_to_sign(self):
        return '\n'.join(
            [
                self._algorithm,
                self.timestamp,
                self.scope,
                sha256(self._canonical_request.encode('utf8')).hexdigest()])

    @property
    def signing_key(self):
        date_key = hmac.new(b'AWS4' + self._secret_access_key.encode('utf8'),
                            datetime.now().strftime('%Y%m%d').encode('utf8'),
                           sha256)
        date_region_key = hmac.new(date_key.digest(),
                                   self._region.encode('utf8'),
                                  sha256)
        date_region_service_key = hmac.new(date_region_key.digest(),
                                           b's3',
                                          sha256)
        return hmac.new(date_region_service_key.digest(),
                        b'aws4_request',
                       sha256)

    @property
    def seed_signature(self):
        return hmac.new(self.signing_key.digest(),
                        self.string_to_sign.encode('utf8'),
                       sha256)

    def __str__(self):
        return self.seed_signature.hexdigest()
