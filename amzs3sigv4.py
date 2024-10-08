"""
Authenticating Request Using Authorization Header by AWS Signature Version 4
"""
from hashlib import sha256
from urllib.parse import quote, urlparse
from datetime import datetime
import hmac
import socket
import ssl

"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature)
from cryptography.hazmat.backends import default_backend
"""


class SimpleTCPClient():
    def __init__(self, host: str, port: int, use_ssl: bool = False):
        self._client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._host = host
        self._port = port

        if port == 443 or use_ssl:
            context = ssl.create_default_context()
            self._client_socket = context.wrap_socket(
                self._client_socket, server_hostname=self._host)

    def _send(self, payload: bytes):
        self._client_socket.connect((self._host, self._port))

        self._client_socket.sendall(payload)

        parts = []
        while True:
            parts.append(self._client_socket.recv(1024 << 10))
            if not parts[len(parts) - 1]:
                break
        self._client_socket.close()
        parts.pop()  # Consume a last empty part
        return b''.join(parts)

    def __call__(self, payload: bytes) -> bytes:
        return self._send(payload)


class SimpleRESTClient(SimpleTCPClient):
    def __init__(self, url: str):
        parsed_url = urlparse(url)
        parsed_netloc = parsed_url.netloc.split(':')

        if len(parsed_netloc) == 2:
            port = parsed_netloc[1]
        elif parsed_url.scheme in ('http', ''):
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

    def __call__(self, method: str = 'GET', headers: dict = None,
                 body: bytes = b'') -> bytes:
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


class StreamingUpload(SimpleRESTClient):
    def __call__(self, body: bytes, headers: dict = None) -> bytes:
        pass


class AuthHeader():
    def __init__(self, http_verb: str, uri: str, algorithm: str, region: str,
                 access_key: str, secret_access_key: str, headers: dict = None,
                 query_strings: dict = None, has_trailer: bool = False):
        self._access_key = access_key
        self._secret_access_key = secret_access_key
        self._region = region
        self._algorithm = algorithm
        self._has_trailer = has_trailer
        self._utcnow = datetime.utcnow()
        self.headers = headers
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
                         for k, v in self._headers.items()]),
                    # Signed Headers
                    ';'.join([list(self.headers)]),
                    # x-amz-content-sha256
                    self.x_amz_content_sha256]))

    @property
    def headers(self):
        return self._headers

    @headers.setter
    def headers(self, headers: dict):
        self._headers = {k.lower: v for k, v in headers.items()}
        if 'x-amz-date' not in self._headers:
            self._headers['x-amz_date'] = self.amz_date
        if 'x-amz-content-sha256' not in self._headers:
            self._headers['x-amz-content-sha256'] = self.x_amz_content_sha256
        sorted_keys = sorted(self._headers)
        self._headers = {
            k: (
                self._headers[k].strip() if self._headers[k] else '')
            for k in sorted_keys}

    @property
    def x_amz_content_sha256(self):
        return (f'STREAMING-{self._algorithm}-PAYLOAD' +
                '-TRAILER' if self._has_trailer else '')

    @property
    def date(self):
        return self._utcnow.strftime('%Y%m%d'),

    @property
    def amz_date(self):
        return self._utcnow.isoformat()  # yyyymmddThhmmssZ

    @property
    def scope(self):
        return '/'.join(
            [
                self.date,
                self._region,
                's3',
                'aws4_request'])

    @property
    def string_to_sign(self):
        return '\n'.join(
            [
                self._algorithm,
                self.amz_date,
                self.scope,
                sha256(self._canonical_request.encode('utf8')).hexdigest()])

    @property
    def signing_key(self):
        date_key = hmac.new(b'AWS4' + self._secret_access_key.encode('utf8'),
                            self.date.encode('utf8'),
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

    @property
    def Authorization(self):
        return (
            f'{self._algorithm} '
            f'Credential={self._access_key}/{self.date}/{self._region}/'
            f's3/aws4_request,'
            f'SignedHeaders={self._signed_headers}',
            f'Signature={self.seed_signature.hexdigest()}')
