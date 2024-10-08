"""
Authenticating Request Using Authorization Header by AWS Signature Version 4
"""
from hashlib import sha256
from urllib.parse import quote, urlparse
from datetime import datetime
import hmac
import socket
import ssl
import time

"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature)
from cryptography.hazmat.backends import default_backend
"""


class SimpleTCPClient:
    """
    Simple TCP Client Implementation
    """
    def __init__(self, host: str, port: int, use_ssl: bool = False):
        self._client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._client_socket.settimeout(5.0)
        self._host = host
        self._port = port

        if port == 443 or use_ssl:
            context = ssl.create_default_context()
            self._client_socket = context.wrap_socket(
                self._client_socket, server_hostname=self._host)

    def _send(self, payload: bytes):
        self._client_socket.connect((self._host, self._port))
        self._client_socket.sendall(payload)
        self._client_socket.setblocking(0)
        print(payload.decode('utf8'))

        parts = []
        while True:
            try:
                r = self._client_socket.recv(1024)
                parts.append(r)
                if not parts[len(parts) - 1]:
                    break
            except BlockingIOError:
                # No data available to read, wait or perform other tasks
                # print("No data available yet, continuing...")
                if parts:
                    break
                time.sleep(0.1)  # Sleep for a while before trying again
            except socket.error as e:
                print(f"Socket error: {e}")
                break

        self._client_socket.close()
        return b''.join(parts)

    def __call__(self, payload: bytes) -> bytes:
        return self._send(payload)


class SimpleRESTClient(SimpleTCPClient):
    """
    Simple REST API Client Implementation
    """
    def __init__(self, method: str, url: str, headers: dict = None,
                 body: bytes = b'') -> bytes:
        parsed_url = urlparse(url)
        parsed_netloc = parsed_url.netloc.split(':')
        if len(parsed_netloc) == 2:  # port specified
            port = int(parsed_netloc[1])
        elif parsed_url.scheme in ('http', ''):
            port = 80
        elif parsed_url.scheme == 'https':
            port = 443
        else:
            raise ValueError('Unrecognized scheme')

        self._method = method
        self._path = parsed_url.path if parsed_url.path else '/'
        self._query = parsed_url.query
        self._headers = headers
        self._body = bytearray(body)

        SimpleTCPClient.__init__(self, parsed_netloc[0], port)

    def __call__(self, **kwargs):
        return self._send(self._get_payload())

    @property
    def headers(self):
        return {k.lower(): v for k, v in (
            self._headers.items() if self._headers else {})}

    @property
    def query_strings(self):
        return self._query

    def _get_payload(self) -> bytes:
        uri = (
            '?'.join([self._path, self.query_strings]) if self.query_strings
            else self._path)

        payload = f'{self._method} {uri} HTTP/1.1'

        return (
            '\n'.join(
                [
                    payload,
                    '\n'.join([f'{k}:{v}' for k, v in self.headers.items()]),
                    '', ''
                ]
            )
        ).encode('utf8') + self._body


class AmzSigV4Request(SimpleRESTClient):
    def __init__(self, method: str, url: str, headers: dict = None,
                 body: bytes = b'', algorithm: str = None, region: str = None,
                 access_key: str = None, secret_access_key: str = None,
                 has_trailer: bool = False, is_streaming: bool = False):
        SimpleRESTClient.__init__(self, method, url, headers, body)

        self._auth_header = AuthoHeader(http_verb=self._method,
                                        uri=self._path,
                                        host=self._host,
                                        algorithm=algorithm,
                                        region=region,
                                        access_key=access_key,
                                        secret_access_key=secret_access_key,
                                        headers=headers,
                                        query_strings=self._query,
                                        has_trailer=has_trailer,
                                        is_streaming=is_streaming)

    @property
    def headers(self):
        headers = self._auth_header.headers
        headers['Authorization'] = self._auth_header.Authorization
        return headers


class AuthoHeader():
    def __init__(self, http_verb: str, uri: str, algorithm: str, region: str,
                 access_key: str, secret_access_key: str, headers: dict = None,
                 query_strings: str = None, has_trailer: bool = False,
                 is_streaming: bool = False, host: str = None,
                 body: bytearray = b''):
        self._http_verb = http_verb
        self._uri = uri
        self._access_key = access_key
        self._secret_access_key = secret_access_key
        self._region = region
        self._algorithm = algorithm
        self._has_trailer = has_trailer
        self._is_streaming = is_streaming
        self._body = body
        self._utcnow = datetime.utcnow()
        self.query_strings = query_strings
        self.headers = headers

    @property
    def canonical_request(self):
        canonical_request = '\n'.join(
            [
                # HTTP Verb
                self._http_verb,
                # Canonical URI
                self.canonical_uri,
                # Canonical Query String
                self.query_strings,
                # Canonical Headers
                self.canonical_headers,
                '',
                # Signed Headers
                self.signed_headers,
                # x-amz-content-sha256
                self.x_amz_content_sha256])
        return canonical_request

    @property
    def canonical_uri(self):
        return quote(self._uri)

    @property
    def query_strings(self):
        return self._canonical_query_strings

    @query_strings.setter
    def query_strings(self, query_strings):
        if not query_strings:
            self._canonical_query_strings = ''
        else:
            parsed_query_strings = {
                quote(k): quote(v)
                for item in query_strings.split('&')
                for k, v in item.split('=')}
            sorted_keys = sorted(parsed_query_strings)
            self._canonical_query_strings = '&'.join(
                [f'{k}={parsed_query_strings[k]}' for k in sorted_keys])

    @property
    def headers(self) -> dict:
        return self._headers.copy()

    @headers.setter
    def headers(self, headers: dict):
        parsed_headers = {
            quote(k.lower()): quote(v) for k, v in headers.items()}
        if 'x-amz-date' not in parsed_headers:
            parsed_headers['x-amz_date'] = self.amz_date
        if 'x-amz-content-sha256' not in parsed_headers:
            parsed_headers['x-amz-content-sha256'] = self.x_amz_content_sha256
        if 'host' not in headers:
            headers['host'] = self._host

        sorted_keys = sorted(parsed_headers)
        self._headers = {k: parsed_headers[k] for k in sorted_keys}

    @property
    def canonical_headers(self):
        return '\n'.join([f'{k}:{v.strip()}' for k, v in self.headers.items()])

    @property
    def signed_headers(self):
        return ';'.join(list(self.headers))

    @property
    def x_amz_content_sha256(self):
        if self._is_streaming:
            return (f'STREAMING-{self._algorithm}-PAYLOAD' +
                    '-TRAILER' if self._has_trailer else '')
        return sha256(self._body).hexdigest()

    @property
    def date(self):
        return self._utcnow.strftime('%Y%m%d')

    @property
    def amz_date(self):
        return self._utcnow.strftime('%Y%m%dT%H%M%SZ')  # yyyymmddThhmmssZ

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
                sha256(self.canonical_request.encode('utf8')).hexdigest()])

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
            f'SignedHeaders={self.signed_headers},'
            f'Signature={self.seed_signature.hexdigest()}')
