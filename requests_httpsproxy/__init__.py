# -*- coding: utf-8 -*-
"""
This module add HTTPS proxies support to requests.

The HTTPS implementation supports the full range of requests features.
"""
import ssl
import logging
from socket import error as SocketError, timeout as SocketTimeout
from functools import partial

import tlslite
from urllib3.poolmanager import ProxyManager as BaseProxyManager
from urllib3.connection import HTTPSConnection as BaseHTTPSConnection
from urllib3.connectionpool import (
    HTTPConnectionPool as BaseHTTPConnectionPool,
    HTTPSConnectionPool as BaseHTTPSConnectionPool
)
from urllib3.exceptions import (
    ConnectTimeoutError,
    NewConnectionError,
)
import OpenSSL

import requests

log = logging.getLogger(__name__)


class ProxyManager(BaseProxyManager):
    def __init__(self, proxy_url, num_pools=10, headers=None,
                 proxy_headers=None, **connection_pool_kw):
        assert proxy_url.startswith('https'), 'only support https proxy'

        super(ProxyManager, self).__init__(
            proxy_url, num_pools, headers, proxy_headers, **connection_pool_kw)

        self.pool_classes_by_scheme = {
            'http': HTTPConnectionPool,
            'https': HTTPSConnectionPool,
        }

    def connection_from_host(self, host, port=None, scheme='http', pool_kwargs=None):
        return super(BaseProxyManager, self).connection_from_host(
            host, port, scheme, pool_kwargs=pool_kwargs)


class HTTPConnectionPool(BaseHTTPConnectionPool):
    ConnectionCls = BaseHTTPSConnection

    def _new_conn(self):
        """
        Return a fresh :class:`httplib.HTTPSConnection`.
        """
        self.num_connections += 1
        log.debug("Starting new HTTPS connection (%d): %s",
                  self.num_connections, self.host)

        actual_host = self.proxy.host
        actual_port = self.proxy.port

        conn = self.ConnectionCls(host=actual_host, port=actual_port,
                                  timeout=self.timeout.connect_timeout,
                                  strict=self.strict, **self.conn_kw)

        return conn


class HTTPSConnection(BaseHTTPSConnection):
    def set_https_tunnel(self, host, port, headers=None):
        self._tunnel_host = host
        self._tunnel_port = port
        self._tunnel_headers = headers

    def connect(self):
        conn = self._new_conn()
        self._origin_sock = conn

        if self.ssl_context is None:
            self.ssl_context = ssl.create_default_context()

        self.sock = self.ssl_context.wrap_socket(
            conn, server_hostname=self.host)

        self._setup_https_tunnel()

        self.is_verified = (
                self.ssl_context.verify_mode == ssl.CERT_REQUIRED or
                self.assert_fingerprint is not None
        )

    def _setup_https_tunnel(self):
        sock = self.sock

        host = self._tunnel_host
        port = self._tunnel_port

        try:
            lines = []
            lines.append('CONNECT %s:%d HTTP/1.1' % (host, port))
            lines.append('Host: %s:%d' % (host, port))

            if self._tunnel_headers:
                for item in self._tunnel_headers.items():
                    lines.append('%s: %s' % item)

            data = '\r\n'.join(lines) + '\r\n\r\n'
            sock.sendall(data.encode())

            data = b''
            code = 0
            pos = -1
            while True:
                s = sock.recv(4096)
                if not s:
                    if code == 0:
                        raise SocketError("Tunnel connection failed: %r" % data)
                    break
                data += s
                if code == 0 and b'\r\n' in data:
                    version, code, message = data.split(b' ', 2)
                    if code != b'200':
                        sock.close()
                        raise SocketError("Tunnel connection failed: %s %s" %
                                          (code, message.strip()))
                pos = data.find(b'\r\n\r\n')
                if pos > 0:
                    break

            tls_conn = tlslite.TLSConnection(sock)
            try:
                tls_conn.handshakeClientCert(serverName=host)
            except Exception:
                sock.close()
                raise

            try:
                ssl.match_hostname(tlslite_getpeercert(tls_conn), host)
            except Exception:
                tls_conn.close()
                raise
        except SocketTimeout as e:
            raise ConnectTimeoutError(
                self, "Connection to %s timed out. (connect timeout=%s)" %
                      (self.host, self.timeout))

        except SocketError as e:
            raise NewConnectionError(
                self, "Failed to establish a new connection: %s" % e)

        # patch fileno,
        # let urllib3.util.connection.is_connection_dropped work as expected
        tls_conn.fileno = partial(self._origin_sock.fileno)
        # patch getpeercert
        tls_conn.getpeercert = partial(tlslite_getpeercert, tls_conn)
        self.sock = tls_conn


class HTTPSConnectionPool(BaseHTTPSConnectionPool):
    ConnectionCls = HTTPSConnection

    def _new_conn(self):
        """
        Return a fresh :class:`httplib.HTTPSConnection`.
        """
        self.num_connections += 1
        log.debug("Starting new HTTPS connection (%d): %s",
                  self.num_connections, self.host)

        actual_host = self.proxy.host
        actual_port = self.proxy.port

        conn = self.ConnectionCls(host=actual_host, port=actual_port,
                                  timeout=self.timeout.connect_timeout,
                                  strict=self.strict, **self.conn_kw)

        return self._prepare_conn(conn)

    def _prepare_conn(self, conn):
        conn.set_cert(assert_hostname=self.proxy.host)
        return conn

    def _prepare_proxy(self, conn):
        conn.set_https_tunnel(self.host, self.port, self.proxy_headers)


def tlslite_getpeercert(conn):
    if not hasattr(conn, '_peercert'):
        x509_bytes = conn.session.serverCertChain.x509List[0].bytes
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1,
                                               bytes(x509_bytes))
        subject = x509.get_subject()
        abbvs = {
            'CN': 'commonName',
            'L': 'localityName',
            'ST': 'stateOrProvinceName',
            'O': 'organizationName',
            'OU': 'organizationalUnitName',
            'C': 'countryName',
            'STREET': 'streetAddress',
            'DC': 'domainComponent',
            'UID': 'userid',
        }
        cert = {}
        cert['subject'] = [[(abbvs.get(k.decode()) or k.decode(), v.decode())
                            for k, v in subject.get_components()]]
        for i in range(x509.get_extension_count()):
            extension = x509.get_extension(i)
            if extension.get_short_name() == b'subjectAltName':
                cert['subjectAltName'] = []
                for p in extension.get_data().split(b'\x82')[1:]:
                    cert['subjectAltName'].append(('DNS', p[1:].decode()))
        conn._peercert = cert
    return conn._peercert


# create a custom http adapter with https secure proxy support
# can be used for patching and separately
origin_proxy_manager_for = requests.adapters.HTTPAdapter.proxy_manager_for


class SecureProxyHTTPAdapter(requests.adapters.HTTPAdapter):
    def proxy_manager_for(self, proxy, **proxy_kwargs):
        if proxy in self.proxy_manager:
            return self.proxy_manager[proxy]
        elif proxy.startswith('https'):
            proxy_headers = self.proxy_headers(proxy)
            manager = self.proxy_manager[proxy] = ProxyManager(
                proxy,
                proxy_headers=proxy_headers,
                num_pools=self._pool_connections,
                maxsize=self._pool_maxsize,
                block=self._pool_block,
                **proxy_kwargs
            )
            return manager
        else:
            return origin_proxy_manager_for(self, proxy, **proxy_kwargs)


# create a custom requests.Session, with https secure proxy support
class SecureProxySession(requests.Session):
    def __init__(self):
        super(SecureProxySession, self).__init__()

        self.mount('http://', SecureProxyHTTPAdapter())
        self.mount('https://', SecureProxyHTTPAdapter())


# patching requests
PATCHED = False


def patch_requests():
    global PATCHED
    if PATCHED:
        raise RuntimeError('patch multiple time')

    requests.sessions.HTTPAdapter = SecureProxyHTTPAdapter

    PATCHED = True
