from os import environ as env

from six.moves.urllib.parse import quote

import requests
import requests_httpsproxy

requests_httpsproxy.patch_requests()


proxy = env['TEST_HTTPS_PROXY']

assert proxy.startswith('https')

proxies = {
    'http': proxy,
    'https': proxy,
}


def test_https_request():
    r = requests.get('https://httpbin.org/status/204', proxies=proxies)
    assert r.status_code == 204


def test_http_request():
    r = requests.get('http://httpbin.org/status/204', proxies=proxies)
    assert r.status_code == 204


def test_redirects():
    session = requests.Session()

    r = session.get(
        'https://httpbin.org/redirect-to',
        params={'url': 'http://httpbin.org/status/204'},
        proxies=proxies,
    )

    assert r.url == 'http://httpbin.org/status/204'
    assert r.status_code == 204

    r = session.get(
        'http://httpbin.org/redirect-to',
        params={'url': 'https://httpbin.org/status/204'},
        proxies=proxies,
    )

    assert r.url == 'https://httpbin.org/status/204'
    assert r.status_code == 204

    r = session.get(
        'https://httpbin.org/redirect-to',
        params={'url': 'http://httpbin.org/redirect-to?url=%s' % (
            quote('https://httpbin.org/status/204')
        )},
        proxies=proxies,
    )

    assert r.url == 'https://httpbin.org/status/204'
    assert r.status_code == 204
