==============
requests-httpsproxy
==============
allow http/https requests through `HTTPS Proxy
<https://www.chromium.org/developers/design-documents/secure-web-proxy>`_.

Requirements
------------
* requests >= 2.19.0
* PyOpenSSL >= 0.11
* tlslite-ng

Usage
-------
The preferred way of using the library is importing and using the SecureProxySession. It has the exact same behavior as
your usual `requests.Session
<https://requests.readthedocs.io/en/master/user/advanced/#session-objects>`_, but has secure HTTPS proxy support:

.. code:: python

  from requests_httpsproxy import SecureProxySession

  https_proxy = 'https://username:password@host:port'

  with SecureProxySession() as s:
    print (s.get('https://httpbin.org/ip', proxies={'http':https_proxy, 'https':https_proxy}).text)

In case you want to enable secure HTTPS proxy support project wise, you can patch the requests library:

.. code:: python

  import requests
  from requests_httpsproxy import patch_requests
  patch_requests()

  https_proxy = 'https://username:password@host:port'
  with requests.Session() as s:
    print (s.get('https://httpbin.org/ip', proxies={'http':https_proxy, 'https':https_proxy}).text)

Keep in mind, that enabling the secure HTTPS proxy breaks the behavior of regular HTTPS proxies. If you want to use both,
use the SecureProxySession for secure proxies and requests.Session for the regular HTTPS proxies.

An other solution would be to always use the patch or SecureProxySession, but set `verify = False
<https://requests.readthedocs.io/en/master/user/advanced/#ssl-cert-verification>`_, which disables
verifying the SSL certificate:

.. code:: python

  from requests_httpsproxy import SecureProxySession

  https_proxy = 'https://username:password@host:port'

  with SecureProxySession() as s:
    s.verify = False
    print (s.get('https://httpbin.org/ip', proxies={'http':https_proxy, 'https':https_proxy}).text)


Common issues
-------
If the proxy credentials contain symbols, that can't be present in a url (causing a parse error), try encoding them with
`quote_plus
<https://docs.python.org/3/library/urllib.parse.html#urllib.parse.quote_plus>`_:

.. code:: python

  import urllib.parse
  from requests_httpsproxy import SecureProxySession

  username_encoded = urllib.parse.quote_plus(username)
  password_encoded = urllib.parse.quote_plus(password)

  https_proxy = 'https://{}:{}@host:port'.format(username_encoded, password_encoded)

  with SecureProxySession() as s:
    s.verify = False
    print (s.get('https://httpbin.org/ip', proxies={'http':https_proxy, 'https':https_proxy}).text)

License
-------
MIT

Related issues
-------
- https://github.com/kennethreitz/requests/issues/1182
- https://github.com/kennethreitz/requests/issues/1622
- https://github.com/kennethreitz/requests/issues/1903
- https://github.com/kennethreitz/requests/issues/3468
- https://github.com/kennethreitz/requests/issues/3806
- https://github.com/kennethreitz/requests/issues/3882
