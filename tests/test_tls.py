import httplib2
import six
import ssl
import tests

# TODO: move tests from test_external.py to here using local server

# TODO: different ssl versions: SSLv3, TLSv1, 1.1, 1.2, 1.3


def test_wrong_ca():
    # Test that we get a SSLHandshakeError if we try to access
    # https://www.google.com, using a CA cert file that doesn't contain
    # the CA Google uses (i.e., simulating a cert that's not signed by a
    # trusted CA).
    http = httplib2.Http(ca_certs=tests.get_tls_paths()['ca-unknown'])
    # FIXME:
    if six.PY2:
        exc = (httplib2.SSLHandshakeError, ssl.SSLError)
    else:
        exc = ssl.SSLError
    with tests.assert_raises(exc):
        with tests.server_const_http(scheme='https') as uri:
            http.request(uri, 'GET')


def test_invalid_ca_certs_path():
    # Test that we get error when specifying a non-existent CA certs file.
    http = httplib2.Http(ca_certs='/nosuchfile')
    with tests.assert_raises(IOError):
        with tests.server_const_http(scheme='https') as uri:
            http.request(uri, 'GET')


def test_get_200():
    # Test that we can handle HTTPS
    http = httplib2.Http(ca_certs=tests.get_tls_paths()['ca'])
    with tests.server_const_http(scheme='https') as uri:
        response, _ = http.request(uri, 'GET')
        assert response.status == 200


def test_http_redirect_https():
    http = httplib2.Http(ca_certs=tests.get_tls_paths()['ca'])
    with tests.server_const_http(scheme='https') as uri_https:
        with tests.server_const_http(status=301, headers={'location': uri_https}) as uri_http:
            response, _ = http.request(uri_http, 'GET')
            assert response.status == 200
            assert response['content-location'] == uri_https
            assert response.previous.status == 301
            assert response.previous['content-location'] == uri_http


def test_https_redirect_http():
    http = httplib2.Http(ca_certs=tests.get_tls_paths()['ca'])
    with tests.server_const_http() as uri_http:
        with tests.server_const_http(scheme='https', status=301, headers={'location': uri_http}) as uri_https:
            response, _ = http.request(uri_https, 'GET')
            assert response.status == 200
            assert response['content-location'] == uri_http
            assert response.previous.status == 301
            assert response.previous['content-location'] == uri_https
