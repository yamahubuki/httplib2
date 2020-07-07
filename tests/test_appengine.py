import os
import sys

import httplib2
import mock
import pytest
import tests

if os.path.basename(sys.argv[0]) in ("pytest", "py.test"):
    if os.environ.get("httplib2_test_appengine") != "1":
        pytest.skip(
            "to run appengine tests, run script/setup-appengine-sdk and set env httplib2_test_appengine=1",
            allow_module_level=True,
        )


# from google.appengine.ext import testbed


def test_appengine_no_socks():
    with mock.patch("httplib2.socks", None):
        http = httplib2.Http(proxy_info=httplib2.ProxyInfo("blah", "localhost", 0))
        with tests.assert_raises(httplib2.ProxiesUnavailableError):
            http.request("http://localhost:-1/")
