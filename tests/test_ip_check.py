import requests
import pytest

from torproxy.ip_check import ProxyCheckError, fetch_exit_ip


class FakeResponse:
    def __init__(self, payload=None, error=None):
        self.payload = payload
        self.error = error

    def raise_for_status(self):
        if self.error:
            raise self.error

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, response=None):
        self.response = response or FakeResponse({"ip": "198.51.100.8"})
        self.trust_env = True
        self.calls = []

    def get(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.response

    def close(self):
        pass


def test_requires_an_explicit_proxy_before_network_access():
    called = []
    with pytest.raises(ProxyCheckError, match="direct requests are disabled"):
        fetch_exit_ip("", session_factory=lambda: called.append(True))
    assert not called


def test_uses_explicit_proxy_for_http_and_https_without_redirect_fallback():
    session = FakeSession()
    address = fetch_exit_ip("http://127.0.0.1:8888", session_factory=lambda: session)
    assert address == "198.51.100.8"
    assert session.trust_env is False
    _, kwargs = session.calls[0]
    assert kwargs["proxies"] == {"http": "http://127.0.0.1:8888", "https": "http://127.0.0.1:8888"}
    assert kwargs["allow_redirects"] is False


def test_invalid_ip_response_is_not_reported_as_verified():
    session = FakeSession(FakeResponse({"ip": "not-an-ip"}))
    with pytest.raises(ProxyCheckError, match="invalid IP"):
        fetch_exit_ip("http://127.0.0.1:8888", session_factory=lambda: session)


def test_proxy_error_does_not_trigger_direct_retry():
    session = FakeSession(FakeResponse(error=requests.Timeout("timeout")))
    with pytest.raises(ProxyCheckError, match="Proxied IP request failed"):
        fetch_exit_ip("http://127.0.0.1:8888", session_factory=lambda: session)
    assert len(session.calls) == 1
