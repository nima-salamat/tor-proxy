from __future__ import annotations

import json

from torproxy.health import MAX_TOR_CHECK_RESPONSE_BYTES, probe_tor_socks


class FakeResponse:
    def __init__(self, payload, status_code=200, chunks=None):
        self.status_code = status_code
        self.payload = payload
        self.chunks = chunks
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True

    def iter_content(self, chunk_size=4096):
        if self.chunks is not None:
            yield from self.chunks
        else:
            yield json.dumps(self.payload).encode("utf-8")


class FakeSession:
    instances = []

    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.trust_env = True
        self.calls = []
        self.closed = False
        self.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs, self.trust_env))
        if self.error is not None:
            raise self.error
        return self.response


def _install_session(monkeypatch, session):
    FakeSession.instances = []
    monkeypatch.setattr("torproxy.health.requests.Session", lambda: session)


def test_probe_uses_remote_dns_bypasses_environment_proxies_and_requires_tor(monkeypatch):
    response = FakeResponse({"IsTor": True, "IP": "203.0.113.8"})
    session = FakeSession(response=response)
    _install_session(monkeypatch, session)

    result = probe_tor_socks(19155, timeout=6)

    assert result.healthy is True
    assert result.latency_ms is not None
    url, kwargs, trust_env = session.calls[0]
    assert url == "https://check.torproject.org/api/ip"
    assert kwargs["proxies"]["https"] == "socks5h://127.0.0.1:19155"
    assert kwargs["timeout"] == (3.0, 3.0)
    assert kwargs["allow_redirects"] is False
    assert kwargs["stream"] is True
    assert trust_env is False
    assert response.closed is True
    assert session.closed is True
    # The exit IP from the response must not be retained in the probe result.
    assert "203.0.113.8" not in repr(result)


def test_probe_rejects_a_response_that_does_not_confirm_tor(monkeypatch):
    response = FakeResponse({"IsTor": False, "IP": "203.0.113.9"})
    session = FakeSession(response=response)
    _install_session(monkeypatch, session)

    result = probe_tor_socks(19156)

    assert result.healthy is False
    assert "did not confirm" in result.detail
    assert "203.0.113.9" not in repr(result)


def test_probe_rejects_oversized_health_response(monkeypatch):
    response = FakeResponse(
        {},
        chunks=[b"x" * (MAX_TOR_CHECK_RESPONSE_BYTES + 1)],
    )
    session = FakeSession(response=response)
    _install_session(monkeypatch, session)

    result = probe_tor_socks(19157)

    assert result.healthy is False
    assert "exceeded" in result.detail
    assert response.closed is True


def test_probe_reports_transport_failures_without_response_details(monkeypatch):
    import requests

    session = FakeSession(error=requests.ConnectionError("private proxy endpoint detail"))
    _install_session(monkeypatch, session)

    result = probe_tor_socks(19158)

    assert result.healthy is False
    assert "ConnectionError" in result.detail
    assert "private proxy endpoint detail" not in result.detail


def test_probe_rejects_invalid_ports_without_network_access(monkeypatch):
    import requests

    def forbidden_session():
        raise AssertionError("invalid ports must not create a network session")

    monkeypatch.setattr(requests, "Session", forbidden_session)
    result = probe_tor_socks(0)

    assert result.healthy is False
    assert "Invalid" in result.detail
