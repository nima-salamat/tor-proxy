from __future__ import annotations

from torproxy.health import probe_tor_socks


def test_probe_uses_remote_dns_and_requires_tor_project_confirmation(monkeypatch):
    calls = []

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {"IsTor": True, "IP": "203.0.113.8"}

        @staticmethod
        def close():
            calls.append("closed")

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return Response()

    monkeypatch.setattr("torproxy.health.requests.get", fake_get)
    result = probe_tor_socks(19155, timeout=6)

    assert result.healthy is True
    assert result.latency_ms is not None
    assert calls[0][0] == "https://check.torproject.org/api/ip"
    assert calls[0][1]["proxies"]["https"] == "socks5h://127.0.0.1:19155"
    assert calls[0][1]["timeout"] == (3.0, 3.0)
    assert calls[-1] == "closed"
    # The exit IP from the response must not be retained in the probe result.
    assert "203.0.113.8" not in repr(result)


def test_probe_rejects_a_response_that_does_not_confirm_tor(monkeypatch):
    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {"IsTor": False, "IP": "203.0.113.9"}

        @staticmethod
        def close():
            pass

    monkeypatch.setattr("torproxy.health.requests.get", lambda *_args, **_kwargs: Response())
    result = probe_tor_socks(19156)

    assert result.healthy is False
    assert "did not confirm" in result.detail
    assert "203.0.113.9" not in repr(result)


def test_probe_reports_transport_failures_without_response_details(monkeypatch):
    import requests

    def fail(*_args, **_kwargs):
        raise requests.ConnectionError("private proxy endpoint detail")

    monkeypatch.setattr("torproxy.health.requests.get", fail)
    result = probe_tor_socks(19157)

    assert result.healthy is False
    assert "ConnectionError" in result.detail
    assert "private proxy endpoint detail" not in result.detail


def test_probe_rejects_invalid_ports_without_network_access():
    result = probe_tor_socks(0)

    assert result.healthy is False
    assert "Invalid" in result.detail
