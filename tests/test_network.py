from __future__ import annotations

import pytest

from torproxy.network import NetworkRouteError, create_session, tor_socks_proxy_url


class FakeSession:
    def __init__(self):
        self.trust_env = True
        self.proxies = {"http": "http://environment-proxy", "https": "http://environment-proxy"}


def test_tor_proxy_url_uses_socks5h_for_remote_dns():
    assert tor_socks_proxy_url("127.0.0.1", 19050) == "socks5h://127.0.0.1:19050"


def test_ipv6_tor_proxy_url_is_bracketed():
    assert tor_socks_proxy_url("::1", 19050) == "socks5h://[::1]:19050"


@pytest.mark.parametrize(("host", "port"), [("8.8.8.8", 9050), ("127.0.0.1", 0), ("127.0.0.1", 65536)])
def test_invalid_tor_listener_is_rejected(host, port):
    with pytest.raises(NetworkRouteError):
        tor_socks_proxy_url(host, port)


def test_no_route_is_rejected_before_session_creation():
    created = []
    with pytest.raises(NetworkRouteError, match="explicitly authorize"):
        create_session(session_factory=lambda: created.append(True))
    assert created == []


def test_session_disables_environment_proxy_and_sets_both_schemes():
    session = create_session("socks5h://127.0.0.1:19050", session_factory=FakeSession)
    assert session.trust_env is False
    assert session.proxies == {
        "http": "socks5h://127.0.0.1:19050",
        "https": "socks5h://127.0.0.1:19050",
    }


def test_direct_route_requires_explicit_opt_in_and_ignores_environment_proxy():
    session = create_session(allow_direct=True, session_factory=FakeSession)
    assert session.trust_env is False
    assert session.proxies == {}


@pytest.mark.parametrize(
    "proxy_url",
    [
        "socks5://127.0.0.1:9050",
        "socks5h://8.8.8.8:9050",
        "socks5h://user:pass@127.0.0.1:9050",
        "socks5h://127.0.0.1",
        "socks5h://127.0.0.1:9050/path",
    ],
)
def test_unsafe_or_non_loopback_proxy_urls_are_rejected(proxy_url):
    with pytest.raises(NetworkRouteError):
        create_session(proxy_url)


def test_direct_and_proxy_routes_cannot_be_enabled_together():
    with pytest.raises(NetworkRouteError, match="either"):
        create_session("socks5h://127.0.0.1:9050", allow_direct=True)
