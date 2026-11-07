from __future__ import annotations

import pytest
import requests

from torproxy.network import (
    NetworkRouteError,
    create_session,
    network_error_message,
    network_route_label,
    tor_socks_proxy_url,
)


class FakeSession:
    def __init__(self):
        self.trust_env = True
        self.proxies = {"http": "http://environment-proxy", "https": "http://environment-proxy"}
        self.adapters = {}

    def mount(self, prefix, adapter):
        self.adapters[prefix] = adapter


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



def test_session_mounts_bounded_retries_for_idempotent_requests():
    session = create_session("socks5h://127.0.0.1:19050", session_factory=FakeSession)
    assert set(session.adapters) == {"http://", "https://"}
    for adapter in session.adapters.values():
        retry = adapter.max_retries
        assert retry.total == 2
        assert retry.connect == 2
        assert retry.read == 1
        assert retry.status == 2
        assert retry.allowed_methods == frozenset({"GET", "HEAD"})
        assert retry.status_forcelist == frozenset({429, 500, 502, 503, 504})
        assert retry.respect_retry_after_header is False


def test_network_route_labels_distinguish_tor_and_direct_bootstrap():
    assert network_route_label("socks5h://127.0.0.1:19050") == "TOR_SOCKS"
    assert network_route_label("http://127.0.0.1:8080") == "LOCAL_HTTP_PROXY"
    assert network_route_label(allow_direct=True) == "DIRECT_BOOTSTRAP"
    assert network_route_label() == "NO_ROUTE"


def test_connection_refusal_message_identifies_route_and_next_action():
    error = requests.ConnectionError(
        "HTTPSConnectionPool(host='dist.torproject.org', port=443): "
        "Failed to establish a new connection: [WinError 10061] actively refused"
    )
    message = network_error_message(
        error,
        purpose="Tor release discovery",
        proxy_url="socks5h://127.0.0.1:19050",
    )
    assert "TOR_SOCKS" in message
    assert "refused the connection" in message
    assert "retry" in message.lower()
