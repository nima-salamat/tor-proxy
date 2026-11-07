"""Explicit routing for TorProxy-owned HTTP requests.

A direct bootstrap request requires a separate, explicit allow_direct=True
decision. Environment proxy settings are never inherited.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

import requests


class NetworkRouteError(RuntimeError):
    """An HTTP request has no explicitly authorized route."""


def tor_socks_proxy_url(host: str, port: int) -> str:
    """Build a loopback-only SOCKS5H URL so destination DNS is resolved via Tor."""
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise NetworkRouteError("The Tor SOCKS port must be an integer between 1 and 65535.")
    normalized_host = str(host or "").strip().strip("[]")
    try:
        address = ipaddress.ip_address(normalized_host)
    except ValueError:
        if normalized_host.lower() != "localhost":
            raise NetworkRouteError("The Tor SOCKS listener must use a loopback address.")
        authority = "localhost"
    else:
        if not address.is_loopback:
            raise NetworkRouteError("The Tor SOCKS listener must use a loopback address.")
        authority = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return f"socks5h://{authority}:{port}"


def _validate_proxy_url(proxy_url: str) -> str:
    parsed = urlsplit(str(proxy_url or "").strip())
    if parsed.scheme not in {"socks5h", "http"} or not parsed.hostname:
        raise NetworkRouteError(
            "Use an explicit local SOCKS5H or HTTP proxy; direct requests are disabled."
        )
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise NetworkRouteError("Proxy URLs must not contain credentials, paths, queries, or fragments.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise NetworkRouteError("The configured proxy URL has an invalid port.") from exc
    if port is None or not 1 <= port <= 65535:
        raise NetworkRouteError("The configured proxy URL must include a valid port.")
    host = parsed.hostname.lower().rstrip(".")
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = host == "localhost"
    if not is_loopback:
        raise NetworkRouteError("TorProxy only accepts an explicitly configured loopback proxy.")
    return str(proxy_url).strip()


def create_session(
    proxy_url: str | None = None,
    *,
    allow_direct: bool = False,
    session_factory=requests.Session,
) -> requests.Session:
    """Create a request session with one explicit route and no environment inheritance."""
    if proxy_url is None:
        if allow_direct is not True:
            raise NetworkRouteError(
                "No Tor route is available. Connect Tor or explicitly authorize direct bootstrap access."
            )
    else:
        if allow_direct:
            raise NetworkRouteError("Choose either the Tor proxy route or explicit direct bootstrap, not both.")
        proxy_url = _validate_proxy_url(proxy_url)

    session = session_factory()
    session.trust_env = False
    if proxy_url is not None:
        session.proxies.clear()
        session.proxies.update({"http": proxy_url, "https": proxy_url})
    else:
        session.proxies.clear()
    return session
