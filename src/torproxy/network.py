"""Explicit routing and bounded retry policy for TorProxy-owned HTTP requests.

A direct bootstrap request requires a separate, explicit allow_direct=True
decision. Environment proxy settings are never inherited.
"""
from __future__ import annotations

import ipaddress
import logging
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


logger = logging.getLogger(__name__)

RETRY_ATTEMPTS = 2
RETRY_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
RETRY_METHODS = frozenset({"GET", "HEAD"})


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


def network_route_label(proxy_url: str | None = None, *, allow_direct: bool = False) -> str:
    """Return a stable, non-sensitive label for the explicitly selected HTTP route."""
    if proxy_url is not None:
        scheme = urlsplit(str(proxy_url).strip()).scheme.lower()
        if scheme == "socks5h":
            return "TOR_SOCKS"
        if scheme == "http":
            return "LOCAL_HTTP_PROXY"
        return "EXPLICIT_PROXY"
    return "DIRECT_BOOTSTRAP" if allow_direct else "NO_ROUTE"


def network_error_message(
    exc: requests.RequestException,
    *,
    purpose: str,
    proxy_url: str | None = None,
    allow_direct: bool = False,
) -> str:
    """Produce actionable network diagnostics without exposing a traceback in the UI."""
    route = network_route_label(proxy_url, allow_direct=allow_direct)
    route_context = {
        "TOR_SOCKS": "through the local Tor SOCKS listener",
        "LOCAL_HTTP_PROXY": "through the configured local HTTP proxy",
        "DIRECT_BOOTSTRAP": "during the explicitly approved direct bootstrap",
    }.get(route, "using the selected network route")
    detail = str(exc).strip()
    lowered = detail.lower()

    if isinstance(exc, requests.exceptions.HTTPError):
        status = getattr(getattr(exc, "response", None), "status_code", None)
        cause = f"The Tor distribution service returned HTTP {status}." if status else (
            "The Tor distribution service returned an HTTP error."
        )
    elif isinstance(exc, requests.exceptions.SSLError):
        cause = "TLS certificate verification or the secure connection failed."
    elif isinstance(exc, requests.exceptions.ProxyError):
        cause = "The selected local proxy could not be reached or rejected the connection."
    elif isinstance(exc, requests.exceptions.Timeout):
        cause = "The connection timed out."
    elif isinstance(exc, requests.exceptions.ConnectionError):
        if "10061" in lowered or "connection refused" in lowered or "actively refused" in lowered:
            cause = "The selected network route refused the connection."
        elif any(term in lowered for term in (
            "name or service not known",
            "getaddrinfo failed",
            "nodename nor servname",
            "temporary failure in name resolution",
        )):
            cause = "DNS resolution failed on the selected network route."
        else:
            cause = "A network connection could not be established."
    else:
        cause = f"The network request failed ({type(exc).__name__})."

    return (
        f"{purpose} failed {route_context} ({route}): {cause} "
        "Check the network connection, Tor connectivity, or firewall settings, then retry."
    )


def _retry_adapter() -> HTTPAdapter:
    """Retry only idempotent reads, with a small bounded backoff and status allowlist."""
    policy = Retry(
        total=RETRY_ATTEMPTS,
        connect=RETRY_ATTEMPTS,
        read=1,
        status=RETRY_ATTEMPTS,
        backoff_factor=0.35,
        status_forcelist=RETRY_STATUS_CODES,
        allowed_methods=RETRY_METHODS,
        respect_retry_after_header=False,
        raise_on_status=False,
    )
    return HTTPAdapter(max_retries=policy)


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
    """Create a session with a bounded retry policy and one explicit route."""
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

    if hasattr(session, "mount"):
        session.mount("http://", _retry_adapter())
        session.mount("https://", _retry_adapter())

    route = network_route_label(proxy_url, allow_direct=allow_direct)
    logger.info("HTTP network route selected: %s", route)
    return session
