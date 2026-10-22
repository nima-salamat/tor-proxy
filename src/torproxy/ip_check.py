"""Exit-IP verification that refuses to make an unproxied request."""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

import requests


class ProxyCheckError(RuntimeError):
    """A proxied exit-IP request failed or could not be verified."""


def fetch_exit_ip(proxy_url: str, endpoint: str = "https://api.ipify.org?format=json",
                  timeout: tuple[float, float] = (5.0, 10.0),
                  session_factory=requests.Session) -> str:
    """Return the observed exit IP through proxy_url; never retry directly."""
    parsed_proxy = urlsplit(proxy_url or "")
    if parsed_proxy.scheme not in {"http", "socks5", "socks5h"} or not parsed_proxy.hostname:
        raise ProxyCheckError("A configured HTTP or SOCKS proxy URL is required; direct requests are disabled.")
    if parsed_proxy.username or parsed_proxy.password:
        raise ProxyCheckError("Proxy URLs containing credentials are not supported by this checker.")
    parsed_endpoint = urlsplit(endpoint)
    if parsed_endpoint.scheme != "https" or not parsed_endpoint.hostname:
        raise ProxyCheckError("The IP-check endpoint must be an HTTPS URL.")

    session = session_factory()
    session.trust_env = False
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        response = session.get(endpoint, proxies=proxies, timeout=timeout, allow_redirects=False)
        response.raise_for_status()
        try:
            payload = response.json()
            address = payload.get("ip") if isinstance(payload, dict) else None
            return str(ipaddress.ip_address(address))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ProxyCheckError("The IP-check service returned an invalid IP address.") from exc
        except requests.RequestException as exc:
            raise ProxyCheckError(f"Proxied IP request failed: {exc}") from exc
    except requests.RequestException as exc:
        raise ProxyCheckError(f"Proxied IP request failed: {exc}") from exc
    finally:
        session.close()
