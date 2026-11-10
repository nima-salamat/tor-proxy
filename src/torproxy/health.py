"""Per-instance Tor connectivity probes through each worker's own SOCKS listener."""
from __future__ import annotations

import time
from dataclasses import dataclass

import requests

TOR_CHECK_URL = "https://check.torproject.org/api/ip"


@dataclass(frozen=True)
class TorProbeResult:
    """A privacy-preserving result from an end-to-end Tor connectivity probe."""

    healthy: bool
    latency_ms: float | None = None
    detail: str = ""


def probe_tor_socks(socks_port: int, *, timeout: float = 8.0) -> TorProbeResult:
    """Verify that a request through one Tor SOCKS port reaches the Tor Project.

    The request uses SOCKS5 remote DNS and TLS certificate verification. The
    response IP is intentionally discarded and never logged or persisted.
    """
    if type(socks_port) is not int or not 1 <= socks_port <= 65535:
        return TorProbeResult(False, detail="Invalid Tor SOCKS listener port.")
    timeout = max(1.0, min(20.0, float(timeout)))
    proxy = f"socks5h://127.0.0.1:{socks_port}"
    proxies = {"http": proxy, "https": proxy}
    started = time.monotonic()
    response = None
    try:
        response = requests.get(
            TOR_CHECK_URL,
            proxies=proxies,
            timeout=(timeout / 2.0, timeout / 2.0),
            allow_redirects=False,
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "User-Agent": "TorProxy-connectivity-check",
            },
        )
        if response.status_code != 200:
            return TorProbeResult(
                False,
                detail=f"Tor Check returned HTTP {int(response.status_code)}.",
            )
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("IsTor") is not True:
            return TorProbeResult(
                False,
                detail="Tor Check did not confirm that the request used the Tor network.",
            )
        return TorProbeResult(
            True,
            latency_ms=max(0.0, (time.monotonic() - started) * 1000.0),
            detail="Tor Check confirmed this SOCKS connection is using Tor.",
        )
    except requests.RequestException as exc:
        # Keep diagnostics useful without exposing response bodies, exit IPs or
        # remote URLs in routine event logs.
        return TorProbeResult(
            False,
            detail=f"Tor connectivity probe failed ({type(exc).__name__}).",
        )
    except (TypeError, ValueError):
        return TorProbeResult(False, detail="Tor Check returned an invalid response.")
    finally:
        if response is not None:
            response.close()
