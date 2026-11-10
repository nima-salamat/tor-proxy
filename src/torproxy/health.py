"""Bounded, environment-independent Tor egress probes through SOCKS5."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

import requests

TOR_CHECK_URL = "https://check.torproject.org/api/ip"
MAX_TOR_CHECK_RESPONSE_BYTES = 16 * 1024


@dataclass(frozen=True)
class TorProbeResult:
    """A privacy-preserving result from an end-to-end Tor connectivity probe."""

    healthy: bool
    latency_ms: float | None = None
    detail: str = ""


def probe_tor_socks(socks_port: int, *, timeout: float = 8.0) -> TorProbeResult:
    """Verify an actual Tor egress request through one worker's SOCKS listener.

    Environment proxy variables are deliberately ignored: a NO_PROXY entry
    must never make a health check silently bypass the worker being measured.
    The response body is bounded, redirects are rejected, TLS verification is
    left enabled, and the returned exit IP is discarded.
    """
    if type(socks_port) is not int or not 1 <= socks_port <= 65535:
        return TorProbeResult(False, detail="Invalid Tor SOCKS listener port.")
    try:
        timeout = max(1.0, min(20.0, float(timeout)))
    except (TypeError, ValueError, OverflowError):
        return TorProbeResult(False, detail="Invalid Tor connectivity probe timeout.")

    proxy = f"socks5h://127.0.0.1:{socks_port}"
    proxies = {"http": proxy, "https": proxy}
    started = time.monotonic()
    try:
        with requests.Session() as session:
            session.trust_env = False
            with session.get(
                TOR_CHECK_URL,
                proxies=proxies,
                timeout=(timeout / 2.0, timeout / 2.0),
                allow_redirects=False,
                stream=True,
                headers={
                    "Accept": "application/json",
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache",
                    "User-Agent": "TorProxy-connectivity-check",
                },
            ) as response:
                if response.status_code != 200:
                    return TorProbeResult(
                        False,
                        detail=f"Tor Check returned HTTP {int(response.status_code)}.",
                    )
                body = bytearray()
                for chunk in response.iter_content(chunk_size=4096):
                    if not chunk:
                        continue
                    if len(body) + len(chunk) > MAX_TOR_CHECK_RESPONSE_BYTES:
                        return TorProbeResult(
                            False,
                            detail="Tor Check response exceeded the permitted size.",
                        )
                    body.extend(chunk)
                payload = json.loads(body)
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
        return TorProbeResult(
            False,
            detail=f"Tor connectivity probe failed ({type(exc).__name__}).",
        )
    except (TypeError, ValueError, UnicodeError):
        return TorProbeResult(False, detail="Tor Check returned an invalid response.")
