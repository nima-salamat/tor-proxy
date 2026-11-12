"""Bounded, environment-independent multi-target Tor egress probes."""
from __future__ import annotations

import json
import statistics
import time
from dataclasses import dataclass

import requests

TOR_CHECK_URL = "https://check.torproject.org/api/ip"
MAX_TOR_CHECK_RESPONSE_BYTES = 16 * 1024
MAX_FALLBACK_RESPONSE_BYTES = 4 * 1024
FALLBACK_PROBES = (
    ("cloudflare_trace", "https://www.cloudflare.com/cdn-cgi/trace", 200),
    ("google_204", "https://www.google.com/generate_204", 204),
)


@dataclass(frozen=True)
class TorProbeResult:
    """Privacy-preserving result from one Tor SOCKS egress probe cycle.

    healthy means either Tor Check positively confirmed Tor, or both
    independent HTTPS fallback targets were reachable through the managed
    SOCKS endpoint. verified_tor is deliberately stricter and is only true
    when Tor Check returned IsTor=true.
    """

    healthy: bool
    latency_ms: float | None = None
    detail: str = ""
    verified_tor: bool = False
    successful_targets: tuple[str, ...] = ()
    failed_targets: tuple[str, ...] = ()
    latency_samples_ms: tuple[float, ...] = ()


def _read_bounded(response, limit: int) -> bytes | None:
    body = bytearray()
    for chunk in response.iter_content(chunk_size=4096):
        if not chunk:
            continue
        if len(body) + len(chunk) > limit:
            return None
        body.extend(chunk)
    return bytes(body)


def probe_tor_socks(socks_port: int, *, timeout: float = 8.0) -> TorProbeResult:
    """Check Tor egress without trusting environment proxy variables.

    The primary probe proves that the managed SOCKS endpoint exits through
    Tor. If that verification service is unavailable (but does not explicitly
    say IsTor=false), two independent HTTPS endpoints are checked through the
    same SOCKS5H route. A fallback result is marked reachable but unverified;
    it is never described as a positive Tor Check result.

    Redirects and oversized bodies are rejected, TLS verification remains
    enabled, destination DNS is resolved remotely, and exit IPs are discarded.
    """
    if type(socks_port) is not int or not 1 <= socks_port <= 65535:
        return TorProbeResult(False, detail="Invalid Tor SOCKS listener port.")
    try:
        timeout = max(1.0, min(20.0, float(timeout)))
    except (TypeError, ValueError, OverflowError):
        return TorProbeResult(False, detail="Invalid Tor connectivity probe timeout.")

    proxy = f"socks5h://127.0.0.1:{socks_port}"
    proxies = {"http": proxy, "https": proxy}
    timeout_pair = (timeout / 2.0, timeout / 2.0)
    headers = {
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "User-Agent": "TorProxy-connectivity-check",
    }
    primary_problem = "Tor Check returned an unexpected response."

    try:
        with requests.Session() as session:
            session.trust_env = False
            started = time.monotonic()
            try:
                with session.get(
                    TOR_CHECK_URL,
                    proxies=proxies,
                    timeout=timeout_pair,
                    allow_redirects=False,
                    stream=True,
                    headers={**headers, "Accept": "application/json"},
                ) as response:
                    elapsed = max(0.0, (time.monotonic() - started) * 1000.0)
                    if response.status_code == 200:
                        body = _read_bounded(response, MAX_TOR_CHECK_RESPONSE_BYTES)
                        if body is None:
                            return TorProbeResult(
                                False,
                                detail="Tor Check response exceeded the permitted size.",
                                failed_targets=("tor_check",),
                            )
                        try:
                            payload = json.loads(body)
                        except (TypeError, ValueError, UnicodeError):
                            primary_problem = "Tor Check returned invalid JSON."
                        else:
                            if isinstance(payload, dict) and payload.get("IsTor") is True:
                                return TorProbeResult(
                                    True,
                                    latency_ms=elapsed,
                                    detail="Tor Check confirmed this SOCKS connection is using Tor.",
                                    verified_tor=True,
                                    successful_targets=("tor_check",),
                                    latency_samples_ms=(elapsed,),
                                )
                            if isinstance(payload, dict) and payload.get("IsTor") is False:
                                return TorProbeResult(
                                    False,
                                    latency_ms=elapsed,
                                    detail="Tor Check explicitly did not confirm that the request used Tor.",
                                    failed_targets=("tor_check",),
                                    latency_samples_ms=(elapsed,),
                                )
                            primary_problem = "Tor Check returned an unrecognized response."
                    else:
                        primary_problem = f"Tor Check returned HTTP {int(response.status_code)}."
            except requests.RequestException as exc:
                primary_problem = f"Tor Check is unavailable ({type(exc).__name__})."

            successful: list[str] = []
            failed: list[str] = []
            samples: list[float] = []
            fallback_timeout = (
                min(timeout_pair[0], 2.5),
                min(timeout_pair[1], 2.5),
            )
            for target_name, target_url, expected_status in FALLBACK_PROBES:
                started = time.monotonic()
                try:
                    with session.get(
                        target_url,
                        proxies=proxies,
                        timeout=fallback_timeout,
                        allow_redirects=False,
                        stream=True,
                        headers={**headers, "Accept": "*/*"},
                    ) as response:
                        elapsed = max(0.0, (time.monotonic() - started) * 1000.0)
                        if response.status_code != expected_status:
                            failed.append(target_name)
                            continue
                        body = _read_bounded(response, MAX_FALLBACK_RESPONSE_BYTES)
                        if body is None:
                            failed.append(target_name)
                            continue
                        successful.append(target_name)
                        samples.append(elapsed)
                except requests.RequestException:
                    failed.append(target_name)

            if len(successful) == len(FALLBACK_PROBES):
                latency = statistics.median(samples)
                return TorProbeResult(
                    True,
                    latency_ms=latency,
                    detail=(
                        "Tor Check was unavailable, but both independent HTTPS reachability "
                        "probes succeeded through the managed SOCKS endpoint."
                    ),
                    verified_tor=False,
                    successful_targets=tuple(successful),
                    failed_targets=(),
                    latency_samples_ms=tuple(samples),
                )

            return TorProbeResult(
                False,
                detail=(
                    f"{primary_problem} Independent HTTPS checks succeeded "
                    f"{len(successful)}/{len(FALLBACK_PROBES)}."
                ),
                verified_tor=False,
                successful_targets=tuple(successful),
                failed_targets=tuple(failed),
                latency_samples_ms=tuple(samples),
            )
    except requests.RequestException as exc:
        return TorProbeResult(
            False,
            detail=f"Tor connectivity probe failed ({type(exc).__name__}).",
            failed_targets=("tor_check",),
        )
    except (TypeError, ValueError, UnicodeError):
        return TorProbeResult(False, detail="Tor connectivity probe returned an invalid response.")
