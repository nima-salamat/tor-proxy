"""Bounded rolling quality metrics for managed Tor SOCKS backends."""
from __future__ import annotations

import math
import statistics
import threading
from collections import deque
from typing import Any


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return ordered[index]


class NetworkQualityWindow:
    """Keep a small rolling sample of probe outcomes without storing destinations.

    Latency measurements are end-to-end HTTPS request times through the
    managed SOCKS endpoint, not ICMP ping or per-hop Tor latency.
    """

    def __init__(self, max_samples: int = 30) -> None:
        if type(max_samples) is not int or not 3 <= max_samples <= 300:
            raise ValueError("max_samples must be an integer between 3 and 300.")
        self._samples: deque[tuple[bool, float | None, bool]] = deque(maxlen=max_samples)
        self._lock = threading.RLock()

    def record(self, result: Any) -> dict[str, float | int | bool | None]:
        healthy = bool(getattr(result, "healthy", False))
        verified = bool(getattr(result, "verified_tor", False))
        raw_latency = getattr(result, "latency_ms", None)
        try:
            latency = max(0.0, float(raw_latency)) if raw_latency is not None else None
        except (TypeError, ValueError, OverflowError):
            latency = None
        with self._lock:
            self._samples.append((healthy, latency, verified))
            return self._snapshot_unlocked()

    def snapshot(self) -> dict[str, float | int | bool | None]:
        with self._lock:
            return self._snapshot_unlocked()

    def _snapshot_unlocked(self) -> dict[str, float | int | bool | None]:
        samples = tuple(self._samples)
        latencies = [latency for _healthy, latency, _verified in samples if latency is not None]
        failures = sum(1 for healthy, _latency, _verified in samples if not healthy)
        failure_ratio = failures / len(samples) if samples else 0.0
        p50 = statistics.median(latencies) if latencies else None
        p95 = _percentile(latencies, 0.95)
        differences = [abs(right - left) for left, right in zip(latencies, latencies[1:])]
        jitter = statistics.median(differences) if differences else 0.0
        if p50 is None or p95 is None:
            quality_cost = None
        else:
            quality_cost = (
                p50
                + max(0.0, p95 - p50) * 0.35
                + jitter * 1.25
                + failure_ratio * 750.0
            )
        latest = samples[-1] if samples else (False, None, False)
        return {
            "sample_count": len(samples),
            "success_rate": (len(samples) - failures) / len(samples) if samples else 0.0,
            "failure_ratio": failure_ratio,
            "latency_p50_ms": p50,
            "latency_p95_ms": p95,
            "jitter_ms": jitter,
            "quality_cost_ms": quality_cost,
            "last_probe_healthy": latest[0],
            "last_probe_verified": latest[2],
        }
