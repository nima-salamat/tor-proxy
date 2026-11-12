from __future__ import annotations

import pytest

from torproxy.health import TorProbeResult
from torproxy.network_quality import NetworkQualityWindow


def test_quality_window_reports_percentiles_jitter_and_probe_failures():
    window = NetworkQualityWindow(max_samples=8)
    window.record(TorProbeResult(True, latency_ms=100.0, verified_tor=True))
    window.record(TorProbeResult(True, latency_ms=300.0, verified_tor=True))
    window.record(TorProbeResult(True, latency_ms=200.0, verified_tor=False))
    snapshot = window.record(TorProbeResult(False, detail="probe timeout"))

    assert snapshot["sample_count"] == 4
    assert snapshot["success_rate"] == 0.75
    assert snapshot["failure_ratio"] == 0.25
    assert snapshot["latency_p50_ms"] == 200.0
    assert snapshot["latency_p95_ms"] == 300.0
    assert snapshot["jitter_ms"] == 150.0
    assert snapshot["quality_cost_ms"] > snapshot["latency_p50_ms"]
    assert snapshot["last_probe_healthy"] is False
    assert snapshot["last_probe_verified"] is False


def test_quality_window_is_bounded_and_discards_old_samples():
    window = NetworkQualityWindow(max_samples=3)
    for latency in (1000.0, 900.0, 100.0, 110.0):
        window.record(TorProbeResult(True, latency_ms=latency))

    snapshot = window.snapshot()
    assert snapshot["sample_count"] == 3
    assert snapshot["latency_p50_ms"] == 110.0


def test_quality_window_rejects_invalid_capacity():
    with pytest.raises(ValueError, match="between 3 and 300"):
        NetworkQualityWindow(max_samples=2)
