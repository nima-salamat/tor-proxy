from __future__ import annotations

import time

import pytest

from torproxy.circuit_monitor import TorEventMonitor


class FakeController:
    def __init__(self, port, pid="1234"):
        self.port = port
        self.pid = pid
        self.listener = None
        self.closed = False
        self.event_types = ()

    def authenticate(self):
        return None

    def get_info(self, key, default=None):
        assert key == "process/pid"
        return self.pid

    def add_event_listener(self, listener, *event_types):
        self.listener = listener
        self.event_types = event_types

    def remove_event_listener(self, listener):
        if self.listener == listener:
            self.listener = None

    def close(self):
        self.closed = True

    def emit(self, event):
        assert self.listener is not None
        self.listener(event)


class CircuitEvent:
    def __init__(self, status, circuit_id):
        self.status = status
        self.id = circuit_id


class StreamEvent:
    def __init__(self, status):
        self.status = status


class ORConnEvent:
    def __init__(self, status):
        self.status = status


class BandwidthEvent:
    def __init__(self, read, written):
        self.read = read
        self.written = written


def _wait_for(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


def test_monitor_collects_aggregate_events_without_retaining_destinations():
    controller = FakeController(19351)
    monitor = TorEventMonitor(
        19351,
        expected_pid=1234,
        controller_factory=lambda port: controller,
        event_types=("CIRC", "STREAM", "ORCONN", "BW"),
    )
    monitor.start()
    try:
        controller.emit(CircuitEvent("LAUNCHED", "42"))
        controller.emit(StreamEvent("FAILED"))
        controller.emit(ORConnEvent("FAILED"))
        controller.emit(BandwidthEvent(4096, 2048))
        time.sleep(0.02)
        controller.emit(CircuitEvent("BUILT", "42"))
        for index in range(4):
            circuit_id = str(100 + index)
            controller.emit(CircuitEvent("LAUNCHED", circuit_id))
            controller.emit(CircuitEvent("BUILT", circuit_id))
        controller.emit(CircuitEvent("LAUNCHED", "999"))
        controller.emit(CircuitEvent("FAILED", "999"))

        assert _wait_for(
            lambda: monitor.snapshot().circuits_built == 5
            and monitor.snapshot().circuits_failed == 1
        )
        snapshot = monitor.snapshot()
        assert snapshot.circuits_launched == 6
        assert snapshot.circuits_built == 5
        assert snapshot.circuits_failed == 1
        assert snapshot.streams_failed == 1
        assert snapshot.or_connections_failed == 1
        assert snapshot.bytes_read == 4096
        assert snapshot.bytes_written == 2048
        assert snapshot.circuit_build_p50_ms is not None
        assert snapshot.recent_circuit_sample_count == 6
        assert snapshot.recent_circuit_failure_ratio == pytest.approx(1 / 6)
        assert snapshot.recent_or_connection_failure_ratio is None
        assert not hasattr(snapshot, "destination")
        assert not hasattr(snapshot, "relay_fingerprint")
    finally:
        monitor.stop()

    assert controller.closed is True


def test_monitor_rejects_control_port_from_a_different_process():
    controller = FakeController(19352, pid="9999")
    monitor = TorEventMonitor(
        19352,
        expected_pid=1234,
        controller_factory=lambda port: controller,
        event_types=("CIRC",),
    )

    with pytest.raises(RuntimeError, match="different process"):
        monitor.start()

    assert controller.closed is True
