from __future__ import annotations

import threading
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



def test_monitor_retains_live_thread_and_refuses_duplicate_start_during_shutdown(monkeypatch):
    controllers = [FakeController(19353), FakeController(19353)]
    monitor = TorEventMonitor(
        19353,
        expected_pid=1234,
        controller_factory=lambda _port: controllers.pop(0),
        event_types=("CIRC",),
    )
    entered = threading.Event()
    release = threading.Event()

    def blocked_consume(_record):
        entered.set()
        assert release.wait(timeout=3)

    monkeypatch.setattr(monitor, "_consume", blocked_consume)
    monitor.start()
    # Emit directly through the authenticated event callback.
    monitor._on_event(CircuitEvent("LAUNCHED", "1"))
    assert entered.wait(timeout=2)

    with pytest.raises(RuntimeError, match="still active"):
        monitor.stop(timeout=0.05)
    first_thread = monitor._thread
    assert first_thread is not None and first_thread.is_alive()

    with pytest.raises(RuntimeError, match="still shutting down"):
        monitor.start()

    release.set()
    first_thread.join(timeout=2)
    assert not first_thread.is_alive()
    monitor.stop(timeout=1)
    assert monitor._thread is None



def test_monitor_closes_controller_when_consumer_thread_cannot_start(monkeypatch):
    controller = FakeController(19354)

    class FailedThread:
        ident = None

        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise RuntimeError("simulated thread resource exhaustion")

        def is_alive(self):
            return False

    monkeypatch.setattr("torproxy.circuit_monitor.threading.Thread", FailedThread)
    monitor = TorEventMonitor(
        19354,
        expected_pid=1234,
        controller_factory=lambda _port: controller,
        event_types=("CIRC",),
    )

    with pytest.raises(RuntimeError, match="resource exhaustion"):
        monitor.start()

    assert controller.closed is True
    assert controller.listener is None
    assert monitor._controller is None
    assert monitor._thread is None
    assert monitor._stop.is_set()
