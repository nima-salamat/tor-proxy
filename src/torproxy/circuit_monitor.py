"""Privacy-preserving Tor ControlPort event monitor for one managed instance."""
from __future__ import annotations

import logging
import queue
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable

LOGGER = logging.getLogger(__name__)
_EVENT_QUEUE_SIZE = 1024
_MAX_TRACKED_CIRCUITS = 512
_BUILD_SAMPLE_LIMIT = 64


@dataclass(frozen=True)
class TorEventSnapshot:
    circuits_launched: int = 0
    circuits_built: int = 0
    circuits_failed: int = 0
    circuit_failure_ratio: float = 0.0
    circuit_build_p50_ms: float | None = None
    circuit_build_p95_ms: float | None = None
    streams_failed: int = 0
    streams_detached: int = 0
    or_connections_connected: int = 0
    or_connections_failed: int = 0
    or_connections_closed: int = 0
    recent_circuit_sample_count: int = 0
    recent_circuit_failure_ratio: float | None = None
    recent_or_connection_sample_count: int = 0
    recent_or_connection_failure_ratio: float | None = None
    bytes_read: int = 0
    bytes_written: int = 0
    dropped_events: int = 0
    queue_depth: int = 0
    last_event_at: float | None = None


def _event_kind(event: object) -> str | None:
    name = type(event).__name__.lower()
    if "circuit" in name:
        return "circuit"
    if "stream" in name:
        return "stream"
    if "orconn" in name or "or_connection" in name:
        return "orconn"
    if "bandwidth" in name:
        return "bandwidth"
    return None


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * percentile + 0.999999) - 1))
    return ordered[index]


class TorEventMonitor:
    """Collect aggregate CIRC/STREAM/ORCONN/BW metrics for one Tor process.

    The callback never performs blocking work and never stores destination
    hosts, stream targets, circuit paths, relay fingerprints, or raw log text.
    A bounded queue isolates Stem's event thread from metrics aggregation.
    """

    def __init__(
        self,
        control_port: int,
        expected_pid: int | None,
        *,
        controller_factory: Callable[[int], object] | None = None,
        event_types: tuple[object, ...] | None = None,
        queue_size: int = _EVENT_QUEUE_SIZE,
    ) -> None:
        if type(control_port) is not int or not 1 <= control_port <= 65535:
            raise ValueError("ControlPort must be an integer between 1 and 65535.")
        if expected_pid is not None and (type(expected_pid) is not int or expected_pid <= 0):
            raise ValueError("expected_pid must be a positive process ID or None.")
        if type(queue_size) is not int or not 32 <= queue_size <= 16384:
            raise ValueError("queue_size must be between 32 and 16384.")
        self.control_port = control_port
        self.expected_pid = expected_pid
        self._controller_factory = controller_factory
        self._event_types = event_types
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=queue_size)
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._controller = None
        self._thread: threading.Thread | None = None
        self._dropped_events = 0
        self._circuit_started: dict[str, float] = {}
        self._build_durations_ms: deque[float] = deque(maxlen=_BUILD_SAMPLE_LIMIT)
        self._recent_circuit_outcomes: deque[bool] = deque(maxlen=64)
        self._recent_or_connection_outcomes: deque[bool] = deque(maxlen=32)
        self._counts = {
            "circuits_launched": 0,
            "circuits_built": 0,
            "circuits_failed": 0,
            "streams_failed": 0,
            "streams_detached": 0,
            "or_connections_connected": 0,
            "or_connections_failed": 0,
            "or_connections_closed": 0,
            "bytes_read": 0,
            "bytes_written": 0,
        }
        self._last_event_at: float | None = None

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    def _make_controller(self):
        if self._controller_factory is not None:
            return self._controller_factory(self.control_port)
        from stem.control import Controller

        return Controller.from_port(address="127.0.0.1", port=self.control_port)

    def _resolve_event_types(self) -> tuple[object, ...]:
        if self._event_types is not None:
            return self._event_types
        from stem.control import EventType

        return (EventType.CIRC, EventType.STREAM, EventType.ORCONN, EventType.BW)

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            self._stop.clear()
            controller = self._make_controller()
            try:
                controller.authenticate()
                reported_pid = controller.get_info("process/pid", None)
                if self.expected_pid is not None:
                    if reported_pid is None or not str(reported_pid).isdecimal():
                        raise RuntimeError("Tor ControlPort did not report its process ID.")
                    if int(reported_pid) != self.expected_pid:
                        raise RuntimeError("Tor ControlPort belongs to a different process.")
                controller.add_event_listener(self._on_event, *self._resolve_event_types())
            except Exception:
                try:
                    controller.close()
                except Exception:
                    pass
                raise
            self._controller = controller
            self._thread = threading.Thread(
                target=self._consume_loop,
                name=f"torproxy-events-{self.control_port}",
                daemon=True,
            )
            self._thread.start()

    def _on_event(self, event: object) -> None:
        kind = _event_kind(event)
        if kind is None or self._stop.is_set():
            return
        record = {
            "kind": kind,
            "status": str(getattr(event, "status", "") or "").upper(),
            "event_id": str(getattr(event, "id", "") or "") if kind == "circuit" else "",
            "read": int(getattr(event, "read", 0) or 0) if kind == "bandwidth" else 0,
            "written": int(getattr(event, "written", 0) or 0) if kind == "bandwidth" else 0,
            "at": time.monotonic(),
        }
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            with self._lock:
                self._dropped_events += 1

    def _consume_loop(self) -> None:
        while not self._stop.is_set() or not self._queue.empty():
            try:
                record = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                self._consume(record)
            except Exception:
                LOGGER.debug("Discarded an invalid Tor event record.", exc_info=True)
            finally:
                self._queue.task_done()

    def _consume(self, record: dict) -> None:
        kind = record["kind"]
        status = record["status"]
        event_id = record["event_id"]
        now = float(record["at"])
        with self._lock:
            self._last_event_at = time.time()
            if kind == "circuit":
                if status == "LAUNCHED":
                    self._counts["circuits_launched"] += 1
                    if event_id:
                        self._circuit_started[event_id] = now
                        if len(self._circuit_started) > _MAX_TRACKED_CIRCUITS:
                            oldest = next(iter(self._circuit_started))
                            self._circuit_started.pop(oldest, None)
                elif status == "BUILT":
                    self._counts["circuits_built"] += 1
                    self._recent_circuit_outcomes.append(True)
                    started = self._circuit_started.pop(event_id, None)
                    if started is not None:
                        self._build_durations_ms.append(max(0.0, now - started) * 1000.0)
                elif status == "FAILED":
                    self._counts["circuits_failed"] += 1
                    self._recent_circuit_outcomes.append(False)
                    started = self._circuit_started.pop(event_id, None)
                    if started is not None:
                        self._build_durations_ms.append(max(0.0, now - started) * 1000.0)
                elif status == "CLOSED" and event_id:
                    self._circuit_started.pop(event_id, None)
            elif kind == "stream":
                if status == "FAILED":
                    self._counts["streams_failed"] += 1
                elif status == "DETACHED":
                    self._counts["streams_detached"] += 1
            elif kind == "orconn":
                if status == "CONNECTED":
                    self._counts["or_connections_connected"] += 1
                    self._recent_or_connection_outcomes.append(True)
                elif status == "FAILED":
                    self._counts["or_connections_failed"] += 1
                    self._recent_or_connection_outcomes.append(False)
                elif status == "CLOSED":
                    self._counts["or_connections_closed"] += 1
            elif kind == "bandwidth":
                self._counts["bytes_read"] += max(0, int(record["read"]))
                self._counts["bytes_written"] += max(0, int(record["written"]))

    def snapshot(self) -> TorEventSnapshot:
        with self._lock:
            built_or_failed = self._counts["circuits_built"] + self._counts["circuits_failed"]
            durations = list(self._build_durations_ms)
            recent_circuits = tuple(self._recent_circuit_outcomes)
            recent_or_connections = tuple(self._recent_or_connection_outcomes)
            return TorEventSnapshot(
                **self._counts,
                circuit_failure_ratio=(
                    self._counts["circuits_failed"] / built_or_failed if built_or_failed else 0.0
                ),
                circuit_build_p50_ms=statistics.median(durations) if durations else None,
                circuit_build_p95_ms=_percentile(durations, 0.95),
                recent_circuit_sample_count=len(recent_circuits),
                recent_circuit_failure_ratio=(
                    recent_circuits.count(False) / len(recent_circuits)
                    if len(recent_circuits) >= 5 else None
                ),
                recent_or_connection_sample_count=len(recent_or_connections),
                recent_or_connection_failure_ratio=(
                    recent_or_connections.count(False) / len(recent_or_connections)
                    if len(recent_or_connections) >= 5 else None
                ),
                dropped_events=self._dropped_events,
                queue_depth=self._queue.qsize(),
                last_event_at=self._last_event_at,
            )

    def stop(self, *, timeout: float = 2.0) -> None:
        self._stop.set()
        with self._lock:
            controller, self._controller = self._controller, None
            thread = self._thread
            self._thread = None
        if controller is not None:
            try:
                controller.remove_event_listener(self._on_event)
            except Exception:
                pass
            try:
                controller.close()
            except Exception:
                pass
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.1, float(timeout)))
        if thread is not None and thread.is_alive():
            LOGGER.warning("Tor event collector did not stop before its bounded shutdown deadline.")
