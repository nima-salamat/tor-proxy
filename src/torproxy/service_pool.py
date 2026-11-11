"""Lifecycle coordinator for multiple isolated Tor service instances.

Each service owns a unique Tor DataDirectory, torrc/log path, and listener-port
set. The pool is deliberately independent of the desktop UI so future profile
screens and headless callers can manage services through the same safe API.
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path

from .health import TorProbeResult, probe_tor_socks
from .paths import user_directories
from .tor_manager import TorManager, TorManagerError, TorSettings, TorState

DEFAULT_SERVICE_WORKERS = 4
MAX_SERVICE_WORKERS = 8
LOGGER = logging.getLogger(__name__)
_SERVICE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class TorServicePoolError(TorManagerError):
    """A service could not be registered or safely managed by the pool."""


@dataclass
class _ServiceEntry:
    service_id: str
    settings: TorSettings
    manager: TorManager
    start_lock: threading.Lock
    start_cancel_event: threading.Event = field(default_factory=threading.Event)
    stop_calls: int = 0
    active_calls: int = 0
    stopping: bool = False
    network_healthy: bool = False
    network_health: str = "unchecked"
    health_latency_ms: float | None = None
    consecutive_health_failures: int = 0
    last_health_check: float | None = None
    last_health_error: str = "A real Tor egress check has not run yet."


ManagerFactory = Callable[[TorSettings], TorManager]


class TorServicePool:
    """Own a registry of independent TorManager instances.

    Registration reserves every configured listener port and state directory,
    even while a service is stopped. start_all/stop_all operate concurrently,
    but each instance remains isolated and failures are returned per service.
    """

    def __init__(
        self,
        *,
        manager_factory: ManagerFactory | None = None,
        reserved_ports: Iterable[int] = (),
        reserved_paths: Iterable[str | Path] = (),
        max_workers: int = DEFAULT_SERVICE_WORKERS,
        directories=None,
        health_probe: Callable[..., TorProbeResult] | None = None,
        health_interval: float = 20.0,
    ) -> None:
        self._manager_factory = manager_factory or TorManager
        self._directories = directories or user_directories()
        self._reserved_ports = {self._validate_port(port) for port in reserved_ports}
        self._reserved_paths = tuple(self._canonical_path(Path(path)) for path in reserved_paths)
        self._max_workers = max(1, min(int(max_workers), MAX_SERVICE_WORKERS))
        self._services: dict[str, _ServiceEntry] = {}
        self._lock = threading.RLock()
        self._health_probe = health_probe or probe_tor_socks
        self._health_interval = max(0.0, min(3600.0, float(health_interval)))
        self._health_stop = threading.Event()
        self._health_thread: threading.Thread | None = None

    @staticmethod
    def _validate_port(port: int) -> int:
        if type(port) is not int or not 1 <= port <= 65535:
            raise TorServicePoolError("Reserved listener ports must be integers in the range 1..65535.")
        return port

    @staticmethod
    def _canonical_path(path: Path) -> Path:
        return Path(os.path.normcase(str(Path(path).expanduser().resolve(strict=False))))

    @classmethod
    def _paths_overlap(cls, left: Path, right: Path) -> bool:
        left_canonical = cls._canonical_path(left)
        right_canonical = cls._canonical_path(right)
        try:
            right_canonical.relative_to(left_canonical)
            return True
        except ValueError:
            pass
        try:
            left_canonical.relative_to(right_canonical)
            return True
        except ValueError:
            return False

    @staticmethod
    def _state_value(manager: TorManager) -> str:
        state = getattr(manager, "state", TorState.STOPPED)
        return str(getattr(state, "value", state)).lower().split(".")[-1]

    @classmethod
    def _reported_state(cls, manager: TorManager) -> str:
        """Expose an exited Tor child immediately, before monitor reconciliation."""
        state = cls._state_value(manager)
        process = getattr(manager, "process", None)
        if state == "ready" and process is not None:
            try:
                if process.poll() is not None:
                    return "failed"
            except Exception:
                # An uninspectable child must never be advertised as healthy.
                return "failed"
        return state

    @staticmethod
    def _process_is_alive(manager: TorManager) -> bool:
        process = getattr(manager, "process", None)
        try:
            return process is not None and process.poll() is None
        except Exception:
            # An uninspectable process is not safe to unregister/reuse.
            return True

    def _prepare_settings(self, service_id: str, settings: TorSettings) -> TorSettings:
        data_root = self._directories.data / "tor-services"
        log_root = self._directories.logs / "tor-services"
        data_directory = Path(settings.data_directory) if settings.data_directory is not None else data_root / service_id
        log_path = Path(settings.log_path) if settings.log_path is not None else log_root / service_id / "tor.log"
        return replace(settings, data_directory=data_directory, log_path=log_path)

    def _validate_resources(self, service_id: str, settings: TorSettings) -> None:
        ports = [settings.socks_port, settings.control_port]
        if settings.dns_port is not None:
            ports.append(settings.dns_port)
        collisions = sorted(set(ports) & self._reserved_ports)
        if collisions:
            raise TorServicePoolError(
                f"Tor service '{service_id}' conflicts with a reserved application listener port: "
                + ", ".join(map(str, collisions))
            )
        if self._paths_overlap(settings.data_directory, settings.log_path):
            raise TorServicePoolError(
                f"Tor service '{service_id}' must keep its log file outside its DataDirectory."
            )

        for reserved_path in self._reserved_paths:
            if self._paths_overlap(settings.data_directory, reserved_path) or self._paths_overlap(
                settings.log_path, reserved_path
            ):
                raise TorServicePoolError(
                    f"Tor service '{service_id}' overlaps a reserved primary Tor state or log path."
                )

        for existing_id, existing in self._services.items():
            existing_ports = {existing.settings.socks_port, existing.settings.control_port}
            if existing.settings.dns_port is not None:
                existing_ports.add(existing.settings.dns_port)
            overlap = sorted(set(ports) & existing_ports)
            if overlap:
                raise TorServicePoolError(
                    f"Tor service '{service_id}' reuses listener port(s) owned by '{existing_id}': "
                    + ", ".join(map(str, overlap))
                )
            if self._paths_overlap(settings.data_directory, existing.settings.data_directory):
                raise TorServicePoolError(
                    f"Tor service '{service_id}' has a DataDirectory that overlaps '{existing_id}'. "
                    "Each isolated Tor process must own a separate, non-nested directory."
                )
            if self._paths_overlap(settings.log_path, existing.settings.log_path):
                raise TorServicePoolError(
                    f"Tor service '{service_id}' has a log path that overlaps '{existing_id}'."
                )
            if self._paths_overlap(settings.data_directory, existing.settings.log_path) or self._paths_overlap(
                settings.log_path, existing.settings.data_directory
            ):
                raise TorServicePoolError(
                    f"Tor service '{service_id}' overlaps the state and log paths owned by '{existing_id}'."
                )

    def register(self, service_id: str, settings: TorSettings) -> TorManager:
        """Register a stopped service and return its dedicated TorManager."""
        service_id = str(service_id).strip()
        if not _SERVICE_ID.fullmatch(service_id):
            raise TorServicePoolError(
                "Service IDs must start with a letter or digit and contain only letters, digits, '.', '_' or '-'."
            )
        if not isinstance(settings, TorSettings):
            raise TypeError("settings must be a TorSettings instance.")

        with self._lock:
            if service_id in self._services:
                raise TorServicePoolError(f"Tor service '{service_id}' is already registered.")
            prepared = self._prepare_settings(service_id, settings)
            self._validate_resources(service_id, prepared)
            manager = self._manager_factory(prepared)
            entry = _ServiceEntry(
                service_id=service_id,
                settings=prepared,
                manager=manager,
                start_lock=threading.Lock(),
            )
            manager._start_cancel_event = entry.start_cancel_event
            self._services[service_id] = entry
            return manager

    def get(self, service_id: str) -> TorManager:
        with self._lock:
            try:
                return self._services[service_id].manager
            except KeyError as exc:
                raise TorServicePoolError(f"Unknown Tor service '{service_id}'.") from exc

    def settings_for(self, service_id: str) -> TorSettings:
        with self._lock:
            try:
                return self._services[service_id].settings
            except KeyError as exc:
                raise TorServicePoolError(f"Unknown Tor service '{service_id}'.") from exc

    @property
    def max_workers(self) -> int:
        with self._lock:
            return self._max_workers

    def set_max_workers(self, max_workers: int) -> None:
        """Update the bounded concurrency used by future start_all/stop_all calls."""
        if type(max_workers) is not int or not 1 <= max_workers <= MAX_SERVICE_WORKERS:
            raise TorServicePoolError(
                f"Service worker count must be an integer between 1 and {MAX_SERVICE_WORKERS}."
            )
        with self._lock:
            if any(entry.active_calls or entry.stopping for entry in self._services.values()):
                raise TorServicePoolError(
                    "Service worker count cannot be changed while a Tor service operation is running."
                )
            self._max_workers = max_workers

    @property
    def service_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._services)

    def status(self, service_id: str | None = None):
        """Return safe lifecycle metadata without exposing bridge records or secrets."""
        with self._lock:
            entries = (
                [self._services[service_id]]
                if service_id is not None and service_id in self._services
                else list(self._services.values()) if service_id is None else []
            )
            if service_id is not None and not entries:
                raise TorServicePoolError(f"Unknown Tor service '{service_id}'.")
            result = {}
            for entry in entries:
                state = self._reported_state(entry.manager)
                process_exited = state == "failed" and self._state_value(entry.manager) == "ready"
                result[entry.service_id] = {
                    "state": state,
                    "socks_port": entry.settings.socks_port,
                    "control_port": entry.settings.control_port,
                    "dns_port": entry.settings.dns_port,
                    "data_directory": str(entry.settings.data_directory),
                    "pid": getattr(getattr(entry.manager, "process", None), "pid", None),
                    "network_healthy": bool(entry.network_healthy and not process_exited),
                    "network_health": "unhealthy" if process_exited else entry.network_health,
                    "latency_ms": None if process_exited else entry.health_latency_ms,
                    "consecutive_health_failures": entry.consecutive_health_failures,
                    "last_health_check": entry.last_health_check,
                    "last_health_error": (
                        "Tor process exited unexpectedly; cleanup is pending."
                        if process_exited else entry.last_health_error
                    ),
                }
        return result[service_id] if service_id is not None else result

    def _run_health_probe(self, port: int) -> TorProbeResult:
        try:
            return self._health_probe(int(port), timeout=8.0)
        except Exception as exc:
            return TorProbeResult(
                False,
                detail=f"Tor connectivity probe failed ({type(exc).__name__}).",
            )

    def _apply_health_result(
        self,
        service_id: str,
        entry: _ServiceEntry,
        result: TorProbeResult,
    ) -> None:
        with self._lock:
            if self._services.get(service_id) is not entry or entry.stopping:
                return
            manager_state = self._state_value(entry.manager)
            reported_state = self._reported_state(entry.manager)
            if manager_state != "ready" or reported_state != "ready":
                entry.network_healthy = False
                entry.network_health = (
                    "unhealthy" if reported_state == "failed"
                    else "stopped" if manager_state == "stopped"
                    else "not_ready"
                )
                entry.health_latency_ms = None
                entry.consecutive_health_failures = 0
                entry.last_health_error = (
                    "Tor process exited unexpectedly; cleanup is pending."
                    if reported_state == "failed"
                    else "The Tor process is not in READY state."
                )
            elif result.healthy:
                sample = max(0.0, float(result.latency_ms or 0.0))
                previous = entry.health_latency_ms
                entry.health_latency_ms = sample if previous is None else previous * 0.65 + sample * 0.35
                entry.network_healthy = True
                entry.network_health = "healthy"
                entry.consecutive_health_failures = 0
                entry.last_health_error = ""
            else:
                failures = entry.consecutive_health_failures + 1
                entry.consecutive_health_failures = failures
                entry.network_healthy = entry.network_healthy and failures < 2
                entry.network_health = "degraded" if entry.network_healthy else "unhealthy"
                entry.last_health_error = result.detail or "Tor egress check failed."
            entry.last_health_check = time.time()

    def _reconcile_exited_services(self) -> None:
        """Reap exited Tor children without racing start/stop operations."""
        with self._lock:
            candidates = list(self._services.items())

        for service_id, entry in candidates:
            # start_service holds this lock across process start and its first
            # egress check. Never stop that manager concurrently.
            if not entry.start_lock.acquire(blocking=False):
                continue
            try:
                with self._lock:
                    if self._services.get(service_id) is not entry or entry.stopping:
                        continue
                    if self._state_value(entry.manager) != "ready":
                        continue
                    process = getattr(entry.manager, "process", None)
                if process is None:
                    continue
                try:
                    exit_code = process.poll()
                except Exception:
                    # An uninspectable child is not safe to treat as dead.
                    continue
                if exit_code is None:
                    continue

                detail = f"Tor process exited unexpectedly (exit code {exit_code})."
                try:
                    # TorManager.stop() closes the stale Stem controller and
                    # releases the per-profile DataDirectory lock after exit.
                    entry.manager.stop()
                except Exception as exc:
                    with self._lock:
                        if self._services.get(service_id) is entry:
                            entry.network_healthy = False
                            entry.network_health = "unhealthy"
                            entry.health_latency_ms = None
                            entry.last_health_error = (
                                f"{detail} Cleanup failed: {type(exc).__name__}: {exc}"
                            )
                    LOGGER.exception(
                        "Could not reconcile an exited isolated Tor process for '%s'.",
                        service_id,
                    )
                    continue

                with self._lock:
                    if self._services.get(service_id) is entry:
                        entry.network_healthy = False
                        entry.network_health = "stopped"
                        entry.health_latency_ms = None
                        entry.consecutive_health_failures = 0
                        entry.last_health_error = detail
                        entry.last_health_check = time.time()
            finally:
                entry.start_lock.release()

    def _probe_running_services(self) -> None:
        self._reconcile_exited_services()
        with self._lock:
            candidates = [
                (service_id, entry, entry.settings.socks_port)
                for service_id, entry in self._services.items()
                if not entry.stopping and self._reported_state(entry.manager) == "ready"
            ]
        if not candidates:
            return
        with ThreadPoolExecutor(
            max_workers=max(1, min(self.max_workers, len(candidates))),
            thread_name_prefix="torproxy-service-health",
        ) as executor:
            futures = {
                executor.submit(self._run_health_probe, port): (service_id, entry)
                for service_id, entry, port in candidates
            }
            for future, (service_id, entry) in futures.items():
                try:
                    result = future.result()
                except Exception as exc:
                    result = TorProbeResult(
                        False,
                        detail=f"Tor connectivity probe failed ({type(exc).__name__}).",
                    )
                self._apply_health_result(service_id, entry, result)

    def _health_monitor_loop(self) -> None:
        while not self._health_stop.wait(self._health_interval):
            try:
                self._probe_running_services()
            except Exception:
                # Monitoring must never terminate service ownership or Stop,
                # but retain a diagnostic rather than silently hiding the bug.
                LOGGER.exception("The isolated Tor health-monitor cycle failed.")

    def _ensure_health_monitor(self) -> None:
        if self._health_interval <= 0:
            return
        with self._lock:
            if self._health_thread is not None and self._health_thread.is_alive():
                return
            self._health_stop.clear()
            self._health_thread = threading.Thread(
                target=self._health_monitor_loop,
                name="torproxy-isolated-service-health",
                daemon=True,
            )
            self._health_thread.start()

    def close(self, *, timeout: float = 10.0) -> None:
        """Stop the health monitor; callers must stop Tor services separately."""
        self._health_stop.set()
        thread = self._health_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.1, float(timeout)))
        if thread is not None and thread.is_alive():
            raise TorServicePoolError("The isolated Tor service health monitor is still active.")
        self._health_thread = None

    def start_service(self, service_id: str) -> None:
        with self._lock:
            entry = self._services.get(service_id)
            if entry is None:
                raise TorServicePoolError(f"Unknown Tor service '{service_id}'.")
            if entry.stopping:
                raise TorServicePoolError(f"Tor service '{service_id}' is stopping.")
            entry.start_cancel_event.clear()
            entry.active_calls += 1
            acquired = entry.start_lock.acquire(blocking=False)
            if not acquired:
                entry.active_calls -= 1
                raise TorServicePoolError(f"Tor service '{service_id}' already has a start operation in progress.")
            entry.network_health = "checking"
            entry.network_healthy = False
            entry.health_latency_ms = None
            entry.consecutive_health_failures = 0
            entry.last_health_error = "Waiting for a real Tor egress check."

        try:
            entry.manager.start()
            result = self._run_health_probe(entry.settings.socks_port)
            self._apply_health_result(service_id, entry, result)
            self._ensure_health_monitor()
        except Exception as exc:
            with self._lock:
                if self._services.get(service_id) is entry:
                    entry.network_healthy = False
                    entry.network_health = "not_ready"
                    entry.last_health_error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            entry.start_lock.release()
            with self._lock:
                entry.active_calls -= 1

    def stop_service(self, service_id: str) -> None:
        with self._lock:
            entry = self._services.get(service_id)
            if entry is None:
                raise TorServicePoolError(f"Unknown Tor service '{service_id}'.")
            if entry.stopping:
                raise TorServicePoolError(f"Tor service '{service_id}' is already stopping.")
            entry.stopping = True
            entry.stop_calls += 1
            entry.start_cancel_event.set()
            entry.active_calls += 1

        error = None
        try:
            # First request stop immediately. This is intentionally allowed to
            # race with start(): TorManager.stop() signals its cancellation event.
            try:
                entry.manager.stop()
            except Exception as exc:
                error = exc

            # Wait for any start() that began just before stopping was marked.
            # Re-issue stop while holding start_lock so a late-starting operation
            # cannot leave a child alive after stop_service() returns.
            with entry.start_lock:
                try:
                    entry.manager.stop()
                except Exception as exc:
                    error = exc
                else:
                    # A failed first stop can be a race with a just-starting
                    # operation. The retry above is authoritative once the
                    # start lock is held and no new start can enter.
                    error = None

            if error is not None:
                raise TorServicePoolError(
                    f"Tor service '{service_id}' did not stop cleanly: {error}"
                ) from error
        finally:
            with self._lock:
                entry.network_healthy = False
                entry.health_latency_ms = None
                entry.consecutive_health_failures = 0
                entry.network_health = (
                    "stopped" if self._state_value(entry.manager) == "stopped" else "not_ready"
                )
                entry.last_health_error = ""
                entry.stop_calls = max(0, entry.stop_calls - 1)
                entry.stopping = entry.stop_calls > 0
                entry.active_calls -= 1

    def force_stop_service(self, service_id: str) -> None:
        """Cancel startup and kill the owned Tor process immediately."""
        with self._lock:
            entry = self._services.get(service_id)
            if entry is None:
                raise TorServicePoolError(f"Unknown Tor service '{service_id}'.")
            # Force-stop may intentionally join an in-progress graceful stop.
            # Count both operations so one completion cannot clear the other's
            # stopping state while the process is still being reconciled.
            entry.stopping = True
            entry.stop_calls += 1
            entry.start_cancel_event.set()
            entry.active_calls += 1

        error = None
        try:
            force_stop = getattr(entry.manager, "force_stop", None)
            try:
                force_stop() if callable(force_stop) else entry.manager.stop()
            except Exception as exc:
                error = exc

            # Reconcile after any concurrent start() has observed cancellation.
            with entry.start_lock:
                force_stop = getattr(entry.manager, "force_stop", None)
                try:
                    force_stop() if callable(force_stop) else entry.manager.stop()
                except Exception as exc:
                    error = exc
                else:
                    error = None

            if error is not None:
                raise TorServicePoolError(
                    f"Tor service '{service_id}' could not be force-stopped: {error}"
                ) from error
        finally:
            with self._lock:
                entry.network_healthy = False
                entry.health_latency_ms = None
                entry.consecutive_health_failures = 0
                entry.network_health = (
                    "stopped" if self._state_value(entry.manager) == "stopped" else "not_ready"
                )
                entry.last_health_error = ""
                entry.stop_calls = max(0, entry.stop_calls - 1)
                entry.stopping = entry.stop_calls > 0
                entry.active_calls -= 1

    def _run_many(self, service_ids: Iterable[str], operation: str) -> dict[str, str | None]:
        selected = tuple(dict.fromkeys(service_ids))
        with self._lock:
            unknown = [service_id for service_id in selected if service_id not in self._services]
        if unknown:
            raise TorServicePoolError("Unknown Tor service(s): " + ", ".join(unknown))

        results: dict[str, str | None] = {}
        if not selected:
            return results
        worker_count = min(self._max_workers, len(selected))
        method = self.start_service if operation == "start" else self.stop_service
        with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix=f"torproxy-{operation}-all") as executor:
            futures = {executor.submit(method, service_id): service_id for service_id in selected}
            for future in as_completed(futures):
                service_id = futures[future]
                try:
                    future.result()
                    results[service_id] = None
                except Exception as exc:
                    results[service_id] = f"{type(exc).__name__}: {exc}"
        return {service_id: results[service_id] for service_id in selected}

    def start_all(self, service_ids: Iterable[str] | None = None) -> dict[str, str | None]:
        """Start registered services concurrently; None means that service succeeded."""
        with self._lock:
            selected = tuple(self._services) if service_ids is None else tuple(service_ids)
        return self._run_many(selected, "start")

    def stop_all(self, service_ids: Iterable[str] | None = None) -> dict[str, str | None]:
        """Stop registered services concurrently; failures are isolated per service."""
        with self._lock:
            selected = tuple(self._services) if service_ids is None else tuple(service_ids)
        return self._run_many(selected, "stop")

    def unregister(self, service_id: str) -> None:
        """Forget a stopped service; never detach a running or starting process."""
        with self._lock:
            entry = self._services.get(service_id)
            if entry is None:
                raise TorServicePoolError(f"Unknown Tor service '{service_id}'.")
            if entry.active_calls or entry.stopping:
                raise TorServicePoolError(f"Tor service '{service_id}' has an operation in progress.")
            if not entry.start_lock.acquire(blocking=False):
                raise TorServicePoolError(f"Tor service '{service_id}' has a start operation in progress.")
            try:
                if (
                    self._process_is_alive(entry.manager)
                    or getattr(entry.manager, "_data_directory_lock_handle", None) is not None
                    or self._state_value(entry.manager) in {
                        "starting", "bootstrapping", "ready", "stopping"
                    }
                ):
                    raise TorServicePoolError(
                        f"Tor service '{service_id}' is still active; stop it before unregistering."
                    )
                del self._services[service_id]
            finally:
                entry.start_lock.release()
