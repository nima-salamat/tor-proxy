"""Lifecycle coordinator for multiple isolated Tor service instances.

Each service owns a unique Tor DataDirectory, torrc/log path, and listener-port
set. The pool is deliberately independent of the desktop UI so future profile
screens and headless callers can manage services through the same safe API.
"""
from __future__ import annotations

import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Iterable

from .paths import user_directories
from .tor_manager import TorManager, TorManagerError, TorSettings, TorState

DEFAULT_SERVICE_WORKERS = 4
MAX_SERVICE_WORKERS = 8
_SERVICE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class TorServicePoolError(TorManagerError):
    """A service could not be registered or safely managed by the pool."""


@dataclass
class _ServiceEntry:
    service_id: str
    settings: TorSettings
    manager: TorManager
    start_lock: threading.Lock
    active_calls: int = 0
    stopping: bool = False


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
        max_workers: int = DEFAULT_SERVICE_WORKERS,
        directories=None,
    ) -> None:
        self._manager_factory = manager_factory or TorManager
        self._directories = directories or user_directories()
        self._reserved_ports = {self._validate_port(port) for port in reserved_ports}
        self._max_workers = max(1, min(int(max_workers), MAX_SERVICE_WORKERS))
        self._services: dict[str, _ServiceEntry] = {}
        self._lock = threading.RLock()

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
            self._services[service_id] = _ServiceEntry(
                service_id=service_id,
                settings=prepared,
                manager=manager,
                start_lock=threading.Lock(),
            )
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
            result = {
                entry.service_id: {
                    "state": self._state_value(entry.manager),
                    "socks_port": entry.settings.socks_port,
                    "control_port": entry.settings.control_port,
                    "dns_port": entry.settings.dns_port,
                    "data_directory": str(entry.settings.data_directory),
                    "pid": getattr(getattr(entry.manager, "process", None), "pid", None),
                }
                for entry in entries
            }
        return result[service_id] if service_id is not None else result

    def start_service(self, service_id: str) -> None:
        with self._lock:
            entry = self._services.get(service_id)
            if entry is None:
                raise TorServicePoolError(f"Unknown Tor service '{service_id}'.")
            if entry.stopping:
                raise TorServicePoolError(f"Tor service '{service_id}' is stopping.")
            entry.active_calls += 1
            acquired = entry.start_lock.acquire(blocking=False)
            if not acquired:
                entry.active_calls -= 1
                raise TorServicePoolError(f"Tor service '{service_id}' already has a start operation in progress.")
        try:
            entry.manager.start()
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
                entry.stopping = False
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
