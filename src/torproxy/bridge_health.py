"""Conservatively test user-supplied Tor bridges in isolated Tor instances."""
from __future__ import annotations

import logging
import socket
import threading
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from pathlib import Path
from collections.abc import Callable, Iterable

from .tor_manager import TorManager, TorSettings

LOGGER = logging.getLogger(__name__)
DEFAULT_PROBE_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_WORKERS = 4
ProbeStatus = bool | None
ProbeCallback = Callable[[int, int, str, str], None]


@dataclass(frozen=True)
class BridgeHealthResult:
    """Outcome of isolated bridge checks, in the user's original bridge order."""

    original: tuple[str, ...]
    working: tuple[str, ...]
    failed: tuple[str, ...]
    inconclusive: tuple[str, ...]

    @property
    def retained(self) -> tuple[str, ...]:
        # Never erase the whole list because the local network, Tor binary, or
        # transport helper may be broken. At least one independent success is
        # required before applying any automatic cleanup.
        if not self.working:
            return self.original
        keep = set(self.working) | set(self.inconclusive)
        return tuple(record for record in self.original if record in keep)

    @property
    def removed(self) -> tuple[str, ...]:
        return self.failed if self.working else ()

    @property
    def should_prune(self) -> bool:
        return bool(self.working and self.failed)


def _allocate_ephemeral_port(
    excluded_ports: set[int], claimed_ports: set[int], allocation_lock: threading.Lock
) -> int:
    """Choose a currently unused loopback port while avoiding collisions between probes."""
    with allocation_lock:
        for _ in range(20):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                port = int(listener.getsockname()[1])
            if port not in excluded_ports and port not in claimed_ports:
                claimed_ports.add(port)
                return port
    raise OSError("Could not reserve a unique temporary Tor probe port.")


def _probe_single_bridge(
    settings: TorSettings,
    record: str,
    timeout_seconds: float,
    excluded_ports: set[int],
    claimed_ports: set[int],
    allocation_lock: threading.Lock,
    cancel_event: threading.Event | None,
) -> ProbeStatus:
    """Return a definite result only when Tor reached the bootstrap phase."""
    if cancel_event is not None and cancel_event.is_set():
        return None

    try:
        socks_port = _allocate_ephemeral_port(excluded_ports, claimed_ports, allocation_lock)
        control_port = _allocate_ephemeral_port(excluded_ports, claimed_ports, allocation_lock)
    except OSError:
        return None

    manager = None
    bootstrap_seen = threading.Event()
    finished = threading.Event()
    watcher: threading.Thread | None = None

    try:
        with tempfile.TemporaryDirectory(prefix="torproxy-bridge-probe-") as temp_directory:
            probe_settings = replace(
                settings,
                socks_port=socks_port,
                control_port=control_port,
                dns_port=None,
                data_directory=Path(temp_directory),
                bridges_enabled=True,
                bridges=record,
                startup_timeout_seconds=timeout_seconds,
            )
            manager = TorManager(probe_settings)

            def on_status(state, _progress, _message):
                state_value = str(getattr(state, "value", state)).lower()
                if state_value.endswith("bootstrapping"):
                    bootstrap_seen.set()

            def cancel_probe():
                while not finished.wait(0.1):
                    if cancel_event is not None and cancel_event.is_set():
                        try:
                            manager.stop()
                        except Exception:
                            LOGGER.debug("Could not stop a cancelled bridge-check process.", exc_info=True)
                        return

            if cancel_event is not None:
                watcher = threading.Thread(
                    target=cancel_probe,
                    name="torproxy-bridge-probe-cancel",
                    daemon=True,
                )
                watcher.start()

            try:
                manager.start(on_status=on_status)
                return True
            except Exception as exc:
                # A failure before Tor reached the bootstrap phase is commonly a
                # local setup/configuration/port problem, not evidence that the
                # bridge itself is dead.
                if cancel_event is not None and cancel_event.is_set():
                    return None
                LOGGER.debug("An isolated bridge check did not finish (%s).", type(exc).__name__)
                return False if bootstrap_seen.is_set() else None
            finally:
                finished.set()
                try:
                    manager.stop()
                except Exception:
                    LOGGER.debug("Bridge-check process cleanup failed.", exc_info=True)
                if watcher is not None and watcher.is_alive():
                    watcher.join(timeout=0.5)
    except Exception as exc:
        LOGGER.debug("Could not prepare an isolated bridge check (%s).", type(exc).__name__)
        return None


def check_bridges(
    settings: TorSettings,
    *,
    timeout_seconds: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
    max_workers: int = DEFAULT_MAX_WORKERS,
    excluded_ports: Iterable[int] = (),
    cancel_event: threading.Event | None = None,
    on_result: ProbeCallback | None = None,
    probe: Callable[..., ProbeStatus] | None = None,
) -> BridgeHealthResult:
    """Check each unique bridge concurrently and retain ambiguous outcomes.

    The caller should persist a reduced list only when should_prune is true.
    The probe callback is injectable for deterministic unit tests; production
    checks use short-lived Tor processes and never log bridge addresses.
    """
    parsed = TorManager._parse_bridges(settings.bridges)
    original = tuple(record for _kind, record in parsed)
    unique_records = tuple(dict.fromkeys(original))
    if not unique_records:
        return BridgeHealthResult(original, (), (), ())

    excluded = {int(port) for port in excluded_ports if port}
    excluded.update((settings.socks_port, settings.control_port))
    if settings.dns_port is not None:
        excluded.add(settings.dns_port)
    claimed_ports: set[int] = set()
    allocation_lock = threading.Lock()

    def run_probe(record: str) -> ProbeStatus:
        if cancel_event is not None and cancel_event.is_set():
            return None
        if probe is not None:
            return probe(
                settings, record, timeout_seconds, excluded, claimed_ports, allocation_lock, cancel_event
            )
        return _probe_single_bridge(
            settings, record, timeout_seconds, excluded, claimed_ports, allocation_lock, cancel_event
        )

    outcomes: dict[str, ProbeStatus] = {}
    completed = 0
    worker_count = max(1, min(int(max_workers), len(unique_records)))
    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="torproxy-bridge-check") as executor:
        futures = {executor.submit(run_probe, record): record for record in unique_records}
        for future in as_completed(futures):
            if cancel_event is not None and cancel_event.is_set():
                for pending in futures:
                    pending.cancel()
                break
            record = futures[future]
            try:
                outcome = future.result()
            except Exception as exc:
                LOGGER.debug("An isolated bridge check could not be classified (%s).", type(exc).__name__)
                outcome = None
            outcomes[record] = outcome
            completed += 1
            if on_result is not None:
                status = "working" if outcome is True else "failed" if outcome is False else "inconclusive"
                try:
                    on_result(completed, len(unique_records), record, status)
                except Exception:
                    LOGGER.debug("Bridge-check progress callback failed.", exc_info=True)

    if cancel_event is not None and cancel_event.is_set():
        return BridgeHealthResult(original, (), (), original)

    working = tuple(record for record in unique_records if outcomes.get(record) is True)
    failed = tuple(record for record in unique_records if outcomes.get(record) is False)
    inconclusive = tuple(record for record in unique_records if outcomes.get(record) is None)
    return BridgeHealthResult(original, working, failed, inconclusive)
