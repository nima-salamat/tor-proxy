"""Conservatively test user-supplied Tor bridges in isolated Tor instances."""
from __future__ import annotations

import logging
import re
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
@dataclass(frozen=True)
class BridgeProbeOutcome:
    """A bridge result, optionally carrying a local setup/transport issue."""

    status: bool | None
    issue: str | None = None


ProbeStatus = bool | None | BridgeProbeOutcome
ProbeCallback = Callable[[int, int, str, str], None]


@dataclass(frozen=True)
class BridgeHealthResult:
    """Outcome of isolated bridge checks, in the user's original bridge order."""

    original: tuple[str, ...]
    working: tuple[str, ...]
    failed: tuple[str, ...]
    inconclusive: tuple[str, ...]
    issues: tuple[str, ...] = ()

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
                log_path=Path(temp_directory) / "tor-probe.log",
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
                # A startup timeout is not proof that a bridge is dead. Bootstrap
                # can be slow and a transport can be missing globally in this
                # selected bundle. Only a bridge-specific failure from Tor's own
                # log is actionable for automatic cleanup.
                try:
                    diagnostic = manager._recent_tor_log_detail(max_lines=20).lower()
                except Exception:
                    diagnostic = ""
                if any(marker in diagnostic for marker in (
                    "createprocessa() failed",
                    "failed to start process",
                    "failed at launch",
                )):
                    return BridgeProbeOutcome(None, "transport_launch_failed")
                missing_transport = re.search(
                    r'no configured transport called\s+["\']([^"\']+)["\']',
                    diagnostic,
                    re.IGNORECASE,
                )
                if missing_transport:
                    name = missing_transport.group(1)
                    return BridgeProbeOutcome(
                        None,
                        f"missing_transport:{name}",
                    )
                if "tls: curvepreferences includes unsupported curve" in diagnostic:
                    return BridgeProbeOutcome(
                        None,
                        "transport_runtime_incompatible",
                    )
                # Do not classify the log as a local transport failure just
                # because Tor prefixes bridge dial errors with the lyrebird.exe
                # path. Match actual transport setup/runtime diagnostics only.
                if any(marker in diagnostic for marker in (
                    "unknown pluggable transport",
                    "could not launch transport",
                    "failed to launch pluggable transport",
                    "clienttransportplugin",
                    "managed proxy failed at launch",
                    "managed proxy terminated",
                    "could not start managed proxy",
                )):
                    return BridgeProbeOutcome(
                        None,
                        "transport_setup_unavailable",
                    )

                dial_lines = [
                    line for line in re.split(r"\s+\|\s+|\r?\n", diagnostic)
                    if "error dialing:" in line
                ]
                # These indicate a specific endpoint failure strongly enough
                # to act on after one attempt: a refused TCP port or a hostname
                # that cannot be resolved at all.
                hard_dial_failures = (
                    "connection refused",
                    "actively refused",
                    "no connection could be made",
                    "no such host",
                    "name or service not known",
                )
                if any(any(marker in line for marker in hard_dial_failures) for line in dial_lines):
                    return False

                # A timeout, reset, EOF, or remote close can be transient (or
                # caused by a front-end/SNI mismatch). Require at least two
                # separate failed dial log lines for this isolated bridge
                # before marking it unusable.
                repeated_dial_failures = (
                    "timed out",
                    "timeout",
                    "i/o timeout",
                    "failed to respond",
                    "period of time",
                    "wsarecv",
                    "connection reset by peer",
                    "connection reset",
                    "connection aborted",
                    "forcibly closed by the remote host",
                    "forcibly closed by remote host",
                    "unexpected eof",
                    "eof",
                    "peer closed",
                )
                repeated_failures = sum(
                    any(marker in line for marker in repeated_dial_failures)
                    for line in dial_lines
                )
                if repeated_failures >= 2:
                    return False
                if any(marker in diagnostic for marker in (
                    "bridge connection failed",
                    "failed to connect to bridge",
                    "bridge is unreachable",
                    "connection to bridge timed out",
                )):
                    return False

                # Relay/guard directory state is not bridge liveness. Tor can
                # temporarily lack a node descriptor even when the bridge
                # transport itself is reachable. It is inconclusive only when
                # no explicit bridge endpoint dial failure was recorded.
                if "failed to find node for hop #1" in diagnostic:
                    return None

                # A plain bootstrap timeout without a bridge-specific dial
                # failure is inconclusive. It might mean a slow network or a
                # missing relay descriptor, not a dead bridge.
                error_text = str(exc).lower()
                if "did not become ready within" in error_text or "timed out" in error_text or "timeout" in error_text:
                    return None
                return False if bootstrap_seen.is_set() and "bridge at" in diagnostic else None
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
    issues: list[str] = []
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
            outcome_status = outcome.status if isinstance(outcome, BridgeProbeOutcome) else outcome
            if isinstance(outcome, BridgeProbeOutcome) and outcome.issue and outcome.issue not in issues:
                issues.append(outcome.issue)
            completed += 1
            if on_result is not None:
                status = (
                    "infrastructure"
                    if isinstance(outcome, BridgeProbeOutcome) and outcome.issue
                    else "working" if outcome_status is True
                    else "failed" if outcome_status is False
                    else "inconclusive"
                )
                try:
                    on_result(completed, len(unique_records), record, status)
                except Exception:
                    LOGGER.debug("Bridge-check progress callback failed.", exc_info=True)

    if cancel_event is not None and cancel_event.is_set():
        return BridgeHealthResult(original, (), (), original)

    def status_for(record: str) -> bool | None:
        outcome = outcomes.get(record)
        return outcome.status if isinstance(outcome, BridgeProbeOutcome) else outcome

    working = tuple(record for record in unique_records if status_for(record) is True)
    failed = tuple(record for record in unique_records if status_for(record) is False)
    inconclusive = tuple(record for record in unique_records if status_for(record) is None)
    return BridgeHealthResult(original, working, failed, inconclusive, tuple(issues))
