"""Compatibility adapters backed by the supervised Tor manager and loopback proxy."""
from __future__ import annotations

import logging
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from config import BUNDLE_DIR, CONFIG, IS_WINDOWS
from proxy import ProxyHandler, ThreadedHTTPServer, worker_data_usage_tracker
from torproxy.bridge_distribution import BridgeDistribution, distribute_bridge_records
from torproxy.bridge_health import DEFAULT_MAX_WORKERS
from torproxy.health import TorProbeResult, probe_tor_socks
from torproxy.paths import user_directories
from torproxy.socks_gateway import SocksFailoverGateway
from torproxy.tor_manager import TorManager, TorManagerError, TorSettings, TorState
from utils import resource_path

logger = logging.getLogger(__name__)


def _bundle_root_for_path(path: Path, managed_root: Path) -> Path | None:
    """Return the managed bundle directory containing a path, if any."""
    try:
        resolved = path.resolve()
        if resolved == managed_root or managed_root not in resolved.parents:
            return None
        for parent in (resolved, *resolved.parents):
            if parent.parent == managed_root and parent.name.startswith("tor-expert-bundle-"):
                return parent
    except OSError:
        return None
    return None


def _verified_managed_bundles(managed_root: Path) -> list[Path]:
    """List verified user-installed and application-packaged Tor bundles."""
    try:
        from updater import (
            get_own_bundles,
            get_packaged_bundles,
            get_version_by_bundle,
            tor_version_sort_key,
        )

        paths = list(dict.fromkeys(
            Path(item).resolve()
            for item in (*get_own_bundles(), *get_packaged_bundles())
        ))
        return sorted(
            paths,
            key=lambda item: tor_version_sort_key(get_version_by_bundle(item.name + ".tar.gz")),
            reverse=True,
        )
    except (ImportError, OSError, ValueError, RuntimeError):
        logger.exception("Could not resolve a verified managed Tor bundle.")
        return []


def _find_executable(candidate: str | os.PathLike[str] | None) -> tuple[Path | None, Path | None]:
    """Resolve Tor without implicitly trusting arbitrary files inside the managed bundle directory."""
    managed_root = Path(resource_path(BUNDLE_DIR)).resolve()
    executable_name = "tor.exe" if IS_WINDOWS else "tor"

    def _usable(path: Path) -> bool:
        return path.is_file() and (os.name == "nt" or os.access(path, os.X_OK))

    if candidate:
        path = Path(candidate).expanduser()
        try:
            resolved = path.resolve()
        except OSError:
            return None, path
        managed_bundle = _bundle_root_for_path(resolved, managed_root)
        if resolved == managed_root or (managed_root in resolved.parents):
            # Managed content is never trusted from its filename alone: it must pass the
            # same marker/digest/signature/executable checks as the bundle manager.
            verified = _verified_managed_bundles(managed_root)
            if managed_bundle is None or managed_bundle not in verified:
                logger.error("Selected managed Tor bundle is missing or has not passed integrity/structure checks.")
                return None, managed_bundle or resolved
            if resolved.is_file():
                expected = managed_bundle / "tor" / executable_name
                if resolved == expected and _usable(resolved):
                    return resolved, managed_bundle
                logger.error("Selected executable does not match the verified bundle layout.")
                return None, managed_bundle
            for executable in (
                managed_bundle / "tor" / executable_name,
                managed_bundle / executable_name,
            ):
                if _usable(executable):
                    return executable.resolve(), managed_bundle
            return None, managed_bundle
        if resolved.is_file():
            # An explicit external executable is a user-selected trust decision, not an
            # automatically discovered/downloaded bundle. Still validate that it can run.
            if _usable(resolved):
                parent = resolved.parent
                root = parent.parent if parent.name.lower() == "tor" else parent
                return resolved, root
            return None, resolved.parent
        if resolved.is_dir():
            candidates = [
                resolved / "tor" / executable_name,
                resolved / executable_name,
                resolved / "tor" / "tor",
                resolved / "tor" / "tor.exe",
            ]
            for executable in candidates:
                if _usable(executable):
                    root = resolved.parent if resolved.name.lower() == "tor" else resolved
                    return executable.resolve(), root
            return None, resolved
        return None, resolved

    # Do not auto-select merely because an old/unverified folder contains tor.exe.
    for bundle in _verified_managed_bundles(managed_root):
        for executable in (
            bundle / "tor" / executable_name,
            bundle / executable_name,
        ):
            if _usable(executable):
                return executable.resolve(), bundle
    return None, None


class TorRunner(QObject):
    """Bridge the old GUI contract to the new supervised TorManager."""
    log_message = Signal(str)
    service_failed = Signal(str)
    bridges_updated = Signal(str)
    bridge_usage_changed = Signal(object)

    def __init__(self, socks_port: int, contorl_port: int, dns_port: int):
        super().__init__()
        self.proc = None
        self.thread: threading.Thread | None = None
        self.socks_port = socks_port
        self.bridge = False
        self.bridges = ""
        self.contorl_port = contorl_port  # retained misspelled attribute for old callers
        self.control_port = contorl_port
        self.dns_port = dns_port
        self.ExcludeNodes: list[str] = []
        self.ExitNodes: list[str] = []
        self.StrictNodes = 0
        try:
            self.MaxCircuitDirtiness = max(10, min(86400, int(CONFIG["MaxCircuitDirtiness"] or 600)))
        except (TypeError, ValueError):
            self.MaxCircuitDirtiness = 600
        try:
            self.NewCircuitPeriod = max(10, min(86400, int(CONFIG["NewCircuitPeriod"] or 60)))
        except (TypeError, ValueError):
            self.NewCircuitPeriod = 60
        self.Log = "notice"
        self.bridge_types = ["obfs4", "webtunnel", "snowflake"]
        self.tor_path: str | None = None
        self.lyrebird_path: str | None = None
        self.geoip_path: str | None = None
        self.geoip6_path: str | None = None
        self.path_set = False
        self.manager: TorManager | None = None
        self.app_window = None
        self._stopping = threading.Event()
        self._last_report: tuple[str, int | None, str] | None = None
        self._last_bridge_usage_report: tuple[object, ...] | None = None
        self._backend_managers: list[TorManager] = []
        self._backend_threads: list[threading.Thread] = []
        self._backend_start_locks: list[threading.Lock] = []
        self._backend_statuses: dict[int, str] = {}
        self._backend_errors: dict[int, str] = {}
        self._backend_health: dict[int, dict[str, object]] = {}
        self._pool_ever_healthy = False
        self._backend_ever_ready: set[int] = set()
        self._backend_restart_attempts: dict[int, int] = {}
        self._backend_restart_at: dict[int, float] = {}
        self._backend_lock = threading.RLock()
        self._gateway: SocksFailoverGateway | None = None
        self._last_pool_ready_count = -1
        self._allocated_backend_ports: set[int] = set()
        self._bridge_distribution: BridgeDistribution | None = None
        self._verified_bridge_records: tuple[str, ...] = ()
        self.state = "STOPPED"
        self.last_error: str | None = None
        self.update_path(CONFIG["tor_path"])

    def update_path(self, base_path=None):
        executable, root = _find_executable(base_path)
        if executable is None:
            self.path_set = False
            self.tor_path = None
            self.lyrebird_path = None
            self.geoip_path = None
            self.geoip6_path = None
            if base_path:
                logger.error("No compatible, structurally validated Tor executable was found under the selected path.")
            return False
        self.tor_path = str(executable)
        if root is not None:
            self.geoip_path = str(root / "data" / "geoip")
            self.geoip6_path = str(root / "data" / "geoip6")
            transport = root / "tor" / "pluggable_transports" / ("lyrebird.exe" if IS_WINDOWS else "lyrebird")
            self.lyrebird_path = str(transport)
        self.path_set = True
        return True

    @staticmethod
    def _allocate_local_port(reserved: set[int]) -> int:
        """Choose an unused loopback TCP port for an internal Tor worker."""
        for _attempt in range(64):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", 0))
                port = int(probe.getsockname()[1])
            if port not in reserved:
                reserved.add(port)
                return port
        raise TorManagerError("Could not allocate distinct local listener ports for the primary Tor instances.")

    def _make_manager(self, worker_index: int = 0) -> TorManager:
        if not self.path_set or not self.tor_path:
            self.update_path(CONFIG["tor_path"])
        if not self.path_set or not self.tor_path:
            raise TorManagerError(
                "No Tor executable is configured. Choose a trusted local Tor Expert Bundle in the updater."
            )

        dirs = user_directories()
        if not self._allocated_backend_ports:
            self._allocated_backend_ports = {int(self.socks_port), int(self.control_port)}
            if self.dns_port is not None:
                self._allocated_backend_ports.add(int(self.dns_port))
            proxy_port = getattr(getattr(self.app_window, "proxy", None), "port", None)
            if proxy_port:
                self._allocated_backend_ports.add(int(proxy_port))
            for profile in (CONFIG.get("tor_services", []) or []):
                if not isinstance(profile, dict):
                    continue
                for key in ("socks_port", "control_port", "dns_port"):
                    value = profile.get(key)
                    if type(value) is int and 1 <= value <= 65535:
                        self._allocated_backend_ports.add(value)
        reserved = self._allocated_backend_ports

        # The configured Tor SOCKS port is the stable gateway. Every Tor worker
        # gets its own private SOCKS listener behind that gateway.
        backend_socks_port = self._allocate_local_port(reserved)
        if worker_index == 0:
            control_port = int(self.control_port)
            dns_port = int(self.dns_port) if self.dns_port is not None else None
        else:
            control_port = self._allocate_local_port(reserved)
            dns_port = self._allocate_local_port(reserved) if self.dns_port is not None else None

        if worker_index == 0:
            data_directory = dirs.data / "tor"
            log_path = dirs.logs / "tor.log"
        else:
            data_directory = dirs.data / "tor-workers" / f"instance-{worker_index + 1}"
            log_path = dirs.logs / "tor-workers" / f"instance-{worker_index + 1}.log"

        return TorManager(TorSettings(
            executable=Path(self.tor_path),
            socks_port=backend_socks_port,
            control_port=control_port,
            dns_port=dns_port,
            data_directory=data_directory,
            log_path=log_path,
            geoip_path=Path(self.geoip_path) if self.geoip_path else None,
            geoip6_path=Path(self.geoip6_path) if self.geoip6_path else None,
            bridges_enabled=bool(self.bridge),
            bridges=str(self.bridges or ""),
            webtunnel_sni_imitation=str(CONFIG["webtunnel_sni_imitation"] or ""),
            max_circuit_dirtiness_seconds=max(10, min(86400, int(self.MaxCircuitDirtiness))),
            new_circuit_period_seconds=max(10, min(86400, int(self.NewCircuitPeriod))),
        ))

    def _process_ready_managers(self) -> list[tuple[int, TorManager]]:
        """Return Tor processes that passed bootstrap and remain alive."""
        with self._backend_lock:
            managers = list(self._backend_managers)
            fallback = self.manager
        if not managers and fallback is not None:
            managers = [fallback]
        ready = []
        for index, manager in enumerate(managers):
            state = getattr(manager, "state", None)
            state = str(getattr(state, "value", state)).lower().split(".")[-1]
            process = getattr(manager, "process", None)
            if state != "ready" or process is None:
                continue
            try:
                if process.poll() is None:
                    ready.append((index, manager))
            except Exception:
                continue
        return ready

    def _healthy_managers(self) -> list[TorManager]:
        """Return only workers confirmed by a real request through their SOCKS port."""
        process_ready = self._process_ready_managers()
        if not process_ready:
            return []
        if not self._backend_managers:
            # Preserve the small compatibility surface for tests/legacy callers
            # that manually provide one already-READY manager.
            if str(self.state).upper() == "READY":
                return [manager for _index, manager in process_ready]
            return []
        with self._backend_lock:
            ranked = [
                (
                    float(self._backend_health.get(index, {}).get("latency_ms") or 750.0),
                    manager,
                )
                for index, manager in process_ready
                if bool(self._backend_health.get(index, {}).get("healthy", False))
            ]
        ranked.sort(key=lambda item: item[0])
        return [manager for _latency, manager in ranked]

    def _ready_backend_endpoints(self) -> list[tuple[str, int, float | None]]:
        endpoints = []
        for index, manager in self._process_ready_managers():
            with self._backend_lock:
                health = dict(self._backend_health.get(index, {}))
            if not health.get("healthy"):
                continue
            endpoints.append((
                "127.0.0.1",
                int(manager.settings.socks_port),
                float(health["latency_ms"]) if health.get("latency_ms") is not None else None,
            ))
        return endpoints

    def _on_worker_status(self, index: int, manager: TorManager, state, progress, message) -> None:
        state_text = getattr(state, "value", str(state))
        normalized = str(state_text).upper().split(".")[-1]
        detail = " ".join(str(message or "").split())
        with self._backend_lock:
            self._backend_statuses[index] = normalized
            if normalized == "FAILED":
                self._backend_errors[index] = detail or "Tor worker failed during startup."
                self._backend_health[index] = {
                    "healthy": False,
                    "latency_ms": None,
                    "consecutive_failures": 0,
                    "last_error": self._backend_errors[index],
                }
            elif normalized == "READY":
                self._backend_errors.pop(index, None)
                self._backend_ever_ready.add(index)
                self._backend_health.setdefault(index, {
                    "healthy": False,
                    "latency_ms": None,
                    "consecutive_failures": 0,
                    "last_error": "Waiting for an end-to-end Tor connectivity check.",
                })

        ready = self._healthy_managers()
        if ready:
            if self.manager not in ready:
                self.manager = ready[0]
            self.proc = getattr(self.manager, "process", None)
            self.state = "READY"
            self.last_error = None
            if self.app_window is not None:
                self.app_window.data.value = "100%"
        else:
            process_ready = self._process_ready_managers()
            pending = any(
                value in {"STARTING", "BOOTSTRAPPING"}
                for value in self._backend_statuses.values()
            )
            self.state = "BOOTSTRAPPING" if pending or process_ready else normalized
            if self.app_window is not None:
                if process_ready:
                    self.app_window.data.value = "Verifying Tor network access…"
                elif progress is not None and progress < 100:
                    self.app_window.data.value = f"{progress}%"

        self._publish_bridge_usage()
        if normalized == "READY":
            self.log_message.emit(
                f"Primary Tor instance {index + 1} completed bootstrap; checking real SOCKS connectivity."
            )
        elif normalized == "FAILED":
            self.log_message.emit(f"Primary Tor instance {index + 1} failed: {detail or 'startup error'}")
        elif progress is not None and normalized in {"BOOTSTRAPPING", "STARTING"}:
            self.log_message.emit(f"Primary Tor instance {index + 1}: {progress}% bootstrap.")

    def _probe_ready_backends(self) -> bool:
        """Probe each bootstrapped worker through its own SOCKS listener in parallel."""
        candidates = self._process_ready_managers()
        if not candidates or self._stopping.is_set():
            return False

        results: dict[int, TorProbeResult] = {}
        worker_count = max(1, min(4, len(candidates)))
        with ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="torproxy-health-check",
        ) as executor:
            futures = {
                index: executor.submit(
                    probe_tor_socks,
                    int(manager.settings.socks_port),
                    timeout=8.0,
                )
                for index, manager in candidates
            }
            for index, future in futures.items():
                if self._stopping.is_set():
                    return False
                try:
                    results[index] = future.result(timeout=10.0)
                except Exception as exc:
                    results[index] = TorProbeResult(
                        False,
                        detail=f"Tor connectivity probe failed ({type(exc).__name__}).",
                    )

        changed = []
        with self._backend_lock:
            current_managers = list(self._backend_managers)
            for index, result in results.items():
                if index >= len(current_managers):
                    continue
                manager = dict(candidates).get(index)
                if current_managers[index] is not manager:
                    continue
                state = dict(self._backend_health.get(index, {}))
                was_healthy = bool(state.get("healthy", False))
                if result.healthy:
                    previous_latency = state.get("latency_ms")
                    if previous_latency is None:
                        latency = float(result.latency_ms or 0.0)
                    else:
                        latency = (
                            float(previous_latency) * 0.65
                            + float(result.latency_ms or 0.0) * 0.35
                        )
                    state.update({
                        "healthy": True,
                        "latency_ms": latency,
                        "consecutive_failures": 0,
                        "last_error": "",
                        "last_check": time.monotonic(),
                    })
                else:
                    failures = int(state.get("consecutive_failures", 0)) + 1
                    # Require two consecutive failures before withdrawing a
                    # previously-working worker, avoiding a single probe flap.
                    healthy = was_healthy and failures < 2
                    state.update({
                        "healthy": healthy,
                        "consecutive_failures": failures,
                        "last_error": result.detail,
                        "last_check": time.monotonic(),
                    })
                self._backend_health[index] = state
                if was_healthy != bool(state.get("healthy")):
                    changed.append((index, bool(state.get("healthy")), result))

        healthy = self._healthy_managers()
        if healthy:
            self._pool_ever_healthy = True
            if self.manager not in healthy:
                self.manager = healthy[0]
            self.proc = getattr(self.manager, "process", None)
            self.state = "READY"
            self.last_error = None
            if self.app_window is not None:
                self.app_window.data.value = "100%"
        elif self._process_ready_managers():
            self.proc = None
            self.state = "BOOTSTRAPPING"
            if self.app_window is not None:
                self.app_window.data.value = (
                    "Rechecking Tor network access…"
                    if self._pool_ever_healthy
                    else "Verifying Tor network access…"
                )

        for index, is_healthy, result in changed:
            if is_healthy:
                latency = result.latency_ms or 0.0
                self.log_message.emit(
                    f"Primary Tor instance {index + 1} passed Tor Check "
                    f"({latency:.0f} ms); it is now available for new connections."
                )
            else:
                self.log_message.emit(
                    f"Primary Tor instance {index + 1} failed two consecutive Tor Check probes; "
                    "new connections have been moved to the remaining healthy instances."
                )
        self._publish_bridge_usage()
        return bool(healthy)

    def _start_backend(self, index: int, manager: TorManager) -> None:
        if index >= len(self._backend_start_locks):
            return
        # Coordinate the gap between stop() and TorManager.start(): a late
        # worker must not clear TorManager's cancellation event and launch
        # another child after the application has begun shutting down.
        with self._backend_start_locks[index]:
            if self._stopping.is_set():
                return
            try:
                manager.start(
                    on_status=lambda state, progress, message: self._on_worker_status(
                        index, manager, state, progress, message
                    )
                )
            except Exception as exc:
                with self._backend_lock:
                    self._backend_statuses[index] = "FAILED"
                    self._backend_errors[index] = str(exc)
                if not self._stopping.is_set():
                    self._on_worker_status(index, manager, TorState.FAILED, None, str(exc))

    def generate_torcc(self):
        return self._make_manager().render_torrc()

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self._stopping.clear()
        self._last_report = None
        self._last_bridge_usage_report = None
        self._last_pool_ready_count = -1
        self._bridge_distribution = None
        self._verified_bridge_records = ()
        self._backend_managers = []
        self._backend_threads = []
        self._backend_start_locks = []
        self._backend_statuses = {}
        self._backend_errors = {}
        self._backend_health = {}
        self._pool_ever_healthy = False
        self._backend_ever_ready = set()
        self._backend_restart_attempts = {}
        self._backend_restart_at = {}
        self._allocated_backend_ports = {int(self.socks_port), int(self.control_port)}
        if self.dns_port is not None:
            self._allocated_backend_ports.add(int(self.dns_port))
        proxy_port = getattr(getattr(self.app_window, "proxy", None), "port", None)
        if proxy_port:
            self._allocated_backend_ports.add(int(proxy_port))
        # Keep manually configured independent profiles away from the primary
        # pool's dynamically allocated internal listener ports.
        for profile in (CONFIG.get("tor_services", []) or []):
            if not isinstance(profile, dict):
                continue
            for key in ("socks_port", "control_port", "dns_port"):
                value = profile.get(key)
                if type(value) is int and 1 <= value <= 65535:
                    self._allocated_backend_ports.add(value)
        self.last_error = None
        try:
            self.manager = self._make_manager(0)
            self._gateway = SocksFailoverGateway(
                int(self.socks_port),
                self._ready_backend_endpoints,
            )
            self._gateway.start()
        except Exception as exc:
            self.state = "FAILED"
            self.last_error = str(exc)
            if self._gateway is not None:
                try:
                    self._gateway.stop()
                except Exception:
                    logger.exception("Could not clean up a failed SOCKS gateway startup.")
                self._gateway = None
            raise
        self.state = "STARTING"
        self.thread = threading.Thread(target=self._run, name="torproxy-primary-tor-pool", daemon=True)
        self.thread.start()
        logger.info("Primary Tor pool supervisor started on loopback SOCKS port %s.", self.socks_port)

    @property
    def pool_health_snapshot(self) -> dict:
        """Return safe per-instance health metadata for the Settings UI."""
        with self._backend_lock:
            managers = list(self._backend_managers)
            statuses = dict(self._backend_statuses)
            health = {
                index: dict(value)
                for index, value in self._backend_health.items()
            }
            if not managers and self.manager is not None:
                managers = [self.manager]
            instances = []
            for index in range(len(managers)):
                state = health.get(index, {})
                worker_state = str(statuses.get(index, "stopped")).lower()
                healthy = bool(state.get("healthy", False)) and worker_state == "ready"
                failures = int(state.get("consecutive_failures", 0) or 0)
                if healthy and worker_state == "ready":
                    worker_state = "healthy"
                elif worker_state == "ready" and failures >= 2:
                    worker_state = "unhealthy"
                elif worker_state == "ready":
                    worker_state = "ready-checking"
                bridge_count = (
                    len(self._bridge_distribution.assignments[index])
                    if self._bridge_distribution is not None
                    and index < len(self._bridge_distribution.assignments)
                    else 0
                )
                instances.append({
                    "index": index + 1,
                    "state": worker_state,
                    "healthy": healthy,
                    "latency_ms": state.get("latency_ms"),
                    "consecutive_failures": failures,
                    "bridge_count": bridge_count,
                })
            distribution = self._bridge_distribution
            bridge_summary = (
                {
                    "unique_records": distribution.unique_records,
                    "unique_groups": distribution.unique_groups,
                    "shared_groups": distribution.shared_groups,
                    "instance_record_counts": distribution.instance_record_counts,
                }
                if distribution is not None else None
            )
        return {
            "ready_instances": sum(1 for item in instances if item["healthy"]),
            "total_instances": len(instances),
            "instances": instances,
            "bridge_distribution": bridge_summary,
        }

    def _publish_bridge_usage(self, manager: TorManager | None = None):
        """Publish bridge identities from every healthy worker without exposing bridge records."""
        managers = self._healthy_managers()
        enabled = bool(self.bridge)
        ready = bool(managers)
        active: set[str] = set()
        if enabled:
            for current in managers:
                try:
                    active.update(current.get_active_bridge_fingerprints())
                except Exception:
                    logger.debug("Could not resolve active bridge fingerprints for a Tor worker.", exc_info=True)
        ready_count = len(managers)
        total_count = len(self._backend_managers) or (1 if self.manager is not None else 0)
        with self._backend_lock:
            distribution = self._bridge_distribution
            bridge_counts = (
                distribution.instance_record_counts if distribution is not None else ()
            )
            bridge_summary = (
                {
                    "unique_records": distribution.unique_records,
                    "unique_groups": distribution.unique_groups,
                    "shared_groups": distribution.shared_groups,
                    "instance_record_counts": distribution.instance_record_counts,
                }
                if distribution is not None else None
            )
            health_items = tuple(
                (
                    index,
                    str(self._backend_statuses.get(index, "stopped")).lower(),
                    bool(state.get("healthy", False)),
                    int(state.get("consecutive_failures", 0) or 0),
                    bridge_counts[index] if index < len(bridge_counts) else 0,
                )
                for index, state in sorted(self._backend_health.items())
            )
            instance_details = [
                {
                    "index": index + 1,
                    "state": (
                        "failed" if self._backend_statuses.get(index) == "FAILED" else
                        "healthy" if bool(state.get("healthy", False)) else
                        "unhealthy" if (
                            self._backend_statuses.get(index) == "READY"
                            and int(state.get("consecutive_failures", 0) or 0) >= 2
                        ) else
                        "ready-checking" if self._backend_statuses.get(index) == "READY" else
                        self._backend_statuses.get(index, "starting").lower()
                    ),
                    "healthy": bool(state.get("healthy", False))
                    and self._backend_statuses.get(index) == "READY",
                    "latency_ms": state.get("latency_ms"),
                    "consecutive_failures": int(state.get("consecutive_failures", 0) or 0),
                    "bridge_count": bridge_counts[index] if index < len(bridge_counts) else 0,
                }
                for index, state in sorted(self._backend_health.items())
            ]
        report = (
            enabled, ready, ready_count, total_count,
            tuple(sorted(active)), health_items,
            (
                bridge_summary["unique_records"],
                bridge_summary["unique_groups"],
                bridge_summary["shared_groups"],
                bridge_summary["instance_record_counts"],
            ) if bridge_summary is not None else None,
        )
        if report == self._last_bridge_usage_report:
            return
        self._last_bridge_usage_report = report
        self.bridge_usage_changed.emit({
            "enabled": enabled,
            "ready": ready,
            "active_fingerprints": report[4],
            "ready_instances": ready_count,
            "total_instances": total_count,
            "instances": instance_details,
            "bridge_distribution": bridge_summary,
        })

    def _on_status(self, state, progress, message):
        state_text = getattr(state, "value", str(state))
        normalized_state = str(state_text).upper().split(".")[-1]
        self.state = normalized_state
        self._publish_bridge_usage(self.manager)
        if normalized_state != "FAILED":
            self.last_error = None
        elif message:
            self.last_error = str(message)
        detail = " ".join(str(message or "").split())
        report = (state_text, progress, detail)
        if report != self._last_report:
            self._last_report = report
            progress_text = f" ({progress}%)" if progress is not None else ""
            detail_text = f" — {detail}" if detail else ""
            self.log_message.emit(f"Tor state: {state_text}{progress_text}{detail_text}")
        if self.app_window is not None and progress is not None:
            if normalized_state == "READY" and progress >= 100:
                self.app_window.data.value = "100%"
            elif progress >= 100:
                # A log line can reach 100% before ControlPort identity and the
                # SOCKS listener are verified. Never let that masquerade as ready.
                self.app_window.data.value = "Verifying Tor listeners…"
            else:
                self.app_window.data.value = f"{progress}%"

    def _auto_prune_bridges_before_start(self, manager: TorManager) -> TorManager:
        """Verify a multi-bridge list without deleting anything on ambiguous outcomes."""
        if not self.bridge or not bool(CONFIG["auto_prune_bridges"]) or self._stopping.is_set():
            return manager

        try:
            parsed = TorManager._parse_bridges(self.bridges)
        except Exception:
            # Keep ordinary Tor configuration validation as the authority.
            # Malformed records must not be rewritten by the health checker.
            self.log_message.emit("Automatic bridge checks skipped because the bridge list needs validation.")
            return manager
        if len({record for _kind, record in parsed}) < 2:
            return manager

        probe_workers = max(
            1,
            min(
                8,
                int(getattr(CONFIG, "bridge_probe_workers", DEFAULT_MAX_WORKERS) or DEFAULT_MAX_WORKERS),
            ),
        )
        self.log_message.emit(
            f"Checking {len(parsed)} unique bridge records concurrently "
            f"(up to {min(probe_workers, len(parsed))} workers). "
            "Each record is tested in an isolated temporary Tor process; bridge addresses are hidden from the event log."
        )
        if self.app_window is not None:
            self.app_window.data.value = "Checking bridges…"
        from torproxy.bridge_health import check_bridges

        reserved_ports = [self.socks_port, self.control_port, self.dns_port]
        reserved_ports.extend((manager.settings.socks_port, manager.settings.control_port, manager.settings.dns_port))
        proxy = getattr(self.app_window, "proxy", None)
        if proxy is not None:
            reserved_ports.append(getattr(proxy, "port", None))

        def report_progress(completed, total, _record, status):
            if status == "working":
                label = "completed bootstrap"
            elif status == "failed":
                label = "bridge-specific connection failure"
            elif status == "infrastructure":
                label = "local transport setup issue; keeping it"
            else:
                label = "not proven either way; keeping it"
            self.log_message.emit(f"Bridge probe finished {completed}/{total}: {label}.")
            if self.app_window is not None:
                self.app_window.data.value = f"Bridge check {completed}/{total}"

        try:
            result = check_bridges(
                manager.settings,
                timeout_seconds=30.0,
                max_workers=probe_workers,
                excluded_ports=(port for port in reserved_ports if port),
                cancel_event=self._stopping,
                on_result=report_progress,
            )
        except Exception as exc:
            logger.warning("Automatic bridge checks could not be completed (%s); keeping the original list.", type(exc).__name__)
            self.log_message.emit("Automatic bridge checks could not be completed; the original bridge list was preserved.")
            return manager

        if self._stopping.is_set():
            return manager
        self._verified_bridge_records = tuple(result.working)
        if result.issues:
            issue = result.issues[0]
            if issue == "transport_launch_failed":
                detail = (
                    "The isolated bridge checks could not launch Lyrebird. This is a local executable path/startup "
                    "problem, not evidence that the configured bridges are dead."
                )
            elif issue == "transport_runtime_incompatible":
                detail = (
                    "The isolated bridge checks found 'tls: CurvePreferences includes unsupported curve' in Lyrebird. "
                    "This is a transport/runtime compatibility error, not evidence that the bridges are dead."
                )
            elif issue.startswith("missing_transport:"):
                transport_name = issue.split(":", 1)[1]
                detail = (
                    f"The selected Tor bundle did not register the '{transport_name}' pluggable transport. "
                    "The result cannot be used to assess bridge availability."
                )
            else:
                detail = (
                    "The selected Tor bundle could not initialize its pluggable transport, so the bridge results "
                    "cannot be trusted."
                )
            if not result.working:
                self.log_message.emit(
                    detail + " Automatic cleanup was skipped; the entire original bridge list was preserved. "
                    "Continuing with Tor's normal startup, which will report any persistent bundle/runtime incompatibility."
                )
                if self.app_window is not None:
                    self.app_window.data.value = "Continuing Tor startup; bridge list preserved"
                # Do not let an isolated preflight error abort TorRunner before
                # the real Tor instance can try configured alternatives.
                return manager

            # At least one bridge completed bootstrap. Results for other records
            # that hit a local transport issue remain inconclusive and retained;
            # only separately confirmed dial failures may be removed below.
            self.log_message.emit(
                detail + " At least one bridge completed bootstrap, so only explicit failures from other records "
                "will be eligible for cleanup; inconclusive records remain saved."
            )
        if not result.working:
            self.log_message.emit(
                "No bridge completed bootstrap within the check timeout. This does not prove the bridges are dead; "
                "the original list was preserved. Check the selected Tor bundle, network access and Live Tor log."
            )
            return manager
        if not result.should_prune:
            self.log_message.emit("Bridge check complete. No confirmed-unusable bridges needed removal.")
            return manager

        retained = result.retained
        updated_bridges = "\n".join(retained)
        if not updated_bridges.strip():
            self.log_message.emit("Bridge cleanup was skipped because it produced an empty list.")
            return manager
        try:
            CONFIG["bridges"] = updated_bridges
        except Exception as exc:
            logger.warning("Could not persist cleaned bridge list (%s); keeping it unchanged.", type(exc).__name__)
            self.log_message.emit("Bridge cleanup was not saved; the configured list remains unchanged.")
            return manager

        removed_count = max(0, len(result.original) - len(retained))
        self.bridges = updated_bridges
        self.bridges_updated.emit(updated_bridges)
        self.log_message.emit(
            f"Automatic bridge cleanup removed {removed_count} unresponsive bridge record(s); {len(retained)} were retained."
        )
        return self._make_manager()

    def _should_recheck_bridges_after_start_failure(self, manager: TorManager, error: Exception) -> bool:
        """Decide whether a failed real bootstrap warrants one fresh bridge check."""
        if (
            self._stopping.is_set()
            or not self.bridge
            or not bool(CONFIG.get("auto_prune_bridges", False))
        ):
            return False

        error_text = str(error).lower()
        try:
            diagnostic = manager._recent_tor_log_detail(max_lines=30).lower()
        except Exception:
            diagnostic = ""
        combined = error_text + "\n" + diagnostic

        startup_timed_out = (
            "did not become ready within" in error_text
            or "startup timed out" in error_text
        )
        dial_failure_markers = (
            "connection refused",
            "actively refused",
            "timed out",
            "timeout",
            "i/o timeout",
            "no connection could be made",
            "failed to respond",
            "period of time",
            "wsarecv",
            "connection reset by peer",
            "forcibly closed by the remote host",
            "forcibly closed by remote host",
            "no such host",
            "server misbehaving",
            "name or service not known",
            "unexpected eof",
            "eof",
        )
        has_explicit_dial_failure = (
            "error dialing:" in combined
            and any(marker in combined for marker in dial_failure_markers)
        )
        # Recheck a failed endpoint even if Tor exited before the overall
        # bootstrap timeout. Do not run a probe wave for other early exits just
        # because an old log happens to contain unrelated diagnostic lines.
        if not startup_timed_out and not has_explicit_dial_failure and "error dialing:" not in error_text:
            return False
        if has_explicit_dial_failure:
            return True

        # A transport executable/registration/TLS-runtime problem is global.
        # Do not spend another full probe wave unless the same log also names
        # a separately identifiable dial failure.
        global_setup_errors = (
            "createprocessa() failed",
            "failed to start process",
            "failed at launch",
            "no configured transport called",
            "curvepreferences includes unsupported curve",
            "unknown pluggable transport",
            "clienttransportplugin",
        )
        if any(marker in combined for marker in global_setup_errors):
            return False

        # Tor may have tried every configured bridge yet failed to complete
        # bootstrap. A fresh isolated check can find a working alternative.
        return startup_timed_out

    def _start_with_bridge_recovery(self, manager: TorManager) -> TorManager:
        """Start Tor, then make one conservative cleanup/retry after a real bootstrap failure."""
        self.manager = manager
        try:
            manager.start(on_status=self._on_status)
            return manager
        except Exception as startup_error:
            if not self._should_recheck_bridges_after_start_failure(manager, startup_error):
                raise
            if self._stopping.is_set():
                raise

            # The first attempt has failed, but do not surface a terminal
            # Failed state while a guarded bridge-recovery attempt is running.
            self.state = "BOOTSTRAPPING"
            self.last_error = None
            self._publish_bridge_usage(manager)
            if self.app_window is not None:
                self.app_window.data.value = "Rechecking bridges…"
            self.log_message.emit(
                "Tor did not complete bootstrap. Rechecking configured bridges independently before deciding "
                "whether any record can safely be removed; the original list is preserved unless an alternative "
                "completes bootstrap."
            )
            replacement = self._auto_prune_bridges_before_start(manager)
            if replacement is manager:
                # Preserve the original startup failure when no alternative
                # passed verification and no reduced configuration was made.
                raise
            if self._stopping.is_set():
                raise TorManagerError("Tor startup was cancelled while checking bridge alternatives.")

            self.manager = replacement
            self.log_message.emit(
                "A working bridge alternative was verified and failed records were removed. Retrying Tor startup "
                "once with the reduced bridge list."
            )
            replacement.start(on_status=self._on_status)
            return replacement



    def _apply_bridge_assignment(
        self,
        manager: TorManager,
        worker_index: int,
        distribution: BridgeDistribution | None = None,
    ) -> None:
        """Apply the worker's stable bridge shard before its Tor process starts."""
        assignment = distribution or self._bridge_distribution
        if assignment is None:
            return
        if not 0 <= worker_index < len(assignment.bridge_texts):
            raise TorManagerError("A Tor worker has no matching bridge assignment.")
        settings = getattr(manager, "settings", None)
        if settings is None or not hasattr(settings, "bridges"):
            raise TorManagerError(
                f"Primary Tor instance {worker_index + 1} does not expose bridge configuration."
            )
        bridge_text = assignment.bridge_texts[worker_index]
        if isinstance(settings, TorSettings):
            # TorSettings is frozen; the process has not started yet, so
            # replace only its bridge list while retaining its own ports
            # and isolated DataDirectory.
            manager.settings = replace(settings, bridges=bridge_text)
        else:
            # Keep the compatibility adapter friendly to lightweight test
            # managers without weakening the production TorSettings path.
            settings.bridges = bridge_text

    def _apply_bridge_distribution(self, managers: list[TorManager]) -> BridgeDistribution | None:
        """Partition the filtered bridge pool across isolated primary Tor workers.

        Records sharing an explicit bridge fingerprint stay in one group so
        alternate transport/configuration lines for the same bridge are not
        spread across separate Tor DataDirectories. When there are fewer
        distinct groups than workers, groups are intentionally shared rather
        than leaving a worker with no configured bridge.
        """
        if not self.bridge:
            self._bridge_distribution = None
            return None
        if not managers:
            raise TorManagerError("The primary Tor pool has no workers for bridge assignment.")

        distribution = distribute_bridge_records(
            self.bridges,
            len(managers),
            preferred_records=self._verified_bridge_records,
        )
        if distribution.unique_records == 0:
            raise TorManagerError(
                "Bridge mode is enabled, but no valid bridge records are available for the primary Tor instances."
            )

        for index, manager in enumerate(managers):
            self._apply_bridge_assignment(manager, index, distribution)

        self._bridge_distribution = distribution
        counts = ", ".join(
            f"{index + 1}:{count}"
            for index, count in enumerate(distribution.instance_record_counts)
        )
        if distribution.shared_groups:
            self.log_message.emit(
                f"Bridge distribution: {distribution.unique_records} unique records across "
                f"{distribution.unique_groups} bridge groups and {len(managers)} Tor instances; "
                f"{distribution.shared_groups} bridge group(s) are shared because the pool is small or fewer verified "
                f"groups were available than instances. Per-instance record counts: {counts}."
            )
        else:
            self.log_message.emit(
                f"Bridge distribution: {distribution.unique_records} unique records across "
                f"{distribution.unique_groups} bridge groups and {len(managers)} Tor instances; "
                f"bridge groups are not shared between instances. Per-instance record counts: {counts}."
            )
        return distribution

    def _run(self):
        try:
            manager = self.manager or self._make_manager(0)
            manager = self._auto_prune_bridges_before_start(manager)
            if self._stopping.is_set():
                return

            try:
                worker_count = max(1, min(4, int(CONFIG.get("primary_tor_instances", 2) or 2)))
            except (AttributeError, TypeError, ValueError):
                worker_count = 2
            managers = [manager]
            for worker_index in range(1, worker_count):
                managers.append(self._make_manager(worker_index))

            self._apply_bridge_distribution(managers)

            workers = [
                threading.Thread(
                    target=self._start_backend,
                    args=(index, current),
                    name=f"torproxy-primary-tor-{index + 1}",
                    daemon=True,
                )
                for index, current in enumerate(managers)
            ]
            with self._backend_lock:
                if self._stopping.is_set():
                    stop_before_start = True
                else:
                    stop_before_start = False
                    self.manager = manager
                    self._backend_managers = managers
                    self._backend_threads = workers
                    self._backend_start_locks = [threading.Lock() for _ in managers]
                    self._backend_statuses = {index: "STARTING" for index in range(len(managers))}
                    self._backend_errors = {}
                    self._backend_health = {
                        index: {
                            "healthy": False,
                            "latency_ms": None,
                            "consecutive_failures": 0,
                            "last_error": "Waiting for an end-to-end Tor connectivity check.",
                        }
                        for index in range(len(managers))
                    }
                    self._pool_ever_healthy = False
                    self._backend_ever_ready = set()
                    self._backend_restart_attempts = {index: 0 for index in range(len(managers))}
                    self._backend_restart_at = {}

            if stop_before_start:
                for current in managers:
                    try:
                        current.stop()
                    except Exception:
                        logger.debug("Primary Tor worker cleanup raced application shutdown.", exc_info=True)
                return

            # A concurrent stop may be issued after this snapshot; each worker
            # checks the shared cancellation event while holding its start lock.
            for worker in workers:
                if self._stopping.is_set():
                    break
                worker.start()

            next_health_probe = 0.0
            network_health_deadline: float | None = None
            while not self._stopping.wait(0.5):
                now = time.monotonic()
                if now >= next_health_probe:
                    if self._process_ready_managers():
                        self._probe_ready_backends()
                        next_health_probe = time.monotonic() + 20.0
                    else:
                        # Do not wait a full health interval while all Tor
                        # workers are still bootstrapping.
                        next_health_probe = now + 2.0
                # TorManager reports READY only after authenticated ControlPort
                # verification and a live SOCKS listener. Re-check process
                # liveness so an exited worker is removed from future routing.
                for index, current in enumerate(tuple(self._backend_managers)):
                    state_value = getattr(current, "state", None)
                    state_value = str(getattr(state_value, "value", state_value)).lower().split(".")[-1]
                    process = getattr(current, "process", None)
                    if state_value == "ready" and (process is None or process.poll() is not None):
                        detail = "The managed Tor worker process exited unexpectedly."
                        try:
                            current._terminate_process()
                            current._release_data_directory_lock()
                        except Exception as cleanup_error:
                            detail += " Cleanup failed: " + str(cleanup_error)
                        current.state = TorState.FAILED
                        current.last_error = detail
                        with self._backend_lock:
                            self._backend_statuses[index] = "FAILED"
                            self._backend_errors[index] = detail
                            health = dict(self._backend_health.get(index, {}))
                            health.update({
                                "healthy": False,
                                "last_error": detail,
                                "consecutive_failures": max(
                                    2, int(health.get("consecutive_failures", 0) or 0)
                                ),
                            })
                            self._backend_health[index] = health
                        self._publish_bridge_usage()
                        self.log_message.emit(
                            f"Primary Tor instance {index + 1} was removed from the failover pool: {detail}"
                        )

                # A worker that was once healthy may be replaced after an
                # unexpected exit. Never endlessly retry initial failures:
                # shared bundle/transport problems can affect every instance.
                now = time.monotonic()
                restart_scheduled = False
                for index, current in enumerate(tuple(self._backend_managers)):
                    with self._backend_lock:
                        was_ready = index in self._backend_ever_ready
                        attempts = self._backend_restart_attempts.get(index, 0)
                        retry_at = self._backend_restart_at.get(index)
                        state_value = self._backend_statuses.get(index, "")
                    worker = self._backend_threads[index] if index < len(self._backend_threads) else None
                    if (
                        (was_ready or bool(self._healthy_managers()))
                        and state_value == "FAILED"
                        and worker is not None
                        and not worker.is_alive()
                        and attempts < 3
                    ):
                        if retry_at is None:
                            retry_at = now + min(5 * (2 ** attempts), 60)
                            with self._backend_lock:
                                self._backend_restart_at[index] = retry_at
                            self.log_message.emit(
                                f"Primary Tor instance {index + 1} will be restarted after an unexpected exit."
                            )
                        if now >= retry_at and not self._stopping.is_set():
                            # A failed startup may have left a Tor child or its
                            # DataDirectory lock alive. Reconcile that exact
                            # manager before reusing its state path.
                            try:
                                current.stop()
                            except Exception as cleanup_error:
                                process = getattr(current, "process", None)
                                process_alive = bool(process is not None and process.poll() is None)
                                lock_handle = getattr(current, "_data_directory_lock_handle", None)
                                if process_alive or lock_handle is not None:
                                    with self._backend_lock:
                                        self._backend_restart_attempts[index] = 3
                                        self._backend_errors[index] = (
                                            f"Previous worker could not be stopped safely: {cleanup_error}"
                                        )
                                    self.log_message.emit(
                                        f"Primary Tor instance {index + 1} will not be replaced because "
                                        "its previous process or DataDirectory lock is still active."
                                    )
                                    continue
                            try:
                                replacement = self._make_manager(index)
                                # A supervised replacement must preserve its
                                # original shard instead of restoring the full
                                # master bridge list to every process.
                                self._apply_bridge_assignment(replacement, index)
                            except Exception as exc:
                                with self._backend_lock:
                                    self._backend_restart_attempts[index] = attempts + 1
                                    self._backend_restart_at[index] = now + min(5 * (2 ** (attempts + 1)), 60)
                                    self._backend_errors[index] = str(exc)
                                self.log_message.emit(
                                    f"Could not recreate primary Tor instance {index + 1}: {exc}"
                                )
                            else:
                                retry_thread = threading.Thread(
                                    target=self._start_backend,
                                    args=(index, replacement),
                                    name=f"torproxy-primary-tor-{index + 1}-restart-{attempts + 1}",
                                    daemon=True,
                                )
                                with self._backend_lock:
                                    if self._stopping.is_set():
                                        restart_scheduled = False
                                        continue
                                    self._backend_managers[index] = replacement
                                    self._backend_threads[index] = retry_thread
                                    self._backend_restart_attempts[index] = attempts + 1
                                    self._backend_restart_at.pop(index, None)
                                    self._backend_statuses[index] = "STARTING"
                                    self._backend_health[index] = {
                                        "healthy": False,
                                        "latency_ms": None,
                                        "consecutive_failures": 0,
                                        "last_error": "Tor worker restarted; waiting for a fresh Tor Check probe.",
                                    }
                                retry_thread.start()
                                self.log_message.emit(
                                    f"Restarting primary Tor instance {index + 1} "
                                    f"(attempt {attempts + 1}/3)."
                                )
                                restart_scheduled = True
                        else:
                            restart_scheduled = True
                    elif was_ready and state_value in {"STARTING", "BOOTSTRAPPING"}:
                        restart_scheduled = True

                ready = self._healthy_managers()
                if ready:
                    if self.manager not in ready:
                        self.manager = ready[0]
                    self.proc = getattr(self.manager, "process", None)
                    self.state = "READY"
                    self.last_error = None
                    self._publish_bridge_usage()
                    if len(ready) != self._last_pool_ready_count:
                        self._last_pool_ready_count = len(ready)
                        self.log_message.emit(
                            f"Primary Tor failover pool: {len(ready)}/{len(managers)} instances ready. "
                            "New connections are routed only to healthy instances."
                        )
                    if self.app_window is not None:
                        self.app_window.data.value = "100%"
                else:
                    self.proc = None
                    startup_pending = (
                        any(worker.is_alive() for worker in self._backend_threads)
                        or restart_scheduled
                    )
                    process_ready = self._process_ready_managers()
                    if process_ready:
                        if startup_pending:
                            # Do not let a slow secondary bootstrap worker get
                            # overtaken by the network-verification deadline.
                            self.state = "BOOTSTRAPPING"
                            if self.app_window is not None:
                                self.app_window.data.value = "Connecting remaining Tor instances…"
                        elif self._pool_ever_healthy:
                            # A network outage is not a dead Tor process. Keep
                            # probing and leave the stable gateway in place so
                            # it can resume automatically when a worker recovers.
                            self.state = "BOOTSTRAPPING"
                            if self.app_window is not None:
                                self.app_window.data.value = "Rechecking Tor network access…"
                        else:
                            if network_health_deadline is None:
                                network_health_deadline = time.monotonic() + 90.0
                            if time.monotonic() < network_health_deadline:
                                self.state = "BOOTSTRAPPING"
                                if self.app_window is not None:
                                    self.app_window.data.value = "Verifying Tor network access…"
                            else:
                                details = []
                                with self._backend_lock:
                                    health = {
                                        index: dict(value)
                                        for index, value in self._backend_health.items()
                                    }
                                for index, _current in process_ready:
                                    detail = str(
                                        health.get(index, {}).get(
                                            "last_error",
                                            "Tor Check did not confirm network access.",
                                        )
                                    )
                                    details.append(f"instance {index + 1}: {detail}")
                                message = (
                                    "Tor bootstrapped, but none of the primary instances passed the "
                                    "end-to-end Tor Check. The connection was not marked as connected. "
                                    + " | ".join(details)
                                )
                                self.state = "FAILED"
                                self.last_error = message
                                self.log_message.emit(message)
                                self.service_failed.emit(message)
                                return
                    elif startup_pending:
                        self.state = "BOOTSTRAPPING"
                        if self.app_window is not None:
                            self.app_window.data.value = "Connecting Tor instances…"
                    else:
                        details = []
                        with self._backend_lock:
                            errors = dict(self._backend_errors)
                        for index in range(len(self._backend_managers)):
                            detail = errors.get(index, "No healthy Tor process remained.")
                            details.append(f"instance {index + 1}: {detail}")
                        message = (
                            "All primary Tor instances failed before a verified network connection "
                            "could be established. " + " | ".join(details)
                        )
                        self.state = "FAILED"
                        self.last_error = message
                        self.log_message.emit(message)
                        self.service_failed.emit(message)
                        return
        except Exception as exc:
            if not self._stopping.is_set():
                message = str(exc)
                self.state = "FAILED"
                self.last_error = message
                logger.exception("Failed to start or supervise the primary Tor pool.")
                self.log_message.emit(f"Primary Tor pool failed: {message}")
                self.service_failed.emit(message)
        finally:
            if self._stopping.is_set():
                self.proc = None

    def request_new_identity(self) -> float:
        """Rotate every healthy worker through its own authenticated ControlPort."""
        managers = self._healthy_managers()
        if not managers and self.manager is not None and self.state == "READY":
            managers = [self.manager]
        if not managers:
            raise TorManagerError("Tor is not ready; identity changes are unavailable.")
        waits = []
        failures = []
        for manager in managers:
            try:
                waits.append(float(manager.request_new_identity()))
            except Exception as exc:
                failures.append(exc)
        if not waits:
            raise TorManagerError("No healthy Tor instance accepted the identity request.") from failures[0]
        if len(failures) == len(managers):
            raise TorManagerError("No healthy Tor instance accepted the identity request.") from failures[0]
        return max(waits, default=0.0)

    def stop(self):
        self.state = "STOPPING"
        self._publish_bridge_usage()
        self._stopping.set()

        gateway_error = None
        gateway = self._gateway
        if gateway is not None:
            try:
                gateway.stop()
            except Exception as exc:
                gateway_error = exc

        with self._backend_lock:
            managers = list(self._backend_managers)
            workers = tuple(self._backend_threads)
            start_locks = tuple(self._backend_start_locks)
            if not managers and self.manager is not None:
                managers = [self.manager]
        for manager in managers:
            try:
                manager.stop()
            except Exception:
                # stop() may race a TorManager.start(). It is retried after the
                # startup thread exits so the final result is authoritative.
                logger.debug("Initial stop raced a primary Tor worker operation.", exc_info=True)

        for worker in workers:
            if worker is not threading.current_thread():
                worker.join(timeout=15)

        stop_errors = []
        for index, manager in enumerate(managers):
            start_lock = start_locks[index] if index < len(start_locks) else None
            acquired = start_lock.acquire(timeout=15) if start_lock is not None else True
            if not acquired:
                stop_errors.append("A Tor worker start operation is still active after cancellation.")
                continue
            try:
                manager.stop()
            except Exception as exc:
                process = getattr(manager, "process", None)
                process_alive = bool(process is not None and process.poll() is None)
                lock_handle = getattr(manager, "_data_directory_lock_handle", None)
                state_value = getattr(manager, "state", None)
                state_value = str(getattr(state_value, "value", state_value)).lower().split(".")[-1]
                if process_alive or lock_handle is not None or state_value in {
                    "starting", "bootstrapping", "ready", "stopping"
                }:
                    stop_errors.append(str(exc))
            finally:
                if start_lock is not None:
                    start_lock.release()

        thread = self.thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout=10)
        thread_alive = bool(thread and thread.is_alive())
        worker_alive = any(worker.is_alive() for worker in workers)
        process_alive = any(
            getattr(manager, "process", None) is not None
            and manager.process.poll() is None
            for manager in managers
        )
        locks_held = any(
            getattr(manager, "_data_directory_lock_handle", None) is not None
            for manager in managers
        )
        if thread_alive or worker_alive or process_alive or locks_held:
            detail = (
                "Tor did not stop completely; its supervisor/process is still active. "
                "The service remains registered and its data-directory locks must not be reused."
            )
            if stop_errors:
                detail += " Stop errors: " + " | ".join(stop_errors)
            if gateway_error is not None:
                detail += " SOCKS gateway shutdown error: " + str(gateway_error)
            self.state = "FAILED"
            self.last_error = detail
            raise TorManagerError(detail)
        if gateway_error is not None:
            self.state = "FAILED"
            self.last_error = f"SOCKS gateway shutdown reported an error: {gateway_error}"
            raise TorManagerError(self.last_error) from gateway_error
        if stop_errors:
            detail = "Tor shutdown reported an error: " + " | ".join(stop_errors)
            self.state = "FAILED"
            self.last_error = detail
            raise TorManagerError(detail)

        self.proc = None
        self.thread = None
        self._backend_threads = []
        self._backend_start_locks = []
        self._backend_managers = []
        self._backend_statuses = {}
        self._backend_errors = {}
        self._backend_ever_ready = set()
        self._backend_restart_attempts = {}
        self._backend_restart_at = {}
        self._gateway = None
        self.manager = None
        self.state = "STOPPED"
        self.last_error = None
        self._publish_bridge_usage()
        logger.info("Primary Tor pool stopped.")


class Runner:
    """Own the optional loopback HTTP proxy and traffic-accounting worker."""

    def __init__(self, port, tor_socks_port, app_window):
        self.app_window = app_window
        self.port = int(port)
        self.tor_socks_port = int(tor_socks_port)
        self.server = None
        self.thread = None
        self.data_usage_tracker = None
        self.stop_data_usage_tracker_event = None
        try:
            self.http_enabled = bool(CONFIG["http_proxy_enabled"])
        except (KeyError, TypeError):
            self.http_enabled = True
        self._started = False
        self._lifecycle_lock = threading.RLock()

    @property
    def is_running(self) -> bool:
        """Whether the HTTP listener thread is currently serving requests."""
        with self._lifecycle_lock:
            return bool(self.server is not None and self.thread is not None and self.thread.is_alive())

    def _start_http_listener(self) -> None:
        if self.server is not None and self.thread is not None and self.thread.is_alive():
            return
        if self.server is not None:
            try:
                self.server.server_close()
            finally:
                self.server = None
                self.thread = None

        ProxyHandler.app_window = self.app_window
        server = ThreadedHTTPServer(("127.0.0.1", self.port), ProxyHandler, self.tor_socks_port)
        thread = threading.Thread(target=server.serve_forever, name="torproxy-http-proxy", daemon=True)
        try:
            thread.start()
        except Exception:
            server.server_close()
            raise
        self.server = server
        self.thread = thread
        logger.info("Loopback HTTP proxy started on 127.0.0.1:%s.", self.port)

    def _stop_http_listener(self) -> None:
        server = self.server
        if server is None:
            return
        thread = self.thread
        if thread is not None and thread.is_alive():
            server.shutdown()
        server.server_close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5)
        if thread is not None and thread.is_alive():
            raise RuntimeError("HTTP listener is still active; shutdown is incomplete.")
        self.server = None
        self.thread = None
        logger.info("Loopback HTTP proxy stopped.")

    def set_http_enabled(self, enabled: bool) -> str:
        """Apply the persisted preference immediately when a Tor session is active."""
        target = bool(enabled)
        with self._lifecycle_lock:
            previous = self.http_enabled
            self.http_enabled = target
            try:
                if self._started:
                    if target:
                        self._start_http_listener()
                    else:
                        self._stop_http_listener()
            except Exception:
                self.http_enabled = previous
                raise
            if target:
                if self.is_running:
                    return f"HTTP proxy listening at 127.0.0.1:{self.port}."
                return "HTTP proxy enabled; it will start with the next Tor connection."
            return "HTTP proxy disabled. Tor SOCKS and System Tunnel remain available."

    def start(self):
        with self._lifecycle_lock:
            try:
                self.http_enabled = bool(CONFIG["http_proxy_enabled"])
            except (KeyError, TypeError):
                self.http_enabled = True
            if self._started:
                if self.http_enabled:
                    self._start_http_listener()
                else:
                    self._stop_http_listener()
                return

            if self.http_enabled:
                self._start_http_listener()

            tracker = self.data_usage_tracker
            if tracker is None or not tracker.is_alive():
                self.stop_data_usage_tracker_event = threading.Event()
                tracker = threading.Thread(
                    target=worker_data_usage_tracker,
                    args=(self.stop_data_usage_tracker_event,),
                    name="torproxy-traffic-accounting",
                    daemon=True,
                )
                try:
                    tracker.start()
                except Exception:
                    self.stop_data_usage_tracker_event = None
                    if self.server is not None:
                        try:
                            self._stop_http_listener()
                        except Exception:
                            logger.exception("Could not roll back HTTP listener after tracker startup failed.")
                    raise
                self.data_usage_tracker = tracker
            self._started = True
            if self.http_enabled:
                logger.info("Local HTTP proxy is enabled for the primary Tor session on 127.0.0.1:%s.", self.port)
            else:
                logger.info("Local HTTP proxy is disabled by Settings.")

    def stop(self):
        with self._lifecycle_lock:
            errors = []
            try:
                self._stop_http_listener()
            except Exception as exc:
                errors.append(f"HTTP listener: {exc}")

            tracker = self.data_usage_tracker
            stop_event = self.stop_data_usage_tracker_event
            if stop_event is not None:
                stop_event.set()
            if tracker is not None and tracker is not threading.current_thread():
                tracker.join(timeout=5)
            if tracker is not None and tracker.is_alive():
                errors.append("traffic-accounting worker is still active")

            if errors:
                raise RuntimeError(
                    "Local proxy shutdown is incomplete; " + " | ".join(errors)
                    + ". Service references were retained for safe recovery."
                )

            self.data_usage_tracker = None
            self.stop_data_usage_tracker_event = None
            self._started = False
            logger.info("Local proxy services stopped.")
