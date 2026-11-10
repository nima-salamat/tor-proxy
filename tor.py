"""Compatibility adapters backed by the supervised Tor manager and loopback proxy."""
from __future__ import annotations

import logging
import os
import socket
import threading
import time
from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from config import BUNDLE_DIR, CONFIG, IS_WINDOWS
from proxy import ProxyHandler, ThreadedHTTPServer, worker_data_usage_tracker
from torproxy.bridge_health import DEFAULT_MAX_WORKERS
from torproxy.paths import user_directories
from torproxy.socks_gateway import SocksGateway
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
        # The configured SOCKS port remains a stable loopback gateway. Tor
        # processes use private backend ports and isolated DataDirectories.
        self.socks_gateway: SocksGateway | None = None
        self.instance_managers: dict[str, TorManager] = {}
        self._instance_lock = threading.RLock()
        self._instance_threads: dict[str, threading.Thread] = {}
        self._instance_states: dict[str, str] = {}
        self._instance_errors: dict[str, str] = {}
        self._instance_attempts: dict[str, int] = {}
        self._instance_retry_at: dict[str, float] = {}
        self._instance_ever_ready = False
        self._active_instance_id: str | None = None
        self.backend_listener_ports: tuple[int, ...] = ()
        self._last_report: tuple[str, int | None, str] | None = None
        self._last_bridge_usage_report: tuple[bool, bool, tuple[str, ...]] | None = None
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

    def _make_manager(self) -> TorManager:
        if not self.path_set or not self.tor_path:
            self.update_path(CONFIG["tor_path"])
        if not self.path_set or not self.tor_path:
            raise TorManagerError(
                "No Tor executable is configured. Choose a trusted local Tor Expert Bundle in the updater."
            )
        dirs = user_directories()
        return TorManager(TorSettings(
            executable=Path(self.tor_path),
            socks_port=int(self.socks_port),
            control_port=int(self.control_port),
            dns_port=int(self.dns_port) if self.dns_port is not None else None,
            data_directory=dirs.data / "tor",
            geoip_path=Path(self.geoip_path) if self.geoip_path else None,
            geoip6_path=Path(self.geoip6_path) if self.geoip6_path else None,
            bridges_enabled=bool(self.bridge),
            bridges=str(self.bridges or ""),
            webtunnel_sni_imitation=str(CONFIG["webtunnel_sni_imitation"] or ""),
            max_circuit_dirtiness_seconds=max(10, min(86400, int(self.MaxCircuitDirtiness))),
            new_circuit_period_seconds=max(10, min(86400, int(self.NewCircuitPeriod))),
        ))

    def generate_torcc(self):
        return self._make_manager().render_torrc()

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self._stopping.clear()
        self._last_report = None
        self._last_bridge_usage_report = None
        self.last_error = None
        self.instance_managers = {}
        self._instance_threads = {}
        self._instance_states = {}
        self._instance_errors = {}
        self._instance_attempts = {}
        self._instance_retry_at = {}
        self._instance_ever_ready = False
        self._active_instance_id = None
        self.backend_listener_ports = ()
        self.socks_gateway = None
        try:
            # This first manager is a settings template. _run() moves its Tor
            # SOCKS listener to a private backend port before launching Tor.
            self.manager = self._make_manager()
        except Exception as exc:
            self.state = "FAILED"
            self.last_error = str(exc)
            raise
        self.state = "STARTING"
        self.thread = threading.Thread(target=self._run, name="torproxy-tor-supervisor", daemon=True)
        self.thread.start()
        logger.info("Managed Tor failover supervisor started.")

    def _publish_bridge_usage(self, manager: TorManager | None = None):
        """Publish only bridge identities verified from Tor's live built circuits."""
        manager = manager or self.manager
        enabled = bool(self.bridge)
        manager_state = getattr(manager, "state", None) if manager is not None else None
        manager_state = getattr(manager_state, "value", manager_state)
        ready = self.state == "READY" and manager is not None and str(manager_state).lower() == "ready"
        active: tuple[str, ...] = ()
        if enabled and ready and manager is not None:
            try:
                active = tuple(sorted(manager.get_active_bridge_fingerprints()))
            except Exception:
                logger.debug("Could not resolve active bridge fingerprints.", exc_info=True)
        report = (enabled, bool(ready), active)
        if report == self._last_bridge_usage_report:
            return
        self._last_bridge_usage_report = report
        self.bridge_usage_changed.emit({
            "enabled": enabled,
            "ready": bool(ready),
            "active_fingerprints": active,
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

        self.log_message.emit("Checking configured bridges independently before connecting. Bridge addresses are hidden from the event log.")
        if self.app_window is not None:
            self.app_window.data.value = "Checking bridges…"
        from torproxy.bridge_health import check_bridges

        reserved_ports = [self.socks_port, self.control_port, self.dns_port]
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
                max_workers=max(1, min(8, int(getattr(CONFIG, "bridge_probe_workers", DEFAULT_MAX_WORKERS) or DEFAULT_MAX_WORKERS))),
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

    def _allocate_backend_ports(self, instance_count: int) -> tuple[list[int], list[int]]:
        """Reserve distinct ephemeral loopback ports for private Tor listeners."""
        needed = instance_count + max(0, instance_count - 1)
        reserved = {
            int(value) for value in (
                self.socks_port,
                self.control_port,
                self.dns_port,
                getattr(getattr(self.app_window, "proxy", None), "port", None),
                *self.backend_listener_ports,
            ) if value
        }
        for profile in CONFIG["tor_services"] or []:
            if isinstance(profile, dict):
                for key in ("socks_port", "control_port", "dns_port"):
                    value = profile.get(key)
                    if type(value) is int and 1 <= value <= 65535:
                        reserved.add(value)
        sockets: list[socket.socket] = []
        allocated: list[int] = []
        try:
            attempts = 0
            while len(allocated) < needed and attempts < needed * 20:
                attempts += 1
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    listener.bind(("127.0.0.1", 0))
                    listener.listen(1)
                    port = int(listener.getsockname()[1])
                    if port in reserved or port in allocated:
                        listener.close()
                        continue
                    sockets.append(listener)
                    allocated.append(port)
                except OSError:
                    listener.close()
                    continue
            if len(allocated) != needed:
                raise TorManagerError("TorProxy could not reserve unique ports for its primary Tor instances.")
        finally:
            for listener in sockets:
                listener.close()
        socks_ports = allocated[:instance_count]
        control_ports = [int(self.control_port), *allocated[instance_count:]]
        return socks_ports, control_ports

    def _prepare_primary_instances(self, template: TorManager, count: int) -> dict[str, TorManager]:
        """Build a primary Tor process plus isolated hot-standby processes."""
        socks_ports, control_ports = self._allocate_backend_ports(count)
        base_settings = template.settings
        directories = user_directories()
        managers: dict[str, TorManager] = {}
        all_ports: list[int] = []
        for index in range(count):
            instance_id = f"primary-{index + 1}"
            if index == 0:
                settings = replace(
                    base_settings,
                    socks_port=socks_ports[index],
                    control_port=control_ports[index],
                )
                manager = template
                manager.settings = settings
            else:
                data_directory = directories.data / "tor-ha" / f"instance-{index + 1:02d}"
                log_path = directories.logs / "tor-ha" / f"instance-{index + 1:02d}" / "tor.log"
                settings = replace(
                    base_settings,
                    socks_port=socks_ports[index],
                    control_port=control_ports[index],
                    dns_port=None,
                    data_directory=data_directory,
                    log_path=log_path,
                )
                manager = TorManager(settings)
            managers[instance_id] = manager
            all_ports.extend((socks_ports[index], control_ports[index]))
            if settings.dns_port is not None:
                all_ports.append(settings.dns_port)
        self.backend_listener_ports = tuple(sorted(set(all_ports)))
        return managers

    @staticmethod
    def _manager_is_ready(manager: TorManager) -> bool:
        state = getattr(manager, "state", None)
        state = getattr(state, "value", state)
        process = getattr(manager, "process", None)
        try:
            process_alive = process is not None and process.poll() is None
        except Exception:
            process_alive = False
        return str(state).lower() == "ready" and process_alive

    def _ready_instances_locked(self) -> list[tuple[str, TorManager]]:
        return [
            (instance_id, manager)
            for instance_id, manager in self.instance_managers.items()
            if self._manager_is_ready(manager)
        ]

    def _refresh_instance_selection(self, *, announce: bool = False) -> None:
        """Keep the active backend sticky; select a standby only after failure."""
        with self._instance_lock:
            ready = self._ready_instances_locked()
            ready_ids = {instance_id for instance_id, _manager in ready}
            previous_id = self._active_instance_id
            if previous_id not in ready_ids:
                self._active_instance_id = ready[0][0] if ready else None
            active_id = self._active_instance_id
            active_manager = self.instance_managers.get(active_id) if active_id else None
            self.manager = active_manager
            self.proc = active_manager.process if active_manager is not None else None
            if active_manager is not None:
                self.state = "READY"
                self.last_error = None
                self._instance_ever_ready = True
            elif self._instance_managers_started():
                self.state = "BOOTSTRAPPING"

            ordered = []
            if active_id:
                ordered.append(active_id)
            ordered.extend(instance_id for instance_id, _manager in ready if instance_id != active_id)
            backends = [
                (instance_id, self.instance_managers[instance_id].settings.socks_port)
                for instance_id in ordered
            ]
            gateway = self.socks_gateway
            changed = previous_id != active_id
        if gateway is not None:
            gateway.set_backends(backends)
        if changed and active_id and announce:
            self.log_message.emit(
                f"Primary Tor route is now using {active_id}; new SOCKS sessions will use this healthy instance."
            )
        if active_manager is not None:
            self._publish_bridge_usage(active_manager)

    def _instance_managers_started(self) -> bool:
        return bool(self.instance_managers)

    def _on_instance_status(self, instance_id: str, manager: TorManager, state, progress, message) -> None:
        state_text = getattr(state, "value", str(state))
        normalized = str(state_text).upper().split(".")[-1]
        previous_pool_state = self.state
        with self._instance_lock:
            self._instance_states[instance_id] = normalized
            if normalized == "FAILED" and message:
                self._instance_errors[instance_id] = str(message)
            if normalized == "READY":
                self._instance_errors.pop(instance_id, None)
        self.log_message.emit(f"{instance_id}: {str(message or state_text).strip()}")
        self._refresh_instance_selection(announce=True)
        if self.state == "READY":
            if (
                previous_pool_state != "READY"
                and self.app_window is not None
                and normalized == "READY"
            ):
                self.app_window.data.value = "100%"
            return
        if self.app_window is not None and progress is not None:
            # Only a real verified READY event produces the exact 100% value
            # consumed by the Home connected-state transition.
            safe_progress = max(0, min(99, int(progress)))
            self.app_window.data.value = f"{instance_id}: {safe_progress}%"

    def _start_backend(self, instance_id: str, manager: TorManager) -> None:
        try:
            manager.start(
                on_status=lambda state, progress, message: self._on_instance_status(
                    instance_id, manager, state, progress, message
                )
            )
        except Exception as exc:
            with self._instance_lock:
                self._instance_errors[instance_id] = f"{type(exc).__name__}: {exc}"
                self._instance_states[instance_id] = "FAILED"
            logger.warning("Primary Tor instance %s failed: %s", instance_id, exc)
            self.log_message.emit(f"{instance_id} failed: {exc}")
            self._refresh_instance_selection(announce=True)

    def _launch_backend(self, instance_id: str, manager: TorManager) -> None:
        thread = threading.Thread(
            target=self._start_backend,
            args=(instance_id, manager),
            name=f"torproxy-{instance_id}",
            daemon=True,
        )
        with self._instance_lock:
            self._instance_threads[instance_id] = thread
            self._instance_attempts[instance_id] = self._instance_attempts.get(instance_id, 0) + 1
            self._instance_states[instance_id] = "STARTING"
        thread.start()

    def _run(self):
        try:
            template = self.manager or self._make_manager()
            template = self._auto_prune_bridges_before_start(template)
            if self._stopping.is_set():
                return

            instance_count = max(1, min(4, int(CONFIG["primary_tor_instances"] or 2)))
            managers = self._prepare_primary_instances(template, instance_count)
            gateway = SocksGateway(int(self.socks_port))
            gateway.start()
            self.socks_gateway = gateway
            self.instance_managers = managers
            self._instance_states = {key: "STARTING" for key in managers}
            self._instance_attempts = {key: 0 for key in managers}
            self.log_message.emit(
                f"Started the stable SOCKS failover gateway on 127.0.0.1:{self.socks_port}; "
                f"bootstrapping {instance_count} isolated Tor instance(s) in parallel."
            )
            for instance_id, manager in managers.items():
                if self._stopping.is_set():
                    return
                self._launch_backend(instance_id, manager)

            while not self._stopping.wait(0.25):
                # Detect a process that exited after it had reached READY.
                for instance_id, manager in tuple(self.instance_managers.items()):
                    process = manager.process
                    if (
                        str(getattr(manager.state, "value", manager.state)).lower() == "ready"
                        and (process is None or process.poll() is not None)
                    ):
                        detail = manager._recent_tor_log_detail(max_lines=12)
                        message = f"{instance_id} exited unexpectedly."
                        if detail:
                            message += " " + detail
                        try:
                            manager.stop()
                        except Exception as exc:
                            message += f" Cleanup failed: {exc}"
                            # An unverified process/lock must never be reused.
                            self._instance_attempts[instance_id] = 3
                        with self._instance_lock:
                            self._instance_errors[instance_id] = message
                            self._instance_states[instance_id] = "FAILED"
                        self.log_message.emit(message)

                self._refresh_instance_selection(announce=True)
                now = time.monotonic()
                for instance_id, manager in tuple(self.instance_managers.items()):
                    worker = self._instance_threads.get(instance_id)
                    worker_alive = bool(worker and worker.is_alive())
                    instance_state = str(
                        getattr(manager.state, "value", manager.state)
                    ).lower()
                    if (
                        not worker_alive
                        and instance_state in {"failed", "stopped"}
                        and self._instance_attempts.get(instance_id, 0) < 3
                        and self._instance_ever_ready
                    ):
                        self._instance_retry_at.setdefault(
                            instance_id,
                            now + min(30.0, 3.0 * (2 ** max(0, self._instance_attempts[instance_id] - 1))),
                        )
                    retry_at = self._instance_retry_at.get(instance_id)
                    if retry_at is not None and now >= retry_at and not worker_alive and not self._stopping.is_set():
                        self._instance_retry_at.pop(instance_id, None)
                        self.log_message.emit(f"Retrying {instance_id} to restore primary Tor redundancy.")
                        self._launch_backend(instance_id, manager)

                ready = self._ready_instances_locked()
                any_worker_alive = any(
                    worker.is_alive() for worker in self._instance_threads.values()
                )
                pending_retry = bool(self._instance_retry_at)
                if not ready and not any_worker_alive and not pending_retry:
                    details = "; ".join(
                        f"{key}: {value}"
                        for key, value in self._instance_errors.items()
                    )
                    raise TorManagerError(
                        "No primary Tor instance is ready. " + (details or "All Tor startup attempts failed.")
                    )
                self._publish_bridge_usage(self.manager)

        except Exception as exc:
            if not self._stopping.is_set():
                message = str(exc)
                self.state = "FAILED"
                self.last_error = message
                logger.exception("Failed to start or supervise the redundant Tor pool.")
                self.log_message.emit(f"Tor failover pool failed: {message}")
                self.service_failed.emit(message)
        finally:
            if self._stopping.is_set():
                self.proc = None

    def request_new_identity(self) -> float:
        """Request NEWNYM from the currently active primary Tor instance."""
        manager = self.manager
        if manager is None or self.state != "READY" or not self._manager_is_ready(manager):
            raise TorManagerError("No primary Tor instance is ready; identity changes are unavailable.")
        return manager.request_new_identity()

    def stop(self):
        self.state = "STOPPING"
        self._publish_bridge_usage(self.manager)
        self._stopping.set()
        managers = list(self.instance_managers.values())
        if not managers and self.manager is not None:
            managers = [self.manager]
        stop_errors: list[str] = []
        for manager in managers:
            try:
                manager.stop()
            except Exception as exc:
                stop_errors.append(f"{type(exc).__name__}: {exc}")

        for worker in tuple(self._instance_threads.values()):
            if worker.is_alive() and worker is not threading.current_thread():
                worker.join(timeout=10)
        thread = self.thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=10)

        alive_instances = []
        for instance_id, manager in self.instance_managers.items():
            process = manager.process
            if process is not None and process.poll() is None:
                alive_instances.append(instance_id)
        worker_alive = [
            instance_id for instance_id, worker in self._instance_threads.items()
            if worker.is_alive()
        ]
        supervisor_alive = bool(thread and thread.is_alive())
        if alive_instances or worker_alive or supervisor_alive or stop_errors:
            detail = (
                "Tor failover pool did not stop completely; a supervisor/process is still active. "
                f"Live instance(s): {', '.join(alive_instances) or 'none'}; "
                f"startup worker(s): {', '.join(worker_alive) or 'none'}; "
                f"supervisor alive: {supervisor_alive}."
            )
            if stop_errors:
                detail += " Shutdown errors: " + " | ".join(stop_errors)
            self.state = "FAILED"
            self.last_error = detail
            raise TorManagerError(detail)

        gateway = self.socks_gateway
        if gateway is not None:
            try:
                gateway.stop()
            except Exception as exc:
                detail = f"Tor processes stopped but the local SOCKS gateway did not: {exc}"
                self.state = "FAILED"
                self.last_error = detail
                raise TorManagerError(detail) from exc

        self.proc = None
        self.thread = None
        self.socks_gateway = None
        self.instance_managers = {}
        self._instance_threads = {}
        self._instance_states = {}
        self._instance_retry_at = {}
        self.backend_listener_ports = ()
        self._active_instance_id = None
        self.state = "STOPPED"
        self.last_error = None
        self._publish_bridge_usage(self.manager)
        logger.info("Managed Tor failover pool stopped.")


class Runner:
    """Own the loopback HTTP proxy and its traffic-counter worker."""

    def __init__(self, port, tor_socks_port, app_window):
        self.app_window = app_window
        self.port = int(port)
        self.tor_socks_port = int(tor_socks_port)
        self.server = None
        self.thread = None
        self.data_usage_tracker = None
        self.stop_data_usage_tracker_event = None

    def start(self):
        if self.server:
            return
        ProxyHandler.app_window = self.app_window
        server = ThreadedHTTPServer(("127.0.0.1", self.port), ProxyHandler, self.tor_socks_port)
        self.server = server
        self.thread = threading.Thread(target=server.serve_forever, name="torproxy-http-proxy", daemon=True)
        self.thread.start()
        self.stop_data_usage_tracker_event = threading.Event()
        self.data_usage_tracker = threading.Thread(
            target=worker_data_usage_tracker,
            args=(self.stop_data_usage_tracker_event,),
            name="torproxy-traffic-accounting",
            daemon=True,
        )
        self.data_usage_tracker.start()
        logger.info("Loopback HTTP proxy started on 127.0.0.1:%s.", self.port)

    def stop(self):
        if not self.server:
            return
        server = self.server
        thread = self.thread
        tracker = self.data_usage_tracker
        if self.stop_data_usage_tracker_event:
            self.stop_data_usage_tracker_event.set()
        server.shutdown()
        server.server_close()
        if thread and thread is not threading.current_thread():
            thread.join(timeout=5)
        if tracker and tracker is not threading.current_thread():
            tracker.join(timeout=5)

        server_thread_alive = bool(thread and thread.is_alive())
        tracker_alive = bool(tracker and tracker.is_alive())
        if server_thread_alive or tracker_alive:
            active = []
            if server_thread_alive:
                active.append("HTTP listener")
            if tracker_alive:
                active.append("traffic-accounting worker")
            raise RuntimeError(
                "Local proxy shutdown is incomplete; "
                + " and ".join(active)
                + " is still active. The service references were retained for safe recovery."
            )

        logger.info("Loopback HTTP proxy stopped.")
        self.server = None
        self.thread = None
        self.data_usage_tracker = None
        self.stop_data_usage_tracker_event = None
