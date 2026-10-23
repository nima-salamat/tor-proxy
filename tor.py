"""Compatibility adapters backed by the supervised Tor manager and loopback proxy."""
from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from config import BUNDLE_DIR, CONFIG, IS_WINDOWS
from proxy import ProxyHandler, ThreadedHTTPServer, worker_data_usage_tracker
from torproxy.paths import user_directories
from torproxy.tor_manager import TorManager, TorManagerError, TorSettings
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
    """List managed bundles whose marker, archive digest, executable and platform pass checks."""
    try:
        from updater import get_own_bundles, get_version_by_bundle, tor_version_sort_key

        paths = [Path(item).resolve() for item in get_own_bundles()]
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
        self._last_report: tuple[str, int | None] | None = None
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
        self.last_error = None
        try:
            self.manager = self._make_manager()
        except Exception as exc:
            self.state = "FAILED"
            self.last_error = str(exc)
            raise
        self.state = "STARTING"
        self.thread = threading.Thread(target=self._run, name="torproxy-tor-supervisor", daemon=True)
        self.thread.start()
        logger.info("Managed Tor supervisor started.")

    def _on_status(self, state, progress, message):
        state_text = getattr(state, "value", str(state))
        normalized_state = str(state_text).upper().split(".")[-1]
        self.state = normalized_state
        if normalized_state != "FAILED":
            self.last_error = None
        elif message:
            self.last_error = str(message)
        report = (state_text, progress)
        if report != self._last_report:
            self._last_report = report
            self.log_message.emit(f"Tor state: {state_text}" + (f" ({progress}%)" if progress is not None else ""))
        if self.app_window is not None and progress is not None:
            self.app_window.data.value = f"{progress}%"

    def _run(self):
        try:
            self.manager.start(on_status=self._on_status)
            self.proc = self.manager.process
            while not self._stopping.wait(0.5):
                process = self.manager.process
                if process is None or process.poll() is not None:
                    if not self._stopping.is_set():
                        self.proc = None
                        detail = self.manager._recent_tor_log_detail() if self.manager is not None else ""
                        message = "The managed Tor process exited unexpectedly."
                        if detail:
                            message += " " + detail
                        self.state = "FAILED"
                        self.last_error = message
                        self.log_message.emit(message)
                        self.service_failed.emit(message)
                    if self.manager is not None:
                        # Do not retain an app-level data-directory lock after
                        # Tor exits outside the startup path.
                        self.manager._terminate_process()
                        self.manager._release_data_directory_lock()
                    return
        except Exception as exc:
            if not self._stopping.is_set():
                message = str(exc)
                self.state = "FAILED"
                self.last_error = message
                logger.exception("Failed to start or supervise Tor.")
                self.log_message.emit(f"Tor failed: {message}")
                self.service_failed.emit(message)
        finally:
            if self._stopping.is_set():
                self.proc = None

    def stop(self):
        self.state = "STOPPING"
        self._stopping.set()
        manager = self.manager
        if manager is not None:
            manager.stop()
        thread = self.thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=10)
        self.proc = None
        self.thread = None
        self.state = "STOPPED"
        logger.info("Managed Tor supervisor stopped.")


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
        if self.stop_data_usage_tracker_event:
            self.stop_data_usage_tracker_event.set()
        self.server.shutdown()
        self.server.server_close()
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=5)
        if self.data_usage_tracker and self.data_usage_tracker is not threading.current_thread():
            self.data_usage_tracker.join(timeout=5)
        logger.info("Loopback HTTP proxy stopped.")
        self.server = None
        self.thread = None
        self.data_usage_tracker = None
        self.stop_data_usage_tracker_event = None
