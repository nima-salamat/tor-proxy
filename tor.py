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


def _find_executable(candidate: str | os.PathLike[str] | None) -> tuple[Path | None, Path | None]:
    if candidate:
        path = Path(candidate).expanduser()
        if path.is_file():
            # A manually selected executable is an explicit trust decision.
            parent = path.resolve().parent
            root = parent.parent if parent.name.lower() == "tor" else parent
            return path.resolve(), root
        if path.is_dir():
            candidates = [
                path / "tor" / ("tor.exe" if IS_WINDOWS else "tor"),
                path / ("tor.exe" if IS_WINDOWS else "tor"),
                path / "tor" / "tor",
                path / "tor" / "tor.exe",
            ]
            for executable in candidates:
                if executable.is_file():
                    root = path.resolve().parent if path.name.lower() == "tor" else path.resolve()
                    return executable.resolve(), root
            return None, path.resolve()
        return None, path

    root = Path(resource_path(BUNDLE_DIR))
    candidates: list[Path] = []
    if root.is_dir():
        for bundle in sorted(root.glob("tor-expert-bundle-*"), reverse=True):
            if not bundle.is_dir():
                continue
            candidates.extend([
                bundle / "tor" / ("tor.exe" if IS_WINDOWS else "tor"),
                bundle / ("tor.exe" if IS_WINDOWS else "tor"),
            ])
    for executable in candidates:
        if executable.is_file():
            return executable.resolve(), executable.parent.parent.resolve()
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
        self.MaxCircuitDirtiness = 600
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
        self.update_path(CONFIG["tor_path"])

    def update_path(self, base_path=None):
        executable, root = _find_executable(base_path)
        if executable is None:
            self.path_set = False
            if base_path:
                logger.error("No Tor executable was found under the selected path.")
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
        self.manager = self._make_manager()
        self.thread = threading.Thread(target=self._run, name="torproxy-tor-supervisor", daemon=True)
        self.thread.start()
        logger.info("Managed Tor supervisor started.")

    def _on_status(self, state, progress, message):
        state_text = getattr(state, "value", str(state))
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
                        message = "The managed Tor process exited unexpectedly. Check the Tor log for details."
                        self.log_message.emit(message)
                        self.service_failed.emit(message)
                    return
        except Exception as exc:
            if not self._stopping.is_set():
                message = str(exc)
                logger.exception("Failed to start or supervise Tor.")
                self.log_message.emit(f"Tor failed: {message}")
                self.service_failed.emit(message)
        finally:
            if self._stopping.is_set():
                self.proc = None

    def stop(self):
        self._stopping.set()
        manager = self.manager
        if manager is not None:
            manager.stop()
        thread = self.thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=10)
        self.proc = None
        self.thread = None
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
