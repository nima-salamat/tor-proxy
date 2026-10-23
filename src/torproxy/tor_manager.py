"""Supervised Tor subprocess lifecycle with explicit loopback ControlPort authentication."""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import subprocess
import tempfile
import threading

import psutil
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

_ACTIVE_DATA_DIRECTORIES: set[str] = set()
_ACTIVE_DATA_DIRECTORIES_LOCK = threading.Lock()
from collections.abc import Callable

from .paths import user_directories

LOGGER = logging.getLogger(__name__)
BootstrapCallback = Callable[["TorState", int | None, str], None]


class TorManagerError(RuntimeError):
    """Tor could not be started, controlled, or shut down safely."""


class TorState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    BOOTSTRAPPING = "bootstrapping"
    READY = "ready"
    STOPPING = "stopping"
    FAILED = "failed"


@dataclass(frozen=True)
class TorSettings:
    executable: Path
    socks_port: int = 9050
    control_port: int = 9051
    dns_port: int | None = None
    data_directory: Path | None = None
    geoip_path: Path | None = None
    geoip6_path: Path | None = None
    bridges_enabled: bool = False
    bridges: str = ""
    max_circuit_dirtiness_seconds: int = 600
    new_circuit_period_seconds: int = 60
    startup_timeout_seconds: float = 180.0
    shutdown_timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        ports = [self.socks_port, self.control_port]
        if self.dns_port is not None:
            ports.append(self.dns_port)
        if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
            raise TorManagerError("Configured listener ports must be valid integers in the range 1..65535.")
        if len(set(ports)) != len(ports):
            raise TorManagerError("SOCKS, ControlPort, and DNSPort must use distinct ports.")
        if not 10 <= self.max_circuit_dirtiness_seconds <= 86400:
            raise TorManagerError("MaxCircuitDirtiness must be between 10 and 86400 seconds.")
        if not 10 <= self.new_circuit_period_seconds <= 86400:
            raise TorManagerError("NewCircuitPeriod must be between 10 and 86400 seconds.")
        if self.startup_timeout_seconds <= 0 or self.shutdown_timeout_seconds <= 0:
            raise TorManagerError("Startup and shutdown timeouts must be positive.")


class TorManager:
    """Own exactly one child process and its data/control resources."""

    def __init__(self, settings: TorSettings, *, popen_factory=subprocess.Popen,
                 run_factory=subprocess.run, controller_factory=None):
        self.settings = settings
        self._popen_factory = popen_factory
        self._run_factory = run_factory
        self._controller_factory = controller_factory
        self._lock = threading.RLock()
        self._start_lock = threading.Lock()
        self._stop_requested = threading.Event()
        self.process: subprocess.Popen | None = None
        self._controller = None
        self._log_handle = None
        self._log_start_offset = 0
        self.state = TorState.STOPPED
        self.bootstrap_progress: int | None = None
        self.last_error: str | None = None
        dirs = user_directories()
        self.data_directory = Path(settings.data_directory or (dirs.data / "tor"))
        self.torrc_path = self.data_directory / "torrc"
        self.log_path = dirs.logs / "tor.log"
        self._data_directory_lock_path = self.data_directory / ".torproxy-data-directory.lock"
        self._data_directory_lock_handle = None
        self._locked_data_directory: str | None = None

    def _acquire_data_directory_lock(self) -> None:
        """Exclusively claim the configured data directory before touching Tor state."""
        self.data_directory.mkdir(parents=True, exist_ok=True)
        canonical = os.path.normcase(str(self.data_directory.resolve()))
        with _ACTIVE_DATA_DIRECTORIES_LOCK:
            if canonical in _ACTIVE_DATA_DIRECTORIES:
                raise TorManagerError(
                    f"Another managed Tor instance already owns data directory {self.data_directory}. "
                    "Stop the existing connection before starting another."
                )
            _ACTIVE_DATA_DIRECTORIES.add(canonical)

        handle = None
        try:
            handle = self._data_directory_lock_path.open("a+b")
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._data_directory_lock_handle = handle
            self._locked_data_directory = canonical
        except OSError as exc:
            if handle is not None:
                handle.close()
            with _ACTIVE_DATA_DIRECTORIES_LOCK:
                _ACTIVE_DATA_DIRECTORIES.discard(canonical)
            raise TorManagerError(
                f"Tor data directory is already locked by another process: {self.data_directory}. "
                "Close the existing Tor/TorProxy process, then retry. TorProxy will not terminate "
                "a process it does not own."
            ) from exc
        except Exception:
            if handle is not None:
                handle.close()
            with _ACTIVE_DATA_DIRECTORIES_LOCK:
                _ACTIVE_DATA_DIRECTORIES.discard(canonical)
            raise

    def _stop_stale_managed_tor_processes(self) -> None:
        """Reap Tor children left behind by an exited TorProxy UI, but only for our exact torrc."""
        target_torrc = os.path.normcase(str(self.torrc_path.resolve()))
        matching = []
        for process in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                info = process.info
                if int(info.get("pid") or 0) == os.getpid():
                    continue
                name = str(info.get("name") or "").casefold()
                command = info.get("cmdline") or []
                executable_name = Path(str(command[0])).name.casefold() if command else ""
                if name not in {"tor", "tor.exe"} and executable_name not in {"tor", "tor.exe"}:
                    continue
                uses_managed_torrc = any(
                    argument
                    and os.path.normcase(str(Path(str(argument).strip('"')).resolve())) == target_torrc
                    for argument in command[1:]
                )
                if uses_managed_torrc:
                    matching.append(process)
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except (OSError, ValueError, TypeError):
                logger.debug("Could not inspect a running process while checking TorProxy's torrc.", exc_info=True)

        if not matching:
            return
        process_ids = [process.pid for process in matching]
        logger.warning(
            "Found stale Tor process(es) %s still referencing TorProxy's dedicated torrc; stopping them "
            "before reusing the data directory.",
            process_ids,
        )
        for process in matching:
            try:
                process.terminate()
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied as exc:
                raise TorManagerError(
                    f"Could not stop stale Tor process {process.pid} using TorProxy's data directory. "
                    "Close that process manually, then retry."
                ) from exc
        _, alive = psutil.wait_procs(matching, timeout=3)
        if alive:
            for process in alive:
                try:
                    process.kill()
                except psutil.NoSuchProcess:
                    pass
                except psutil.AccessDenied as exc:
                    raise TorManagerError(
                        f"Stale Tor process {process.pid} could not be stopped. Close it manually, then retry."
                    ) from exc
            _, alive = psutil.wait_procs(alive, timeout=2)
        if alive:
            raise TorManagerError(
                "A stale Tor process is still using TorProxy's data directory (PID(s): {}). "
                "Close that process manually before retrying.".format(
                    ", ".join(str(process.pid) for process in alive)
                )
            )

    def _release_data_directory_lock(self) -> None:
        handle, self._data_directory_lock_handle = self._data_directory_lock_handle, None
        canonical, self._locked_data_directory = self._locked_data_directory, None
        if handle is not None:
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                LOGGER.debug("Could not explicitly release Tor data-directory lock.", exc_info=True)
            finally:
                handle.close()
        if canonical is not None:
            with _ACTIVE_DATA_DIRECTORIES_LOCK:
                _ACTIVE_DATA_DIRECTORIES.discard(canonical)

    @staticmethod
    def _torrc_quote(value: str | Path) -> str:
        text = str(value)
        if "\n" in text or "\r" in text or "\0" in text:
            raise TorManagerError("Tor configuration paths cannot contain control characters.")
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'

    @staticmethod
    def _parse_bridges(text: str) -> list[tuple[str, str]]:
        allowed = {"obfs4", "snowflake", "webtunnel"}
        parsed: list[tuple[str, str]] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("bridge "):
                line = line[7:].strip()
            fields = line.split()
            if len(fields) < 2 or fields[0].lower() not in allowed:
                raise TorManagerError(
                    "Each bridge must be a supported bridge record beginning with obfs4, snowflake, webtunnel, or meek_lite."
                )
            address = fields[1]
            if address.startswith("["):
                match = re.fullmatch(r"\[([^\]]+)\]:([0-9]{1,5})", address)
                if not match:
                    raise TorManagerError("A bridge address has an invalid IPv6 authority.")
                try:
                    ipaddress.IPv6Address(match.group(1))
                except ValueError as exc:
                    raise TorManagerError("A bridge address contains an invalid IPv6 literal.") from exc
                port = int(match.group(2))
            else:
                match = re.fullmatch(r"([^:\s]+):([0-9]{1,5})", address)
                if not match:
                    raise TorManagerError("A bridge address must be an IP literal followed by a port.")
                try:
                    ipaddress.IPv4Address(match.group(1))
                except ValueError as exc:
                    raise TorManagerError("Bridge addresses must use IPv4 or bracketed IPv6 literals.") from exc
                port = int(match.group(2))
            if not 1 <= port <= 65535:
                raise TorManagerError("A bridge port must be between 1 and 65535.")
            parsed.append((fields[0].lower(), line))
        return parsed

    def render_torrc(self) -> str:
        settings = self.settings
        self.data_directory.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.data_directory.chmod(0o700)
        lines = [
            f"DataDirectory {self._torrc_quote(self.data_directory)}",
            f"SocksPort 127.0.0.1:{settings.socks_port}",
            f"ControlPort 127.0.0.1:{settings.control_port}",
            "CookieAuthentication 1",
            "CookieAuthFile " + self._torrc_quote(self.data_directory / "control_auth_cookie"),
            "CookieAuthFileGroupReadable 0",
            "Log notice stdout",
            f"MaxCircuitDirtiness {settings.max_circuit_dirtiness_seconds}",
            f"NewCircuitPeriod {settings.new_circuit_period_seconds}",
            "ClientUseIPv4 1",
            "ClientUseIPv6 1",
        ]
        if settings.dns_port is not None:
            lines.insert(3, f"DNSPort 127.0.0.1:{settings.dns_port}")
        if settings.geoip_path and Path(settings.geoip_path).is_file():
            lines.append("GeoIPFile " + self._torrc_quote(settings.geoip_path))
        if settings.geoip6_path and Path(settings.geoip6_path).is_file():
            lines.append("GeoIPv6File " + self._torrc_quote(settings.geoip6_path))
        if settings.bridges_enabled:
            bridge_records = self._parse_bridges(settings.bridges)
            if not bridge_records:
                raise TorManagerError("Bridge mode is enabled but no valid bridge records were provided.")
            executable = Path(settings.executable)
            transport_dir = executable.parent / "pluggable_transports"
            transport_candidates = [
                transport_dir / ("lyrebird.exe" if os.name == "nt" else "lyrebird"),
                transport_dir / "lyrebird",
                transport_dir / "lyrebird.exe",
            ]
            transport = next((candidate for candidate in transport_candidates if candidate.is_file()), None)
            if transport is None:
                raise TorManagerError("Bridge transport executable (lyrebird) was not found beside the selected Tor bundle.")
            lines.append("UseBridges 1")
            for kind in sorted({item[0] for item in bridge_records}):
                lines.append(f"ClientTransportPlugin {kind} exec {self._torrc_quote(transport)}")
            lines.extend("Bridge " + record for _, record in bridge_records)
        elif settings.bridges.strip():
            LOGGER.warning("Bridge records are configured but bridge mode is disabled.")
        return "\n".join(lines) + "\n"

    def _connect_controller(self):
        factory = self._controller_factory
        if factory is None:
            try:
                from stem.control import Controller
            except ImportError as exc:
                raise TorManagerError("The Stem library is required for authenticated Tor control.") from exc
            def factory():
                return Controller.from_port(
                    address="127.0.0.1", port=self.settings.control_port
                )
        controller = factory()
        controller.authenticate()
        return controller

    @staticmethod
    def _port_ready(port: int, timeout: float = 0.2) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=timeout):
                return True
        except OSError:
            return False

    def _emit(self, callback: BootstrapCallback | None, state: TorState, progress: int | None, message: str) -> None:
        self.state = state
        self.bootstrap_progress = progress
        if callback:
            try:
                callback(state, progress, message)
            except Exception:
                LOGGER.exception("Tor status callback failed.")

    def _recent_tor_log_detail(self, *, max_lines: int = 5) -> str:
        """Return bounded recent Tor diagnostics for early process-exit errors."""
        try:
            with self.log_path.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                start = max(self._log_start_offset, size - 8192)
                handle.seek(start)
                if start > self._log_start_offset:
                    handle.readline()  # Skip a partial first line from the bounded tail.
                recent_text = handle.read().decode("utf-8", errors="replace")
            lines = [line.strip() for line in recent_text.splitlines() if line.strip()]
        except OSError as exc:
            return f"Tor log unavailable at {self.log_path}: {exc}"
        if not lines:
            return f"Tor log is empty ({self.log_path})."
        # Keep the user-facing error actionable without flooding the notification UI.
        recent = " | ".join(line[-220:] for line in lines[-max_lines:])
        return f"Recent Tor log ({self.log_path}): {recent}"

    @staticmethod
    def _summarize_process_output(output: str | None, *, max_lines: int = 5) -> str:
        lines = [line.strip() for line in (output or "").splitlines() if line.strip()]
        return " | ".join(line[-220:] for line in lines[-max_lines:])

    def start(self, on_status: BootstrapCallback | None = None) -> None:
        if not self._start_lock.acquire(blocking=False):
            raise TorManagerError("A Tor start operation is already in progress.")
        try:
            with self._lock:
                if self.process is not None and self.process.poll() is None:
                    if self.state is TorState.READY:
                        return
                    raise TorManagerError("Tor is already starting or running.")
                self._stop_requested.clear()
                self.last_error = None
                self._emit(on_status, TorState.STARTING, 0, "Validating Tor configuration.")
            executable = Path(self.settings.executable).expanduser().resolve()
            if not executable.is_file():
                raise TorManagerError(f"Tor executable not found: {executable}")
            if os.name != "nt" and not os.access(executable, os.X_OK):
                raise TorManagerError(f"Tor executable is not executable: {executable}")

            self.data_directory.mkdir(parents=True, exist_ok=True)
            self._acquire_data_directory_lock()
            self._stop_stale_managed_tor_processes()
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                self.data_directory.chmod(0o700)
                self.log_path.parent.chmod(0o700)
            torrc_text = self.render_torrc()
            fd, temp_name = tempfile.mkstemp(prefix=".torrc-", suffix=".tmp", dir=self.data_directory)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as config_file:
                    config_file.write(torrc_text)
                    config_file.flush()
                    os.fsync(config_file.fileno())
                if os.name != "nt":
                    os.chmod(temp_name, 0o600)
                os.replace(temp_name, self.torrc_path)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)

            try:
                check = self._run_factory(
                    [str(executable), "-f", str(self.torrc_path), "--verify-config"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, timeout=10, check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise TorManagerError("Tor configuration validation timed out.") from exc
            if check.returncode != 0:
                details = self._summarize_process_output(check.stdout)
                raise TorManagerError(
                    "Tor rejected its configuration: "
                    + (details or "unknown validation error")
                )

            self._log_handle = self.log_path.open("ab", buffering=0)
            self._log_handle.seek(0, os.SEEK_END)
            self._log_start_offset = self._log_handle.tell()
            kwargs = {
                "stdin": subprocess.DEVNULL,
                "stdout": self._log_handle,
                "stderr": subprocess.STDOUT,
                "close_fds": True,
            }
            if os.name == "nt":
                kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            else:
                kwargs["start_new_session"] = True
            with self._lock:
                self.process = self._popen_factory([str(executable), "-f", str(self.torrc_path)], **kwargs)
            deadline = time.monotonic() + self.settings.startup_timeout_seconds
            last_detail = "Waiting for Tor ControlPort."
            while time.monotonic() < deadline:
                if self._stop_requested.is_set():
                    raise TorManagerError("Tor startup was cancelled.")
                proc = self.process
                if proc is None or proc.poll() is not None:
                    code = None if proc is None else proc.returncode
                    detail = self._recent_tor_log_detail()
                    if "another Tor process is running with the same data directory" in detail.lower():
                        raise TorManagerError(
                            f"Another Tor process is already using data directory {self.data_directory}. "
                            "Stop that process before retrying; TorProxy will not terminate an unmanaged process. "
                            + detail
                        )
                    raise TorManagerError(
                        f"Tor exited unexpectedly during startup (exit code {code}). {detail}"
                    )
                try:
                    if self._controller is None:
                        if not self._port_ready(self.settings.control_port):
                            time.sleep(0.25)
                            continue
                        self._controller = self._connect_controller()
                        reported_pid = self._controller.get_info("process/pid", None)
                        if (reported_pid is None or not str(reported_pid).isdecimal()
                                or int(reported_pid) != int(proc.pid)):
                            try:
                                self._controller.close()
                            except Exception:
                                pass
                            self._controller = None
                            raise TorManagerError(
                                "The authenticated ControlPort did not identify the Tor process started by this application."
                            )
                    phase = self._controller.get_info("status/bootstrap-phase", "")
                    match = re.search(r"PROGRESS=(\d+)", phase)
                    progress = int(match.group(1)) if match else None
                    last_detail = phase[:240] if phase else "Tor is responding on the authenticated ControlPort."
                    if progress is not None and progress >= 100 and self._port_ready(self.settings.socks_port):
                        self._emit(on_status, TorState.READY, 100, "Tor bootstrap completed; SOCKS listener is accepting connections.")
                        return
                    self._emit(on_status, TorState.BOOTSTRAPPING, progress, last_detail)
                except TorManagerError:
                    raise
                except Exception as exc:
                    last_detail = f"Tor control/bootstrap check failed: {type(exc).__name__}"
                    if self._controller is not None:
                        try:
                            self._controller.close()
                        except Exception:
                            pass
                        self._controller = None
                    LOGGER.debug("%s", last_detail)
                time.sleep(0.5)
            raise TorManagerError(f"Tor did not become ready within {self.settings.startup_timeout_seconds:.0f}s. Last status: {last_detail}")
        except Exception as exc:
            self.last_error = str(exc)
            was_stopped = self._stop_requested.is_set()
            self._terminate_process()
            self._release_data_directory_lock()
            self._emit(on_status, TorState.STOPPED if was_stopped else TorState.FAILED, None, self.last_error)
            if isinstance(exc, TorManagerError):
                raise
            raise TorManagerError(str(exc)) from exc
        finally:
            self._start_lock.release()

    def request_new_identity(self) -> float:
        with self._lock:
            if self.state is not TorState.READY or self._controller is None:
                raise TorManagerError("Tor is not ready; identity changes are unavailable.")
            wait = float(self._controller.get_newnym_wait())
            if wait > 0:
                return wait
            try:
                from stem import Signal
            except ImportError as exc:
                raise TorManagerError("The Stem library is required to request a new identity.") from exc
            self._controller.signal(Signal.NEWNYM)
            return 0.0

    def _terminate_process(self) -> None:
        with self._lock:
            controller, self._controller = self._controller, None
            process = self.process
        if controller is not None:
            try:
                controller.close()
            except Exception:
                pass
        if process is not None and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=self.settings.shutdown_timeout_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    LOGGER.error("Tor did not exit after force termination.")
            except OSError:
                LOGGER.exception("Could not terminate the managed Tor process.")
        with self._lock:
            if process is not None and self.process is process:
                self.process = None
            if self._log_handle is not None:
                try:
                    self._log_handle.close()
                except OSError:
                    pass
                self._log_handle = None

    def stop(self) -> None:
        self._stop_requested.set()
        self._emit(None, TorState.STOPPING, None, "Stopping the managed Tor process.")
        self._terminate_process()
        self._release_data_directory_lock()
        self._emit(None, TorState.STOPPED, None, "Tor stopped.")
