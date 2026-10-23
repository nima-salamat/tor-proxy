"""Supervised Tor subprocess lifecycle with explicit loopback ControlPort authentication."""
from __future__ import annotations

import logging
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import psutil

from .paths import user_directories
from .bridges import SUPPORTED_BRIDGE_TRANSPORTS, normalize_sni_hostname, parse_bridge_text


_ACTIVE_DATA_DIRECTORIES: set[str] = set()
_ACTIVE_DATA_DIRECTORIES_LOCK = threading.Lock()

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
    log_path: Path | None = None
    webtunnel_sni_imitation: str = ""

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
        try:
            normalize_sni_hostname(self.webtunnel_sni_imitation or "")
        except (TypeError, ValueError) as exc:
            raise TorManagerError(f"Invalid WebTunnel SNI imitation hostname: {exc}") from exc
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
        self._bootstrap_log_offset = 0
        self._bootstrap_log_pending = b""
        self._last_log_bootstrap_report: tuple[int, str] | None = None
        self.state = TorState.STOPPED
        self.bootstrap_progress: int | None = None
        self.last_error: str | None = None
        dirs = user_directories()
        self.data_directory = Path(settings.data_directory or (dirs.data / "tor"))
        self.torrc_path = self.data_directory / "torrc"
        self.log_path = Path(settings.log_path) if settings.log_path is not None else dirs.logs / "tor.log"
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
            except psutil.Error:
                LOGGER.debug("Could not inspect a running process while checking TorProxy's torrc.", exc_info=True)
            except (OSError, ValueError, TypeError):
                LOGGER.debug("Could not normalize a process command line while checking TorProxy's torrc.", exc_info=True)

        if not matching:
            return
        process_ids = [process.pid for process in matching]
        LOGGER.warning(
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
    def _transport_exec_path(path: Path) -> str:
        """Return the PT executable path without quotes that Tor passes to CreateProcess.

        Tor's ClientTransportPlugin parser forwards this token to its managed
        proxy launcher. Torrc quoting escapes used for DataDirectory/CookieAuthFile
        are therefore not valid here: on Windows they can reach CreateProcessA
        as literal quote characters, producing the doubled-quote launch failure.
        """
        value = str(path)
        if any(character.isspace() for character in value):
            if os.name == "nt":
                # Windows short paths avoid literal quotes in Tor's PT command.
                try:
                    import ctypes
                    from ctypes import wintypes

                    get_short_path = ctypes.windll.kernel32.GetShortPathNameW
                    get_short_path.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
                    get_short_path.restype = wintypes.DWORD
                    buffer = ctypes.create_unicode_buffer(32768)
                    length = get_short_path(value, buffer, len(buffer))
                    if length and length < len(buffer):
                        short_value = buffer.value
                        if not any(character.isspace() for character in short_value):
                            value = short_value
                        else:
                            raise OSError("Windows did not provide a space-free short path.")
                    else:
                        raise OSError("Windows could not resolve a short path.")
                except (AttributeError, OSError) as exc:
                    raise TorManagerError(
                        "The path to the Tor bridge transport contains spaces and Windows could not "
                        "resolve a short path. Move the Tor Expert Bundle to a directory without "
                        "spaces and select it again."
                    ) from exc
            else:
                raise TorManagerError(
                    "The path to the Tor bridge transport contains spaces. Move the Tor Expert Bundle "
                    "to a directory without spaces and select it again."
                )
        if '"' in value or "\n" in value or "\r" in value:
            raise TorManagerError("The Tor bridge transport path contains unsupported characters.")
        return value

    @staticmethod
    def _parse_bridges(text: str) -> list[tuple[str, str]]:
        """Use the same strict bridge parser as Settings and QR imports."""
        result = parse_bridge_text(text)
        if result.invalid_records:
            details = " ".join(result.errors[:3])
            if len(result.errors) > 3:
                details += f" Plus {len(result.errors) - 3} more invalid item(s)."
            raise TorManagerError(
                "One or more supported bridge records are malformed. "
                + details
                + " Each record must contain at most one address:port. IPv6 endpoints must be written as "
                "[address]:port; quotes around the endpoint are normalized automatically. "
                "A supported transport (obfs4, snowflake, webtunnel, or meek_lite) is optional. "
                "Separate bridges with newlines, or paste them together and TorProxy will split them."
            )
        parsed: list[tuple[str, str]] = []
        for record in result.records:
            first = record.split(maxsplit=1)[0].casefold()
            transport = first if first in SUPPORTED_BRIDGE_TRANSPORTS else ""
            parsed.append((transport, record))
        return parsed

    @staticmethod
    def _has_non_webtunnel_bridge_alternative(bridges: list[tuple[str, str]]) -> bool:
        """Return whether a configured bridge does not depend on WebTunnel TLS."""
        return any(transport != "webtunnel" for transport, _record in bridges)

    @staticmethod
    def _bridge_input_shape_diagnostics(text: str, *, max_records: int = 8) -> str:
        """Summarize bridge token shapes without logging endpoints or fingerprints."""
        parsed = parse_bridge_text(text)
        parts: list[str] = []
        for index, record in enumerate(parsed.records[:max_records], start=1):
            fields = record.split()
            first = fields[0].casefold() if fields else ""
            has_transport = first in SUPPORTED_BRIDGE_TRANSPORTS
            transport = first if has_transport else "direct"
            endpoint_index = 1 if has_transport else 0
            remainder = fields[endpoint_index + 1:]
            bare = [token for token in remainder if "=" not in token]
            fingerprint_options = [
                token.split("=", 1)[1]
                for token in remainder
                if token.casefold().startswith("fingerprint=")
            ]
            if bare:
                digest_summary = ", ".join(
                    f"bare-token length={len(token)} hex={bool(re.fullmatch(r'[0-9a-fA-F]{40}', token))}"
                    for token in bare
                )
            else:
                digest_summary = "no bare identity fingerprint"
            for option in fingerprint_options:
                digest_summary += (
                    f"; fingerprint option length={len(option)} "
                    f"hex={bool(re.fullmatch(r'[0-9a-fA-F]{40}', option))}"
                )
            option_names = [
                token.split("=", 1)[0]
                for token in remainder
                if "=" in token
            ]
            options = ",".join(option_names[:12]) or "none"
            parts.append(f"item {index} ({transport}): {digest_summary}; options={options}")
        if len(parsed.records) > max_records:
            parts.append(f"{len(parsed.records) - max_records} more bridge item(s) omitted")
        if parsed.invalid_records:
            parts.append(f"{len(parsed.invalid_records)} item(s) were rejected by the bridge parser")
        return "Bridge input shape (secret values hidden): " + " | ".join(parts or ["no records parsed"])

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
            lines.append("UseBridges 1")
            needs_transport = any(transport for transport, _record in bridge_records)
            if needs_transport:
                transport_dir = executable.parent / "pluggable_transports"
                transport_candidates = [
                    transport_dir / ("lyrebird.exe" if os.name == "nt" else "lyrebird"),
                    transport_dir / "lyrebird",
                    transport_dir / "lyrebird.exe",
                ]
                transport = next((candidate for candidate in transport_candidates if candidate.is_file()), None)
                if transport is None:
                    raise TorManagerError(
                        "Bridge transport executable (lyrebird) was not found beside the selected Tor bundle."
                    )
                # A single plugin declaration is important for Lyrebird: it registers
                # all supported PT names from the same managed executable.
                transport_exec = self._transport_exec_path(transport)
                lines.append(
                    "ClientTransportPlugin meek_lite,obfs4,snowflake,webtunnel exec "
                    + transport_exec
                )
            sni_imitation = normalize_sni_hostname(settings.webtunnel_sni_imitation or "")
            for bridge_transport, record in bridge_records:
                if bridge_transport.casefold() == "webtunnel" and sni_imitation:
                    has_explicit_sni = any(
                        token.casefold().startswith("sni-imitation=")
                        for token in record.split()[2:]
                    )
                    if not has_explicit_sni:
                        record += " sni-imitation=" + sni_imitation
                lines.append("Bridge " + record)
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

    def get_active_bridge_fingerprints(self) -> frozenset[str]:
        """Return bridge identities observed as the first hop of a built Tor circuit.

        A configured bridge is not reported as active merely because it was
        pasted or passed a reachability check. We require Tor's authenticated
        ControlPort to report a currently BUILT circuit and match its first hop
        to a fingerprint explicitly present in the bridge record.
        """
        if (
            not self.settings.bridges_enabled
            or self.state is not TorState.READY
            or self._controller is None
        ):
            return frozenset()

        try:
            with self._lock:
                circuits = self._controller.get_circuits()
        except Exception:
            LOGGER.debug("Could not read active Tor circuits for bridge status.", exc_info=True)
            return frozenset()

        active: set[str] = set()
        for circuit in circuits:
            status_value = getattr(circuit, "status", "")
            status = str(getattr(status_value, "value", status_value)).upper().split(".")[-1]
            if status != "BUILT":
                continue
            path = getattr(circuit, "path", ()) or ()
            if not path:
                continue
            try:
                first_hop = str(path[0][0]).upper()
            except (IndexError, TypeError):
                continue
            match = re.search(r"[0-9A-F]{40}", first_hop)
            if match:
                active.add(match.group(0))
        return frozenset(active)

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
    def _parse_bootstrap_log_line(line: str) -> tuple[int, str] | None:
        """Parse bootstrap progress emitted to Tor's configured notice log."""
        match = re.search(r"\bPROGRESS=(\d{1,3})\b", line, re.IGNORECASE)
        if match:
            progress = int(match.group(1))
            if not 0 <= progress <= 100:
                return None
            summary = re.search(r'\bSUMMARY=(?:"([^"]*)"|(.*?))(?:\s+\w+=|$)', line, re.IGNORECASE)
            tag = re.search(r"\bTAG=([A-Za-z0-9_-]+)", line, re.IGNORECASE)
            detail = (summary.group(1) or summary.group(2) or "").strip() if summary else ""
            if not detail:
                detail = tag.group(1).replace("_", " ") if tag else "Tor bootstrap in progress"
            return progress, detail

        match = re.search(
            r"\bBootstrapped\s+(\d{1,3})%\s*(?:\(([^)]*)\))?\s*:?[ \t]*(.*)$",
            line,
            re.IGNORECASE,
        )
        if match:
            progress = int(match.group(1))
            if not 0 <= progress <= 100:
                return None
            stage = (match.group(2) or "").replace("_", " ").strip()
            summary = match.group(3).strip()
            detail = summary or stage or "Tor bootstrap in progress"
            return progress, detail
        return None

    def _read_bootstrap_log_updates(self) -> list[tuple[int, str]]:
        """Read newly appended Tor log lines and extract real bootstrap progress."""
        try:
            with self.log_path.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                if size < self._bootstrap_log_offset:
                    # A user cleared/rotated the log while Tor was running.
                    self._bootstrap_log_offset = size
                    self._bootstrap_log_pending = b""
                    return []
                handle.seek(self._bootstrap_log_offset)
                chunk = handle.read()
                self._bootstrap_log_offset = handle.tell()
        except OSError:
            return []
        if not chunk:
            return []

        payload = self._bootstrap_log_pending + chunk
        lines = payload.split(b"\n")
        self._bootstrap_log_pending = lines.pop() if lines else b""
        updates: list[tuple[int, str]] = []
        for raw_line in lines:
            parsed = self._parse_bootstrap_log_line(raw_line.decode("utf-8", errors="replace").strip())
            if parsed is None or parsed == self._last_log_bootstrap_report:
                continue
            self._last_log_bootstrap_report = parsed
            updates.append(parsed)
        return updates

    def clear_log_file(self) -> None:
        """Clear the current Tor log while retaining the active stdout handle."""
        with self._lock:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            handle = self._log_handle
            try:
                if handle is not None and not handle.closed:
                    handle.flush()
                    os.ftruncate(handle.fileno(), 0)
                    handle.seek(0, os.SEEK_END)
                else:
                    with self.log_path.open("wb"):
                        pass
            except OSError as exc:
                raise TorManagerError(f"Could not clear Tor log file {self.log_path}: {exc}") from exc
            self._log_start_offset = 0
            self._bootstrap_log_offset = 0
            self._bootstrap_log_pending = b""
            self._last_log_bootstrap_report = None

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
                lowered_details = details.lower()
                # Read the preference from this manager instance; no local
                # variable named "settings" exists in start().
                bridges_enabled = bool(self.settings.bridges_enabled)
                if bridges_enabled and "key digest for bridge is wrong length" in lowered_details:
                    raise TorManagerError(
                        "Tor rejected a bridge identity fingerprint because its digest has the wrong length. "
                        "A supplied bridge fingerprint must be the complete 40-character hexadecimal value. "
                        "Copy the bridge line directly from the Tor Project bridge source; do not paste a nickname, "
                        "partial fingerprint, or hashed fingerprint. "
                        + self._bridge_input_shape_diagnostics(self.settings.bridges)
                        + " Tor diagnostics: "
                        + (details or "no further details")
                    )
                if bridges_enabled and (
                    "bridge line did not parse" in lowered_details
                    or "is not a k=v value" in lowered_details
                    or "is not a k=v item" in lowered_details
                ):
                    raise TorManagerError(
                        "Tor rejected one of the configured Bridge records. IPv6 endpoints must be written as "
                        "[address]:port without quotes, followed by the bridge fingerprint and transport parameters "
                        "(for example url=… and ver=0.0.1 for WebTunnel). TorProxy now removes quotes around IPv6 "
                        "endpoints automatically; if this error persists, check that the complete bridge line was "
                        "pasted and contains its fingerprint/required parameters. Tor diagnostics: "
                        + (details or "no further details")
                    )
                raise TorManagerError(
                    "Tor rejected its configuration: "
                    + (details or "unknown validation error")
                )

            self._log_handle = self.log_path.open("ab", buffering=0)
            self._log_handle.seek(0, os.SEEK_END)
            self._log_start_offset = self._log_handle.tell()
            self._bootstrap_log_offset = self._log_start_offset
            self._bootstrap_log_pending = b""
            self._last_log_bootstrap_report = None
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
            curve_warning_reported = False
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
                for log_progress, log_detail in self._read_bootstrap_log_updates():
                    last_detail = log_detail
                    self._emit(on_status, TorState.BOOTSTRAPPING, log_progress, log_detail)
                if self.settings.bridges_enabled:
                    diagnostic = self._recent_tor_log_detail(max_lines=20)
                    lowered_diagnostic = diagnostic.lower()
                    if any(marker in lowered_diagnostic for marker in (
                        "createprocessa() failed",
                        "failed to start process",
                        "failed at launch",
                    )):
                        raise TorManagerError(
                            "Tor could not launch the bundled bridge transport executable. "
                            "Check the transport executable path and its file permissions. The bridge itself "
                            "has not been shown to be offline. Live Tor log details: " + diagnostic
                        )
                    if "tls: curvepreferences includes unsupported curve" in lowered_diagnostic:
                        try:
                            configured_bridges = self._parse_bridges(self.settings.bridges)
                        except TorManagerError:
                            configured_bridges = []
                        # This error is associated with WebTunnel's TLS setup,
                        # not proof that the remote bridge is dead. Give any
                        # non-WebTunnel alternative (including obfs4/Snowflake or
                        # a direct bridge) a chance before declaring startup failed.
                        has_non_webtunnel_alternative = self._has_non_webtunnel_bridge_alternative(
                            configured_bridges
                        )
                        if not has_non_webtunnel_alternative:
                            raise TorManagerError(
                                "The bundled Lyrebird WebTunnel transport cannot negotiate TLS with this "
                                "Go/TLS runtime ('CurvePreferences includes unsupported curve'). This is a "
                                "transport-bundle compatibility issue, not proof that the configured bridges "
                                "are dead. Automatic cleanup will not remove bridge records for this error. "
                                "The installed bundle appears to be an alpha/prerelease; try a verified stable "
                                "Tor Expert Bundle in the updater. Live Tor log details: " + diagnostic
                            )
                        if not curve_warning_reported:
                            LOGGER.warning(
                                "Lyrebird's WebTunnel TLS settings are incompatible, but a non-WebTunnel "
                                "alternative exists; continuing bootstrap rather than aborting on that transport."
                            )
                            curve_warning_reported = True
                    if "no configured transport called" in lowered_diagnostic:
                        transport_match = re.search(
                            r'no configured transport called\s+["\']([^"\']+)["\']',
                            diagnostic,
                            re.IGNORECASE,
                        )
                        transport_name = transport_match.group(1) if transport_match else "a configured bridge transport"
                        raise TorManagerError(
                            f"Tor cannot use the configured {transport_name} bridge because the selected "
                            "Lyrebird executable did not register that transport. Update the Tor Expert Bundle "
                            "from the updater, select a bundle that supports this transport, and open Live Tor log "
                            f"for details. {diagnostic}"
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
            if self.settings.bridges_enabled:
                diagnostic = self._recent_tor_log_detail(max_lines=20)
                if "tls: curvepreferences includes unsupported curve" in diagnostic.lower():
                    raise TorManagerError(
                        f"Tor did not become ready within {self.settings.startup_timeout_seconds:.0f}s. "
                        "Lyrebird also reported 'tls: CurvePreferences includes unsupported curve'. "
                        "Any direct-bridge alternatives were allowed to continue, but no ready Tor connection was "
                        "verified. The original bridge list remains intact. Live Tor log details: "
                        + diagnostic
                    )
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
