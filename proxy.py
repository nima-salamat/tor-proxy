"""Loopback-only threaded HTTP proxy with consistent host policy and bounded accounting."""
from __future__ import annotations

import ipaddress
import json
import os
import logging
import queue
import sqlite3
import select
import socket
import threading
import time
import tempfile
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import urlsplit

import socks
import psutil

from config import CONFIG
from torproxy.host_rules import HostRuleError, HostRules, normalize_hostname
from torproxy.paths import user_directories
from torproxy.traffic_history import TrafficHistoryStore
from utils import resource_path

SRC_ROOT = Path(__file__).resolve().parent / "src"
if SRC_ROOT.is_dir() and str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

logger = logging.getLogger(__name__)
BLOCKED_FILE = "blocked_hosts.json"
EXCLUDE_FILE = "exclude_hosts.json"
MAX_REQUEST_BODY_BYTES = 32 * 1024 * 1024
SOCKET_TIMEOUT_SECONDS = 30.0
REQUEST_READ_TIMEOUT_SECONDS = 30.0
RELAY_IDLE_TIMEOUT_SECONDS = 120.0
RELAY_SHUTDOWN_POLL_SECONDS = 0.25

_rule_lock = threading.RLock()
_blocked_rules = HostRules()
_excluded_rules = HostRules()
queue_bytes: queue.Queue[tuple[float, int, str | None]] = queue.Queue(maxsize=65536)
_traffic_direction_lock = threading.Lock()
_traffic_direction_totals = {"upload": 0, "download": 0}
_accounting_drop_lock = threading.Lock()
_accounting_dropped_events = 0


def get_traffic_direction_snapshot() -> dict[str, int]:
    """Return thread-safe in-process upload/download byte totals."""
    with _traffic_direction_lock:
        return dict(_traffic_direction_totals)


def _read_system_tun_io_counters() -> tuple[int, int] | None:
    """Read cumulative sent/received bytes from TorProxy's TUN adapter.

    This is sampled by the background accounting worker, never from a relay
    socket callback, so interface polling cannot add latency to user traffic.
    """
    try:
        counters = psutil.net_io_counters(pernic=True) or {}
    except (OSError, RuntimeError, AttributeError, TypeError, psutil.Error):
        logger.debug("Could not read per-interface traffic counters.", exc_info=True)
        return None
    for name, counter in counters.items():
        if str(name).casefold() in {"torproxy", "torproxy-tun"}:
            try:
                return max(0, int(counter.bytes_sent)), max(0, int(counter.bytes_recv))
            except (AttributeError, TypeError, ValueError, OverflowError):
                return None
    return None


def _rules_path(filename: str) -> Path:
    return user_directories().config / filename


def _atomic_json(path: Path, value: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + "-", suffix=".tmp", dir=path.parent)
    temp = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if temp.stat().st_size > 1024 * 1024:
            raise ValueError("Host rule file is too large.")
        if os.name != "nt":
            temp.chmod(0o600)
        os.replace(temp, path)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def _load_rules(filename: str) -> HostRules:
    path = _rules_path(filename)
    if not path.exists():
        # Import the old working-directory file once, but never write runtime data
        # back into the installation directory.
        legacy = Path(resource_path(filename))
        if legacy.is_file():
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                raw = json.loads(legacy.read_text(encoding="utf-8"))
                if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
                    rules = HostRules.from_values(raw)
                    _atomic_json(path, rules.as_list())
                    return rules
            except (OSError, ValueError, json.JSONDecodeError):
                logger.warning("Could not migrate legacy host rules from %s.", legacy)
        return HostRules()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
            raise ValueError("expected a JSON list of strings")
        return HostRules.from_values(raw)
    except (OSError, ValueError, json.JSONDecodeError, HostRuleError):
        logger.exception("Could not load host rules from %s; using an empty rule set.", path)
        return HostRules()


def load_blocked() -> None:
    global _blocked_rules
    rules = _load_rules(BLOCKED_FILE)
    with _rule_lock:
        _blocked_rules = rules


def add_to_blocked_hosts(host: str) -> bool:
    global _blocked_rules
    rule = HostRules.from_values([host]).rules[0]
    with _rule_lock:
        if rule in _blocked_rules.rules:
            return False
        updated = _blocked_rules.add(host)
        _atomic_json(_rules_path(BLOCKED_FILE), updated.as_list())
        _blocked_rules = updated
    return True


def get_blocked() -> list[str]:
    with _rule_lock:
        return _blocked_rules.as_list()


def remove_blocked(host: str) -> None:
    global _blocked_rules
    with _rule_lock:
        updated = _blocked_rules.remove(host)
        # Persist first: a failed disk write must not silently disable a live block rule.
        _atomic_json(_rules_path(BLOCKED_FILE), updated.as_list())
        _blocked_rules = updated


def save_blocked() -> None:
    _atomic_json(_rules_path(BLOCKED_FILE), get_blocked())


def load_exclude() -> None:
    global _excluded_rules
    rules = _load_rules(EXCLUDE_FILE)
    with _rule_lock:
        _excluded_rules = rules


def add_to_exclude_hosts(host: str) -> bool:
    global _excluded_rules
    rule = HostRules.from_values([host]).rules[0]
    with _rule_lock:
        if rule in _excluded_rules.rules:
            return False
        updated = _excluded_rules.add(host)
        _atomic_json(_rules_path(EXCLUDE_FILE), updated.as_list())
        _excluded_rules = updated
    return True


def get_exclude() -> list[str]:
    with _rule_lock:
        return _excluded_rules.as_list()


def remove_exclude(host: str) -> None:
    global _excluded_rules
    with _rule_lock:
        updated = _excluded_rules.remove(host)
        # Keep runtime policy unchanged if the persisted update fails.
        _atomic_json(_rules_path(EXCLUDE_FILE), updated.as_list())
        _excluded_rules = updated


def save_exclude() -> None:
    _atomic_json(_rules_path(EXCLUDE_FILE), get_exclude())


def save_all() -> None:
    save_exclude()
    save_blocked()


def _record_bytes(amount: int, direction: str | None = None) -> None:
    """Enqueue a compact traffic event without waiting for disk or a worker lock."""
    global _accounting_dropped_events
    if amount <= 0:
        return
    normalized_direction = direction if direction in {"upload", "download"} else None
    event = (time.time(), int(amount), normalized_direction)
    try:
        queue_bytes.put_nowait(event)
    except queue.Full:
        # Do not let accounting pressure block socket relay threads. Log sparsely
        # so a burst cannot turn logging itself into a hot-path bottleneck.
        with _accounting_drop_lock:
            _accounting_dropped_events += 1
            dropped = _accounting_dropped_events
        if dropped == 1 or dropped & (dropped - 1) == 0:
            logger.warning(
                "Traffic accounting queue is full; %s byte events have been skipped.",
                dropped,
            )
        return
    if normalized_direction is not None:
        with _traffic_direction_lock:
            _traffic_direction_totals[normalized_direction] += int(amount)


def _safe_data_usage_total() -> int:
    try:
        return max(0, int(CONFIG["data_usage"] or 0))
    except (KeyError, OSError, RuntimeError, TypeError, ValueError, OverflowError):
        return 0


def worker_data_usage_tracker(stop_event: threading.Event) -> None:
    """Persist byte-event batches and minute history on the proxy's writer thread."""
    pending_total = 0
    pending_upload = 0
    pending_download = 0
    pending_config_total = 0
    pending_minutes: dict[int, list[int]] = {}
    last_flush = time.monotonic()
    last_config_sync = last_flush
    config_sync_needed = False
    final_write_failures = 0
    history_store = None
    last_tun_counters = _read_system_tun_io_counters()
    last_tun_poll = time.monotonic()

    try:
        try:
            history_store = TrafficHistoryStore(initial_total_bytes=_safe_data_usage_total())
            persisted_total = history_store.get_totals()["total_bytes"]
            if _safe_data_usage_total() != persisted_total:
                try:
                    CONFIG["data_usage"] = persisted_total
                except (OSError, RuntimeError, TypeError, ValueError):
                    config_sync_needed = True
        except Exception:
            history_store = None
            logger.exception("Could not initialize persistent traffic history; retrying in the background.")

        while (
            not stop_event.is_set()
            or not queue_bytes.empty()
            or (pending_total > 0 and final_write_failures < 3)
        ):
            try:
                event = queue_bytes.get(timeout=0.1)
            except queue.Empty:
                event = None

            if event is not None:
                try:
                    if isinstance(event, tuple) and len(event) == 3:
                        event_timestamp, amount, direction = event
                        event_timestamp = float(event_timestamp)
                    else:
                        # Retain compatibility with any legacy integer events already in the queue.
                        event_timestamp, amount, direction = time.time(), event, None
                    amount = max(0, int(amount))
                except (TypeError, ValueError, OverflowError):
                    logger.warning("Ignoring a malformed traffic accounting event.")
                    amount = 0
                    event_timestamp = time.time()
                    direction = None
                if amount:
                    pending_total += amount
                    pending_config_total += amount
                    if direction == "upload":
                        pending_upload += amount
                    elif direction == "download":
                        pending_download += amount
                    bucket_start = max(0, int(event_timestamp // 60) * 60)
                    bucket = pending_minutes.setdefault(bucket_start, [0, 0, 0])
                    bucket[0] += amount
                    if direction == "upload":
                        bucket[1] += amount
                    elif direction == "download":
                        bucket[2] += amount

            now_monotonic = time.monotonic()
            if now_monotonic - last_tun_poll >= 1.0:
                current_tun_counters = _read_system_tun_io_counters()
                if current_tun_counters is None:
                    # Do not count bytes across an interval where the adapter was absent.
                    last_tun_counters = None
                elif last_tun_counters is not None:
                    sent_delta = max(0, current_tun_counters[0] - last_tun_counters[0])
                    received_delta = max(0, current_tun_counters[1] - last_tun_counters[1])
                    if sent_delta:
                        _record_bytes(sent_delta, "upload")
                    if received_delta:
                        _record_bytes(received_delta, "download")
                last_tun_counters = current_tun_counters
                last_tun_poll = now_monotonic

            if config_sync_needed and history_store is not None and now_monotonic - last_config_sync >= 2.0:
                try:
                    CONFIG["data_usage"] = history_store.get_totals()["total_bytes"]
                    config_sync_needed = False
                except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
                    logger.debug("Legacy traffic counter synchronization will be retried.", exc_info=True)
                last_config_sync = now_monotonic

            should_flush = pending_total > 0 and (
                now_monotonic - last_flush >= 1.0
                or (stop_event.is_set() and queue_bytes.empty())
            )
            if not should_flush:
                continue

            try:
                if history_store is None:
                    history_store = TrafficHistoryStore(initial_total_bytes=_safe_data_usage_total())
                totals = history_store.record_batch(
                    total_delta=pending_config_total,
                    upload_delta=pending_upload,
                    download_delta=pending_download,
                    minute_deltas={key: tuple(value) for key, value in pending_minutes.items()},
                    total_floor=_safe_data_usage_total(),
                    now=int(time.time()),
                )
            except Exception:
                logger.exception(
                    "Could not persist proxy traffic history; retaining the pending batch for retry."
                )
                if pending_config_total:
                    try:
                        # Keep the legacy all-time total useful if SQLite is temporarily
                        # unavailable. The minute history and direction totals remain queued
                        # in memory and will be committed when the database can be opened.
                        CONFIG["data_usage"] = _safe_data_usage_total() + pending_config_total
                        pending_config_total = 0
                    except (OSError, RuntimeError, TypeError, ValueError):
                        logger.exception("Could not update the legacy traffic counter fallback.")
                last_flush = time.monotonic()
                if stop_event.is_set() and queue_bytes.empty():
                    final_write_failures += 1
                    if final_write_failures >= 3:
                        logger.error(
                            "Traffic history remained unavailable during shutdown; the legacy total was preserved where possible."
                        )
                    else:
                        time.sleep(0.1 * final_write_failures)
                continue

            pending_total = 0
            pending_upload = 0
            pending_download = 0
            pending_config_total = 0
            pending_minutes.clear()
            final_write_failures = 0
            last_flush = time.monotonic()
            try:
                persisted_total = totals["total_bytes"]
                if _safe_data_usage_total() != persisted_total:
                    CONFIG["data_usage"] = persisted_total
                config_sync_needed = False
            except (OSError, RuntimeError, TypeError, ValueError):
                config_sync_needed = True
                logger.exception("Traffic history was saved but the legacy JSON counter could not be synchronized.")
    finally:
        if history_store is not None:
            try:
                history_store.close()
            except Exception:
                logger.debug("Could not close the traffic history database cleanly.", exc_info=True)


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def is_port_free(host: str, port: int, timeout: float = 0.15) -> bool:
    del timeout  # Binding is the correct test; connect_ex can misclassify closed ports.
    try:
        address = ipaddress.ip_address(host)
        if not address.is_loopback:
            return False
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.bind((str(address), port))
        return True
    except (OSError, ValueError):
        return False


def _route_for_host(host: str) -> str:
    normalized = normalize_hostname(host)
    with _rule_lock:
        blocked = _blocked_rules
        excluded = _excluded_rules
    if blocked.matches(normalized):
        return "blocked"
    if excluded.matches(normalized):
        return "direct"
    return "tor"


def is_host_blocked(host: str) -> bool:
    """Return whether a normalized destination matches the shared block policy."""
    normalized = normalize_hostname(host)
    with _rule_lock:
        blocked = _blocked_rules
    return blocked.matches(normalized)


def _parse_authority(authority: str, default_port: int | None = None) -> tuple[str, int]:
    if not authority or any(char in authority for char in ("/", "?", "#", "@", "\r", "\n")):
        raise ValueError("Malformed request authority.")

    # Some Python versions accept non-IP text inside square brackets as a
    # hostname. Brackets are reserved for IPv6 literals in an authority, so
    # validate the literal explicitly before urlsplit can normalize it.
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            raise ValueError("Malformed bracketed IPv6 authority.")
        literal = authority[1:closing]
        try:
            host = ipaddress.IPv6Address(literal).compressed.lower()
        except ValueError as exc:
            raise ValueError("Bracketed hosts must be valid IPv6 literals.") from exc
        suffix = authority[closing + 1:]
        if not suffix:
            port = default_port
        elif suffix.startswith(":") and suffix[1:].isdecimal():
            try:
                port = int(suffix[1:])
            except ValueError as exc:
                raise ValueError("Invalid destination port.") from exc
        else:
            raise ValueError("Malformed bracketed IPv6 authority.")
        if port is None or not 1 <= port <= 65535:
            raise ValueError("Invalid destination port.")
        return host, port

    parsed = urlsplit("//" + authority)
    if parsed.username or parsed.password or not parsed.hostname:
        raise ValueError("Malformed request authority.")
    try:
        port = parsed.port if parsed.port is not None else default_port
    except ValueError as exc:
        raise ValueError("Invalid destination port.") from exc
    if port is None or not 1 <= port <= 65535:
        raise ValueError("Invalid destination port.")
    return normalize_hostname(parsed.hostname), port


def _register_upstream(server, remote: socket.socket) -> None:
    register = getattr(server, "register_upstream", None)
    if callable(register) and not register(remote):
        try:
            remote.close()
        except OSError:
            pass
        raise OSError("The local HTTP proxy is shutting down.")


def _unregister_upstream(server, remote: socket.socket | None) -> None:
    if remote is None:
        return
    unregister = getattr(server, "unregister_upstream", None)
    if callable(unregister):
        unregister(remote)


def _run_interruptible_upstream_operation(operation, server=None, *, thread_name: str):
    """Run a blocking resolver/connect outside the HTTP handler's shutdown path.

    On Windows, closing a socket from another thread does not always interrupt
    an in-progress blocking connect immediately. The handler polls the shutdown
    event while a daemon worker owns the blocking operation, so application
    shutdown does not wait for the full network timeout.
    """
    stop_event = getattr(server, "shutdown_event", None)
    if stop_event is None:
        return operation()
    if stop_event.is_set():
        raise OSError("The local HTTP proxy is shutting down.")

    finished = threading.Event()
    results = []
    errors: list[Exception] = []

    def operation_worker() -> None:
        try:
            results.append(operation())
        except Exception as exc:
            errors.append(exc)
        finally:
            finished.set()

    worker = threading.Thread(
        target=operation_worker,
        name=thread_name,
        daemon=True,
    )
    worker.start()
    while not finished.wait(RELAY_SHUTDOWN_POLL_SECONDS):
        if stop_event.is_set():
            raise OSError("The local HTTP proxy is shutting down.")
    if stop_event.is_set():
        raise OSError("The local HTTP proxy is shutting down.")
    if errors:
        raise errors[0]
    return results[0] if results else None


def _connect_with_shutdown(remote: socket.socket, address, server=None) -> None:
    _run_interruptible_upstream_operation(
        lambda: remote.connect(address),
        server,
        thread_name="torproxy-http-upstream-connect",
    )


def _connect_upstream(
    host: str,
    port: int,
    route: str,
    tor_socks_port: int,
    *,
    server=None,
) -> socket.socket:
    if route == "direct":
        # Explicit bypass; track the socket before connect so shutdown can cancel it.
        last_error = None
        addresses = _run_interruptible_upstream_operation(
            lambda: socket.getaddrinfo(host, port, type=socket.SOCK_STREAM),
            server,
            thread_name="torproxy-http-dns-lookup",
        )
        for family, socktype, proto, _canonname, sockaddr in addresses:
            remote = socket.socket(family, socktype, proto)
            remote.settimeout(SOCKET_TIMEOUT_SECONDS)
            try:
                _register_upstream(server, remote)
                _connect_with_shutdown(remote, sockaddr, server)
                return remote
            except OSError as exc:
                last_error = exc
                _unregister_upstream(server, remote)
                remote.close()
        if last_error is not None:
            raise last_error
        raise OSError("No usable network address was returned for the destination.")

    remote = socks.socksocket()
    remote.set_proxy(socks.SOCKS5, "127.0.0.1", tor_socks_port, rdns=True)
    remote.settimeout(SOCKET_TIMEOUT_SECONDS)
    try:
        # Register before SOCKS CONNECT: the Tor circuit/destination handshake
        # may still be in progress when the user disconnects the proxy.
        _register_upstream(server, remote)
        _connect_with_shutdown(remote, (host, port), server)
        return remote
    except Exception:
        _unregister_upstream(server, remote)
        try:
            remote.close()
        except OSError:
            pass
        raise


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # CONNECT is a raw TCP tunnel after its headers. Disable read-ahead so early
    # tunnel bytes cannot be stranded in a buffered reader instead of the relay.
    rbufsize = 0

    def setup(self) -> None:
        # Close idle or incomplete client requests instead of pinning a worker thread.
        self.request.settimeout(REQUEST_READ_TIMEOUT_SECONDS)
        super().setup()

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except ConnectionError as exc:
            # Local clients may cancel requests or close their sockets abruptly.
            # This is not evidence that the Tor upstream or circuit has failed.
            self.close_connection = True
            logger.debug(
                "HTTP proxy client disconnected while handling a request "
                "(client=%s, error=%s).",
                self.client_address[0],
                type(exc).__name__,
            )

    def log_message(self, format_string: str, *args) -> None:
        # BaseHTTPRequestHandler passes request lines here; do not persist URLs,
        # query strings, credentials, or destination content in routine logs.
        del format_string, args
        logger.info("HTTP proxy activity from client=%s", self.client_address[0])

    def do_CONNECT(self) -> None:
        remote = None
        # Once CONNECT succeeds, this socket is a byte stream, not HTTP keep-alive.
        self.close_connection = True
        try:
            host, port = _parse_authority(self.path)
            route = _route_for_host(host)
            if route == "blocked":
                self.send_error(403, "Destination blocked by host policy")
                return
            remote = _connect_upstream(
                host, port, route, self.server.tor_socks_port, server=self.server
            )
            self.connection.settimeout(RELAY_IDLE_TIMEOUT_SECONDS)
            remote.settimeout(RELAY_IDLE_TIMEOUT_SECONDS)
            self.send_response(200, "Connection Established")
            self.end_headers()
            self.wfile.flush()
            self._relay(
                self.connection,
                remote,
                left_to_right_direction="upload",
                stop_event=self.server.shutdown_event,
            )
        except (ValueError, HostRuleError):
            self.send_error(400, "Malformed CONNECT authority")
        except (OSError, socks.ProxyError, socks.GeneralProxyError):
            logger.warning("CONNECT upstream failed for host=%s", locals().get("host", "<invalid>"))
            if not self.wfile.closed:
                self.send_error(502, "Upstream connection failed")
        finally:
            if remote is not None:
                _unregister_upstream(self.server, remote)
                try:
                    remote.close()
                except OSError:
                    pass

    def do_GET(self) -> None:
        self._handle_http()

    def do_HEAD(self) -> None:
        self._handle_http()

    def do_POST(self) -> None:
        self._handle_http()

    def do_PUT(self) -> None:
        self._handle_http()

    def do_DELETE(self) -> None:
        self._handle_http()

    def do_OPTIONS(self) -> None:
        self._handle_http()

    def do_PATCH(self) -> None:
        self._handle_http()

    def do_TRACE(self) -> None:
        self.send_error(405, "TRACE is not supported by this proxy")

    def _handle_http(self) -> None:
        remote = None
        try:
            parsed = urlsplit(self.path)
            if parsed.scheme.lower() != "http" or not parsed.hostname:
                self.send_error(400, "An absolute-form HTTP request target is required")
                return
            if parsed.username or parsed.password:
                self.send_error(400, "Credentials are not allowed in the request target")
                return
            try:
                port = parsed.port or 80
            except ValueError:
                self.send_error(400, "Invalid destination port")
                return
            if not 1 <= port <= 65535:
                self.send_error(400, "Invalid destination port")
                return
            host = normalize_hostname(parsed.hostname)
            route = _route_for_host(host)
            if route == "blocked":
                self.send_error(403, "Destination blocked by host policy")
                return
            if self.headers.get("Expect"):
                self.send_error(417, "Expect headers are not supported")
                return
            transfer_encoding = self.headers.get("Transfer-Encoding", "")
            if transfer_encoding and transfer_encoding.lower() != "identity":
                self.send_error(501, "Transfer-encoded request bodies are not supported")
                return
            length_text = self.headers.get("Content-Length", "0")
            if not length_text.isdecimal():
                self.send_error(400, "Invalid Content-Length")
                return
            body_length = int(length_text)
            if body_length < 0 or body_length > MAX_REQUEST_BODY_BYTES:
                self.send_error(413, "Request body exceeds the proxy limit")
                return

            remote = _connect_upstream(
                host, port, route, self.server.tor_socks_port, server=self.server
            )
            remote.settimeout(RELAY_IDLE_TIMEOUT_SECONDS)
            request_path = parsed.path or "/"
            if parsed.query:
                request_path += "?" + parsed.query
            default_port = 80
            host_literal = f"[{host}]" if ":" in host else host
            host_header = host_literal if port == default_port else f"{host_literal}:{port}"
            headers = []
            connection_tokens = {
                token.strip().lower()
                for token in self.headers.get("Connection", "").split(",")
                if token.strip()
            }
            hop_by_hop = {"connection", "proxy-connection", "proxy-authorization",
                          "proxy-authenticate", "keep-alive", "te", "trailer", "upgrade"}
            for key, value in self.headers.items():
                lowered = key.lower()
                if lowered in hop_by_hop or lowered in connection_tokens or lowered in {"host", "content-length", "transfer-encoding"}:
                    continue
                headers.append(f"{key}: {value}\r\n")
            request_line = f"{self.command} {request_path} HTTP/1.1\r\n"
            wire_headers = request_line + f"Host: {host_header}\r\n" + "".join(headers)
            wire_headers += "Connection: close\r\n"
            if body_length:
                wire_headers += f"Content-Length: {body_length}\r\n"
            wire_headers += "\r\n"
            remote.sendall(wire_headers.encode("iso-8859-1", errors="strict"))
            _record_bytes(len(wire_headers.encode("iso-8859-1", errors="strict")), "upload")
            remaining = body_length
            while remaining:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    raise OSError("Client disconnected during request body.")
                remote.sendall(chunk)
                _record_bytes(len(chunk), "upload")
                remaining -= len(chunk)
            self.connection.settimeout(RELAY_IDLE_TIMEOUT_SECONDS)
            self._relay(
                remote,
                self.connection,
                left_to_right_direction="download",
                stop_event=self.server.shutdown_event,
            )
        except (ValueError, HostRuleError):
            if not self.wfile.closed:
                self.send_error(400, "Malformed HTTP proxy request")
        except (OSError, socks.ProxyError, socks.GeneralProxyError):
            logger.warning("HTTP upstream failed for host=%s", locals().get("host", "<invalid>"))
            if not self.wfile.closed:
                self.send_error(502, "Upstream connection failed")
        finally:
            if remote is not None:
                _unregister_upstream(self.server, remote)
                try:
                    remote.close()
                except OSError:
                    pass

    @staticmethod
    def _relay(
        left: socket.socket,
        right: socket.socket,
        left_to_right_direction: str = "upload",
        stop_event: threading.Event | None = None,
    ) -> None:
        active = {left, right}
        peers = {left: right, right: left}
        last_activity = time.monotonic()
        try:
            while active:
                if stop_event is not None and stop_event.is_set():
                    break
                idle_remaining = RELAY_IDLE_TIMEOUT_SECONDS - (time.monotonic() - last_activity)
                if idle_remaining <= 0:
                    logger.debug("Proxy relay ended after idle timeout.")
                    break
                poll_timeout = min(
                    idle_remaining,
                    RELAY_SHUTDOWN_POLL_SECONDS if stop_event is not None else idle_remaining,
                )
                try:
                    readable, _, _ = select.select(list(active), [], [], poll_timeout)
                except (OSError, ValueError):
                    break
                if not readable:
                    if stop_event is not None and stop_event.is_set():
                        break
                    continue
                for source in readable:
                    try:
                        data = source.recv(65536)
                    except (OSError, TimeoutError):
                        active.discard(source)
                        try:
                            peers[source].shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    destination = peers[source]
                    if not data:
                        active.discard(source)
                        try:
                            destination.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    direction = (
                        left_to_right_direction
                        if source is left
                        else ("download" if left_to_right_direction == "upload" else "upload")
                    )
                    _record_bytes(len(data), direction)
                    last_activity = time.monotonic()
                    try:
                        destination.sendall(data)
                    except (OSError, TimeoutError):
                        active.discard(source)
                        active.discard(destination)
                        break
        finally:
            # The caller owns the sockets and closes the upstream endpoint.
            pass


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, addr, handler, tor_socks_port, max_clients=128):
        if type(max_clients) is not int or not 1 <= max_clients <= 4096:
            raise ValueError("The HTTP proxy client limit must be between 1 and 4096.")
        self._max_clients = max_clients
        self._client_slots = threading.BoundedSemaphore(max_clients)
        self._client_lock = threading.RLock()
        self._active_clients: set[socket.socket] = set()
        self._active_upstreams: set[socket.socket] = set()
        self.shutdown_event = threading.Event()
        self._rejected_clients = 0
        host = addr[0]
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = host.lower() == "localhost"
        if not is_loopback:
            raise ValueError("The HTTP proxy can only bind to loopback; remote access is disabled.")
        self.tor_socks_port = int(tor_socks_port)
        super().__init__(addr, handler)

    @property
    def client_metrics(self) -> dict[str, int]:
        with self._client_lock:
            return {
                "active_clients": len(self._active_clients),
                "max_clients": self._max_clients,
                "rejected_clients": self._rejected_clients,
            }

    def register_upstream(self, remote: socket.socket) -> bool:
        """Track outbound sockets before connect so shutdown can cancel the dial."""
        with self._client_lock:
            if self.shutdown_event.is_set():
                return False
            self._active_upstreams.add(remote)
            return True

    def unregister_upstream(self, remote: socket.socket) -> None:
        with self._client_lock:
            self._active_upstreams.discard(remote)

    def begin_shutdown(self) -> None:
        """Signal handlers and close both sides of every in-flight tunnel."""
        self.shutdown_event.set()
        with self._client_lock:
            sockets = tuple(self._active_clients | self._active_upstreams)
        for current in sockets:
            try:
                current.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                current.close()
            except OSError:
                pass

    def process_request(self, request, client_address):
        # Check shutdown and reserve the slot under one lock. This prevents a
        # just-accepted socket from slipping past the final shutdown snapshot.
        with self._client_lock:
            if self.shutdown_event.is_set():
                rejected = True
            elif not self._client_slots.acquire(blocking=False):
                self._rejected_clients += 1
                rejected = True
            else:
                self._active_clients.add(request)
                rejected = False
        if rejected:
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            with self._client_lock:
                self._active_clients.discard(request)
                self._rejected_clients += 1
            self._client_slots.release()
            self.shutdown_request(request)
            logger.exception("Could not start an HTTP proxy client handler.")

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._client_lock:
                self._active_clients.discard(request)
            self._client_slots.release()

    def server_close(self):
        self.begin_shutdown()
        super().server_close()
