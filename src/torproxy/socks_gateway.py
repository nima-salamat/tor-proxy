"""Loopback SOCKS5 gateway with per-connection failover across healthy Tor backends."""
from __future__ import annotations

import logging
import select
import socket
import threading
import time
from collections.abc import Callable, Iterable

LOGGER = logging.getLogger(__name__)


class SocksGatewayError(RuntimeError):
    """The local failover SOCKS gateway could not start or stop safely."""


class SocksFailoverGateway:
    """Expose one stable SOCKS5 endpoint and route each new CONNECT to a ready Tor.

    Existing TCP streams remain attached to the Tor process that accepted them;
    only new SOCKS CONNECT requests can fail over.
    """

    def __init__(
        self,
        port: int,
        backend_provider: Callable[[], Iterable[tuple[str, int] | tuple[str, int, float | None]]],
        *,
        host: str = "127.0.0.1",
        connect_timeout: float = 8.0,
        handshake_timeout: float = 12.0,
        idle_timeout: float = 120.0,
        max_sessions: int = 256,
    ) -> None:
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("The Tor SOCKS gateway must bind to loopback.")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("The Tor SOCKS gateway port must be in the range 1..65535.")
        self.host = host
        self.port = port
        self._backend_provider = backend_provider
        self._connect_timeout = max(0.5, float(connect_timeout))
        self._handshake_timeout = max(1.0, float(handshake_timeout))
        self._idle_timeout = max(5.0, float(idle_timeout))
        if type(max_sessions) is not int or not 1 <= max_sessions <= 4096:
            raise ValueError("The SOCKS gateway session limit must be between 1 and 4096.")
        self._max_sessions = max_sessions
        self._session_slots = threading.BoundedSemaphore(max_sessions)
        self._session_threads: set[threading.Thread] = set()
        self._rejected_sessions = 0
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._clients: set[socket.socket] = set()
        self._cursor = 0
        self._backend_stats: dict[tuple[str, int], dict[str, float | int]] = {}

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            stale_sessions = tuple(
                worker for worker in self._session_threads if worker.is_alive()
            )
            if stale_sessions:
                raise SocksGatewayError(
                    "The primary Tor SOCKS gateway cannot restart while previous client sessions are still active."
                )
            self._session_threads.clear()
            family = socket.AF_INET6 if self.host == "::1" else socket.AF_INET
            listener = socket.socket(family, socket.SOCK_STREAM)
            try:
                # Permit a clean local restart after old TCP tuples enter
                # TIME_WAIT, without allowing another process to hijack the
                # listening endpoint on Windows.
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                else:
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((self.host, self.port))
                listener.listen(min(256, self._max_sessions))
                listener.settimeout(0.5)
            except OSError:
                listener.close()
                raise
            self._stop.clear()
            self._rejected_sessions = 0
            self._listener = listener
            self._thread = threading.Thread(
                target=self._accept_loop,
                name="torproxy-socks-failover",
                daemon=True,
            )
            try:
                self._thread.start()
            except Exception:
                self._stop.set()
                self._listener = None
                self._thread = None
                listener.close()
                raise
        LOGGER.info("Primary Tor SOCKS failover gateway listening on %s:%s.", self.host, self.port)

    def _track(self, sock: socket.socket, add: bool) -> bool:
        with self._lock:
            if add and self._stop.is_set():
                return False
            if add:
                self._clients.add(sock)
            else:
                self._clients.discard(sock)
            return True

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            listener = self._listener
            if listener is None:
                return
            try:
                client, _address = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self._stop.is_set():
                    LOGGER.exception("SOCKS failover gateway accept failed.")
                return
            if not self._track(client, True):
                client.close()
                return
            if not self._session_slots.acquire(blocking=False):
                with self._lock:
                    self._rejected_sessions += 1
                self._track(client, False)
                client.close()
                continue

            worker = threading.Thread(
                target=self._run_client_session,
                args=(client,),
                name="torproxy-socks-session",
                daemon=True,
            )
            with self._lock:
                self._session_threads.add(worker)
            try:
                worker.start()
            except RuntimeError:
                with self._lock:
                    self._session_threads.discard(worker)
                    self._rejected_sessions += 1
                self._session_slots.release()
                self._track(client, False)
                client.close()
                LOGGER.exception("Could not start a SOCKS client session thread.")

    def _run_client_session(self, client: socket.socket) -> None:
        """Run one client session and always return its bounded worker slot."""
        current = threading.current_thread()
        try:
            self._handle_client(client)
        finally:
            self._track(client, False)
            with self._lock:
                self._session_threads.discard(current)
            self._session_slots.release()

    @property
    def session_metrics(self) -> dict[str, int]:
        """Return bounded gateway session capacity and overload counters."""
        with self._lock:
            return {
                "active_sessions": len(self._session_threads),
                "max_sessions": self._max_sessions,
                "rejected_sessions": self._rejected_sessions,
            }

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise OSError("SOCKS peer closed during handshake.")
            data.extend(chunk)
        return bytes(data)

    @classmethod
    def _read_request(cls, client: socket.socket) -> bytes:
        header = cls._recv_exact(client, 4)
        if header[0] != 5:
            raise ValueError("Only SOCKS5 clients are supported.")
        if header[2] != 0:
            raise ValueError("SOCKS5 request reserved byte must be zero.")
        if header[1] != 1:
            raise ValueError("The Tor SOCKS gateway supports TCP CONNECT only.")
        atyp = header[3]
        if atyp == 1:
            address = cls._recv_exact(client, 4)
        elif atyp == 4:
            address = cls._recv_exact(client, 16)
        elif atyp == 3:
            length = cls._recv_exact(client, 1)
            if length[0] == 0:
                raise ValueError("SOCKS domain name is empty.")
            address = length + cls._recv_exact(client, length[0])
        else:
            raise ValueError("Unsupported SOCKS address type.")
        return header + address + cls._recv_exact(client, 2)

    @classmethod
    def _read_reply(cls, upstream: socket.socket) -> bytes:
        header = cls._recv_exact(upstream, 4)
        if header[0] != 5 or header[2] != 0:
            raise OSError("Tor returned an invalid SOCKS reply header.")
        atyp = header[3]
        if atyp == 1:
            tail = cls._recv_exact(upstream, 6)
        elif atyp == 4:
            tail = cls._recv_exact(upstream, 18)
        elif atyp == 3:
            size = cls._recv_exact(upstream, 1)
            tail = size + cls._recv_exact(upstream, size[0] + 2)
        else:
            raise OSError("Tor returned an invalid SOCKS address type.")
        return header + tail

    @staticmethod
    def _failure_reply(code: int = 1) -> bytes:
        return b"\x05" + bytes((code,)) + b"\x00\x01\x00\x00\x00\x00\x00\x00"

    def _ordered_backends(self) -> list[tuple[str, int]]:
        candidates: list[tuple[str, int]] = []
        health_latencies: dict[tuple[str, int], float] = {}
        for item in self._backend_provider() or ():
            try:
                values = tuple(item)
                if len(values) not in {2, 3}:
                    continue
                host = str(values[0])
                port = int(values[1])
                if host in {"127.0.0.1", "::1", "localhost"} and 1 <= port <= 65535:
                    candidate = (host, port)
                    if candidate not in candidates:
                        candidates.append(candidate)
                    if len(values) == 3 and values[2] is not None:
                        latency = float(values[2])
                        if latency >= 0:
                            health_latencies[candidate] = latency
            except (TypeError, ValueError):
                continue
        if not candidates:
            return []

        now = time.monotonic()
        with self._lock:
            # Ports are dynamically allocated when Tor workers restart. Retain
            # statistics for old endpoints only while an existing stream still
            # holds a reservation; otherwise stale entries would grow forever.
            for endpoint in tuple(self._backend_stats):
                if endpoint not in candidates and int(self._backend_stats[endpoint]["active"]) == 0:
                    del self._backend_stats[endpoint]
            for endpoint in candidates:
                self._backend_stats.setdefault(endpoint, {
                    "active": 0,
                    "latency_ms": 750.0,
                    "health_latency_ms": 750.0,
                    "failures": 0,
                    "cooldown_until": 0.0,
                    "last_success": 0.0,
                })
                if endpoint in health_latencies:
                    self._backend_stats[endpoint]["health_latency_ms"] = health_latencies[endpoint]
            # Healthy backends are always preferred, but cooled-down peers
            # remain as fallbacks in case every preferred endpoint fails.
            available = list(candidates)
            offset = self._cursor % len(available)
            self._cursor = (self._cursor + 1) % max(1, len(available))
            tie_order = {
                endpoint: (position - offset) % len(available)
                for position, endpoint in enumerate(available)
            }
            def backend_score(endpoint: tuple[str, int]):
                stats = self._backend_stats[endpoint]
                cooldown_until = float(stats["cooldown_until"])
                active = int(stats["active"])
                latency = (
                    float(stats["health_latency_ms"]) * 0.65
                    + float(stats["latency_ms"]) * 0.35
                )
                return (
                    1 if cooldown_until > now else 0,
                    cooldown_until if cooldown_until > now else 0.0,
                    active * max(1.0, latency),
                    active,
                    # With no active streams, rotate evenly rather than
                    # sending every short-lived connection to one fast node.
                    tie_order[endpoint] if active == 0 else 0,
                    latency,
                    int(stats["failures"]),
                )

            available.sort(key=backend_score)
            return available

    def _reserve_backend(self, endpoint: tuple[str, int]) -> bool:
        with self._lock:
            if self._stop.is_set():
                return False
            stats = self._backend_stats.setdefault(endpoint, {
                "active": 0,
                "latency_ms": 750.0,
                "health_latency_ms": 750.0,
                "failures": 0,
                "cooldown_until": 0.0,
                "last_success": 0.0,
            })
            stats["active"] = int(stats["active"]) + 1
            return True

    def _record_backend_success(self, endpoint: tuple[str, int], latency_ms: float) -> None:
        with self._lock:
            stats = self._backend_stats.setdefault(endpoint, {
                "active": 0,
                "latency_ms": float(latency_ms),
                "health_latency_ms": float(latency_ms),
                "failures": 0,
                "cooldown_until": 0.0,
                "last_success": 0.0,
            })
            previous = float(stats["latency_ms"])
            stats["latency_ms"] = max(0.0, latency_ms) if previous <= 0 else (
                previous * 0.7 + max(0.0, latency_ms) * 0.3
            )
            stats["failures"] = 0
            stats["cooldown_until"] = 0.0
            stats["last_success"] = time.monotonic()

    def _record_backend_failure(self, endpoint: tuple[str, int]) -> None:
        with self._lock:
            stats = self._backend_stats.setdefault(endpoint, {
                "active": 0,
                "latency_ms": 750.0,
                "health_latency_ms": 750.0,
                "failures": 0,
                "cooldown_until": 0.0,
                "last_success": 0.0,
            })
            failures = int(stats["failures"]) + 1
            stats["failures"] = failures
            stats["cooldown_until"] = time.monotonic() + min(30.0, float(2 ** min(failures, 5)))

    def _release_backend(self, endpoint: tuple[str, int]) -> None:
        with self._lock:
            stats = self._backend_stats.get(endpoint)
            if stats is not None:
                stats["active"] = max(0, int(stats["active"]) - 1)

    @property
    def backend_metrics(self) -> dict[tuple[str, int], dict[str, float | int]]:
        """Return a snapshot of per-backend active load and recent dial quality."""
        with self._lock:
            return {
                endpoint: dict(stats)
                for endpoint, stats in self._backend_stats.items()
            }

    @staticmethod
    def _relay(left: socket.socket, right: socket.socket, idle_timeout: float) -> None:
        active = {left, right}
        peers = {left: right, right: left}
        while active:
            try:
                readable, _, _ = select.select(list(active), [], [], idle_timeout)
            except (OSError, ValueError):
                return
            if not readable:
                return
            for source in readable:
                try:
                    payload = source.recv(65536)
                except (OSError, TimeoutError):
                    payload = b""
                destination = peers[source]
                if not payload:
                    active.discard(source)
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                try:
                    destination.sendall(payload)
                except (OSError, TimeoutError):
                    return

    def _handle_client(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        leased_backend: tuple[str, int] | None = None
        try:
            client.settimeout(self._handshake_timeout)
            version_and_count = self._recv_exact(client, 2)
            if version_and_count[0] != 5 or version_and_count[1] == 0:
                return
            methods = self._recv_exact(client, version_and_count[1])
            if 0 not in methods:
                client.sendall(b"\x05\xff")
                return
            # The local gateway intentionally exposes no-auth only. It is loopback
            # restricted and does not forward arbitrary client credentials to Tor.
            client.sendall(b"\x05\x00")
            request = self._read_request(client)
            last_reply: bytes | None = None

            for endpoint in self._ordered_backends():
                if self._stop.is_set():
                    return
                if not self._reserve_backend(endpoint):
                    continue
                candidate: socket.socket | None = None
                keep_reservation = False
                attempt_started = time.monotonic()
                try:
                    candidate = socket.create_connection(
                        endpoint,
                        timeout=self._connect_timeout,
                    )
                    if not self._track(candidate, True):
                        raise OSError("SOCKS gateway is stopping.")
                    candidate.settimeout(self._handshake_timeout)
                    candidate.sendall(b"\x05\x01\x00")
                    if self._recv_exact(candidate, 2) != b"\x05\x00":
                        raise OSError("Tor SOCKS backend rejected no-auth negotiation.")
                    candidate.sendall(request)
                    reply = self._read_reply(candidate)
                    elapsed_ms = (time.monotonic() - attempt_started) * 1000.0
                    if reply[1] == 0:
                        self._record_backend_success(endpoint, elapsed_ms)
                        try:
                            client.sendall(reply)
                        except OSError:
                            # The local application may close while the SOCKS
                            # reply is being written; that is not a Tor failure.
                            return
                        client.settimeout(None)
                        candidate.settimeout(None)
                        upstream = candidate
                        candidate = None
                        leased_backend = endpoint
                        keep_reservation = True
                        self._relay(client, upstream, self._idle_timeout)
                        return
                    # A destination refusal is not evidence that the Tor worker
                    # is unhealthy. Record a successful backend handshake and
                    # let another healthy instance try the same destination.
                    self._record_backend_success(endpoint, elapsed_ms)
                    last_reply = reply
                except (OSError, TimeoutError, ValueError):
                    self._record_backend_failure(endpoint)
                    LOGGER.debug("A Tor SOCKS backend failed before CONNECT was established.", exc_info=True)
                finally:
                    if candidate is not None:
                        self._track(candidate, False)
                        try:
                            candidate.close()
                        except OSError:
                            pass
                    if not keep_reservation:
                        self._release_backend(endpoint)

            try:
                client.sendall(last_reply or self._failure_reply(1))
            except OSError:
                pass
        except (OSError, TimeoutError, ValueError):
            LOGGER.debug("Rejected or interrupted local SOCKS client.", exc_info=True)
        finally:
            if upstream is not None:
                self._track(upstream, False)
                try:
                    upstream.close()
                except OSError:
                    pass
            if leased_backend is not None:
                self._release_backend(leased_backend)
            self._track(client, False)
            try:
                client.close()
            except OSError:
                pass

    def stop(self, *, timeout: float = 5.0) -> None:
        self._stop.set()
        with self._lock:
            listener, self._listener = self._listener, None
            clients = tuple(self._clients)
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass
        deadline = time.monotonic() + max(0.1, float(timeout))
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if thread is not None and thread.is_alive():
            raise SocksGatewayError("The primary Tor SOCKS failover listener is still active.")

        with self._lock:
            session_threads = tuple(self._session_threads)
        for worker in session_threads:
            if worker is not threading.current_thread():
                worker.join(timeout=max(0.0, deadline - time.monotonic()))
        with self._lock:
            active_sessions = sum(1 for worker in self._session_threads if worker.is_alive())
        if active_sessions:
            raise SocksGatewayError(
                "The primary Tor SOCKS gateway cannot stop while previous client sessions are "
                f"still active ({active_sessions})."
            )
        with self._lock:
            self._thread = None
            self._session_threads.clear()
            self._clients.clear()
        LOGGER.info("Primary Tor SOCKS failover gateway stopped.")
