"""Stable loopback SOCKS endpoint with failover across healthy Tor instances.

The gateway does not interpret or resolve destination names. It selects one
verified Tor SOCKS listener for each incoming TCP session and transparently
relays the SOCKS5 byte stream. Existing sessions remain pinned to their Tor
instance; new sessions can use another instance after a backend failure.
"""
from __future__ import annotations

import ipaddress
import logging
import select
import socket
import socketserver
import threading
from collections.abc import Iterable

LOGGER = logging.getLogger(__name__)
CONNECT_TIMEOUT_SECONDS = 3.0
RELAY_IDLE_TIMEOUT_SECONDS = 120.0


class SocksBackendSelector:
    """Thread-safe, priority-ordered registry of ready Tor SOCKS backends."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._backends: tuple[tuple[str, int], ...] = ()

    def set_backends(self, backends: Iterable[tuple[str, int]]) -> None:
        normalized: list[tuple[str, int]] = []
        seen_ids: set[str] = set()
        seen_ports: set[int] = set()
        for raw_id, raw_port in backends:
            backend_id = str(raw_id).strip()
            if not backend_id or backend_id in seen_ids:
                raise ValueError("SOCKS backend IDs must be non-empty and unique.")
            if type(raw_port) is not int or not 1 <= raw_port <= 65535:
                raise ValueError("SOCKS backend ports must be valid TCP ports.")
            if raw_port in seen_ports:
                raise ValueError("SOCKS backend ports must be unique.")
            seen_ids.add(backend_id)
            seen_ports.add(raw_port)
            normalized.append((backend_id, raw_port))
        with self._lock:
            self._backends = tuple(normalized)

    def candidates(self) -> tuple[tuple[str, int], ...]:
        """Return the current failover order, preferred backend first."""
        with self._lock:
            return self._backends


class _SocksRelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        upstream: socket.socket | None = None
        tried: set[str] = set()
        selector: SocksBackendSelector = self.server.selector

        try:
            # Connect before forwarding any client bytes. If the preferred Tor
            # process died between the supervisor poll and this accept, try
            # the next ready instance without leaking traffic outside Tor.
            while True:
                candidate = next(
                    (item for item in selector.candidates() if item[0] not in tried),
                    None,
                )
                if candidate is None:
                    return
                backend_id, backend_port = candidate
                tried.add(backend_id)
                try:
                    upstream = socket.create_connection(
                        ("127.0.0.1", backend_port),
                        timeout=CONNECT_TIMEOUT_SECONDS,
                    )
                    break
                except OSError as exc:
                    LOGGER.debug(
                        "Tor SOCKS backend %s on loopback port %s was unavailable (%s).",
                        backend_id,
                        backend_port,
                        type(exc).__name__,
                    )

            client.settimeout(RELAY_IDLE_TIMEOUT_SECONDS)
            upstream.settimeout(RELAY_IDLE_TIMEOUT_SECONDS)
            active = {client, upstream}
            peers = {client: upstream, upstream: client}
            while active:
                try:
                    readable, _, _ = select.select(
                        list(active), [], [], RELAY_IDLE_TIMEOUT_SECONDS
                    )
                except (OSError, ValueError):
                    break
                if not readable:
                    break
                for source in readable:
                    try:
                        payload = source.recv(65536)
                    except (OSError, TimeoutError):
                        active.discard(source)
                        try:
                            peers[source].shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
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
                        active.discard(source)
                        active.discard(destination)
                        break
        except (OSError, TimeoutError):
            LOGGER.debug("A local SOCKS gateway session ended unexpectedly.", exc_info=True)
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass


class _ThreadedSocksServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True
    block_on_close = False

    def __init__(self, address: tuple[str, int], selector: SocksBackendSelector):
        self.selector = selector
        super().__init__(address, _SocksRelayHandler)


class SocksGateway:
    """A stable 127.0.0.1 SOCKS endpoint backed by one or more Tor instances."""

    def __init__(self, port: int, host: str = "127.0.0.1") -> None:
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError("The SOCKS gateway can bind only to a loopback address.")
        except ValueError as exc:
            raise ValueError("The SOCKS gateway can bind only to a loopback address.") from exc
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("The SOCKS gateway port must be an integer in the range 1..65535.")
        self.host = host
        self.port = port
        self.selector = SocksBackendSelector()
        self._server: _ThreadedSocksServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()

    @property
    def running(self) -> bool:
        with self._lock:
            return bool(
                self._server is not None
                and self._thread is not None
                and self._thread.is_alive()
            )

    def set_backends(self, backends: Iterable[tuple[str, int]]) -> None:
        self.selector.set_backends(backends)

    def start(self) -> None:
        with self._lock:
            if self._server is not None:
                if self.running:
                    return
                raise RuntimeError("A previous SOCKS gateway instance was not shut down cleanly.")
            server = _ThreadedSocksServer((self.host, self.port), self.selector)
            thread = threading.Thread(
                target=server.serve_forever,
                name="torproxy-socks-failover-gateway",
                daemon=True,
            )
            self._server = server
            self._thread = thread
            try:
                thread.start()
            except Exception:
                self._server = None
                self._thread = None
                server.server_close()
                raise
        LOGGER.info("Stable loopback SOCKS gateway started on %s:%s.", self.host, self.port)

    def stop(self) -> None:
        with self._lock:
            server = self._server
            thread = self._thread
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5)
        if thread is not None and thread.is_alive():
            raise RuntimeError("The SOCKS failover gateway did not stop cleanly.")
        with self._lock:
            if self._server is server:
                self._server = None
                self._thread = None
        LOGGER.info("Stable loopback SOCKS gateway stopped.")
