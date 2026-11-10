"""Loopback SOCKS5 gateway with per-connection failover across healthy Tor backends."""
from __future__ import annotations

import logging
import select
import socket
import threading
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
        backend_provider: Callable[[], Iterable[tuple[str, int]]],
        *,
        host: str = "127.0.0.1",
        connect_timeout: float = 8.0,
        handshake_timeout: float = 12.0,
        idle_timeout: float = 120.0,
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
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._clients: set[socket.socket] = set()
        self._cursor = 0

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            family = socket.AF_INET6 if self.host == "::1" else socket.AF_INET
            listener = socket.socket(family, socket.SOCK_STREAM)
            try:
                listener.bind((self.host, self.port))
                listener.listen(128)
                listener.settimeout(0.5)
            except OSError:
                listener.close()
                raise
            self._stop.clear()
            self._listener = listener
            self._thread = threading.Thread(
                target=self._accept_loop,
                name="torproxy-socks-failover",
                daemon=True,
            )
            self._thread.start()
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
            except socket.timeout:
                continue
            except OSError:
                if not self._stop.is_set():
                    LOGGER.exception("SOCKS failover gateway accept failed.")
                return
            if not self._track(client, True):
                client.close()
                return
            threading.Thread(
                target=self._handle_client,
                args=(client,),
                name="torproxy-socks-session",
                daemon=True,
            ).start()

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
        for item in self._backend_provider() or ():
            try:
                host, port = item
                host = str(host)
                port = int(port)
                if host in {"127.0.0.1", "::1", "localhost"} and 1 <= port <= 65535:
                    candidate = (host, port)
                    if candidate not in candidates:
                        candidates.append(candidate)
            except (TypeError, ValueError):
                continue
        if not candidates:
            return []
        with self._lock:
            offset = self._cursor % len(candidates)
            self._cursor = (self._cursor + 1) % len(candidates)
        return candidates[offset:] + candidates[:offset]

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

            for host, port in self._ordered_backends():
                if self._stop.is_set():
                    return
                candidate: socket.socket | None = None
                try:
                    candidate = socket.create_connection((host, port), timeout=self._connect_timeout)
                    if not self._track(candidate, True):
                        raise OSError("SOCKS gateway is stopping.")
                    candidate.settimeout(self._handshake_timeout)
                    candidate.sendall(b"\x05\x01\x00")
                    if self._recv_exact(candidate, 2) != b"\x05\x00":
                        raise OSError("Tor SOCKS backend rejected no-auth negotiation.")
                    candidate.sendall(request)
                    reply = self._read_reply(candidate)
                    if reply[1] == 0:
                        client.sendall(reply)
                        client.settimeout(None)
                        candidate.settimeout(None)
                        upstream = candidate
                        candidate = None
                        self._relay(client, upstream, self._idle_timeout)
                        return
                    last_reply = reply
                except (OSError, TimeoutError, ValueError):
                    LOGGER.debug("A Tor SOCKS backend failed before CONNECT was established.", exc_info=True)
                finally:
                    if candidate is not None:
                        self._track(candidate, False)
                        try:
                            candidate.close()
                        except OSError:
                            pass

            try:
                client.sendall(last_reply or self._failure_reply(4))
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
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.1, float(timeout)))
        if thread is not None and thread.is_alive():
            raise SocksGatewayError("The primary Tor SOCKS failover listener is still active.")
        with self._lock:
            self._thread = None
            self._clients.clear()
        LOGGER.info("Primary Tor SOCKS failover gateway stopped.")
