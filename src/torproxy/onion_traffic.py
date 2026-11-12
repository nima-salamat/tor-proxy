"""Per-service TCP accounting and privacy-conscious Onion access history.

The relay is deliberately protocol-transparent: it forwards the original byte
stream unchanged and observes only byte counts plus the first visible HTTP
request/status line. TLS application data remains encrypted and is never
inspected or logged.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import re
import select
import socket
import sqlite3
import threading
import time
from typing import Any
from urllib.parse import urlsplit

LOGGER = logging.getLogger(__name__)
_REQUEST_LINE_RE = re.compile(rb"^([A-Z]{3,12})\s+(\S+)\s+HTTP/\d(?:\.\d)?$")
_STATUS_LINE_RE = re.compile(rb"^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s|$)")
_MAX_EVENT_ROWS_PER_SERVICE = 2000
_MAX_CONNECTIONS_PER_PORT = 128
_MAX_CONNECTIONS_GLOBAL = 512


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_request_path(raw_target: bytes) -> str:
    """Keep the path but never persist query strings, fragments, or request headers."""
    try:
        target = raw_target.decode("ascii", errors="replace")
        parsed = urlsplit(target)
        path = parsed.path or ("/" if target.startswith("/") else target)
    except Exception:
        path = "/"
    path = path.split("?", 1)[0].split("#", 1)[0]
    return path[:256] or "/"


class OnionTrafficStore:
    """Small local SQLite store for cumulative counters and bounded access history."""

    def __init__(self, data_directory: Path) -> None:
        self.path = Path(data_directory) / "developer-tor" / "traffic.sqlite3"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            try:
                self.path.parent.chmod(0o700)
            except OSError:
                pass
        self._lock = threading.RLock()
        # Shared by every service and port mapping in the Developer Tor runtime.
        self.connection_slots = threading.BoundedSemaphore(_MAX_CONNECTIONS_GLOBAL)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    @contextmanager
    def _database(self):
        """Provide a transaction and always close the short-lived SQLite handle."""
        db = self._connect()
        try:
            with db:
                yield db
        finally:
            db.close()

    def _initialize(self) -> None:
        with self._lock, self._database() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS service_totals (
                    service_id TEXT PRIMARY KEY,
                    incoming_bytes INTEGER NOT NULL DEFAULT 0,
                    outgoing_bytes INTEGER NOT NULL DEFAULT 0,
                    connections INTEGER NOT NULL DEFAULT 0,
                    http_requests INTEGER NOT NULL DEFAULT 0,
                    errors INTEGER NOT NULL DEFAULT 0,
                    active_connections INTEGER NOT NULL DEFAULT 0,
                    last_activity TEXT NOT NULL DEFAULT ''
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS service_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_id TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    onion_port INTEGER NOT NULL,
                    local_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    method TEXT NOT NULL DEFAULT '',
                    path TEXT NOT NULL DEFAULT '',
                    status_code INTEGER,
                    incoming_bytes INTEGER NOT NULL DEFAULT 0,
                    outgoing_bytes INTEGER NOT NULL DEFAULT 0,
                    duration_ms INTEGER NOT NULL DEFAULT 0,
                    error TEXT NOT NULL DEFAULT ''
                )
                """
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_service_events_service_id "
                "ON service_events(service_id, id DESC)"
            )
            # Any non-zero count belongs to a process that no longer exists.
            db.execute("UPDATE service_totals SET active_connections=0")

        if os.name != "nt":
            try:
                self.path.chmod(0o600)
            except OSError:
                pass

    def begin_connection(self, service_id: str) -> None:
        with self._lock, self._database() as db:
            db.execute(
                "INSERT OR IGNORE INTO service_totals(service_id) VALUES (?)",
                (service_id,),
            )
            db.execute(
                "UPDATE service_totals SET active_connections=active_connections+1 WHERE service_id=?",
                (service_id,),
            )

    def finish_connection(
        self,
        service_id: str,
        *,
        onion_port: int,
        local_port: int,
        protocol: str,
        method: str = "",
        path: str = "",
        status_code: int | None = None,
        incoming_bytes: int = 0,
        outgoing_bytes: int = 0,
        duration_ms: int = 0,
        error: str = "",
    ) -> None:
        occurred_at = _timestamp()
        incoming_bytes = max(0, int(incoming_bytes))
        outgoing_bytes = max(0, int(outgoing_bytes))
        with self._lock, self._database() as db:
            db.execute(
                "INSERT OR IGNORE INTO service_totals(service_id) VALUES (?)",
                (service_id,),
            )
            db.execute(
                """
                UPDATE service_totals SET
                    incoming_bytes=incoming_bytes+?,
                    outgoing_bytes=outgoing_bytes+?,
                    connections=connections+1,
                    http_requests=http_requests+?,
                    errors=errors+?,
                    active_connections=CASE
                        WHEN active_connections>0 THEN active_connections-1 ELSE 0 END,
                    last_activity=?
                WHERE service_id=?
                """,
                (
                    incoming_bytes,
                    outgoing_bytes,
                    1 if method else 0,
                    1 if error else 0,
                    occurred_at,
                    service_id,
                ),
            )
            db.execute(
                """
                INSERT INTO service_events (
                    service_id, occurred_at, onion_port, local_port, protocol,
                    method, path, status_code, incoming_bytes, outgoing_bytes,
                    duration_ms, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    service_id,
                    occurred_at,
                    int(onion_port),
                    int(local_port),
                    str(protocol or "TCP")[:12],
                    str(method or "")[:12],
                    str(path or "")[:256],
                    int(status_code) if status_code is not None else None,
                    incoming_bytes,
                    outgoing_bytes,
                    max(0, int(duration_ms)),
                    str(error or "")[:180],
                ),
            )
            db.execute(
                """
                DELETE FROM service_events
                WHERE service_id=? AND id NOT IN (
                    SELECT id FROM service_events
                    WHERE service_id=? ORDER BY id DESC LIMIT ?
                )
                """,
                (service_id, service_id, _MAX_EVENT_ROWS_PER_SERVICE),
            )

    def snapshot(self, service_id: str | None = None) -> dict[str, Any]:
        with self._lock, self._database() as db:
            if service_id is None:
                row = db.execute(
                    """
                    SELECT
                        COALESCE(SUM(incoming_bytes), 0) AS incoming_bytes,
                        COALESCE(SUM(outgoing_bytes), 0) AS outgoing_bytes,
                        COALESCE(SUM(connections), 0) AS connections,
                        COALESCE(SUM(http_requests), 0) AS http_requests,
                        COALESCE(SUM(errors), 0) AS errors,
                        COALESCE(SUM(active_connections), 0) AS active_connections,
                        COALESCE(MAX(last_activity), '') AS last_activity
                    FROM service_totals
                    """
                ).fetchone()
            else:
                row = db.execute(
                    """
                    SELECT incoming_bytes, outgoing_bytes, connections,
                           http_requests, errors, active_connections, last_activity
                    FROM service_totals WHERE service_id=?
                    """,
                    (service_id,),
                ).fetchone()
        if row is None:
            return {
                "incoming_bytes": 0, "outgoing_bytes": 0, "connections": 0,
                "http_requests": 0, "errors": 0, "active_connections": 0,
                "last_activity": "",
            }
        return {key: row[key] for key in row.keys()}

    def events(self, service_id: str, limit: int = 250) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 1000))
        with self._lock, self._database() as db:
            rows = db.execute(
                """
                SELECT id, occurred_at, onion_port, local_port, protocol,
                       method, path, status_code, incoming_bytes, outgoing_bytes,
                       duration_ms, error
                FROM service_events
                WHERE service_id=? ORDER BY id DESC LIMIT ?
                """,
                (service_id, bounded_limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_service(self, service_id: str) -> None:
        """Remove the traffic history when its owning service is permanently deleted."""
        with self._lock, self._database() as db:
            db.execute("DELETE FROM service_events WHERE service_id=?", (service_id,))
            db.execute("DELETE FROM service_totals WHERE service_id=?", (service_id,))


class _HttpLineProbe:
    """Identify the first plaintext HTTP/1 request and response line only."""

    def __init__(self) -> None:
        self.protocol = "TCP"
        self.method = ""
        self.path = ""
        self.status_code: int | None = None
        self._request_buffer = bytearray()
        self._response_buffer = bytearray()
        self._request_done = False
        self._response_done = False

    @staticmethod
    def _is_tls(data: bytes) -> bool:
        return len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03

    def observe(self, direction: str, data: bytes) -> None:
        if direction == "request" and not self._request_done:
            self._request_buffer.extend(data[:8192])
            if len(self._request_buffer) >= 3 and self._is_tls(bytes(self._request_buffer[:3])):
                self.protocol = "TLS"
                self._request_done = True
                self._response_done = True
                self._request_buffer.clear()
                return
            end = self._request_buffer.find(b"\r\n")
            if end < 0 and len(self._request_buffer) < 8192:
                return
            line = bytes(self._request_buffer[:end if end >= 0 else 8192]).strip()
            match = _REQUEST_LINE_RE.match(line)
            if match:
                self.protocol = "HTTP"
                self.method = match.group(1).decode("ascii", errors="replace")
                self.path = _safe_request_path(match.group(2))
            self._request_done = True
        elif direction == "response" and self.protocol == "HTTP" and not self._response_done:
            self._response_buffer.extend(data[:4096])
            end = self._response_buffer.find(b"\r\n")
            if end < 0 and len(self._response_buffer) < 4096:
                return
            line = bytes(self._response_buffer[:end if end >= 0 else 4096]).strip()
            match = _STATUS_LINE_RE.match(line)
            if match:
                try:
                    self.status_code = int(match.group(1))
                except ValueError:
                    self.status_code = None
            self._response_done = True


class _TcpPortRelay:
    """One loopback listener transparently forwards a mapping to its local target."""

    def __init__(self, service_id: str, mapping: dict[str, Any], store: OnionTrafficStore) -> None:
        self.service_id = service_id
        self.mapping = dict(mapping)
        self.store = store
        self._stop = threading.Event()
        self._active_lock = threading.RLock()
        self._active_sockets: set[socket.socket] = set()
        self._connection_threads: set[threading.Thread] = set()
        self._port_connection_slots = threading.BoundedSemaphore(_MAX_CONNECTIONS_PER_PORT)
        self._connection_slots = store.connection_slots
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(128)
        self.listener.settimeout(0.5)
        self.port = int(self.listener.getsockname()[1])
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name=f"onion-relay-{service_id[:8]}-{self.port}",
            daemon=True,
        )

    def start(self) -> int:
        self._accept_thread.start()
        return self.port

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                client, _peer = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            if not self._port_connection_slots.acquire(blocking=False):
                try:
                    client.close()
                except OSError:
                    pass
                continue
            if not self._connection_slots.acquire(blocking=False):
                self._port_connection_slots.release()
                # A shared process-wide ceiling prevents many services or port
                # mappings from multiplying their individual concurrency limits.
                try:
                    client.close()
                except OSError:
                    pass
                continue
            thread = threading.Thread(
                target=self._serve,
                args=(client,),
                name=f"onion-traffic-{self.service_id[:8]}",
                daemon=True,
            )
            with self._active_lock:
                if self._stop.is_set():
                    self._connection_slots.release()
                    self._port_connection_slots.release()
                    try:
                        client.close()
                    except OSError:
                        pass
                    break
                self._active_sockets.add(client)
                self._connection_threads.add(thread)
            try:
                thread.start()
            except Exception:
                with self._active_lock:
                    self._active_sockets.discard(client)
                    self._connection_threads.discard(thread)
                self._connection_slots.release()
                self._port_connection_slots.release()
                client.close()
                LOGGER.exception("Could not start Onion Service traffic worker.")

    def _serve(self, client: socket.socket) -> None:
        started = time.monotonic()
        bytes_in = 0
        bytes_out = 0
        error = ""
        probe = _HttpLineProbe()
        upstream: socket.socket | None = None
        connection_started = False
        try:
            self.store.begin_connection(self.service_id)
            connection_started = True
            client.setblocking(True)
            target_host = str(self.mapping["local_host"])
            target_port = int(self.mapping["local_port"])
            upstream = socket.create_connection((target_host, target_port), timeout=5.0)
            upstream.setblocking(True)
            with self._active_lock:
                self._active_sockets.add(upstream)
            bytes_in, bytes_out = self._forward(client, upstream, probe)
        except (OSError, ValueError) as exc:
            error = f"{type(exc).__name__}: {str(exc)[:140]}"
        finally:
            for endpoint in (client, upstream):
                if endpoint is not None:
                    with self._active_lock:
                        self._active_sockets.discard(endpoint)
                    try:
                        endpoint.close()
                    except OSError:
                        pass
            if connection_started:
                try:
                    self.store.finish_connection(
                        self.service_id,
                        onion_port=int(self.mapping["onion_port"]),
                        local_port=int(self.mapping["local_port"]),
                        protocol=probe.protocol,
                        method=probe.method,
                        path=probe.path,
                        status_code=probe.status_code,
                        incoming_bytes=bytes_in,
                        outgoing_bytes=bytes_out,
                        duration_ms=int((time.monotonic() - started) * 1000),
                        error=error,
                    )
                except Exception:
                    LOGGER.exception("Could not store Onion Service traffic history.")
            with self._active_lock:
                self._connection_threads.discard(threading.current_thread())
            self._connection_slots.release()
            self._port_connection_slots.release()

    def _forward(
        self,
        client: socket.socket,
        upstream: socket.socket,
        probe: _HttpLineProbe,
    ) -> tuple[int, int]:
        open_sockets = {client: "request", upstream: "response"}
        bytes_in = 0
        bytes_out = 0
        while open_sockets and not self._stop.is_set():
            try:
                readable, _writable, exceptional = select.select(
                    list(open_sockets), [], list(open_sockets), 1.0
                )
            except (OSError, ValueError):
                break
            if exceptional:
                break
            for source in readable:
                direction = open_sockets.get(source)
                if direction is None:
                    continue
                destination = upstream if source is client else client
                try:
                    payload = source.recv(65536)
                    if not payload:
                        open_sockets.pop(source, None)
                        try:
                            destination.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    destination.sendall(payload)
                except OSError:
                    return bytes_in, bytes_out
                probe.observe(direction, payload)
                if direction == "request":
                    bytes_in += len(payload)
                else:
                    bytes_out += len(payload)
        return bytes_in, bytes_out

    def close(self) -> None:
        self._stop.set()
        try:
            self.listener.close()
        except OSError:
            pass
        with self._active_lock:
            sockets = tuple(self._active_sockets)
            threads = tuple(self._connection_threads)
        for endpoint in sockets:
            try:
                endpoint.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                endpoint.close()
            except OSError:
                pass
        deadline = time.monotonic() + 6.0
        if self._accept_thread.is_alive():
            self._accept_thread.join(timeout=min(0.75, max(0.0, deadline - time.monotonic())))
        # All client sockets are shut down together above. Join the bounded
        # worker set against one shared deadline instead of waiting one second
        # per client (which could multiply into minutes during a busy shutdown).
        for thread in threads:
            if not thread.is_alive():
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            thread.join(timeout=remaining)


class OnionServiceRelay:
    """Owns all per-port TCP relays for one published Onion Service."""

    def __init__(
        self,
        service_id: str,
        mappings: list[dict[str, Any]],
        store: OnionTrafficStore,
    ) -> None:
        self.service_id = service_id
        self.mappings = [dict(item) for item in mappings]
        self.store = store
        self._listeners: list[_TcpPortRelay] = []
        self._closed = False

    def start(self) -> list[dict[str, Any]]:
        if self._listeners:
            raise RuntimeError("The Onion Service relay is already started.")
        forwarded = []
        try:
            for mapping in self.mappings:
                relay = _TcpPortRelay(self.service_id, mapping, self.store)
                port = relay.start()
                self._listeners.append(relay)
                forwarded.append({
                    "onion_port": int(mapping["onion_port"]),
                    "local_host": "127.0.0.1",
                    "local_port": port,
                })
            return forwarded
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for relay in reversed(self._listeners):
            relay.close()
        self._listeners.clear()
