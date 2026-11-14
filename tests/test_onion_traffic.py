from __future__ import annotations

import socket
import sqlite3
import threading
import time

from torproxy.onion_traffic import OnionServiceRelay, OnionTrafficStore, _HttpLineProbe


def test_http_probe_keeps_path_but_discards_query_and_fragment():
    probe = _HttpLineProbe()
    probe.observe(
        "request",
        b"GET /docs/page?session=secret#section HTTP/1.1\r\nHost: local\r\n",
    )
    probe.observe("response", b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n")

    assert probe.protocol == "HTTP"
    assert probe.method == "GET"
    assert probe.path == "/docs/page"
    assert "secret" not in probe.path
    assert probe.status_code == 201


def test_tls_probe_never_attempts_to_decode_encrypted_application_data():
    probe = _HttpLineProbe()
    probe.observe("request", b"\x16\x03")
    probe.observe("request", b"\x01\x00\x10encrypted")

    assert probe.protocol == "TLS"
    assert probe.method == ""
    assert probe.path == ""
    assert probe.status_code is None


def test_service_relay_forwards_http_and_records_directional_bytes_and_request_history(tmp_path):
    application = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    application.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    application.bind(("127.0.0.1", 0))
    application.listen(1)
    application.settimeout(3.0)
    application_port = int(application.getsockname()[1])

    request = (
        b"GET /health?token=do-not-log HTTP/1.1\r\n"
        b"Host: service.local\r\n"
        b"Connection: close\r\n\r\n"
    )
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 2\r\n"
        b"Connection: close\r\n\r\nOK"
    )
    application_errors = []

    def serve_application():
        try:
            client, _peer = application.accept()
            with client:
                received = bytearray()
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    received.extend(chunk)
                assert bytes(received) == request
                client.sendall(response)
        except Exception as exc:
            application_errors.append(exc)
        finally:
            application.close()

    application_thread = threading.Thread(target=serve_application, daemon=True)
    application_thread.start()

    store = OnionTrafficStore(tmp_path)
    relay = OnionServiceRelay(
        "service-test",
        [{
            "onion_port": 80,
            "local_host": "127.0.0.1",
            "local_port": application_port,
        }],
        store,
    )
    try:
        mapping = relay.start()[0]
        assert mapping["onion_port"] == 80
        assert mapping["local_host"] == "127.0.0.1"
        assert mapping["local_port"] != application_port

        with socket.create_connection(
            ("127.0.0.1", mapping["local_port"]), timeout=3.0
        ) as visitor:
            visitor.settimeout(3.0)
            visitor.sendall(request)
            visitor.shutdown(socket.SHUT_WR)
            received_response = bytearray()
            while True:
                chunk = visitor.recv(4096)
                if not chunk:
                    break
                received_response.extend(chunk)

        assert bytes(received_response) == response
        application_thread.join(timeout=3.0)
        assert not application_thread.is_alive()
        assert not application_errors

        deadline = time.monotonic() + 3.0
        events = []
        while time.monotonic() < deadline:
            events = store.events("service-test")
            if events:
                break
            time.sleep(0.02)

        assert len(events) == 1
        event = events[0]
        assert event["protocol"] == "HTTP"
        assert event["method"] == "GET"
        assert event["path"] == "/health"
        assert event["status_code"] == 200
        assert "do-not-log" not in event["path"]
        assert event["incoming_bytes"] == len(request)
        assert event["outgoing_bytes"] == len(response)
        assert event["duration_ms"] >= 0

        totals = store.snapshot("service-test")
        assert totals["incoming_bytes"] == len(request)
        assert totals["outgoing_bytes"] == len(response)
        assert totals["connections"] == 1
        assert totals["http_requests"] == 1
        assert totals["active_connections"] == 0
    finally:
        relay.close()
        if application_thread.is_alive():
            application.close()
            application_thread.join(timeout=1.0)


def test_batched_traffic_snapshot_returns_global_and_selected_service_totals(tmp_path):
    store = OnionTrafficStore(tmp_path)
    for service_id, incoming, outgoing in (
        ("service-a", 120, 45),
        ("service-b", 300, 80),
    ):
        store.begin_connection(service_id)
        store.finish_connection(
            service_id,
            onion_port=80,
            local_port=8080,
            protocol="HTTP",
            method="GET",
            path="/health",
            status_code=200,
            incoming_bytes=incoming,
            outgoing_bytes=outgoing,
        )

    snapshot = store.snapshot_many(["service-a", "service-b", "missing", "service-a"])
    assert snapshot["global"]["incoming_bytes"] == 420
    assert snapshot["global"]["outgoing_bytes"] == 125
    assert snapshot["global"]["connections"] == 2
    assert snapshot["services"]["service-a"]["incoming_bytes"] == 120
    assert snapshot["services"]["service-b"]["outgoing_bytes"] == 80
    assert snapshot["services"]["missing"]["connections"] == 0



def _request_through_test_relay(store, *, service_id: str) -> bytes:
    """Send one HTTP request through a relay and return the application response."""
    application = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    application.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    application.bind(("127.0.0.1", 0))
    application.listen(1)
    application.settimeout(3.0)
    application_port = int(application.getsockname()[1])
    request = b"GET /health HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    failures = []

    def serve_application():
        try:
            client, _peer = application.accept()
            with client:
                received = bytearray()
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    received.extend(chunk)
                if bytes(received) != request:
                    raise AssertionError("The local application received an altered request.")
                client.sendall(response)
        except Exception as exc:
            failures.append(exc)
        finally:
            application.close()

    application_thread = threading.Thread(target=serve_application, daemon=True)
    application_thread.start()
    relay = OnionServiceRelay(
        service_id,
        [{"onion_port": 80, "local_host": "127.0.0.1", "local_port": application_port}],
        store,
    )
    try:
        mapping = relay.start()[0]
        with socket.create_connection(("127.0.0.1", mapping["local_port"]), timeout=1.5) as visitor:
            visitor.settimeout(1.5)
            visitor.sendall(request)
            visitor.shutdown(socket.SHUT_WR)
            received_response = bytearray()
            while True:
                chunk = visitor.recv(4096)
                if not chunk:
                    break
                received_response.extend(chunk)
        application_thread.join(timeout=2.0)
        assert not application_thread.is_alive()
        assert not failures
        return bytes(received_response)
    finally:
        relay.close()
        application.close()
        if application_thread.is_alive():
            application_thread.join(timeout=1.0)


def test_relay_forwards_while_traffic_database_has_a_write_lock(tmp_path):
    store = OnionTrafficStore(tmp_path)
    blocker = sqlite3.connect(str(store.path), timeout=1.0)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        started = time.monotonic()
        received = _request_through_test_relay(store, service_id="locked-db")
        elapsed = time.monotonic() - started
    finally:
        blocker.rollback()
        blocker.close()

    assert received.startswith(b"HTTP/1.1 200 OK")
    assert elapsed < 1.5

    deadline = time.monotonic() + 3.0
    events = []
    while time.monotonic() < deadline:
        events = store.events("locked-db")
        if events:
            break
        time.sleep(0.02)
    assert len(events) == 1


def test_relay_keeps_forwarding_when_telemetry_writer_fails(tmp_path, monkeypatch):
    store = OnionTrafficStore(tmp_path)

    def fail_persist(*_args, **_kwargs):
        raise sqlite3.OperationalError("simulated telemetry write failure")

    monkeypatch.setattr(store, "_persist_connection", fail_persist)
    received = _request_through_test_relay(store, service_id="failed-db")
    assert received.startswith(b"HTTP/1.1 200 OK")

    deadline = time.monotonic() + 2.0
    while store._write_queue.unfinished_tasks and time.monotonic() < deadline:
        time.sleep(0.01)
    assert store._write_queue.unfinished_tasks == 0
    assert store._writer_thread.is_alive()
