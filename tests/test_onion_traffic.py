from __future__ import annotations

import socket
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
