from __future__ import annotations

import socket
import threading
import time

import pytest

from torproxy.socks_gateway import SocksFailoverGateway, SocksGatewayError


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("peer closed early")
        data.extend(chunk)
    return bytes(data)


def _start_echo_socks_backend(*, connect_delay: float = 0.0):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = int(listener.getsockname()[1])

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                assert _recv_exact(connection, 3) == b"\x05\x01\x00"
                connection.sendall(b"\x05\x00")
                header = _recv_exact(connection, 4)
                atyp = header[3]
                if atyp == 1:
                    _address = _recv_exact(connection, 4)
                elif atyp == 4:
                    _address = _recv_exact(connection, 16)
                else:
                    length = _recv_exact(connection, 1)
                    _address = length + _recv_exact(connection, length[0])
                _recv_exact(connection, 2)
                if connect_delay:
                    time.sleep(connect_delay)
                connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01")
                payload = _recv_exact(connection, 4)
                connection.sendall(payload)
        except OSError:
            # The Onion-specific deadline may close the delayed backend first.
            pass
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, thread



def test_gateway_uses_shorter_connect_budget_for_onion_service_hosts():
    backend_port, backend_thread = _start_echo_socks_backend(connect_delay=1.2)
    gateway_port = _free_port()
    gateway = SocksFailoverGateway(
        gateway_port,
        lambda: [("127.0.0.1", backend_port)],
        connect_timeout=1,
        handshake_timeout=2,
        backend_connect_timeout=2.0,
        onion_connect_timeout=0.3,
        idle_timeout=5,
    )
    gateway.start()
    try:
        with socket.create_connection(("127.0.0.1", gateway_port), timeout=2) as client:
            client.settimeout(2)
            client.sendall(b"\x05\x01\x00")
            assert _recv_exact(client, 2) == b"\x05\x00"
            host = b"new-address.onion"
            request = b"\x05\x01\x00\x03" + bytes((len(host),)) + host + b"\x00\x50"
            started = time.monotonic()
            client.sendall(request)
            response = _recv_exact(client, 10)
            elapsed = time.monotonic() - started

            assert response[0] == 5
            assert response[1] != 0
            assert elapsed < 0.9
    finally:
        gateway.stop()
        backend_thread.join(timeout=2)

    assert not backend_thread.is_alive()

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.mark.parametrize(
    ("raw_request", "expected_host"),
    [
        (b"\x05\x01\x00\x03\x0fblocked.example\x01\xbb", "blocked.example"),
        (b"\x05\x01\x00\x01\x7f\x00\x00\x02\x01\xbb", "127.0.0.2"),
    ],
)
def test_gateway_rejects_blocked_socks_connect_before_backend_selection(raw_request, expected_host):
    seen_hosts = []
    gateway_port = _free_port()
    gateway = SocksFailoverGateway(
        gateway_port,
        lambda: [],
        host_router=lambda host: (seen_hosts.append(host), "blocked" if host == expected_host else "tor")[1],
    )
    gateway.start()
    try:
        with socket.create_connection(("127.0.0.1", gateway_port), timeout=2) as client:
            client.settimeout(2)
            client.sendall(b"\x05\x01\x00")
            assert _recv_exact(client, 2) == b"\x05\x00"
            client.sendall(raw_request)
            assert _recv_exact(client, 10) == (
                b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00"
            )
    finally:
        gateway.stop()

    assert seen_hosts == [expected_host]


def test_gateway_routes_excluded_socks_domain_directly_without_using_tor_backends(monkeypatch):
    target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target.bind(("127.0.0.1", 0))
    target.listen()
    target.settimeout(2)
    target_port = int(target.getsockname()[1])
    target_received = []
    target_finished = threading.Event()

    original_getaddrinfo = socket.getaddrinfo

    def resolve_test_domain(host, port, *args, **kwargs):
        # Keep the test independent of hosts-file/DNS differences across OSes.
        if host == "excluded.example":
            host = "127.0.0.1"
        return original_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", resolve_test_domain)

    def serve_target():
        try:
            connection, _address = target.accept()
            with connection:
                payload = _recv_exact(connection, 5)
                target_received.append(payload)
                connection.sendall(payload)
        except TimeoutError:
            pass
        finally:
            target.close()
            target_finished.set()

    target_thread = threading.Thread(target=serve_target, daemon=True)
    target_thread.start()
    gateway_port = _free_port()
    backend_provider_called = []
    routed_hosts = []
    gateway = SocksFailoverGateway(
        gateway_port,
        lambda: backend_provider_called.append(True) or [],
        host_router=lambda host: routed_hosts.append(host) or ("direct" if host == "excluded.example" else "tor"),
        connect_timeout=2,
        handshake_timeout=2,
        idle_timeout=5,
    )
    gateway.start()
    try:
        with socket.create_connection(("127.0.0.1", gateway_port), timeout=2) as client:
            client.settimeout(3)
            client.sendall(b"\x05\x01\x00")
            assert _recv_exact(client, 2) == b"\x05\x00"
            encoded_host = b"excluded.example"
            request = (
                b"\x05\x01\x00\x03"
                + bytes((len(encoded_host),))
                + encoded_host
                + target_port.to_bytes(2, "big")
            )
            client.sendall(request)
            response = _recv_exact(client, 10)
            assert response[:4] == b"\x05\x00\x00\x01"
            client.sendall(b"hello")
            assert _recv_exact(client, 5) == b"hello"
    finally:
        gateway.stop()
        target.close()
        target_thread.join(timeout=3)

    assert routed_hosts == ["excluded.example"]
    assert backend_provider_called == []
    assert target_received == [b"hello"]
    assert target_finished.is_set()
    assert not target_thread.is_alive()


def test_gateway_fails_over_to_next_ready_backend_before_connect_reply():
    # Reserve then release a local port so the first backend is guaranteed to
    # refuse the connection; the second backend is a tiny SOCKS5 test server.
    unavailable_port = _free_port()
    backend_port, backend_thread = _start_echo_socks_backend()
    gateway_port = _free_port()
    gateway = SocksFailoverGateway(
        gateway_port,
        lambda: [
            ("127.0.0.1", unavailable_port),
            ("127.0.0.1", backend_port),
        ],
        connect_timeout=1,
        handshake_timeout=2,
        idle_timeout=5,
    )
    gateway.start()
    try:
        with socket.create_connection(("127.0.0.1", gateway_port), timeout=2) as client:
            client.settimeout(2)
            client.sendall(b"\x05\x01\x00")
            assert _recv_exact(client, 2) == b"\x05\x00"
            client.sendall(b"\x05\x01\x00\x03\x0bexample.com\x00\x50")
            assert _recv_exact(client, 10) == b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01"
            client.sendall(b"ping")
            assert _recv_exact(client, 4) == b"ping"
    finally:
        gateway.stop()
        backend_thread.join(timeout=2)
    assert not backend_thread.is_alive()


def test_gateway_waits_for_tor_connect_reply_after_frontend_handshake_timeout():
    backend_port, backend_thread = _start_echo_socks_backend(connect_delay=0.3)
    gateway_port = _free_port()
    gateway = SocksFailoverGateway(
        gateway_port,
        lambda: [("127.0.0.1", backend_port)],
        connect_timeout=1,
        handshake_timeout=0.1,
        backend_connect_timeout=1.5,
        idle_timeout=5,
    )
    gateway.start()
    try:
        with socket.create_connection(("127.0.0.1", gateway_port), timeout=2) as client:
            client.settimeout(2)
            client.sendall(b"\x05\x01\x00")
            assert _recv_exact(client, 2) == b"\x05\x00"
            client.sendall(b"\x05\x01\x00\x03\x0bexample.com\x00\x50")
            assert _recv_exact(client, 10) == b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01"
            client.sendall(b"ping")
            assert _recv_exact(client, 4) == b"ping"
    finally:
        gateway.stop()
        backend_thread.join(timeout=2)

    assert not backend_thread.is_alive()


def _start_failing_socks_backend(reply_code: int):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(4)
    port = int(listener.getsockname()[1])

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(3)
                assert _recv_exact(connection, 3) == b"\x05\x01\x00"
                connection.sendall(b"\x05\x00")
                header = _recv_exact(connection, 4)
                if header[3] == 1:
                    _recv_exact(connection, 4)
                elif header[3] == 4:
                    _recv_exact(connection, 16)
                elif header[3] == 3:
                    size = _recv_exact(connection, 1)[0]
                    _recv_exact(connection, size)
                else:
                    raise AssertionError("unsupported test address type")
                _recv_exact(connection, 2)
                connection.sendall(
                    b"\x05" + bytes((reply_code,)) + b"\x00\x01\x00\x00\x00\x00\x00\x00"
                )
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, thread


def test_gateway_logs_each_tor_destination_failure_and_preserves_socks_reply(caplog):
    first_port, first_thread = _start_failing_socks_backend(0x01)
    second_port, second_thread = _start_failing_socks_backend(0x04)
    gateway_port = _free_port()
    gateway = SocksFailoverGateway(
        gateway_port,
        lambda: [("127.0.0.1", first_port), ("127.0.0.1", second_port)],
        connect_timeout=2,
        handshake_timeout=2,
        idle_timeout=5,
    )
    gateway.start()
    try:
        with socket.create_connection(("127.0.0.1", gateway_port), timeout=2) as client:
            client.settimeout(3)
            client.sendall(b"\x05\x01\x00")
            assert _recv_exact(client, 2) == b"\x05\x00"
            host = b"diagnostic-example.onion"
            request = (
                b"\x05\x01\x00\x03"
                + bytes((len(host),))
                + host
                + (80).to_bytes(2, "big")
            )
            client.sendall(request)
            # The gateway attempts each ready backend and relays the last
            # SOCKS failure rather than changing the protocol response.
            assert _recv_exact(client, 10) in {
                b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00",
                b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00",
            }
    finally:
        gateway.stop()
        first_thread.join(timeout=2)
        second_thread.join(timeout=2)

    assert f"backend=127.0.0.1:{first_port}" in caplog.text
    assert f"backend=127.0.0.1:{second_port}" in caplog.text
    assert "reply=0x01 (general SOCKS server failure)" in caplog.text
    assert "reply=0x04 (host unreachable)" in caplog.text
    assert "After trying 2 available Tor SOCKS backend(s), no connection was established" in caplog.text


def test_gateway_rejects_clients_that_do_not_offer_no_auth():
    gateway_port = _free_port()
    gateway = SocksFailoverGateway(gateway_port, lambda: [])
    gateway.start()
    try:
        with socket.create_connection(("127.0.0.1", gateway_port), timeout=2) as client:
            client.settimeout(2)
            client.sendall(b"\x05\x01\x02")
            assert _recv_exact(client, 2) == b"\x05\xff"
    finally:
        gateway.stop()


def test_gateway_prefers_the_least_loaded_and_lowest_latency_backend():
    first = ("127.0.0.1", 25001)
    second = ("127.0.0.1", 25002)
    gateway = SocksFailoverGateway(
        25003,
        lambda: [
            ("127.0.0.1", 25001, 300.0),
            ("127.0.0.1", 25002, 90.0),
        ],
    )
    gateway._backend_stats[first] = {
        "active": 5,
        "latency_ms": 10.0,
        "health_latency_ms": 300.0,
        "failures": 0,
        "cooldown_until": 0.0,
        "last_success": 0.0,
    }
    gateway._backend_stats[second] = {
        "active": 1,
        "latency_ms": 250.0,
        "health_latency_ms": 90.0,
        "failures": 0,
        "cooldown_until": 0.0,
        "last_success": 0.0,
    }

    assert gateway._ordered_backends()[0] == second


def test_gateway_prefers_a_healthy_backend_before_one_in_cooldown():
    first = ("127.0.0.1", 25101)
    second = ("127.0.0.1", 25102)
    gateway = SocksFailoverGateway(
        25103,
        lambda: [first, second],
    )
    gateway._backend_stats[first] = {
        "active": 0,
        "latency_ms": 20.0,
        "health_latency_ms": 20.0,
        "failures": 1,
        "cooldown_until": 9999999999.0,
        "last_success": 0.0,
    }
    gateway._backend_stats[second] = {
        "active": 2,
        "latency_ms": 200.0,
        "health_latency_ms": 200.0,
        "failures": 0,
        "cooldown_until": 0.0,
        "last_success": 0.0,
    }

    assert gateway._ordered_backends()[0] == second


def test_gateway_tracks_backend_reservations_for_active_load_balancing():
    endpoint = ("127.0.0.1", 25201)
    gateway = SocksFailoverGateway(25202, lambda: [endpoint])

    assert gateway._reserve_backend(endpoint) is True
    assert gateway.backend_metrics[endpoint]["active"] == 1
    gateway._release_backend(endpoint)
    assert gateway.backend_metrics[endpoint]["active"] == 0



def test_gateway_rejects_sessions_over_configured_capacity_and_releases_slots():
    gateway_port = _free_port()
    gateway = SocksFailoverGateway(
        gateway_port,
        lambda: [],
        max_sessions=1,
        handshake_timeout=5,
    )
    gateway.start()
    first = None
    second = None
    try:
        first = socket.create_connection(("127.0.0.1", gateway_port), timeout=2)
        first.settimeout(2)
        deadline = time.monotonic() + 2
        while gateway.session_metrics["active_sessions"] != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert gateway.session_metrics["active_sessions"] == 1

        second = socket.create_connection(("127.0.0.1", gateway_port), timeout=2)
        second.settimeout(2)
        assert second.recv(1) == b""

        metrics = gateway.session_metrics
        assert metrics["max_sessions"] == 1
        assert metrics["rejected_sessions"] == 1
        assert metrics["active_sessions"] == 1
    finally:
        if first is not None:
            first.close()
        if second is not None:
            second.close()
        gateway.stop()

    assert gateway.session_metrics["active_sessions"] == 0


def test_gateway_rejects_invalid_session_limits():
    gateway_port = _free_port()
    try:
        SocksFailoverGateway(gateway_port, lambda: [], max_sessions=0)
    except ValueError as exc:
        assert "between 1 and 4096" in str(exc)
    else:
        raise AssertionError("A zero-sized gateway must not be accepted")


def test_gateway_refuses_restart_while_a_previous_session_thread_is_alive():
    gateway_port = _free_port()
    entered = threading.Event()
    release = threading.Event()
    gateway = SocksFailoverGateway(gateway_port, lambda: [], max_sessions=1)

    def blocked_handler(_client):
        entered.set()
        release.wait(timeout=3)

    gateway._handle_client = blocked_handler
    gateway.start()
    client = socket.create_connection(("127.0.0.1", gateway_port), timeout=2)
    try:
        assert entered.wait(timeout=2)
        with pytest.raises(SocksGatewayError, match="previous client sessions"):
            gateway.stop(timeout=1.0)
        with pytest.raises(SocksGatewayError, match="cannot restart"):
            gateway.start()
    finally:
        release.set()
        client.close()

    deadline = time.monotonic() + 2
    while gateway.session_metrics["active_sessions"] and time.monotonic() < deadline:
        time.sleep(0.01)
    assert gateway.session_metrics["active_sessions"] == 0

    gateway.start()
    gateway.stop(timeout=2)



def test_latency_selection_mode_prioritizes_the_best_quality_backend():
    second = ("127.0.0.1", 25302)
    gateway = SocksFailoverGateway(
        25303,
        lambda: [
            ("127.0.0.1", 25301, 300.0),
            ("127.0.0.1", 25302, 90.0),
        ],
        selection_mode="latency",
    )

    assert gateway.selection_mode == "latency"
    assert gateway._ordered_backends()[0] == second

    gateway.set_selection_mode("balanced")
    assert gateway.selection_mode == "balanced"


def test_gateway_rejects_unknown_backend_selection_mode():
    with pytest.raises(ValueError, match="balanced.*latency"):
        SocksFailoverGateway(25304, lambda: [], selection_mode="fastest")



class _HandshakePeer:
    def __init__(self, address: str, payload: bytes):
        self._address = address
        self._payload = bytearray(payload)
        self.sent = bytearray()

    def getpeername(self):
        return (self._address, 54321)

    def recv(self, size):
        part = bytes(self._payload[:size])
        del self._payload[:size]
        return part

    def sendall(self, payload):
        self.sent.extend(payload)


def test_remote_gateway_requires_rfc1929_authentication_and_rejects_no_auth():
    gateway = SocksFailoverGateway(
        _free_port(),
        lambda: [],
        host="0.0.0.0",
        username="client-user",
        password="strong-client-password",
    )
    rejected = _HandshakePeer("192.0.2.20", b"")
    assert gateway._authenticate_client(rejected, bytes((0,))) is False
    assert bytes(rejected.sent) == bytes((5, 255))

    username = b"client-user"
    password = b"strong-client-password"
    auth_payload = (
        bytes((1, len(username))) + username
        + bytes((len(password),)) + password
    )
    accepted = _HandshakePeer("192.0.2.20", auth_payload)
    assert gateway._authenticate_client(accepted, bytes((2,))) is True
    assert bytes(accepted.sent) == bytes((5, 2, 1, 0))

    wrong = _HandshakePeer("192.0.2.20", auth_payload[:-1] + b"X")
    assert gateway._authenticate_client(wrong, bytes((2,))) is False
    assert bytes(wrong.sent) == bytes((5, 2, 1, 1))


def test_wildcard_gateway_keeps_loopback_no_auth_compatibility():
    gateway = SocksFailoverGateway(
        _free_port(),
        lambda: [],
        host="0.0.0.0",
        username="client-user",
        password="client-password",
    )
    local = _HandshakePeer("127.0.0.1", b"")
    assert gateway._authenticate_client(local, bytes((0,))) is True
    assert bytes(local.sent) == bytes((5, 0))


def test_gateway_rejects_wildcard_bind_without_credentials():
    with pytest.raises(ValueError, match="requires username/password"):
        SocksFailoverGateway(_free_port(), lambda: [], host="0.0.0.0")


def test_gateway_relay_records_upload_and_download_bytes():
    client, gateway_client = socket.socketpair()
    gateway_upstream, upstream = socket.socketpair()
    events = []
    gateway = SocksFailoverGateway(
        _free_port(),
        lambda: [],
        traffic_recorder=lambda amount, direction: events.append((amount, direction)),
    )
    worker = threading.Thread(
        target=gateway._relay,
        args=(gateway_client, gateway_upstream, 2),
        daemon=True,
    )
    worker.start()
    try:
        client.sendall(b"upstream")
        assert _recv_exact(upstream, 8) == b"upstream"
        upstream.sendall(b"down")
        assert _recv_exact(client, 4) == b"down"
        client.shutdown(socket.SHUT_WR)
        upstream.shutdown(socket.SHUT_WR)
        worker.join(timeout=3)
    finally:
        for peer in (client, gateway_client, gateway_upstream, upstream):
            peer.close()
    assert not worker.is_alive()
    assert events == [(8, "upload"), (4, "download")]
