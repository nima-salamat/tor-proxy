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


def _start_echo_socks_backend():
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
                connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01")
                payload = _recv_exact(connection, 4)
                connection.sendall(payload)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, thread


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


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
