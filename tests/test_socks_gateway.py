from __future__ import annotations

import socket
import socketserver
import threading

import pytest

from torproxy.socks_gateway import SocksBackendSelector, SocksGateway


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            payload = self.request.recv(4096)
            if not payload:
                return
            self.request.sendall(payload)


class _EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def test_selector_preserves_active_backend_priority_and_rejects_duplicates():
    selector = SocksBackendSelector()
    selector.set_backends((("active", 21001), ("standby", 21002)))

    assert selector.candidates() == (("active", 21001), ("standby", 21002))

    with pytest.raises(ValueError, match="unique"):
        selector.set_backends((("same", 21001), ("same", 21002)))
    with pytest.raises(ValueError, match="unique"):
        selector.set_backends((("one", 21001), ("two", 21001)))


def test_gateway_fails_over_to_a_healthy_standby_for_new_sessions():
    echo_server = _EchoServer(("127.0.0.1", 0), _EchoHandler)
    echo_thread = threading.Thread(target=echo_server.serve_forever, daemon=True)
    echo_thread.start()
    dead_port = _free_loopback_port()
    while dead_port == echo_server.server_address[1]:
        dead_port = _free_loopback_port()

    gateway = SocksGateway(_free_loopback_port())
    gateway.set_backends((
        ("primary", dead_port),
        ("standby", int(echo_server.server_address[1])),
    ))
    try:
        gateway.start()
        with socket.create_connection(("127.0.0.1", gateway.port), timeout=3) as client:
            client.settimeout(3)
            client.sendall(b"standby-session")
            assert client.recv(64) == b"standby-session"
    finally:
        gateway.stop()
        echo_server.shutdown()
        echo_server.server_close()
        echo_thread.join(timeout=3)


def test_gateway_refuses_non_loopback_bind_addresses():
    with pytest.raises(ValueError, match="loopback"):
        SocksGateway(19050, host="0.0.0.0")


def test_gateway_with_no_ready_backend_does_not_open_a_direct_route():
    gateway = SocksGateway(_free_loopback_port())
    try:
        gateway.start()
        with socket.create_connection(("127.0.0.1", gateway.port), timeout=3) as client:
            client.settimeout(3)
            client.sendall(b"no-backend")
            assert client.recv(1) == b""
    finally:
        gateway.stop()
