from __future__ import annotations

import socket
import threading

from torproxy.socks_gateway import SocksFailoverGateway


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
