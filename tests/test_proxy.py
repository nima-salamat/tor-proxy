from __future__ import annotations

import select
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer as TargetServer

import pytest

import proxy as proxy_module
from torproxy.host_rules import HostRules


def test_proxy_server_only_binds_loopback():
    server = proxy_module.ThreadedHTTPServer(("127.0.0.1", 0), proxy_module.ProxyHandler, 9050)
    try:
        assert server.server_address[0] == "127.0.0.1"
    finally:
        server.server_close()


@pytest.mark.parametrize("address", ["0.0.0.0", "192.0.2.1", "::"])
def test_proxy_server_rejects_non_loopback_listeners(address):
    with pytest.raises(ValueError, match="only bind to loopback"):
        proxy_module.ThreadedHTTPServer((address, 0), proxy_module.ProxyHandler, 9050)


@pytest.mark.parametrize(("authority", "expected"), [
    ("example.org:443", ("example.org", 443)),
    ("[2001:db8::1]:8443", ("2001:db8::1", 8443)),
    ("localhost", ("localhost", 80)),
])
def test_authority_parser_handles_ipv6_and_default_ports(authority, expected):
    assert proxy_module._parse_authority(authority, 80 if authority == "localhost" else None) == expected


@pytest.mark.parametrize("authority", ["", "https://example.org", "user@example.org:443",
                                       "example.org:0", "example.org:99999", "[not-ipv6]:443"])
def test_authority_parser_rejects_malformed_authorities(authority):
    with pytest.raises(ValueError):
        proxy_module._parse_authority(authority, 443)


def test_block_and_bypass_rules_are_consistent_and_block_takes_precedence(monkeypatch):
    monkeypatch.setattr(proxy_module, "_blocked_rules", HostRules.from_values(["blocked.example"]))
    monkeypatch.setattr(proxy_module, "_excluded_rules", HostRules.from_values(["*.example"]))
    assert proxy_module._route_for_host("blocked.example") == "blocked"
    assert proxy_module._route_for_host("sub.blocked.example") == "blocked"
    assert proxy_module._route_for_host("safe.example") == "direct"
    assert proxy_module._route_for_host("other.net") == "tor"


def _receive_exact(sock, length):
    chunks = bytearray()
    while len(chunks) < length:
        part = sock.recv(length - len(chunks))
        if not part:
            raise OSError("peer disconnected during SOCKS handshake")
        chunks.extend(part)
    return bytes(chunks)


class FakeSocksServer:
    """Minimal local SOCKS5 relay that records whether remote DNS was requested."""
    def __init__(self):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.stopping = threading.Event()
        self.address_types = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stopping.is_set():
            try:
                client, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client):
        destination = None
        try:
            client.settimeout(3)
            version, method_count = _receive_exact(client, 2)
            _receive_exact(client, method_count)
            if version != 5:
                return
            client.sendall(b"\x05\x00")
            version, command, _reserved, address_type = _receive_exact(client, 4)
            self.address_types.append(address_type)
            if version != 5 or command != 1:
                client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            if address_type == 1:
                host = socket.inet_ntop(socket.AF_INET, _receive_exact(client, 4))
            elif address_type == 4:
                host = socket.inet_ntop(socket.AF_INET6, _receive_exact(client, 16))
            elif address_type == 3:
                host_length = _receive_exact(client, 1)[0]
                host = _receive_exact(client, host_length).decode("idna")
            else:
                return
            port = int.from_bytes(_receive_exact(client, 2), "big")
            destination = socket.create_connection((host, port), timeout=3)
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            client.settimeout(None)
            destination.settimeout(None)
            active = [client, destination]
            peers = {client: destination, destination: client}
            while active:
                readable, _, _ = select.select(active, [], [], 3)
                if not readable:
                    break
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        active.remove(source)
                        try:
                            peers[source].shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    peers[source].sendall(data)
        except (OSError, ValueError):
            pass
        finally:
            if destination:
                destination.close()
            client.close()

    def close(self):
        self.stopping.set()
        self.listener.close()
        self.thread.join(timeout=2)


class _ResponseHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        body = b"proxied-local-test"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def test_http_request_is_forwarded_through_socks_with_remote_dns(monkeypatch, caplog):
    monkeypatch.setattr(proxy_module, "_blocked_rules", HostRules())
    monkeypatch.setattr(proxy_module, "_excluded_rules", HostRules())
    target = TargetServer(("127.0.0.1", 0), _ResponseHandler)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()
    socks_server = FakeSocksServer()
    proxy_server = proxy_module.ThreadedHTTPServer(
        ("127.0.0.1", 0), proxy_module.ProxyHandler, socks_server.port
    )
    proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    proxy_thread.start()
    try:
        client = socket.create_connection(("127.0.0.1", proxy_server.server_address[1]), timeout=5)
        client.settimeout(5)
        target_port = target.server_address[1]
        client.sendall(
            f"GET http://localhost:{target_port}/check?private=query HTTP/1.1\r\n"
            f"Host: localhost:{target_port}\r\nConnection: close\r\n\r\n".encode("ascii")
        )
        result = bytearray()
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            result.extend(chunk)
        client.close()
        assert b"200 OK" in result
        assert b"proxied-local-test" in result
        assert 3 in socks_server.address_types
        assert "private=query" not in caplog.text
    finally:
        proxy_server.shutdown()
        proxy_server.server_close()
        proxy_thread.join(timeout=2)
        socks_server.close()
        target.shutdown()
        target.server_close()
        target_thread.join(timeout=2)
