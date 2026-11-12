from __future__ import annotations

import select
import socket
import socketserver
import threading
import time
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


def test_http_proxy_caps_concurrent_client_handlers(monkeypatch):
    monkeypatch.setattr(proxy_module, "REQUEST_READ_TIMEOUT_SECONDS", 5.0)
    server = proxy_module.ThreadedHTTPServer(
        ("127.0.0.1", 0),
        proxy_module.ProxyHandler,
        9050,
        max_clients=1,
    )
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    first = second = None
    try:
        first = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=2)
        deadline = time.monotonic() + 2
        while server.client_metrics["active_clients"] != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.client_metrics["active_clients"] == 1

        second = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=2)
        second.settimeout(2)
        assert second.recv(1) == b""
        assert server.client_metrics["rejected_clients"] == 1
    finally:
        if first is not None:
            first.close()
        if second is not None:
            second.close()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=3)
        deadline = time.monotonic() + 2
        while server.client_metrics["active_clients"] and time.monotonic() < deadline:
            time.sleep(0.01)
    assert server.client_metrics["active_clients"] == 0


def test_proxy_server_allows_wildcard_bind_only_with_explicit_lan_opt_in():
    with pytest.raises(ValueError, match="only to 0.0.0.0"):
        proxy_module.ThreadedHTTPServer(
            ("0.0.0.0", 0), proxy_module.ProxyHandler, 9050
        )

    server = proxy_module.ThreadedHTTPServer(
        ("0.0.0.0", 0),
        proxy_module.ProxyHandler,
        9050,
        allow_remote=True,
    )
    try:
        assert server.server_address[0] == "0.0.0.0"
    finally:
        server.server_close()


@pytest.mark.parametrize("address", ["192.0.2.1", "::"])
def test_proxy_server_rejects_non_loopback_listeners(address):
    with pytest.raises(ValueError, match="only to 0.0.0.0"):
        proxy_module.ThreadedHTTPServer((address, 0), proxy_module.ProxyHandler, 9050)


@pytest.mark.parametrize(
    "error_type",
    [ConnectionAbortedError, ConnectionResetError, BrokenPipeError],
)
def test_handler_contains_expected_client_disconnects(monkeypatch, caplog, error_type):
    handler = object.__new__(proxy_module.ProxyHandler)
    handler.client_address = ("127.0.0.1", 12345)
    handler.close_connection = False

    def disconnect(_handler):
        raise error_type("simulated client disconnect")

    monkeypatch.setattr(proxy_module.BaseHTTPRequestHandler, "handle_one_request", disconnect)
    with caplog.at_level("DEBUG", logger=proxy_module.__name__):
        handler.handle_one_request()

    assert handler.close_connection is True
    assert "client disconnected" in caplog.text
    assert error_type.__name__ in caplog.text


def test_incomplete_request_line_times_out_and_closes_client(monkeypatch):
    monkeypatch.setattr(proxy_module, "REQUEST_READ_TIMEOUT_SECONDS", 0.05)
    server = proxy_module.ThreadedHTTPServer(
        ("127.0.0.1", 0), proxy_module.ProxyHandler, 9050
    )
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    client = None
    try:
        client = socket.create_connection(
            ("127.0.0.1", server.server_address[1]), timeout=2
        )
        client.settimeout(2)
        assert client.recv(1) == b""
    finally:
        if client is not None:
            client.close()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)


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


def test_onion_destinations_cannot_be_sent_direct_by_exclude_rules(monkeypatch):
    onion_host = "a" * 56 + ".onion"
    monkeypatch.setattr(proxy_module, "_blocked_rules", HostRules())
    monkeypatch.setattr(
        proxy_module, "_excluded_rules", HostRules.from_values(["*.onion"])
    )

    assert proxy_module._route_for_host(onion_host) == "tor"

    # An explicit Block rule remains authoritative even for Onion Services.
    monkeypatch.setattr(
        proxy_module, "_blocked_rules", HostRules.from_values([onion_host])
    )
    assert proxy_module._route_for_host(onion_host) == "blocked"


def test_block_and_bypass_rules_are_consistent_and_block_takes_precedence(monkeypatch):
    monkeypatch.setattr(proxy_module, "_blocked_rules", HostRules.from_values(["blocked.example"]))
    monkeypatch.setattr(proxy_module, "_excluded_rules", HostRules.from_values(["*.example"]))
    assert proxy_module._route_for_host("blocked.example") == "blocked"
    assert proxy_module._route_for_host("sub.blocked.example") == "blocked"
    assert proxy_module._route_for_host("safe.example") == "direct"
    assert proxy_module._route_for_host("other.net") == "tor"



@pytest.mark.parametrize(
    ("rules_attribute", "remove_rule", "host"),
    [
        ("_blocked_rules", proxy_module.remove_blocked, "blocked.example"),
        ("_excluded_rules", proxy_module.remove_exclude, "excluded.example"),
    ],
)
def test_host_rule_removal_keeps_live_policy_when_disk_write_fails(
    tmp_path, monkeypatch, rules_attribute, remove_rule, host
):
    original = HostRules.from_values([host])
    monkeypatch.setattr(proxy_module, rules_attribute, original)
    monkeypatch.setattr(
        proxy_module, "_rules_path", lambda filename: tmp_path / filename
    )

    def fail_write(*_args, **_kwargs):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(proxy_module, "_atomic_json", fail_write)

    with pytest.raises(OSError, match="simulated disk failure"):
        remove_rule(host)

    assert getattr(proxy_module, rules_attribute).matches(host)

def test_glob_patterns_apply_to_block_and_exclude_routes_with_block_precedence(monkeypatch):
    monkeypatch.setattr(
        proxy_module,
        "_blocked_rules",
        HostRules.from_values(["*-api.something.com", "*.ir"]),
    )
    monkeypatch.setattr(
        proxy_module,
        "_excluded_rules",
        HostRules.from_values(["*.something.com", "*.x.com", "service-*.example.com"]),
    )

    assert proxy_module._route_for_host("v2-api.something.com") == "blocked"
    assert proxy_module._route_for_host("api.example.ir") == "blocked"
    assert proxy_module._route_for_host("deep.api.example.ir") == "blocked"
    assert proxy_module._route_for_host("api.x.com") == "direct"
    assert proxy_module._route_for_host("service-v2.example.com") == "direct"
    assert proxy_module._route_for_host("x.com") == "tor"
    assert proxy_module._route_for_host("v2-api.other.net") == "tor"


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


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)


def test_tor_http_proxy_allows_the_full_gateway_connect_budget(monkeypatch):
    class FakeSocksSocket:
        def __init__(self):
            self.proxy = None
            self.timeout = None

        def set_proxy(self, *args, **kwargs):
            self.proxy = (args, kwargs)

        def settimeout(self, timeout):
            self.timeout = timeout

    remote = FakeSocksSocket()
    monkeypatch.setattr(proxy_module.socks, "socksocket", lambda: remote)
    monkeypatch.setattr(proxy_module, "_connect_with_shutdown", lambda *_args: None)

    result = proxy_module._connect_upstream("149.154.167.50", 443, "tor", 19050)

    assert result is remote
    assert remote.timeout == proxy_module.TOR_SOCKS_CONNECT_TIMEOUT_SECONDS
    assert remote.timeout > 120.0


def test_http_connect_tunnels_raw_tcp_and_preserves_early_payload(monkeypatch):
    monkeypatch.setattr(proxy_module, "_blocked_rules", HostRules())
    monkeypatch.setattr(proxy_module, "_excluded_rules", HostRules())
    target = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _EchoHandler)
    target.daemon_threads = True
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()
    socks_server = FakeSocksServer()
    proxy_server = proxy_module.ThreadedHTTPServer(
        ("127.0.0.1", 0), proxy_module.ProxyHandler, socks_server.port
    )
    proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    proxy_thread.start()
    client = None
    try:
        client = socket.create_connection(("127.0.0.1", proxy_server.server_address[1]), timeout=5)
        client.settimeout(5)
        target_port = target.server_address[1]
        payload = b"\x16\x03\x01early-tunnel-data\x00\xff"
        request = (
            f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{target_port}\r\n"
            "Proxy-Connection: Keep-Alive\r\n\r\n"
        ).encode("ascii")
        # Send tunnel bytes with CONNECT headers to catch buffered reader read-ahead.
        client.sendall(request + payload)

        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = client.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        header, separator, body = bytes(response).partition(b"\r\n\r\n")
        body = bytearray(body)
        assert separator
        assert b"200 Connection Established" in header
        while len(body) < len(payload):
            chunk = client.recv(len(payload) - len(body))
            if not chunk:
                break
            body.extend(chunk)
        assert bytes(body) == payload
    finally:
        if client is not None:
            client.close()
        proxy_server.shutdown()
        proxy_server.server_close()
        proxy_thread.join(timeout=2)
        socks_server.close()
        target.shutdown()
        target.server_close()
        target_thread.join(timeout=2)


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


def test_http_upstream_failure_logs_tor_hop_and_cause_without_request_path(monkeypatch, caplog):
    monkeypatch.setattr(proxy_module, "_blocked_rules", HostRules())
    monkeypatch.setattr(proxy_module, "_excluded_rules", HostRules())

    def fail_upstream(_host, _port, _route, _tor_port, server=None):
        raise proxy_module.socks.GeneralProxyError("SOCKS5 relay: host unreachable")

    monkeypatch.setattr(proxy_module, "_connect_upstream", fail_upstream)
    proxy_server = proxy_module.ThreadedHTTPServer(
        ("127.0.0.1", 0), proxy_module.ProxyHandler, 9050
    )
    proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    proxy_thread.start()
    client = None
    try:
        client = socket.create_connection(
            ("127.0.0.1", proxy_server.server_address[1]), timeout=5
        )
        client.settimeout(5)
        client.sendall(
            b"GET http://hidden-service.example/private/path?token=secret HTTP/1.1\r\n"
            b"Host: hidden-service.example\r\n"
            b"Connection: close\r\n\r\n"
        )
        response = bytearray()
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            response.extend(chunk)

        assert b"502" in response
        assert b"Upstream connection failed" in response
        assert "destination=hidden-service.example:80" in caplog.text
        assert "route=tor" in caplog.text
        assert "Main Tor SOCKS gateway 127.0.0.1:9050" in caplog.text
        assert "GeneralProxyError" in caplog.text
        assert "host unreachable" in caplog.text
        assert "/private/path" not in caplog.text
        assert "token=secret" not in caplog.text
    finally:
        if client is not None:
            client.close()
        proxy_server.shutdown()
        proxy_server.server_close()
        proxy_thread.join(timeout=2)


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




def test_blocked_http_proxy_request_is_rejected_before_opening_upstream(monkeypatch):
    monkeypatch.setattr(
        proxy_module, "_blocked_rules", HostRules.from_values(["127.0.0.1"])
    )
    monkeypatch.setattr(proxy_module, "_excluded_rules", HostRules())
    proxy_server = proxy_module.ThreadedHTTPServer(
        ("127.0.0.1", 0), proxy_module.ProxyHandler, 9050
    )
    proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    proxy_thread.start()
    client = None
    try:
        client = socket.create_connection(
            ("127.0.0.1", proxy_server.server_address[1]), timeout=5
        )
        client.settimeout(5)
        client.sendall(
            b"GET http://127.0.0.1:18080/blocked HTTP/1.1\r\n"
            b"Host: 127.0.0.1:18080\r\nConnection: close\r\n\r\n"
        )
        response = client.recv(4096)
        assert b"403" in response
        assert b"Destination blocked by host policy" in response
    finally:
        if client is not None:
            client.close()
        proxy_server.shutdown()
        proxy_server.server_close()
        proxy_thread.join(timeout=2)


def test_excluded_http_proxy_request_uses_direct_connection_not_tor(monkeypatch):
    monkeypatch.setattr(proxy_module, "_blocked_rules", HostRules())
    monkeypatch.setattr(
        proxy_module, "_excluded_rules", HostRules.from_values(["127.0.0.1"])
    )
    target = TargetServer(("127.0.0.1", 0), _ResponseHandler)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()
    socks_server = FakeSocksServer()
    proxy_server = proxy_module.ThreadedHTTPServer(
        ("127.0.0.1", 0), proxy_module.ProxyHandler, socks_server.port
    )
    proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    proxy_thread.start()
    client = None
    try:
        client = socket.create_connection(
            ("127.0.0.1", proxy_server.server_address[1]), timeout=5
        )
        client.settimeout(5)
        target_port = target.server_address[1]
        client.sendall(
            (
                f"GET http://127.0.0.1:{target_port}/direct HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target_port}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
        )
        response = bytearray()
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
        assert b"200 OK" in response
        assert b"proxied-local-test" in response
        assert socks_server.address_types == []
    finally:
        if client is not None:
            client.close()
        proxy_server.shutdown()
        proxy_server.server_close()
        proxy_thread.join(timeout=2)
        socks_server.close()
        target.shutdown()
        target.server_close()
        target_thread.join(timeout=2)

def test_legacy_kill_switch_preference_does_not_change_direct_exclusion_routing(monkeypatch):
    monkeypatch.setattr(proxy_module, "_blocked_rules", HostRules())
    monkeypatch.setattr(
        proxy_module, "_excluded_rules", HostRules.from_values(["*.example"])
    )
    monkeypatch.setitem(proxy_module.CONFIG.data, "kill_switch_enabled", True)

    assert proxy_module._route_for_host("safe.example") == "direct"
    assert proxy_module._route_for_host("unlisted.example.net") == "tor"


def test_shutdown_cancels_an_idle_connect_relay_and_reaps_its_handler(monkeypatch):
    remote, remote_peer = socket.socketpair()
    monkeypatch.setattr(
        proxy_module,
        "_connect_upstream",
        lambda _host, _port, _route, _tor_port, server=None: remote,
    )
    server = proxy_module.ThreadedHTTPServer(
        ("127.0.0.1", 0), proxy_module.ProxyHandler, 9050
    )
    listener_thread = threading.Thread(target=server.serve_forever, daemon=True)
    listener_thread.start()
    client = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=2)
    client.settimeout(2)
    try:
        client.sendall(
            b"CONNECT example.com:443 HTTP/1.1\r\n"
            b"Host: example.com:443\r\n"
            b"\r\n"
        )
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = client.recv(1024)
            assert chunk, "HTTP CONNECT closed before returning 200"
            response.extend(chunk)
        assert b"200 Connection Established" in response

        deadline = time.monotonic() + 2
        while server.client_metrics["active_clients"] != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.client_metrics["active_clients"] == 1

        started = time.monotonic()
        server.begin_shutdown()
        server.shutdown()
        server.server_close()
        listener_thread.join(timeout=2)
        deadline = time.monotonic() + 2
        while server.client_metrics["active_clients"] and time.monotonic() < deadline:
            time.sleep(0.01)

        assert not listener_thread.is_alive()
        assert server.shutdown_event.is_set()
        assert server.client_metrics["active_clients"] == 0
        assert time.monotonic() - started < 2
        assert remote.fileno() == -1
    finally:
        client.close()
        remote_peer.close()
        server.begin_shutdown()
        server.shutdown()
        server.server_close()
        listener_thread.join(timeout=2)






def test_shutdown_interrupts_a_blocking_tor_socks_connect_on_windows(monkeypatch):
    class BlockingSocksSocket:
        def __init__(self):
            self.connect_started = threading.Event()
            self.release_connect = threading.Event()
            self.closed = False

        def set_proxy(self, *_args, **_kwargs):
            pass

        def settimeout(self, _timeout):
            pass

        def connect(self, _address):
            # Simulate a Winsock/PySocks connect that does not immediately
            # unwind when another thread closes its socket.
            self.connect_started.set()
            self.release_connect.wait(timeout=10)
            if self.closed:
                raise OSError("socket was closed during connect")

        def shutdown(self, _how):
            self.closed = True

        def close(self):
            self.closed = True

    remote = BlockingSocksSocket()
    monkeypatch.setattr(proxy_module.socks, "socksocket", lambda: remote)
    monkeypatch.setattr(proxy_module, "_route_for_host", lambda _host: "tor")

    server = proxy_module.ThreadedHTTPServer(
        ("127.0.0.1", 0), proxy_module.ProxyHandler, 9050
    )
    listener_thread = threading.Thread(target=server.serve_forever, daemon=True)
    listener_thread.start()
    client = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=2)
    try:
        client.sendall(
            b"CONNECT telegram.example:443 HTTP/1.1\r\n"
            b"Host: telegram.example:443\r\n"
            b"\r\n"
        )
        assert remote.connect_started.wait(timeout=2)

        started = time.monotonic()
        server.begin_shutdown()
        server.shutdown()
        server.server_close()
        listener_thread.join(timeout=2)

        deadline = time.monotonic() + 2
        while server.client_metrics["active_clients"] and time.monotonic() < deadline:
            time.sleep(0.01)

        assert not listener_thread.is_alive()
        assert remote.closed is True
        assert server.client_metrics["active_clients"] == 0
        assert not server._active_upstreams
        assert time.monotonic() - started < 2
    finally:
        remote.release_connect.set()
        client.close()
        server.begin_shutdown()
        server.shutdown()
        server.server_close()
        listener_thread.join(timeout=2)


def test_http_server_rejects_a_client_racing_with_shutdown():
    server = proxy_module.ThreadedHTTPServer(
        ("127.0.0.1", 0), proxy_module.ProxyHandler, 9050
    )
    request, peer = socket.socketpair()
    try:
        server.begin_shutdown()
        server.process_request(request, ("127.0.0.1", 12345))

        assert server.client_metrics["active_clients"] == 0
        assert request.fileno() == -1
    finally:
        request.close()
        peer.close()
        server.server_close()


def test_http_server_rejects_new_upstream_sockets_after_shutdown():
    server = proxy_module.ThreadedHTTPServer(
        ("127.0.0.1", 0), proxy_module.ProxyHandler, 9050
    )
    remote, peer = socket.socketpair()
    try:
        assert server.register_upstream(remote) is True
        server.begin_shutdown()
        assert server.shutdown_event.is_set()
        assert remote.fileno() == -1
        replacement, replacement_peer = socket.socketpair()
        try:
            assert server.register_upstream(replacement) is False
        finally:
            replacement_peer.close()
        assert server.client_metrics["active_clients"] == 0
    finally:
        server.server_close()
        peer.close()




@pytest.mark.parametrize("record_traffic", [False, True])
def test_http_proxy_relay_can_defer_tor_routed_accounting_to_socks_gateway(monkeypatch, record_traffic):
    recorded = []
    monkeypatch.setattr(
        proxy_module,
        "_record_bytes",
        lambda amount, direction=None: recorded.append((amount, direction)),
    )
    client, proxy_side = socket.socketpair()
    proxy_upstream, upstream = socket.socketpair()
    worker = threading.Thread(
        target=proxy_module.ProxyHandler._relay,
        args=(proxy_side, proxy_upstream),
        kwargs={"record_traffic": record_traffic},
        daemon=True,
    )
    worker.start()
    try:
        client.sendall(b"upload")
        assert _receive_exact(upstream, 6) == b"upload"
        upstream.sendall(b"download")
        assert _receive_exact(client, 8) == b"download"
        client.shutdown(socket.SHUT_WR)
        upstream.shutdown(socket.SHUT_WR)
        worker.join(timeout=3)
    finally:
        for peer in (client, proxy_side, proxy_upstream, upstream):
            peer.close()
    assert not worker.is_alive()
    assert recorded == ([(6, "upload"), (8, "download")] if record_traffic else [])
