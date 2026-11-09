from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path

import pytest

from torproxy import system_tunnel
from torproxy.system_tunnel import SystemTunnelError, SystemTunnelManager


class FakeDirectories:
    def __init__(self, root: Path):
        self.data = root / "data"
        self.state = root / "state"
        self.cache = root / "cache"
        self.logs = root / "logs"


def _manager(tmp_path: Path) -> SystemTunnelManager:
    return SystemTunnelManager(FakeDirectories(tmp_path))


def test_system_tunnel_config_uses_tcp_tor_socks_and_hijacks_dns(tmp_path, monkeypatch):
    monkeypatch.setattr(system_tunnel.platform, "system", lambda: "Linux")
    manager = _manager(tmp_path)
    manager.engine_dir.mkdir(parents=True)
    manager.engine_path.write_bytes(b"pinned test engine")
    tor = tmp_path / ("tor.exe" if os.name == "nt" else "tor")
    tor.write_bytes(b"test tor executable")

    config = manager.build_config(9150, tor_executables=[tor])
    assert config["log"] == {"level": "info", "timestamp": True}
    inbound = config["inbounds"][0]
    outbound = next(item for item in config["outbounds"] if item["tag"] == "tor-socks")
    rules = config["route"]["rules"]

    assert inbound["type"] == "tun"
    assert inbound["auto_route"] is True
    assert inbound["strict_route"] is True
    assert inbound["dns_mode"] == "hijack"
    assert inbound["auto_redirect"] is True
    assert outbound["server"] == "127.0.0.1"
    assert outbound["server_port"] == 9150
    assert outbound["network"] == "tcp"
    assert outbound["inet4_bind_address"] == "127.0.0.1"
    assert config["dns"]["servers"][0]["detour"] == "tor-socks"
    assert rules[0]["outbound"] == "direct"
    expected_names = {manager.engine_path.name.casefold(), tor.name.casefold()}
    assert expected_names.issubset(set(rules[0]["process_name"]))
    assert str(manager.engine_path.resolve()) in rules[1]["process_path"]
    assert str(tor.resolve()) in rules[1]["process_path"]
    assert rules[2] == {"action": "hijack-dns"}
    assert rules[3] == {
        "ip_cidr": ["172.19.0.0/30", "fdfe:dcba:9876::/126"],
        "action": "reject",
        "method": "drop",
    }
    assert rules[4] == {"network": "udp", "action": "reject", "method": "default"}
    assert rules[5] == {"network": "tcp", "action": "route", "outbound": "tor-socks"}
    assert config["route"]["final"] == "block"



def test_tor_socks_dialer_binds_to_loopback_even_with_default_interface_detection(tmp_path):
    manager = _manager(tmp_path)
    tor = tmp_path / ("tor.exe" if os.name == "nt" else "tor")
    tor.write_bytes(b"tor")
    config = manager.build_config(9150, tor_executables=[tor])

    assert config["route"]["auto_detect_interface"] is True
    outbound = next(item for item in config["outbounds"] if item["tag"] == "tor-socks")
    assert outbound["server"] == "127.0.0.1"
    assert outbound["inet4_bind_address"] == "127.0.0.1"


def test_windows_and_linux_helpers_share_one_complete_argument_builder(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    monkeypatch.setattr(SystemTunnelManager, "engine_sha256", property(lambda _self: "a" * 64))
    args = manager._helper_action_arguments("start", tmp_path / "helper.json")
    mapping = {}
    index = 1  # args[0] is the helper action ("start" or "stop").
    while index < len(args):
        flag = args[index]
        if flag == "--unverified-release":
            mapping[flag] = True
            index += 1
        else:
            mapping[flag] = args[index + 1]
            index += 2
    assert mapping["--version"] == manager.version
    assert mapping["--source-url"] == manager.platform_asset["url"]
    assert mapping["--archive-type"] == manager.platform_asset["archive"]
    assert "--release-sha256" in mapping
    assert "--archive-sha256" in mapping
    assert "--result" in mapping


def test_socks5_connect_probe_sends_protocol_bytes_and_completes_connect(monkeypatch):
    class FakeSocket:
        def __init__(self):
            self.responses = bytearray(bytes((5, 0, 5, 0, 0, 1, 1, 1, 1, 1, 1, 187)))
            self.sent = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _timeout):
            pass

        def sendall(self, payload):
            self.sent.append(payload)

        def recv(self, size):
            result = bytes(self.responses[:size])
            del self.responses[:size]
            return result

    fake = FakeSocket()
    monkeypatch.setattr(
        system_tunnel.socket,
        "create_connection",
        lambda _address, timeout=None: fake,
    )

    SystemTunnelManager._socks5_connect_probe(9150, "1.1.1.1", 443)

    assert fake.sent == [
        bytes((5, 1, 0)),
        bytes((5, 1, 0, 1, 1, 1, 1, 1, 1, 187)),
    ]


def test_windows_start_uses_one_gvisor_attempt_without_network_probes_or_restarts(tmp_path, monkeypatch):
    monkeypatch.setattr(system_tunnel.platform, "system", lambda: "Windows")
    manager = _manager(tmp_path)
    monkeypatch.setattr(manager, "is_installed", lambda: True)
    monkeypatch.setattr(system_tunnel, "_interface_exists", lambda _name: False)

    config_writes = []
    monkeypatch.setattr(manager, "_write_and_check_config", lambda *args, **kwargs: config_writes.append((args, kwargs)))
    helper_actions = []
    monkeypatch.setattr(
        manager, "_invoke_helper",
        lambda action: helper_actions.append(action) or {"ok": True, "active": True},
    )
    monkeypatch.setattr(manager, "_socks5_connect_probe",
                        lambda *_args, **_kwargs: pytest.fail("Start must not run remote network probes"))
    monkeypatch.setattr(manager, "_verify_tunnel_tcp_tls",
                        lambda *_args, **_kwargs: pytest.fail("Start must not probe TUN traffic"))
    monkeypatch.setattr(manager, "stop",
                        lambda: pytest.fail("Start must not stop/restart the tunnel automatically"))

    result = manager.start(9150, tor_executables=[tmp_path / "tor.exe"])

    assert len(config_writes) == 1
    assert config_writes[0][0] == (9150, [tmp_path / "tor.exe"])
    assert config_writes[0][1] == {}
    assert helper_actions == ["start"]
    assert "Test traffic" in result


def test_system_tunnel_115_uses_native_stack_without_legacy_stack_option(tmp_path, monkeypatch):
    monkeypatch.setattr(system_tunnel.platform, "system", lambda: "Windows")
    manager = _manager(tmp_path)
    manager.version = "1.15.0"
    tor = tmp_path / "tor.exe"
    tor.write_bytes(b"test tor")
    manager.engine_dir.mkdir(parents=True, exist_ok=True)
    manager.engine_path.write_bytes(b"test sing-box")

    config = manager.build_config(9150, tor_executables=[tor])

    assert "stack" not in config["inbounds"][0]


def test_socks5_connect_probe_can_verify_tls_before_tun_start(monkeypatch):
    class FakeSocket:
        def __init__(self):
            self.responses = bytearray(bytes((5, 0, 5, 0, 0, 1, 1, 1, 1, 1, 1, 187)))
            self.sent = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _timeout):
            pass

        def sendall(self, payload):
            self.sent.append(payload)

        def recv(self, size):
            result = bytes(self.responses[:size])
            del self.responses[:size]
            return result

    class FakeTLS:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def getpeercert(self):
            return {"subject": ((("commonName", "cloudflare-dns.com"),),)}

    class FakeSSLContext:
        def wrap_socket(self, _sock, *, server_hostname):
            assert server_hostname == "cloudflare-dns.com"
            return FakeTLS()

    fake = FakeSocket()
    monkeypatch.setattr(system_tunnel.socket, "create_connection", lambda *_args, **_kwargs: fake)
    monkeypatch.setattr(system_tunnel.ssl, "create_default_context", lambda: FakeSSLContext())

    SystemTunnelManager._socks5_connect_probe(
        9150, "1.1.1.1", 443, server_name="cloudflare-dns.com"
    )


def test_system_tunnel_start_does_not_gate_startup_on_network_connectivity(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    monkeypatch.setattr(manager, "is_installed", lambda: True)
    monkeypatch.setattr(system_tunnel, "_interface_exists", lambda _name: False)
    config_writes = []
    monkeypatch.setattr(manager, "_write_and_check_config", lambda *args, **kwargs: config_writes.append((args, kwargs)))
    helper_actions = []
    monkeypatch.setattr(
        manager, "_invoke_helper",
        lambda action: helper_actions.append(action) or {"ok": True, "active": True},
    )
    monkeypatch.setattr(manager, "_socks5_connect_probe",
                        lambda *_args, **_kwargs: pytest.fail("Network testing belongs to test_connection"))
    monkeypatch.setattr(manager, "_verify_tunnel_tcp_tls",
                        lambda *_args, **_kwargs: pytest.fail("Network testing belongs to test_connection"))
    monkeypatch.setattr(manager, "stop",
                        lambda: pytest.fail("A failed external probe must not roll back a created TUN"))

    result = manager.start(9150, tor_executables=[tmp_path / "tor"])

    assert config_writes
    assert helper_actions == ["start"]
    assert "TUN interface are active" in result


def test_test_connection_runs_remote_checks_without_starting_or_stopping_helper(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    monkeypatch.setattr(manager, "status", lambda: {"active": True, "verified": True, "detail": "active"})
    socks_calls = []
    tun_calls = []
    monkeypatch.setattr(manager, "_socks5_connect_probe", lambda *args, **kwargs: socks_calls.append((args, kwargs)))
    monkeypatch.setattr(manager, "_verify_tunnel_tcp_tls", lambda *args, **kwargs: tun_calls.append((args, kwargs)))
    monkeypatch.setattr(manager, "_invoke_helper",
                        lambda *_args, **_kwargs: pytest.fail("Traffic tests must not request elevation"))

    result = manager.test_connection(9150, timeout=3.0)

    assert "Tunnel traffic verified" in result
    assert len(socks_calls) == 1
    assert socks_calls[0][0] == (9150, "1.1.1.1", 443)
    assert socks_calls[0][1]["server_name"] == "cloudflare-dns.com"
    assert socks_calls[0][1]["timeout"] == 3.0
    assert tun_calls == [((("1.1.1.1", "cloudflare-dns.com"),), {"timeout": 3.0})]


def test_test_connection_refuses_to_probe_when_tunnel_is_not_active(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    monkeypatch.setattr(manager, "status", lambda: {"active": False, "verified": True, "detail": "stopped"})
    monkeypatch.setattr(manager, "_socks5_connect_probe",
                        lambda *_args, **_kwargs: pytest.fail("A stopped tunnel must not be probed"))

    with pytest.raises(SystemTunnelError, match="stopped"):
        manager.test_connection(9150)


def test_windows_tun_config_is_ipv4_only_and_uses_gvisor_stack(tmp_path, monkeypatch):
    monkeypatch.setattr(system_tunnel.platform, "system", lambda: "Windows")
    manager = _manager(tmp_path)
    manager.engine_dir.mkdir(parents=True, exist_ok=True)
    manager.engine_path.write_bytes(b"engine")
    tor = tmp_path / "tor.exe"
    tor.write_bytes(b"tor")

    config = manager.build_config(9150, tor_executables=[tor])
    inbound = config["inbounds"][0]

    assert inbound["stack"] == "gvisor"
    assert "auto_redirect" not in inbound
    assert inbound["address"] == ["172.19.0.1/30"]
    assert inbound["dns_address"] == ["172.19.0.2"]
    assert config["route"]["rules"][2] == {"action": "hijack-dns"}
    assert config["route"]["rules"][3] == {
        "ip_cidr": ["172.19.0.0/30"],
        "action": "reject",
        "method": "drop",
    }
    assert config["route"]["rules"][5] == {
        "network": "tcp", "action": "route", "outbound": "tor-socks"
    }
    assert config["route"]["final"] == "block"
    system_config = manager.build_config(9150, tor_executables=[tor], tun_stack="system")
    assert system_config["inbounds"][0]["stack"] == "system"
    assert system_config["inbounds"][0]["address"] == ["172.19.0.1/30"]


def test_tunnel_engine_download_refuses_an_unspecified_network_route(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    monkeypatch.setattr(manager, "is_running", lambda: False)

    def reject_route(*_args, **_kwargs):
        raise system_tunnel.NetworkRouteError("No explicit route was selected.")

    monkeypatch.setattr(system_tunnel, "create_session", reject_route)
    with pytest.raises(SystemTunnelError, match="safe sing-box download route"):
        manager.install_engine("1.14.4")


def test_latest_tunnel_release_check_refuses_an_unspecified_network_route(monkeypatch):
    def reject_route(*_args, **_kwargs):
        raise system_tunnel.NetworkRouteError("No explicit route was selected.")

    monkeypatch.setattr(system_tunnel, "create_session", reject_route)
    with pytest.raises(SystemTunnelError, match="safe release-check route"):
        SystemTunnelManager.check_latest_release()


def test_supported_sing_box_versions_have_pinned_platform_assets(tmp_path):
    manager = _manager(tmp_path)

    assert manager.supported_versions() == ("1.14.4", "1.14.3", "1.14.2")
    for version in manager.supported_versions():
        manager.select_version(version)
        asset = manager.platform_asset
        assert f"/v{version}/" in asset["url"]
        assert len(asset["sha256"]) == 64
        assert asset["archive"] in {"zip", "tar.gz"}
        assert asset["executable"] in {"sing-box.exe", "sing-box"}


def test_upstream_release_can_be_selected_only_with_explicit_approval(tmp_path, monkeypatch):
    monkeypatch.setattr(system_tunnel.platform, "system", lambda: "Windows")
    monkeypatch.setattr(system_tunnel.platform, "machine", lambda: "AMD64")
    manager = _manager(tmp_path)
    asset = {
        "url": "https://github.com/SagerNet/sing-box/releases/download/v1.15.0/sing-box-1.15.0-windows-amd64.zip",
        "filename": "sing-box-1.15.0-windows-amd64.zip",
        "archive": "zip",
        "size": 32 * 1024 * 1024,
        "sha256": "a" * 64,
    }

    with pytest.raises(SystemTunnelError, match="explicitly accept"):
        manager.select_version("1.15.0", release_asset=asset)

    manager.select_version("1.15.0", release_asset=asset, allow_unpinned=True)

    assert manager.version == "1.15.0"
    assert manager.platform_asset["url"] == asset["url"]
    assert manager.platform_asset["sha256"] == "a" * 64


def test_upstream_release_asset_rejects_non_github_download_hosts(tmp_path, monkeypatch):
    monkeypatch.setattr(system_tunnel.platform, "system", lambda: "Windows")
    monkeypatch.setattr(system_tunnel.platform, "machine", lambda: "AMD64")
    manager = _manager(tmp_path)
    asset = {
        "url": "https://example.invalid/sing-box-1.15.0-windows-amd64.zip",
        "filename": "sing-box-1.15.0-windows-amd64.zip",
        "archive": "zip",
        "size": 1024,
        "sha256": "a" * 64,
    }

    with pytest.raises(SystemTunnelError, match="exact official SagerNet GitHub"):
        manager.select_version("1.15.0", release_asset=asset, allow_unpinned=True)


def test_version_selection_uses_a_version_specific_archive_and_rejects_unpinned_versions(tmp_path):
    manager = _manager(tmp_path)
    latest_archive = manager.archive_path

    manager.select_version("1.14.3")

    assert manager.archive_path != latest_archive
    assert "1.14.3" in manager.archive_path.name
    with pytest.raises(SystemTunnelError, match="not been pinned"):
        manager.select_version("1.14.1")


def test_active_tunnel_cannot_change_engine_version(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    manager.select_version("1.14.4")
    monkeypatch.setattr(manager, "is_running", lambda: True)

    with pytest.raises(SystemTunnelError, match="Stop the active"):
        manager.select_version("1.14.3")


def test_system_tunnel_config_requires_a_valid_tor_executable(tmp_path):
    manager = _manager(tmp_path)
    with pytest.raises(SystemTunnelError, match="Tor executable"):
        manager.build_config(9150, tor_executables=[])


@pytest.mark.parametrize("member", ["../sing-box", "/sing-box", "folder/../../sing-box", r"..\\sing-box.exe"])
def test_system_tunnel_rejects_unsafe_archive_paths(member):
    with pytest.raises(SystemTunnelError, match="unsafe"):
        SystemTunnelManager._safe_archive_member(member)


def test_windows_archive_extracts_only_allowlisted_regular_runtime_files(tmp_path):
    archive = tmp_path / "sing-box.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("sing-box-1.14.4-windows-amd64/sing-box.exe", b"engine")
        bundle.writestr("sing-box-1.14.4-windows-amd64/libcronet.dll", b"runtime")
        bundle.writestr("sing-box-1.14.4-windows-amd64/wintun.dll", b"wintun runtime")
        bundle.writestr("sing-box-1.14.4-windows-amd64/LICENSE", b"GPL text")
        bundle.writestr("sing-box-1.14.4-windows-amd64/unexpected.txt", b"ignore")
    destination = tmp_path / "engine"
    destination.mkdir()

    hashes = SystemTunnelManager._extract_zip_runtime(archive, destination, "sing-box.exe")

    assert set(hashes) == {"sing-box.exe", "libcronet.dll", "wintun.dll", "LICENSE"}
    assert (destination / "sing-box.exe").read_bytes() == b"engine"
    assert (destination / "wintun.dll").read_bytes() == b"wintun runtime"
    assert not (destination / "unexpected.txt").exists()


def test_archive_engine_checksum_is_derived_from_verified_member(tmp_path):
    archive = tmp_path / "sing-box.zip"
    payload = b"pinned executable payload"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("sing-box-1.14.4-windows-amd64/sing-box.exe", payload)

    digest = SystemTunnelManager._archive_executable_sha256(archive, "zip", "sing-box.exe")

    assert digest == hashlib.sha256(payload).hexdigest()


def test_system_tunnel_install_state_checks_both_archive_and_executable_hashes(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    manager.engine_dir.mkdir(parents=True)
    manager.engine_path.write_bytes(b"engine")
    manager.archive_path.parent.mkdir(parents=True, exist_ok=True)
    manager.archive_path.write_bytes(b"archive")
    engine_hash = hashlib.sha256(b"engine").hexdigest()
    archive_hash = manager.platform_asset["sha256"]
    manager.install_manifest.write_text(
        json.dumps({
            "version": system_tunnel.SING_BOX_VERSION,
            "archive_sha256": archive_hash,
            "files": {manager.engine_path.name: engine_hash},
        }),
        encoding="utf-8",
    )
    real_hash = system_tunnel._sha256

    def fake_hash(path):
        if Path(path) == manager.archive_path:
            return archive_hash
        return real_hash(Path(path))

    monkeypatch.setattr(system_tunnel, "_sha256", fake_hash)
    assert manager.is_installed() is True
    assert manager.engine_sha256 == engine_hash

    manager.engine_path.write_bytes(b"modified engine")
    assert manager.is_installed() is False


def test_tunnel_stop_clears_only_a_dead_stale_pid_record(tmp_path, monkeypatch):
    state_path = tmp_path / "tunnel-state.json"
    state_path.write_text(json.dumps({"pid": 2_000_000_000}), encoding="utf-8")
    monkeypatch.setattr(system_tunnel.psutil, "pid_exists", lambda _pid: False)

    result = system_tunnel._helper_stop(state_path, "torproxy-tun")

    assert result["active"] is False
    assert not state_path.exists()


def test_tunnel_stop_refuses_to_take_over_a_live_unmatched_pid(tmp_path, monkeypatch):
    state_path = tmp_path / "tunnel-state.json"
    state_path.write_text(json.dumps({"pid": 321}), encoding="utf-8")
    monkeypatch.setattr(system_tunnel, "_process_matches", lambda _state: None)
    monkeypatch.setattr(system_tunnel.psutil, "pid_exists", lambda _pid: True)

    with pytest.raises(SystemTunnelError, match="refus"):
        system_tunnel._helper_stop(state_path, "torproxy-tun")
    assert state_path.exists()


def test_pinned_archive_hashes_all_runtime_files_not_only_the_executable(tmp_path):
    archive = tmp_path / "sing-box.zip"
    payloads = {
        "sing-box-1.14.4-windows-amd64/sing-box.exe": b"engine",
        "sing-box-1.14.4-windows-amd64/libcronet.dll": b"runtime",
        "sing-box-1.14.4-windows-amd64/wintun.dll": b"wintun",
        "sing-box-1.14.4-windows-amd64/LICENSE": b"license",
    }
    with zipfile.ZipFile(archive, "w") as bundle:
        for name, data in payloads.items():
            bundle.writestr(name, data)
    hashes = SystemTunnelManager._archive_runtime_file_hashes(archive, "zip", "sing-box.exe")
    assert set(hashes) == {"sing-box.exe", "libcronet.dll", "wintun.dll", "LICENSE"}
    assert hashes["wintun.dll"] == hashlib.sha256(b"wintun").hexdigest()


def test_install_state_rejects_extra_runtime_files_next_to_elevated_engine(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    manager.engine_dir.mkdir(parents=True)
    manager.engine_path.write_bytes(b"engine")
    manager.archive_path.write_bytes(b"archive")
    engine_hash = hashlib.sha256(b"engine").hexdigest()
    archive_hash = manager.platform_asset["sha256"]
    manager.install_manifest.write_text(
        json.dumps({
            "version": system_tunnel.SING_BOX_VERSION,
            "archive_sha256": archive_hash,
            "files": {manager.engine_path.name: engine_hash},
        }),
        encoding="utf-8",
    )
    real_hash = system_tunnel._sha256
    def fake_hash(path):
        if Path(path) == manager.archive_path:
            return archive_hash
        return real_hash(Path(path))
    monkeypatch.setattr(system_tunnel, "_sha256", fake_hash)
    assert manager.is_installed() is True
    (manager.engine_dir / "unexpected.dll").write_bytes(b"untrusted side-load")
    assert manager.is_installed() is False


def test_status_flags_an_untracked_tun_interface_as_unverified(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    monkeypatch.setattr(system_tunnel, "_interface_exists", lambda _name: True)

    status = manager.status()

    assert status["active"] is False
    assert status["verified"] is False
    assert "untracked" in status["detail"]


def test_stop_refuses_to_claim_success_when_an_untracked_tun_interface_remains(tmp_path, monkeypatch):
    state_path = tmp_path / "tunnel-state.json"
    monkeypatch.setattr(system_tunnel, "_interface_exists", lambda _name: True)

    with pytest.raises(SystemTunnelError, match="verified sing-box process record"):
        system_tunnel._helper_stop(state_path, "torproxy-tun")


def test_stop_refuses_to_clear_a_stale_process_record_when_tun_adapter_remains(tmp_path, monkeypatch):
    state_path = tmp_path / "tunnel-state.json"
    state_path.write_text(json.dumps({"pid": 2_000_000_000}), encoding="utf-8")
    monkeypatch.setattr(system_tunnel.psutil, "pid_exists", lambda _pid: False)
    monkeypatch.setattr(system_tunnel, "_interface_exists", lambda _name: True)

    with pytest.raises(SystemTunnelError, match="adapter remains"):
        system_tunnel._helper_stop(state_path, "torproxy-tun")
    assert state_path.exists()


def test_tunnel_process_uses_graceful_termination_on_linux(monkeypatch):
    class FakeProcess:
        pid = 4321
        terminated = False
        killed = False
        def terminate(self):
            self.terminated = True
        def wait(self, timeout=None):
            assert timeout == 6
            return 0
        def kill(self):
            self.killed = True

    fake = FakeProcess()
    monkeypatch.setattr(system_tunnel.os, "name", "posix")
    monkeypatch.setattr(system_tunnel, "_process_matches", lambda _state: fake)

    system_tunnel._stop_verified_process(fake, {"pid": fake.pid})

    assert fake.terminated is True
    assert fake.killed is False


def test_windows_tunnel_stop_uses_short_graceful_ctrl_break_window(monkeypatch):
    class FakeProcess:
        pid = 6543
        waited = []
        def wait(self, timeout=None):
            self.waited.append(timeout)
            return 0

    fake = FakeProcess()
    monkeypatch.setattr(system_tunnel.os, "name", "nt")
    monkeypatch.setattr(system_tunnel, "_send_windows_ctrl_break", lambda pid: pid == fake.pid)

    system_tunnel._stop_verified_process(fake, {"pid": fake.pid})

    assert fake.waited == [3]


def test_windows_tunnel_stop_uses_verified_terminate_when_ctrl_break_fails(monkeypatch):
    class FakeProcess:
        pid = 9876
        terminated = False
        waited = []
        def terminate(self):
            self.terminated = True
        def wait(self, timeout=None):
            self.waited.append(timeout)
            return 0

    fake = FakeProcess()
    monkeypatch.setattr(system_tunnel.os, "name", "nt")
    monkeypatch.setattr(system_tunnel, "_send_windows_ctrl_break", lambda _pid: False)
    monkeypatch.setattr(system_tunnel, "_process_matches", lambda _state: fake)

    system_tunnel._stop_verified_process(fake, {"pid": fake.pid})

    assert fake.terminated is True
    assert fake.waited == [3]
