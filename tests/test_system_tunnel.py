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
    assert config["dns"]["servers"][0]["detour"] == "tor-socks"
    assert rules[0]["outbound"] == "direct"
    expected_names = {manager.engine_path.name.casefold(), tor.name.casefold()}
    assert expected_names.issubset(set(rules[0]["process_name"]))
    assert str(manager.engine_path.resolve()) in rules[1]["process_path"]
    assert str(tor.resolve()) in rules[1]["process_path"]
    assert rules[2] == {"action": "hijack-dns"}
    assert rules[3] == {"network": "udp", "action": "reject", "method": "default"}
    assert config["route"]["final"] == "tor-socks"



def test_windows_and_linux_helpers_share_one_complete_argument_builder(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    monkeypatch.setattr(SystemTunnelManager, "engine_sha256", property(lambda _self: "a" * 64))
    args = manager._helper_action_arguments("start", tmp_path / "helper.json")
    mapping = {args[i]: args[i + 1] for i in range(0, len(args) - 1, 2) if args[i].startswith("--")}
    assert mapping["--version"] == manager.version
    assert mapping["--source-url"] == manager.platform_asset["url"]
    assert mapping["--archive-type"] == manager.platform_asset["archive"]
    assert "--release-sha256" in mapping
    assert "--archive-sha256" in mapping
    assert "--result" in mapping


def test_system_tunnel_start_rolls_back_when_tun_has_no_outbound_tcp_tls(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    monkeypatch.setattr(manager, "is_installed", lambda: True)
    monkeypatch.setattr(system_tunnel, "_interface_exists", lambda _name: False)
    monkeypatch.setattr(manager, "_write_and_check_config", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(manager, "_invoke_helper", lambda _action: {"ok": True, "active": True})
    monkeypatch.setattr(manager, "_socks5_connect_probe", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(manager, "_verify_tunnel_tcp_tls", lambda: (_ for _ in ()).throw(
        SystemTunnelError("probe timeout")
    ))
    real_connect = system_tunnel.socket.create_connection
    stopped = []

    def fake_connect(address, timeout=None, **kwargs):
        if address == ("127.0.0.1", 9150):
            class Listener:
                def __enter__(self): return self
                def __exit__(self, *_args): return False
            return Listener()
        raise OSError("simulated blackholed TUN traffic")

    monkeypatch.setattr(system_tunnel.socket, "create_connection", fake_connect)
    monkeypatch.setattr(manager, "stop", lambda: stopped.append(True) or "stopped")
    with pytest.raises(SystemTunnelError, match="stopped automatically"):
        manager.start(9150, tor_executables=[tmp_path / "tor"])
    assert stopped == [True]
    monkeypatch.setattr(system_tunnel.socket, "create_connection", real_connect)


def test_windows_tun_config_forces_gvisor_stack_for_known_windows_forwarding_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(system_tunnel.platform, "system", lambda: "Windows")
    manager = _manager(tmp_path)
    manager.engine_dir.mkdir(parents=True, exist_ok=True)
    manager.engine_path.write_bytes(b"engine")
    tor = tmp_path / "tor.exe"
    tor.write_bytes(b"tor")

    config = manager.build_config(9150, tor_executables=[tor])

    assert config["inbounds"][0]["stack"] == "gvisor"
    assert "auto_redirect" not in config["inbounds"][0]


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
            assert timeout == system_tunnel.HELPER_STOP_TIMEOUT_SECONDS
            return 0
        def kill(self):
            self.killed = True

    fake = FakeProcess()
    monkeypatch.setattr(system_tunnel.os, "name", "posix")
    monkeypatch.setattr(system_tunnel, "_process_matches", lambda _state: fake)

    system_tunnel._stop_verified_process(fake, {"pid": fake.pid})

    assert fake.terminated is True
    assert fake.killed is False
