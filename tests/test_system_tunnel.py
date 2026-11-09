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
    assert str(manager.engine_path.resolve()) in rules[0]["process_path"]
    assert str(tor.resolve()) in rules[0]["process_path"]
    assert rules[1] == {"action": "hijack-dns"}
    assert rules[2] == {"network": "udp", "action": "reject", "method": "default"}
    assert config["route"]["final"] == "tor-socks"


def test_windows_wfp_tun_exception_is_installed_after_live_adapter_creation(tmp_path):
    helper = tmp_path / "TorProxyWfpHelper.exe"
    helper.write_bytes(b"test helper")
    calls = []

    class Result:
        def __init__(self, stdout, returncode=0):
            self.stdout = stdout
            self.returncode = returncode

    def fake_run(args, **kwargs):
        calls.append(args)
        assert kwargs["timeout"] == 10
        if args[-1] == "status":
            return Result("ACTIVE filters=11 tun_interface_allowed=false")
        assert args[-1] == "allow-tun"
        return Result("ACTIVE filters=13 tun_interface_allowed=true")

    enabled = system_tunnel._apply_wfp_tun_exception(helper, fake_run)

    assert enabled is True
    assert calls == [
        [str(helper), "status"],
        [str(helper), "allow-tun"],
    ]


def test_windows_wfp_tun_exception_fails_closed_without_active_policy(tmp_path):
    helper = tmp_path / "TorProxyWfpHelper.exe"
    helper.write_bytes(b"test helper")

    class Result:
        returncode = 0
        stdout = "INACTIVE filters=0 tun_interface_allowed=false"

    with pytest.raises(SystemTunnelError, match="WFP Kill Switch is no longer active"):
        system_tunnel._apply_wfp_tun_exception(
            helper, lambda *_args, **_kwargs: Result()
        )


def test_windows_wfp_tun_exception_preserves_a_legacy_snapshot_policy(tmp_path):
    helper = tmp_path / "TorProxyWfpHelper.exe"
    helper.write_bytes(b"test helper")
    snapshot = tmp_path / "windows-firewall-snapshot.json"
    snapshot.write_text('{"version": 1}', encoding="utf-8")

    class Result:
        returncode = 0
        stdout = "INACTIVE filters=0 tun_interface_allowed=false"

    enabled = system_tunnel._apply_wfp_tun_exception(
        helper, lambda *_args, **_kwargs: Result(), legacy_snapshot=snapshot
    )

    assert enabled is False


def test_windows_wfp_tun_exception_refuses_incomplete_filter_policy(tmp_path):
    helper = tmp_path / "TorProxyWfpHelper.exe"
    helper.write_bytes(b"test helper")

    class Result:
        returncode = 0
        stdout = "INCOMPLETE filters=4 tun_interface_allowed=false"

    with pytest.raises(SystemTunnelError, match="incomplete filter set"):
        system_tunnel._apply_wfp_tun_exception(helper, lambda *_args, **_kwargs: Result())


def test_windows_wfp_tun_exception_requires_verified_adapter_luid_result(tmp_path):
    helper = tmp_path / "TorProxyWfpHelper.exe"
    helper.write_bytes(b"test helper")

    class Result:
        def __init__(self, stdout, returncode=0):
            self.stdout = stdout
            self.returncode = returncode

    responses = iter([
        Result("ACTIVE filters=11 tun_interface_allowed=false"),
        Result("ACTIVE filters=11 tun_interface_allowed=false"),
    ])

    with pytest.raises(SystemTunnelError, match="did not confirm its exact interface exception"):
        system_tunnel._apply_wfp_tun_exception(
            helper, lambda *_args, **_kwargs: next(responses)
        )


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
