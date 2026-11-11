from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

import torproxy.onion_hosting as onion_module
from torproxy.onion_hosting import (
    OnionHostingError,
    OnionHostingManager,
    validate_loopback_target,
)
from torproxy.tor_manager import TorState


class MemoryConfig:
    def __init__(self):
        self.values = {"onion_hosting_services": []}

    def __getitem__(self, key):
        return self.values[key]

    def update_many(self, values):
        self.values.update(values)


class FakeTorManager:
    def __init__(self, service_id):
        self.state = TorState.READY
        self.last_error = None
        self.service_id = service_id
        self.commands = []
        self.new_key = "ED25519-V3:YWJjZGVmZ2hpamtsbW5vcA"
        self.process = SimpleNamespace(pid=4242, poll=lambda: None)
        self.stop_called = False

    def send_control_command(self, command):
        self.commands.append(command)
        if command.startswith("DEL_ONION "):
            return "250 OK"
        if command.startswith("ADD_ONION NEW:ED25519-V3"):
            return (
                f"250-ServiceID={self.service_id}\r\n"
                f"250-PrivateKey={self.new_key}\r\n"
                "250 OK\r\n"
            )
        if command.startswith("ADD_ONION ED25519-V3:"):
            return f"250-ServiceID={self.service_id}\r\n250 OK\r\n"
        raise AssertionError("Unexpected command")

    def stop(self):
        self.stop_called = True
        self.state = TorState.STOPPED
        self.process = None

    def force_stop(self):
        self.stop()


@pytest.fixture
def hosting(tmp_path, monkeypatch):
    config = MemoryConfig()
    directories = SimpleNamespace(data=tmp_path / "data", logs=tmp_path / "logs")
    manager = OnionHostingManager(
        lambda: None,
        config=config,
        directories=directories,
    )
    fake_tor = FakeTorManager("a" * 56)
    manager._manager = fake_tor

    def fake_connection(*_args, **_kwargs):
        return nullcontext()

    monkeypatch.setattr(onion_module.socket, "create_connection", fake_connection)
    return manager, config, fake_tor


def test_only_literal_loopback_targets_are_accepted():
    assert validate_loopback_target("127.0.0.1", 8000) == ("127.0.0.1", 8000)
    assert validate_loopback_target("::1", 9000) == ("::1", 9000)
    for host in ("localhost", "0.0.0.0", "192.168.1.10", "example.com"):
        with pytest.raises(OnionHostingError):
            validate_loopback_target(host, 8000)


def test_private_persistent_service_uses_detached_v3_auth_and_keeps_secrets_out_of_config(hosting):
    manager, config, tor = hosting
    profile_id = manager.create_service(
        display_name="Development API",
        local_host="127.0.0.1",
        local_port=8000,
        onion_port=443,
        persistent=True,
        access_mode="private",
        auto_start=True,
    )

    address = manager.start_service(profile_id)
    assert address == ("a" * 56) + ".onion"
    command = next(item for item in tor.commands if item.startswith("ADD_ONION"))
    assert "Flags=Detach,V3Auth" in command
    assert "Port=443,127.0.0.1:8000" in command
    assert "ClientAuthV3=" in command

    # The private credentials are only in the protected key file, never config.json.
    saved = config["onion_hosting_services"][0]
    assert saved["access_mode"] == "private"
    assert saved["service_id"] == "a" * 56
    assert "tor_private_key" not in saved
    assert "client_private_key" not in saved
    assert "client_public_key" in saved

    private_file = manager.client_auth_private_file(profile_id)
    parts = private_file.split(":")
    assert parts[:3] == ["a" * 56, "descriptor", "x25519"]
    assert len(parts[3]) == 52
    assert parts[3] == parts[3].upper()


def test_persistent_service_reuses_its_ed25519_identity_after_stop(hosting):
    manager, _config, tor = hosting
    profile_id = manager.create_service(
        display_name="Website",
        local_host="127.0.0.1",
        local_port=3000,
        persistent=True,
    )
    manager.start_service(profile_id)
    manager.stop_service(profile_id)
    previous_count = len(tor.commands)

    manager.start_service(profile_id)
    second_add = next(
        command for command in tor.commands[previous_count:]
        if command.startswith("ADD_ONION")
    )
    assert second_add.startswith("ADD_ONION ED25519-V3:")
    assert "NEW:ED25519-V3" not in second_add
    assert manager.services_snapshot()[0]["address"] == ("a" * 56) + ".onion"


def test_temporary_service_metadata_and_keys_are_removed_when_runtime_stops(hosting):
    manager, config, tor = hosting
    profile_id = manager.create_service(
        display_name="Temporary site",
        local_host="127.0.0.1",
        local_port=5173,
        persistent=False,
        access_mode="private",
    )
    assert config["onion_hosting_services"] == []
    manager.start_service(profile_id)
    manager.stop_runtime()

    assert tor.stop_called
    assert manager.services_snapshot() == []
    assert manager.runtime_snapshot()["state"] == "stopped"


def test_persistent_to_temporary_transition_keeps_private_client_key(hosting):
    manager, _config, _tor = hosting
    profile_id = manager.create_service(
        display_name="Private app",
        local_host="127.0.0.1",
        local_port=8080,
        persistent=True,
        access_mode="private",
    )
    manager.start_service(profile_id)
    manager.stop_service(profile_id)
    before = manager.client_auth_private_file(profile_id).split(":")[-1]

    manager.update_service(profile_id, persistent=False)
    after = manager.client_auth_private_file(profile_id).split(":")[-1]
    assert before == after
    assert manager._key_path(profile_id).exists() is False


def test_unavailable_local_target_fails_before_contacting_tor(hosting, monkeypatch):
    manager, _config, tor = hosting
    profile_id = manager.create_service(
        display_name="Offline local app",
        local_host="127.0.0.1",
        local_port=65534,
        persistent=True,
    )

    def unreachable(*_args, **_kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(onion_module.socket, "create_connection", unreachable)
    with pytest.raises(OnionHostingError, match="not accepting TCP"):
        manager.start_service(profile_id)
    assert not any(command.startswith("ADD_ONION") for command in tor.commands)


def test_unexpected_runtime_exit_reconciles_active_services(hosting):
    manager, _config, tor = hosting
    profile_id = manager.create_service(
        display_name="Website",
        local_host="127.0.0.1",
        local_port=9001,
        persistent=True,
    )
    manager.start_service(profile_id)
    tor.process = SimpleNamespace(pid=4242, poll=lambda: 1)

    runtime = manager.runtime_snapshot()
    service = manager.services_snapshot()[0]

    assert runtime["state"] == "failed"
    assert service["running"] is False
    assert "no longer published" in service["error"]


def test_missing_persistent_identity_is_not_silently_regenerated(hosting):
    manager, _config, tor = hosting
    profile_id = manager.create_service(
        display_name="Identity-bound site",
        local_host="127.0.0.1",
        local_port=9010,
        persistent=True,
    )
    manager.start_service(profile_id)
    manager.stop_service(profile_id)
    manager._key_path(profile_id).unlink()

    add_count = sum(command.startswith("ADD_ONION") for command in tor.commands)
    with pytest.raises(OnionHostingError, match="will not be recreated"):
        manager.start_service(profile_id)

    assert sum(command.startswith("ADD_ONION") for command in tor.commands) == add_count
