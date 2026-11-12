from __future__ import annotations

from contextlib import nullcontext
import threading
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
    yield manager, config, fake_tor
    # Keep the test process free of relay listeners even when a test stops
    # immediately after verifying ADD_ONION behavior.
    for relay in tuple(manager._traffic_relays.values()):
        relay.close()


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
    mappings = [part for part in command.split() if part.startswith("Port=")]
    assert len(mappings) == 1
    assert mappings[0].startswith("Port=443,127.0.0.1:")
    assert not mappings[0].endswith(":8000")
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


def test_application_shutdown_cancels_an_inflight_developer_tor_start(tmp_path):
    entered_start = threading.Event()
    stop_seen = threading.Event()

    class BlockingTorManager(FakeTorManager):
        def __init__(self):
            super().__init__("b" * 56)
            self.state = TorState.STOPPED

        def start(self, on_status=None):
            self.process = SimpleNamespace(pid=5252, poll=lambda: None)
            self.state = TorState.STARTING
            entered_start.set()
            cancel_event = getattr(self, "_start_cancel_event", None)
            assert cancel_event is not None
            if not cancel_event.wait(timeout=3):
                raise AssertionError("Application shutdown did not cancel Developer Tor startup")
            raise OnionHostingError("Developer Tor startup cancelled by application shutdown.")

        def stop(self):
            super().stop()
            stop_seen.set()

    config = MemoryConfig()
    directories = SimpleNamespace(data=tmp_path / "data", logs=tmp_path / "logs")
    fake = BlockingTorManager()
    manager = OnionHostingManager(
        lambda: object(),
        config=config,
        manager_factory=lambda _settings: fake,
        directories=directories,
    )
    start_errors = []

    def start_runtime():
        try:
            manager.start_runtime()
        except Exception as exc:
            start_errors.append(exc)

    starter = threading.Thread(target=start_runtime, daemon=True)
    starter.start()
    assert entered_start.wait(timeout=2)

    manager.shutdown_runtime()
    starter.join(timeout=2)

    assert not starter.is_alive()
    assert start_errors
    assert stop_seen.is_set()
    assert fake.process is None
    assert manager.manager is None
    assert manager.runtime_snapshot()["state"] == "stopped"
    with pytest.raises(OnionHostingError, match="shutting down"):
        manager.start_runtime()


def test_stop_runtime_is_restartable_but_shutdown_runtime_is_terminal_until_rollback(hosting):
    manager, _config, tor = hosting
    manager.stop_runtime()
    assert manager._shutdown_requested is False
    assert manager.manager is None

    # Explicit application shutdown prevents a late page action from starting
    # another Tor process after the application has begun exiting.
    manager._manager = tor
    manager.shutdown_runtime()
    assert manager._shutdown_requested is True
    with pytest.raises(OnionHostingError, match="shutting down"):
        manager.start_runtime()

    manager.resume_after_cancelled_shutdown()
    assert manager._shutdown_requested is False


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


def test_edit_refuses_persistent_service_with_missing_identity_key(hosting):
    manager, _config, tor = hosting
    profile_id = manager.create_service(
        display_name="Persistent app",
        local_host="127.0.0.1",
        local_port=9011,
        persistent=True,
    )
    manager.start_service(profile_id)
    manager.stop_service(profile_id)
    manager._key_path(profile_id).unlink()

    with pytest.raises(OnionHostingError, match="cannot be safely edited"):
        manager.update_service(profile_id, display_name="Renamed app")


def test_private_service_without_client_private_key_is_not_published(hosting):
    manager, _config, tor = hosting
    profile_id = manager.create_service(
        display_name="Private app",
        local_host="127.0.0.1",
        local_port=9020,
        persistent=True,
        access_mode="private",
    )
    manager._key_path(profile_id).unlink()

    with pytest.raises(OnionHostingError, match="client authorization material is missing"):
        manager.start_service(profile_id)
    assert not any(command.startswith("ADD_ONION") for command in tor.commands)


def test_mismatched_private_client_key_is_not_published(hosting):
    manager, _config, tor = hosting
    profile_id = manager.create_service(
        display_name="Private app",
        local_host="127.0.0.1",
        local_port=9021,
        persistent=True,
        access_mode="private",
    )
    material = manager._read_key_material(profile_id)
    material["client_private_key"] = "a" * 52
    manager._write_key_material(profile_id, material)

    with pytest.raises(OnionHostingError, match="do not match"):
        manager.start_service(profile_id)
    assert not any(command.startswith("ADD_ONION") for command in tor.commands)


def test_multiple_onion_ports_publish_through_one_service_and_preflight_each_target(hosting, monkeypatch):
    manager, _config, tor = hosting
    checked_targets = []

    def check_target(address, timeout):
        checked_targets.append((address, timeout))
        return nullcontext()

    monkeypatch.setattr(onion_module.socket, "create_connection", check_target)
    profile_id = manager.create_service(
        display_name="Web application",
        local_host="127.0.0.1",
        local_port=8080,
        onion_port=80,
        port_mappings=[
            {"onion_port": 443, "local_host": "127.0.0.1", "local_port": 8443},
        ],
    )

    address = manager.start_service(profile_id)

    command = next(item for item in tor.commands if item.startswith("ADD_ONION"))
    assert address == ("a" * 56) + ".onion"
    mappings = [part for part in command.split() if part.startswith("Port=")]
    assert len(mappings) == 2
    assert mappings[0].startswith("Port=80,127.0.0.1:")
    assert mappings[1].startswith("Port=443,127.0.0.1:")
    relay_ports = {
        int(part.rsplit(":", 1)[1]) for part in mappings
    }
    assert len(relay_ports) == 2
    assert not relay_ports.intersection({8080, 8443})
    assert checked_targets == [
        (("127.0.0.1", 8080), 2.5),
        (("127.0.0.1", 8443), 2.5),
    ]
    saved = manager.services_snapshot()[0]
    assert [item["onion_port"] for item in saved["port_mappings"]] == [80, 443]
    manager.stop_service(profile_id)


def test_onion_port_mappings_reject_duplicate_virtual_ports_and_non_loopback(hosting):
    manager, _config, _tor = hosting

    with pytest.raises(OnionHostingError, match="unique Onion port"):
        manager.create_service(
            display_name="Duplicate virtual port",
            local_host="127.0.0.1",
            local_port=8000,
            onion_port=80,
            port_mappings=[
                {"onion_port": 80, "local_host": "127.0.0.1", "local_port": 8443},
            ],
        )

    with pytest.raises(OnionHostingError, match="loopback"):
        manager.create_service(
            display_name="Unsafe target",
            local_host="127.0.0.1",
            local_port=8000,
            onion_port=80,
            port_mappings=[
                {"onion_port": 443, "local_host": "192.168.1.10", "local_port": 8443},
            ],
        )


def test_legacy_single_port_service_keeps_single_port_control_command(hosting):
    manager, _config, tor = hosting
    profile_id = manager.create_service(
        display_name="Legacy-compatible site",
        local_host="127.0.0.1",
        local_port=9000,
        onion_port=8080,
    )

    manager.start_service(profile_id)

    command = next(item for item in tor.commands if item.startswith("ADD_ONION"))
    mappings = [part for part in command.split() if part.startswith("Port=")]
    assert len(mappings) == 1
    assert mappings[0].startswith("Port=8080,127.0.0.1:")
    assert not mappings[0].endswith(":9000")
    manager.stop_service(profile_id)


def test_editing_port_mappings_preserves_the_persistent_onion_identity(hosting):
    manager, _config, tor = hosting
    profile_id = manager.create_service(
        display_name="Editable website",
        local_host="127.0.0.1",
        local_port=8080,
        onion_port=80,
        port_mappings=[
            {"onion_port": 443, "local_host": "127.0.0.1", "local_port": 8443},
        ],
    )
    first_address = manager.start_service(profile_id)
    manager.stop_service(profile_id)

    manager.update_service(
        profile_id,
        port_mappings=[
            {"onion_port": 9443, "local_host": "::1", "local_port": 9443},
        ],
    )
    second_address = manager.start_service(profile_id)

    assert second_address == first_address
    command = next(item for item in reversed(tor.commands) if item.startswith("ADD_ONION"))
    mappings = [part for part in command.split() if part.startswith("Port=")]
    assert len(mappings) == 2
    assert mappings[0].startswith("Port=80,127.0.0.1:")
    assert mappings[1].startswith("Port=9443,127.0.0.1:")
    assert "Port=443,127.0.0.1:" not in command
    manager.stop_service(profile_id)



def test_rotating_service_identity_generates_new_onion_address_and_keeps_private_client_key(hosting):
    manager, _config, tor = hosting
    profile_id = manager.create_service(
        display_name="Private rotating site",
        local_host="127.0.0.1",
        local_port=9100,
        persistent=True,
        access_mode="private",
    )
    first_address = manager.start_service(profile_id)
    manager.stop_service(profile_id)
    private_auth_before = manager._read_key_material(profile_id)["client_private_key"]

    manager.rotate_service_identity(profile_id)
    saved = manager.services_snapshot()[0]
    rotated_material = manager._read_key_material(profile_id)
    assert saved["address"] == ""
    assert rotated_material.get("tor_private_key") is None
    assert rotated_material["client_private_key"] == private_auth_before

    tor.service_id = "b" * 56
    second_address = manager.start_service(profile_id)
    assert second_address == ("b" * 56) + ".onion"
    assert second_address != first_address
    add_command = next(
        command for command in reversed(tor.commands)
        if command.startswith("ADD_ONION")
    )
    assert add_command.startswith("ADD_ONION NEW:ED25519-V3")
    assert "ClientAuthV3=" in add_command
    assert manager._read_key_material(profile_id)["client_private_key"] == private_auth_before
    manager.stop_service(profile_id)


def test_deleting_service_also_deletes_its_persisted_traffic_history(hosting):
    manager, _config, _tor = hosting
    profile_id = manager.create_service(
        display_name="Disposable site",
        local_host="127.0.0.1",
        local_port=9101,
        persistent=True,
    )
    manager._traffic_store.finish_connection(
        profile_id,
        onion_port=80,
        local_port=9101,
        protocol="HTTP",
        method="GET",
        path="/",
        status_code=200,
        incoming_bytes=100,
        outgoing_bytes=250,
        duration_ms=12,
    )
    assert manager.traffic_snapshot(profile_id)["incoming_bytes"] == 100
    assert manager.traffic_snapshot()["outgoing_bytes"] == 250

    manager.delete_service(profile_id)
    assert manager.traffic_snapshot(profile_id)["incoming_bytes"] == 0
    assert manager.traffic_events(profile_id) == []
    assert manager.traffic_snapshot()["outgoing_bytes"] == 0



def test_temporary_service_traffic_totals_are_removed_when_runtime_stops(hosting):
    manager, _config, _tor = hosting
    profile_id = manager.create_service(
        display_name="Ephemeral traffic",
        local_host="127.0.0.1",
        local_port=9102,
        persistent=False,
    )
    manager._traffic_store.finish_connection(
        profile_id,
        onion_port=80,
        local_port=9102,
        protocol="TLS",
        incoming_bytes=512,
        outgoing_bytes=1024,
        duration_ms=20,
    )
    assert manager.traffic_snapshot(profile_id)["incoming_bytes"] == 512
    assert manager.traffic_snapshot()["outgoing_bytes"] == 1024

    manager.stop_runtime()

    assert manager.services_snapshot() == []
    assert manager.traffic_snapshot(profile_id)["incoming_bytes"] == 0
    assert manager.traffic_events(profile_id) == []
    assert manager.traffic_snapshot()["outgoing_bytes"] == 0
