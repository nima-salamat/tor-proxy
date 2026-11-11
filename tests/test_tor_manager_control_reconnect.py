from __future__ import annotations

from types import SimpleNamespace

import pytest

from torproxy.tor_manager import TorManager, TorSettings, TorState


class ReconnectingController:
    def __init__(self, *, alive=True, pid="4242", failure=None):
        self.alive = alive
        self.pid = pid
        self.failure = failure
        self.closed = False
        self.commands = []

    def is_alive(self):
        return self.alive

    def close(self):
        self.closed = True

    def get_info(self, key, default=None):
        return self.pid if key == "process/pid" else default

    def msg(self, command):
        self.commands.append(command)
        if self.failure:
            raise self.failure
        return "250 OK"


def _manager(tmp_path):
    settings = TorSettings(
        executable=tmp_path / "tor",
        socks_port=0,
        control_port=19052,
        data_directory=tmp_path / "developer-tor",
    )
    manager = TorManager(settings)
    manager.state = TorState.READY
    manager.process = SimpleNamespace(pid=4242, poll=lambda: None)
    manager._port_ready = lambda _port: True
    return manager


def test_control_port_reconnect_authenticates_and_verifies_process(tmp_path):
    manager = _manager(tmp_path)
    previous = ReconnectingController(alive=False)
    replacement = ReconnectingController(pid="4242")
    manager._controller = previous
    manager._connect_controller = lambda: replacement

    result = manager.send_control_command("GETINFO version")

    assert result == "250 OK"
    assert previous.closed
    assert replacement.commands == ["GETINFO version"]
    assert manager._controller is replacement


def test_control_port_reconnect_rejects_a_different_tor_process(tmp_path):
    manager = _manager(tmp_path)
    manager._controller = ReconnectingController(alive=False)
    replacement = ReconnectingController(pid="9876")
    manager._connect_controller = lambda: replacement

    with pytest.raises(Exception, match="did not identify the Tor process"):
        manager.send_control_command("GETINFO version")

    assert replacement.closed
    assert manager._controller is None


def test_control_command_is_not_retried_after_transmission_failure(tmp_path):
    manager = _manager(tmp_path)
    controller = ReconnectingController(failure=OSError("socket closed"))
    manager._controller = controller

    with pytest.raises(Exception, match="ControlPort command failed"):
        manager.send_control_command("ADD_ONION NEW:ED25519-V3 Flags=Detach")

    assert controller.commands == ["ADD_ONION NEW:ED25519-V3 Flags=Detach"]
