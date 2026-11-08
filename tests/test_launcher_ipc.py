from __future__ import annotations

import json
import os
import uuid

import pytest

from torproxy.launcher_ipc import notify_launcher

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


_QT_APP = None


def _ensure_qt_application():
    global _QT_APP
    qt_widgets = pytest.importorskip("PySide6.QtWidgets")
    _QT_APP = qt_widgets.QApplication.instance() or qt_widgets.QApplication([])
    return _QT_APP


def test_notify_launcher_is_a_noop_for_direct_launch(monkeypatch):
    monkeypatch.delenv("TORPROXY_LAUNCHER_SERVER", raising=False)
    monkeypatch.delenv("TORPROXY_LAUNCHER_STATUS_FILE", raising=False)
    monkeypatch.delenv("TORPROXY_LAUNCHER_TOKEN", raising=False)

    assert notify_launcher("ready") is False


def test_notify_launcher_sends_authenticated_ready_message(monkeypatch):
    _ensure_qt_application()
    qt_network = pytest.importorskip("PySide6.QtNetwork")
    server = qt_network.QLocalServer()
    server_name = "torproxy-test-" + uuid.uuid4().hex
    token = uuid.uuid4().hex
    received = []
    assert server.listen(server_name)
    connect_name = server.fullServerName() or server_name

    def accept_client():
        peer = server.nextPendingConnection()
        assert peer is not None

        def acknowledge():
            if not peer.canReadLine():
                return
            payload = json.loads(bytes(peer.readLine()).decode("utf-8").strip())
            received.append(payload)
            peer.write(b"ACK\n")
            peer.flush()
            peer.disconnectFromServer()

        peer.readyRead.connect(acknowledge)
        # The peer may already have received bytes before the newConnection
        # callback attaches readyRead (especially with Windows named pipes).
        if peer.canReadLine():
            acknowledge()

    server.newConnection.connect(accept_client)
    monkeypatch.setenv("TORPROXY_LAUNCHER_SERVER", connect_name)
    monkeypatch.setenv("TORPROXY_LAUNCHER_TOKEN", token)
    try:
        assert notify_launcher("ready", "Window displayed")
        assert received == [{
            "token": token,
            "status": "ready",
            "message": "Window displayed",
        }]
    finally:
        server.close()
        qt_network.QLocalServer.removeServer(server_name)


def test_notify_launcher_writes_atomic_windows_status_file(tmp_path, monkeypatch):
    status_file = tmp_path / "startup.status"
    token = "per-launch-random-token"
    monkeypatch.setenv("TORPROXY_LAUNCHER_STATUS_FILE", str(status_file))
    monkeypatch.setenv("TORPROXY_LAUNCHER_TOKEN", token)
    monkeypatch.delenv("TORPROXY_LAUNCHER_SERVER", raising=False)

    assert notify_launcher("starting", "Loading Python…") is True
    lines = status_file.read_text(encoding="ascii").splitlines()
    assert lines[:2] == [token, "starting"]
    assert bytes.fromhex(lines[2]).decode("utf-8") == "Loading Python…"
    assert list(tmp_path.glob("*.tmp")) == []


def test_notify_launcher_rejects_unknown_status(monkeypatch):
    monkeypatch.setenv("TORPROXY_LAUNCHER_SERVER", "unused-channel")
    monkeypatch.setenv("TORPROXY_LAUNCHER_TOKEN", "unused-token")

    assert notify_launcher("unknown") is False
