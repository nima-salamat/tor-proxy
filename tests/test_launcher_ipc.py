"""Regression tests for the authenticated native-launcher status channel."""

from __future__ import annotations

import os
import stat

from torproxy.launcher_ipc import notify_launcher


def test_status_file_is_atomic_private_and_does_not_fsync(tmp_path, monkeypatch):
    status_path = tmp_path / "startup.status"
    monkeypatch.setenv("TORPROXY_LAUNCHER_STATUS_FILE", str(status_path))
    monkeypatch.setenv("TORPROXY_LAUNCHER_TOKEN", "test-token-123")
    monkeypatch.delenv("TORPROXY_LAUNCHER_SERVER", raising=False)

    def unexpected_fsync(_fd):
        raise AssertionError("startup progress must not fsync the status file")

    monkeypatch.setattr(os, "fsync", unexpected_fsync)
    assert notify_launcher("starting", "Loading Python – مرحبا")
    lines = status_path.read_text(encoding="ascii").splitlines()
    assert lines[:2] == ["test-token-123", "starting"]
    assert bytes.fromhex(lines[2]).decode("utf-8") == "Loading Python – مرحبا"
    assert not list(tmp_path.glob(".startup.status.*.tmp"))
    if os.name != "nt":
        assert stat.S_IMODE(status_path.stat().st_mode) == 0o600


def test_status_file_rejects_unknown_status_without_writing(tmp_path, monkeypatch):
    status_path = tmp_path / "startup.status"
    monkeypatch.setenv("TORPROXY_LAUNCHER_STATUS_FILE", str(status_path))
    monkeypatch.setenv("TORPROXY_LAUNCHER_TOKEN", "test-token")
    assert not notify_launcher("unknown", "ignored")
    assert not status_path.exists()


def test_direct_launch_without_launcher_environment_is_unchanged(monkeypatch):
    monkeypatch.delenv("TORPROXY_LAUNCHER_STATUS_FILE", raising=False)
    monkeypatch.delenv("TORPROXY_LAUNCHER_TOKEN", raising=False)
    monkeypatch.delenv("TORPROXY_LAUNCHER_SERVER", raising=False)
    assert not notify_launcher("starting", "ordinary direct launch")


def test_status_file_requires_a_launcher_token(tmp_path, monkeypatch):
    status_path = tmp_path / "startup.status"
    monkeypatch.setenv("TORPROXY_LAUNCHER_STATUS_FILE", str(status_path))
    monkeypatch.delenv("TORPROXY_LAUNCHER_TOKEN", raising=False)
    assert not notify_launcher("ready")
    assert not status_path.exists()
