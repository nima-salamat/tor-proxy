from __future__ import annotations

import sys

import pytest

import set_proxy
from set_proxy import Handler


class FakeWinReg:
    HKEY_CURRENT_USER = 1
    KEY_READ = 0x20019
    KEY_SET_VALUE = 0x0002
    REG_SZ = 1
    REG_BINARY = 3
    REG_DWORD = 4

    def __init__(self, values):
        self.values = values

    class Key:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False

    def OpenKey(self, *_args):
        return self.Key()

    def QueryValueEx(self, _key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        return self.values[name]

    def SetValueEx(self, _key, name, _reserved, kind, value):
        self.values[name] = (value, kind)

    def DeleteValue(self, _key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        del self.values[name]


def _fake_windows(monkeypatch, tmp_path):
    values = {
        "ProxyEnable": (0, FakeWinReg.REG_DWORD),
        "ProxyServer": ("previous.example:3128", FakeWinReg.REG_SZ),
        "ProxyOverride": ("localhost;127.*", FakeWinReg.REG_SZ),
        "AutoConfigURL": ("https://proxy.example/pac", FakeWinReg.REG_SZ),
        "AutoDetect": (1, FakeWinReg.REG_DWORD),
        "DefaultConnectionSettings": (b"saved-binary-settings", FakeWinReg.REG_BINARY),
    }
    registry = FakeWinReg(values)
    monkeypatch.setitem(sys.modules, "winreg", registry)
    monkeypatch.setattr(set_proxy, "_snapshot_path", lambda: tmp_path / "snapshot.json")
    return values


def test_system_proxy_rejects_non_loopback_targets():
    with pytest.raises(ValueError, match="loopback"):
        Handler("0.0.0.0", 8888)
    with pytest.raises(ValueError, match="port"):
        Handler("127.0.0.1", 70000)


def test_windows_proxy_restores_original_values_including_binary(monkeypatch, tmp_path):
    values = _fake_windows(monkeypatch, tmp_path)
    original = dict(values)
    handler = Handler("127.0.0.1", 8888)
    assert handler.set_windows_proxy() is True
    assert values["ProxyEnable"] == (1, FakeWinReg.REG_DWORD)
    assert values["ProxyServer"] == ("127.0.0.1:8888", FakeWinReg.REG_SZ)

    assert Handler("127.0.0.1", 8888).clear_windows_proxy() is True
    assert values == original
    assert not (tmp_path / "snapshot.json").exists()


def test_windows_proxy_does_not_overwrite_external_changes(monkeypatch, tmp_path):
    values = _fake_windows(monkeypatch, tmp_path)
    handler = Handler("127.0.0.1", 8888)
    assert handler.set_windows_proxy() is True
    values["ProxyServer"] = ("external.example:8080", FakeWinReg.REG_SZ)
    assert handler.clear_windows_proxy() is False
    assert values["ProxyServer"] == ("external.example:8080", FakeWinReg.REG_SZ)
    assert (tmp_path / "snapshot.json").exists()


def test_unsupported_system_proxy_platform_fails_closed(monkeypatch):
    monkeypatch.setattr(set_proxy.platform, "system", lambda: "Darwin")
    assert set_proxy.manage_proxy("127.0.0.1", 8888, "set") is False
