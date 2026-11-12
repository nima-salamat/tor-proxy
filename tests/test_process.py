from __future__ import annotations

from types import SimpleNamespace

import torproxy.process as process_module


def test_hidden_subprocess_kwargs_suppress_windows_console_creation(monkeypatch):
    startup_info = SimpleNamespace(dwFlags=0, wShowWindow=-1)
    fake_subprocess = SimpleNamespace(
        STARTUPINFO=lambda: startup_info,
        STARTF_USESHOWWINDOW=1,
        CREATE_NO_WINDOW=0x08000000,
    )
    monkeypatch.setattr(process_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(process_module, "subprocess", fake_subprocess)

    options = process_module.hidden_subprocess_kwargs()

    assert options["creationflags"] == 0x08000000
    assert options["startupinfo"] is startup_info
    assert startup_info.dwFlags & 1
    assert startup_info.wShowWindow == 0


def test_hidden_subprocess_kwargs_are_unchanged_on_non_windows(monkeypatch):
    monkeypatch.setattr(process_module, "os", SimpleNamespace(name="posix"))
    assert process_module.hidden_subprocess_kwargs() == {}
