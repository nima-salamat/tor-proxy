import os
import threading

import pytest

import torproxy.hotkeys as hotkeys_module
from torproxy.hotkeys import HotkeyManager, MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, parse_hotkey


def test_global_hotkey_is_normalized_and_maps_to_win32_chord():
    parsed = parse_hotkey("control+alt+p")
    assert parsed.text == "Ctrl+Alt+P"
    assert parsed.virtual_key == ord("P")
    assert parsed.modifiers == MOD_CONTROL | MOD_ALT | MOD_NOREPEAT


def test_global_hotkey_supports_shift_and_function_keys():
    parsed = parse_hotkey("Shift+Ctrl+F3")
    assert parsed.text == "Ctrl+Shift+F3"
    assert parsed.virtual_key == 0x72
    assert parsed.modifiers & MOD_CONTROL
    assert parsed.modifiers & 0x0004


@pytest.mark.parametrize(
    "shortcut",
    ["P", "Ctrl", "Ctrl+Ctrl+P", "Ctrl+Alt+P+Q", "Ctrl+F12", "Ctrl+unsupported"],
)
def test_invalid_global_hotkeys_are_rejected(shortcut):
    with pytest.raises(ValueError):
        parse_hotkey(shortcut)


def test_named_registry_allows_changing_shortcuts_without_replacing_callbacks():
    manager = HotkeyManager()
    hits = []
    manager.register("window_visibility", "Ctrl+Alt+P", lambda: hits.append("toggle"))
    assert manager.get_shortcut("window_visibility") == "Ctrl+Alt+P"

    assert manager.update_shortcut("window_visibility", "Ctrl+Shift+K") == "Ctrl+Shift+K"
    assert manager.get_shortcut("window_visibility") == "Ctrl+Shift+K"
    manager._bindings["window_visibility"].callback()
    assert hits == ["toggle"]


def test_named_registry_rejects_unknown_action_changes():
    manager = HotkeyManager()
    with pytest.raises(KeyError, match="Unknown hotkey action"):
        manager.update_shortcut("missing", "Ctrl+Alt+P")


def test_failed_shortcut_update_rolls_back_registry_and_backend():
    class FakeBackend:
        def __init__(self):
            self.bindings = {}

        def set_bindings(self, bindings):
            if any(shortcut == "Ctrl+Shift+K" for shortcut, _callback in bindings.values()):
                raise RuntimeError("shortcut already in use")
            self.bindings = dict(bindings)

        def start(self):
            pass

        def stop(self):
            pass

    manager = HotkeyManager()
    backend = FakeBackend()
    manager._backend = backend
    manager.register("window_visibility", "Ctrl+Alt+P", lambda: None)

    with pytest.raises(RuntimeError, match="already in use"):
        manager.update_shortcut("window_visibility", "Ctrl+Shift+K")

    assert manager.get_shortcut("window_visibility") == "Ctrl+Alt+P"
    assert backend.bindings["window_visibility"][0] == "Ctrl+Alt+P"



def test_named_hotkeys_can_be_suspended_and_updated_during_capture():
    class FakeBackend:
        def __init__(self):
            self.bindings = {}

        def set_bindings(self, bindings):
            self.bindings = dict(bindings)

        def start(self):
            pass

        def stop(self):
            pass

    manager = HotkeyManager()
    backend = FakeBackend()
    manager._backend = backend

    def callback():
        return None

    manager.register("window_visibility", "Ctrl+Alt+P", callback)
    assert backend.bindings["window_visibility"][0] == "Ctrl+Alt+P"

    manager.suspend()
    manager.suspend()
    assert backend.bindings == {}

    manager.update_shortcut("window_visibility", "Ctrl+Shift+K")
    assert manager.get_shortcut("window_visibility") == "Ctrl+Shift+K"
    assert backend.bindings == {}

    manager.resume()
    assert backend.bindings == {}
    manager.resume()
    assert backend.bindings["window_visibility"] == ("Ctrl+Shift+K", callback)



@pytest.mark.skipif(os.name != "nt", reason="Exercises the native Windows message-thread owner.")
def test_windows_hotkey_backend_retains_thread_after_timed_out_stop(monkeypatch):
    backend = hotkeys_module._WindowsBackend(lambda _message: None)

    class FakeThread:
        def __init__(self):
            self.alive = True
            self.join_calls = 0

        def is_alive(self):
            return self.alive

        def join(self, timeout=None):
            self.join_calls += 1

    class FakeUser32:
        def PostMessageW(self, hwnd, message, _wparam, _lparam):
            assert hwnd == 123
            assert message == backend.WM_CLOSE
            return 1

    thread = FakeThread()
    backend._thread = thread
    backend._hwnd = 123
    backend._user32 = FakeUser32()
    backend._started.set()

    with pytest.raises(RuntimeError, match="reference was retained"):
        backend.stop()
    assert backend._thread is thread
    assert backend._started.is_set() is False

    # A new message window must not be launched while the old owner remains alive.
    with pytest.raises(RuntimeError, match="duplicate message window was refused"):
        backend.start()
    assert backend._thread is thread

    thread.alive = False
    backend.stop()
    assert backend._thread is None
