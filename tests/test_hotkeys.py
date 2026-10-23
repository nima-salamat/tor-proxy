import pytest

from torproxy.hotkeys import HotkeyManager, MOD_CONTROL, MOD_NOREPEAT, parse_hotkey


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
