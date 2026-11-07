from __future__ import annotations

import os
from pathlib import Path

from torproxy.browsers import Browser, BrowserInventoryStore, CustomBrowserStore


def _executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("browser", encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o755)
    return path


def test_sqlite_browser_inventory_round_trips_all_launch_metadata(tmp_path):
    executable = _executable(tmp_path / "bin" / "opera")
    icon = tmp_path / "icons" / "opera.svg"
    icon.parent.mkdir(parents=True)
    icon.write_text("<svg/>", encoding="utf-8")
    desktop_file = tmp_path / "applications" / "opera.desktop"
    browser = Browser(
        "opera",
        "Opera",
        "chromium",
        str(executable),
        arguments=("--launcher-argument", "value"),
        source="desktop-entry",
        desktop_file=str(desktop_file),
        icon=str(icon),
    )

    store = BrowserInventoryStore(tmp_path / "browser_inventory.sqlite3")
    refreshed = store.replace_snapshot([browser])

    assert refreshed == [browser]
    assert BrowserInventoryStore(tmp_path / "browser_inventory.sqlite3").load() == [browser]


def test_browser_inventory_replaces_removed_apps_and_preserves_live_custom_entries(tmp_path):
    removed_executable = _executable(tmp_path / "bin" / "removed-browser")
    custom_executable = _executable(tmp_path / "custom" / "browser")
    current_executable = _executable(tmp_path / "bin" / "firefox")
    removed = Browser("old", "Old Browser", "chromium", str(removed_executable))
    custom = Browser(
        "custom-browser", "My Browser", "firefox", str(custom_executable), source="custom"
    )
    current = Browser("firefox", "Firefox", "firefox", str(current_executable))

    store = BrowserInventoryStore(tmp_path / "browser_inventory.sqlite3")
    store.replace_snapshot([removed, custom])
    store.upsert(custom)

    first_refresh = store.replace_snapshot([current])
    assert {browser.id for browser in first_refresh} == {"custom-browser", "firefox"}

    custom_executable.unlink()
    second_refresh = store.replace_snapshot([current])
    assert second_refresh == [current]
    assert store.load() == [current]


def test_browser_inventory_remove_checks_executable_identity(tmp_path):
    first_executable = _executable(tmp_path / "first")
    second_executable = _executable(tmp_path / "second")
    store = BrowserInventoryStore(tmp_path / "browser_inventory.sqlite3")
    first = Browser("same-id", "Browser", "chromium", str(first_executable))
    second = Browser("same-id", "Browser", "chromium", str(second_executable))
    store.upsert(second)

    assert store.remove(first.id, first.executable) is False
    assert store.load() == [second]
    assert store.remove(second.id, second.executable) is True
    assert store.load() == []


def test_custom_browser_store_removes_missing_registration_and_keeps_icons(tmp_path):
    executable = _executable(tmp_path / "custom" / "browser")
    icon = tmp_path / "custom" / "browser.svg"
    icon.write_text("<svg/>", encoding="utf-8")
    store = CustomBrowserStore(tmp_path / "custom_browsers.json")
    browser = Browser(
        "custom-browser",
        "Custom Browser",
        "chromium",
        str(executable),
        source="custom",
        icon=str(icon),
    )
    store.add(browser)

    restored = CustomBrowserStore(tmp_path / "custom_browsers.json").list()
    assert restored == [browser]
    assert store.remove(browser.id, browser.executable) is True
    assert store.list() == []
