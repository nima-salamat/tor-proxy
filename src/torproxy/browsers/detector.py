"""Cross-platform discovery for common Chromium and Firefox-family browsers."""
from __future__ import annotations

import configparser
import os
import re
import shlex
import shutil
import sys
from pathlib import Path
from collections.abc import Iterable

from .models import Browser
from .registry import CustomBrowserStore


# Product names are mapped to stable IDs and a browser family. Detection is based
# on install metadata and executable names; no browser settings are modified here.
_ALIASES = (
    ("opera_gx", "Opera GX", "chromium", ("opera gx", "operagx")),
    ("ungoogled_chromium", "Ungoogled Chromium", "chromium", ("ungoogled",)),
    ("yandex", "Yandex Browser", "chromium", ("yandex",)),
    ("vivaldi", "Vivaldi", "chromium", ("vivaldi",)),
    ("brave", "Brave", "chromium", ("brave",)),
    ("edge", "Microsoft Edge", "chromium", ("microsoft edge", "msedge")),
    ("chrome", "Google Chrome", "chromium", ("google chrome", "google-chrome", "chrome.exe")),
    ("chromium", "Chromium", "chromium", ("chromium",)),
    ("opera", "Opera", "chromium", ("opera",)),
    ("librewolf", "LibreWolf", "firefox", ("librewolf",)),
    ("waterfox", "Waterfox", "firefox", ("waterfox",)),
    ("floorp", "Floorp", "firefox", ("floorp",)),
    ("zen", "Zen Browser", "firefox", ("zen browser", "zen-browser", "zen.exe")),
    ("firefox_esr", "Firefox ESR", "firefox", ("firefox-esr", "firefox esr")),
    ("firefox", "Firefox", "firefox", ("mozilla firefox", "firefox")),
)

_WINDOWS_CANDIDATES = {
    "chrome": (("Google", "Chrome", "Application", "chrome.exe"),),
    "chromium": (("Chromium", "Application", "chrome.exe"), ("Chromium", "chrome.exe")),
    "edge": (("Microsoft", "Edge", "Application", "msedge.exe"),),
    "brave": (("BraveSoftware", "Brave-Browser", "Application", "brave.exe"),),
    "vivaldi": (("Vivaldi", "Application", "vivaldi.exe"),),
    "opera": (("Programs", "Opera", "launcher.exe"), ("Opera", "launcher.exe")),
    "opera_gx": (("Programs", "Opera GX", "launcher.exe"), ("Opera GX", "launcher.exe")),
    "yandex": (("Yandex", "YandexBrowser", "Application", "browser.exe"),),
    "ungoogled_chromium": (
        ("Ungoogled Chromium", "Application", "chrome.exe"),
        ("Ungoogled Chromium", "chrome.exe"),
    ),
    "firefox": (("Mozilla Firefox", "firefox.exe"),),
    "firefox_esr": (("Mozilla Firefox ESR", "firefox.exe"),),
    "librewolf": (("LibreWolf", "librewolf.exe"),),
    "waterfox": (("Waterfox", "waterfox.exe"),),
    "floorp": (("Floorp", "floorp.exe"),),
    "zen": (("Zen", "zen.exe"), ("Zen Browser", "zen.exe")),
}
_WINDOWS_EXECUTABLES = {
    "chrome": "chrome.exe", "edge": "msedge.exe",
    "brave": "brave.exe", "vivaldi": "vivaldi.exe",
    "yandex": "browser.exe",
    "firefox": "firefox.exe",
    "librewolf": "librewolf.exe",
    "waterfox": "waterfox.exe", "floorp": "floorp.exe", "zen": "zen.exe",
}


def _match_browser(text: str) -> tuple[str, str, str] | None:
    candidate = str(text or "").casefold()
    if any(marker in candidate for marker in ("tor browser", "tor-browser", "torbrowser")):
        return None
    for browser_id, name, family, aliases in _ALIASES:
        if any(alias in candidate for alias in aliases):
            return browser_id, name, family
    return None


def _resolve_executable(value: str, *, search_path: str | None = None) -> str | None:
    candidate = str(value or "").strip().strip('"')
    if not candidate:
        return None
    expanded = os.path.expandvars(os.path.expanduser(candidate))
    path = Path(expanded)
    if path.is_file():
        return str(path.resolve())
    found = shutil.which(expanded, path=search_path)
    return str(Path(found).resolve()) if found else None


def _desktop_exec(value: str, *, search_path: str | None = None) -> tuple[str, tuple[str, ...]] | None:
    """Parse a Desktop Entry Exec value without invoking a shell."""
    try:
        tokens = shlex.split(value, posix=(os.name != "nt"))
    except ValueError:
        return None
    cleaned: list[str] = []
    for token in tokens:
        if token in {"%f", "%F", "%u", "%U", "%i", "%c", "%k"}:
            continue
        token = re.sub(r"%[fFuUdDnNickvm]", "", token)
        if token:
            cleaned.append(token)
    if not cleaned:
        return None
    executable = _resolve_executable(cleaned[0], search_path=search_path)
    if executable is None:
        return None
    return executable, tuple(cleaned[1:])


def _data_application_dirs(environ: dict[str, str]) -> list[Path]:
    home = Path(environ.get("HOME") or Path.home())
    data_home = Path(environ.get("XDG_DATA_HOME") or (home / ".local" / "share"))
    data_dirs = environ.get("XDG_DATA_DIRS", "/usr/local/share:/usr/share")
    result = [
        data_home / "applications",
        data_home / "flatpak" / "exports" / "share" / "applications",
        Path("/var/lib/flatpak/exports/share/applications"),
        Path("/var/lib/snapd/desktop/applications"),
    ]
    result.extend(Path(item) / "applications" for item in data_dirs.split(os.pathsep) if item)
    # Preserve precedence: per-user entries appear before system-wide entries.
    seen: set[str] = set()
    unique: list[Path] = []
    for path in result:
        key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


class BrowserDetector:
    """Discover supported browsers without shell execution or global preference changes."""

    def __init__(
        self, *, system: str | None = None, environ: dict[str, str] | None = None,
        custom_store: CustomBrowserStore | None = None,
    ):
        self.system = system or sys.platform
        self.environ = dict(os.environ if environ is None else environ)
        self.custom_store = custom_store or CustomBrowserStore()

    def register_custom(self, browser: Browser) -> None:
        """Persist a manually added executable for future chooser sessions."""
        self.custom_store.add(browser)

    def detect(self) -> list[Browser]:
        if self.system.lower().startswith("win"):
            found = self._detect_windows()
        elif self.system.lower().startswith("linux"):
            found = self._detect_linux()
        else:
            found = []
        by_id = {browser.id: browser for browser in found}
        for browser in self.custom_store.list():
            by_id.setdefault(browser.id, browser)
        return sorted(by_id.values(), key=lambda item: (item.family, item.name.casefold()))

    def _detect_windows(self) -> list[Browser]:
        env = {key.casefold(): value for key, value in self.environ.items()}
        roots = [
            Path(env.get("programfiles", r"C:\Program Files")),
            Path(env.get("programfiles(x86)", r"C:\Program Files (x86)")),
            Path(env.get("localappdata", str(Path.home() / "AppData" / "Local"))),
        ]
        found: dict[str, Browser] = {}

        try:
            import winreg  # type: ignore[import-not-found]

            hives = (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE)
            views = (getattr(winreg, "KEY_WOW64_64KEY", 0), getattr(winreg, "KEY_WOW64_32KEY", 0))
            for browser_id, name, family, _aliases in _ALIASES:
                executable_name = _WINDOWS_EXECUTABLES.get(browser_id)
                if not executable_name:
                    continue
                for hive in hives:
                    for view in views:
                        key_path = rf"Software\Microsoft\Windows\CurrentVersion\App Paths\{executable_name}"
                        try:
                            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view) as key:
                                value, _kind = winreg.QueryValueEx(key, "")
                        except OSError:
                            continue
                        executable = _resolve_executable(str(value))
                        if executable:
                            found.setdefault(
                                browser_id, Browser(browser_id, name, family, executable, source="registry")
                            )
                            break
                    if browser_id in found:
                        break
        except ImportError:
            pass

        for browser_id, name, family, _aliases in _ALIASES:
            for relative in _WINDOWS_CANDIDATES.get(browser_id, ()):
                for root in roots:
                    executable = root.joinpath(*relative)
                    if executable.is_file():
                        found.setdefault(
                            browser_id,
                            Browser(browser_id, name, family, str(executable.resolve()), source="known-path"),
                        )
                        break
                if browser_id in found:
                    break
            if browser_id in found:
                continue
            command = _WINDOWS_EXECUTABLES.get(browser_id)
            resolved = _resolve_executable(command) if command else None
            if resolved:
                found[browser_id] = Browser(browser_id, name, family, resolved, source="PATH")
        return sorted(found.values(), key=lambda item: (item.family, item.name.casefold()))

    def _detect_linux(self) -> list[Browser]:
        found: dict[str, Browser] = {}
        for directory in _data_application_dirs(self.environ):
            if not directory.is_dir():
                continue
            try:
                desktop_files: Iterable[Path] = sorted(directory.rglob("*.desktop"))
                for desktop_file in desktop_files:
                    parser = configparser.ConfigParser(interpolation=None, strict=False)
                    try:
                        parser.read(desktop_file, encoding="utf-8")
                        entry = parser["Desktop Entry"]
                    except (OSError, KeyError, configparser.Error):
                        continue
                    try:
                        hidden = entry.getboolean("Hidden", fallback=False)
                        no_display = entry.getboolean("NoDisplay", fallback=False)
                    except ValueError:
                        continue
                    if hidden or no_display:
                        continue
                    name = entry.get("Name", fallback=desktop_file.stem)
                    command_text = entry.get("Exec", fallback="")
                    try_exec = entry.get("TryExec", fallback="")
                    match = _match_browser(
                        " ".join((desktop_file.name, name, command_text, entry.get("StartupWMClass", fallback="")))
                    )
                    if not match:
                        continue
                    browser_id, canonical_name, family = match
                    if browser_id in found:
                        continue
                    search_path = self.environ.get("PATH")
                    if try_exec and _resolve_executable(try_exec, search_path=search_path) is None:
                        continue
                    command = _desktop_exec(command_text, search_path=search_path)
                    if command is None:
                        continue
                    executable, arguments = command
                    found[browser_id] = Browser(
                        browser_id, canonical_name, family, executable, arguments,
                        source="desktop-entry", desktop_file=str(desktop_file),
                    )
            except OSError:
                continue

        # Some minimal desktops install a browser but omit its .desktop file.
        path_commands = (
            ("google-chrome-stable", "chrome"), ("google-chrome", "chrome"),
            ("ungoogled-chromium", "ungoogled_chromium"),
            ("chromium", "chromium"), ("chromium-browser", "chromium"),
            ("microsoft-edge", "edge"), ("msedge", "edge"),
            ("brave-browser", "brave"), ("vivaldi-stable", "vivaldi"),
            ("opera", "opera"), ("opera-gx", "opera_gx"), ("yandex-browser", "yandex"),
            ("firefox-esr", "firefox_esr"), ("firefox", "firefox"),
            ("librewolf", "librewolf"), ("waterfox", "waterfox"),
            ("floorp", "floorp"), ("zen", "zen"),
        )
        names = {item[0]: (item[1], item[2]) for item in _ALIASES}
        for command, browser_id in path_commands:
            if browser_id in found:
                continue
            executable = shutil.which(command, path=self.environ.get("PATH"))
            if executable:
                name, family = names[browser_id]
                found[browser_id] = Browser(
                    browser_id, name, family, str(Path(executable).resolve()), source="PATH"
                )
        return sorted(found.values(), key=lambda item: (item.family, item.name.casefold()))
