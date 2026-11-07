"""Cross-platform discovery for installed Chromium and Firefox-family browsers."""
from __future__ import annotations

import configparser
import ctypes
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

from .models import Browser
from .registry import CustomBrowserStore


# Long/specific aliases are intentionally checked before generic browser names.
_ALIASES = (
    ("opera_gx", "Opera GX", "chromium", ("opera gx", "operagx")),
    ("ungoogled_chromium", "Ungoogled Chromium", "chromium", ("ungoogled",)),
    ("firefox_esr", "Firefox ESR", "firefox", ("firefox-esr", "firefox esr")),
    ("yandex", "Yandex Browser", "chromium", ("yandex",)),
    ("vivaldi", "Vivaldi", "chromium", ("vivaldi",)),
    ("brave", "Brave", "chromium", ("brave",)),
    ("edge", "Microsoft Edge", "chromium", ("microsoft edge", "msedge")),
    ("chrome", "Google Chrome", "chromium", ("google chrome", "google-chrome", "chrome.exe")),
    ("chromium", "Chromium", "chromium", ("chromium",)),
    ("librewolf", "LibreWolf", "firefox", ("librewolf",)),
    ("waterfox", "Waterfox", "firefox", ("waterfox",)),
    ("floorp", "Floorp", "firefox", ("floorp",)),
    ("zen", "Zen Browser", "firefox", ("zen browser", "zen-browser", "zen.exe")),
    ("opera", "Opera", "chromium", ("opera",)),
    ("firefox", "Firefox", "firefox", ("mozilla firefox", "firefox")),
)

_WINDOWS_CANDIDATES = {
    "chrome": (("Google", "Chrome", "Application", "chrome.exe"),),
    "chromium": (("Chromium", "Application", "chrome.exe"), ("Chromium", "chrome.exe")),
    "edge": (("Microsoft", "Edge", "Application", "msedge.exe"),),
    "brave": (("BraveSoftware", "Brave-Browser", "Application", "brave.exe"),),
    "vivaldi": (("Vivaldi", "Application", "vivaldi.exe"),),
    "opera": (
        ("Programs", "Opera", "launcher.exe"),
        ("Programs", "Opera", "opera.exe"),
        ("Opera", "launcher.exe"),
        ("Opera", "opera.exe"),
    ),
    "opera_gx": (
        ("Programs", "Opera GX", "launcher.exe"),
        ("Programs", "Opera GX", "opera.exe"),
        ("Opera GX", "launcher.exe"),
        ("Opera GX", "opera.exe"),
    ),
    "yandex": (("Yandex", "YandexBrowser", "Application", "browser.exe"),),
    "ungoogled_chromium": (
        ("Ungoogled Chromium", "Application", "chrome.exe"),
        ("Ungoogled Chromium", "chrome.exe"),
    ),
    "firefox": (
        ("Mozilla Firefox", "firefox.exe"),
        ("Programs", "Mozilla Firefox", "firefox.exe"),
    ),
    "firefox_esr": (
        ("Mozilla Firefox ESR", "firefox.exe"),
        ("Programs", "Mozilla Firefox ESR", "firefox.exe"),
    ),
    "librewolf": (("LibreWolf", "librewolf.exe"),),
    "waterfox": (("Waterfox", "waterfox.exe"),),
    "floorp": (("Floorp", "floorp.exe"),),
    "zen": (("Zen", "zen.exe"), ("Zen Browser", "zen.exe")),
}
_WINDOWS_EXECUTABLES = {
    "chrome": ("chrome.exe",),
    "edge": ("msedge.exe",),
    "brave": ("brave.exe",),
    "vivaldi": ("vivaldi.exe",),
    "yandex": ("browser.exe",),
    "ungoogled_chromium": ("chrome.exe",),
    "firefox": ("firefox.exe",),
    "firefox_esr": ("firefox.exe",),
    "librewolf": ("librewolf.exe",),
    "waterfox": ("waterfox.exe",),
    "floorp": ("floorp.exe",),
    "zen": ("zen.exe",),
}
_WINDOWS_INSTALL_EXECUTABLES = {
    "chrome": ("Application", "chrome.exe"),
    "chromium": ("chrome.exe",),
    "edge": ("Application", "msedge.exe"),
    "brave": ("Application", "brave.exe"),
    "vivaldi": ("vivaldi.exe",),
    "opera": ("launcher.exe", "opera.exe"),
    "opera_gx": ("launcher.exe", "opera.exe"),
    "yandex": ("Application", "browser.exe"),
    "ungoogled_chromium": ("chrome.exe",),
    "firefox": ("firefox.exe",),
    "firefox_esr": ("firefox.exe",),
    "librewolf": ("librewolf.exe",),
    "waterfox": ("waterfox.exe",),
    "floorp": ("floorp.exe",),
    "zen": ("zen.exe",),
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
        tokens = shlex.split(value, posix=True)
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


def _windows_commandline_split(value: str) -> list[str]:
    """Split a Windows command line using the native parser when available."""
    command = str(value or "").strip()
    if not command:
        return []
    if os.name == "nt":
        argc = ctypes.c_int()
        argv = ctypes.windll.shell32.CommandLineToArgvW(command, ctypes.byref(argc))
        if argv:
            try:
                return [str(argv[index]) for index in range(argc.value)]
            finally:
                ctypes.windll.kernel32.LocalFree(argv)
    try:
        return [token.strip('"') for token in shlex.split(command, posix=False)]
    except ValueError:
        return []


def _clean_windows_icon(value: str | None) -> str | None:
    icon = str(value or "").strip().strip('"')
    if not icon:
        return None
    # DefaultIcon and .lnk IconLocation commonly append a resource index.
    icon = re.sub(r",\s*-?\d+\s*$", "", icon).strip().strip('"')
    path = Path(os.path.expandvars(icon))
    return str(path.resolve()) if path.is_file() else None


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
    seen: set[str] = set()
    unique: list[Path] = []
    for path in result:
        key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


class BrowserDetector:
    """Discover browsers from Windows registrations/Start Menu or Linux XDG entries."""

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
        system = self.system.lower()
        if system.startswith("win"):
            found = self._detect_windows()
        elif system.startswith("linux"):
            found = self._detect_linux()
        else:
            found = []
        by_id = {browser.id: browser for browser in found}
        for browser in self.custom_store.list():
            by_id.setdefault(browser.id, browser)
        return sorted(by_id.values(), key=lambda item: (item.family, item.name.casefold()))

    @staticmethod
    def _merge_browser(found: dict[str, Browser], browser: Browser, *, prefer: bool = False) -> None:
        existing = found.get(browser.id)
        if existing is None or prefer:
            found[browser.id] = browser
            return
        if not existing.icon and browser.icon:
            found[browser.id] = Browser(
                existing.id,
                existing.name,
                existing.family,
                existing.executable,
                existing.arguments,
                existing.source,
                existing.desktop_file,
                browser.icon,
            )

    def _detect_windows(self) -> list[Browser]:
        env = {key.casefold(): value for key, value in self.environ.items()}
        roots = [
            Path(env.get("programfiles", r"C:\Program Files")),
            Path(env.get("programfiles(x86)", r"C:\Program Files (x86)")),
            Path(env.get("localappdata", str(Path.home() / "AppData" / "Local"))),
        ]
        found: dict[str, Browser] = {}

        self._detect_windows_start_menu_internet(found)
        self._detect_windows_app_paths(found)
        self._detect_windows_uninstall_entries(found, roots)

        for browser_id, name, family, _aliases in _ALIASES:
            if browser_id in found:
                continue
            for relative in _WINDOWS_CANDIDATES.get(browser_id, ()):
                for root in roots:
                    executable = root.joinpath(*relative)
                    if executable.is_file():
                        self._merge_browser(
                            found,
                            Browser(
                                browser_id, name, family, str(executable.resolve()),
                                source="known-path", icon=str(executable.resolve()),
                            ),
                        )
                        break
                if browser_id in found:
                    break

        self._detect_windows_start_menu_shortcuts(found)
        return sorted(found.values(), key=lambda item: (item.family, item.name.casefold()))

    def _detect_windows_start_menu_internet(self, found: dict[str, Browser]) -> None:
        """Read the browser list registered with Windows' StartMenuInternet shell."""
        try:
            import winreg  # type: ignore[import-not-found]
        except ImportError:
            return

        base = r"Software\Clients\StartMenuInternet"
        hives = (
            ("HKCU", winreg.HKEY_CURRENT_USER),
            ("HKLM", winreg.HKEY_LOCAL_MACHINE),
        )
        views = (
            getattr(winreg, "KEY_WOW64_64KEY", 0),
            getattr(winreg, "KEY_WOW64_32KEY", 0),
        )
        seen: set[tuple[str, str]] = set()
        for hive_name, hive in hives:
            for view in dict.fromkeys(views):
                try:
                    with winreg.OpenKey(hive, base, 0, winreg.KEY_READ | view) as root:
                        count = winreg.QueryInfoKey(root)[0]
                        for index in range(count):
                            try:
                                subkey_name = winreg.EnumKey(root, index)
                                identity = (hive_name, subkey_name.casefold())
                                if identity in seen:
                                    continue
                                seen.add(identity)
                                with winreg.OpenKey(root, subkey_name) as app_key:
                                    try:
                                        display_name = str(winreg.QueryValueEx(app_key, "")[0])
                                    except OSError:
                                        display_name = subkey_name
                                command_key = base + "\\" + subkey_name + r"\shell\open\command"
                                icon_key = base + "\\" + subkey_name + r"\DefaultIcon"
                                with winreg.OpenKey(hive, command_key, 0, winreg.KEY_READ | view) as command_handle:
                                    command_line = str(winreg.QueryValueEx(command_handle, "")[0])
                                tokens = _windows_commandline_split(command_line)
                                if not tokens:
                                    continue
                                executable = _resolve_executable(tokens[0])
                                if not executable:
                                    continue
                                match = _match_browser(" ".join((subkey_name, display_name, executable)))
                                if not match:
                                    continue
                                browser_id, name, family = match
                                arguments = tuple(arg for arg in tokens[1:] if not arg.startswith("%"))
                                icon_path = None
                                try:
                                    with winreg.OpenKey(hive, icon_key, 0, winreg.KEY_READ | view) as icon_handle:
                                        icon_path = _clean_windows_icon(str(winreg.QueryValueEx(icon_handle, "")[0]))
                                except OSError:
                                    pass
                                self._merge_browser(
                                    found,
                                    Browser(
                                        browser_id, name, family, executable, arguments,
                                        source="start-menu-registration", icon=icon_path or executable,
                                    ),
                                )
                            except OSError:
                                continue
                except OSError:
                    continue

    def _detect_windows_app_paths(self, found: dict[str, Browser]) -> None:
        """Use registered executable paths, excluding ambiguous launcher.exe entries."""
        try:
            import winreg  # type: ignore[import-not-found]
        except ImportError:
            return

        base = r"Software\Microsoft\Windows\CurrentVersion\App Paths"
        hives = (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE)
        views = dict.fromkeys((
            getattr(winreg, "KEY_WOW64_64KEY", 0),
            getattr(winreg, "KEY_WOW64_32KEY", 0),
        ))
        for browser_id, executable_names in _WINDOWS_EXECUTABLES.items():
            alias = next(item for item in _ALIASES if item[0] == browser_id)
            _identifier, name, family, _ = alias
            for hive in hives:
                for view in views:
                    for executable_name in executable_names:
                        try:
                            with winreg.OpenKey(
                                hive, base + "\\" + executable_name, 0, winreg.KEY_READ | view
                            ) as key:
                                value = str(winreg.QueryValueEx(key, "")[0])
                        except OSError:
                            continue
                        executable = _resolve_executable(value)
                        if executable:
                            self._merge_browser(
                                found,
                                Browser(
                                    browser_id, name, family, executable,
                                    source="registry-app-paths", icon=executable,
                                ),
                            )
                            break
                    if browser_id in found:
                        break
                if browser_id in found:
                    break

    def _detect_windows_uninstall_entries(
        self, found: dict[str, Browser], roots: list[Path]
    ) -> None:
        """Use standard uninstall metadata to cover custom and per-user install folders."""
        try:
            import winreg  # type: ignore[import-not-found]
        except ImportError:
            return

        uninstall_roots = (
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        )
        hives = (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE)
        views = dict.fromkeys((
            getattr(winreg, "KEY_WOW64_64KEY", 0),
            getattr(winreg, "KEY_WOW64_32KEY", 0),
        ))
        for hive in hives:
            for view in views:
                for uninstall_root in uninstall_roots:
                    try:
                        with winreg.OpenKey(hive, uninstall_root, 0, winreg.KEY_READ | view) as root:
                            count = winreg.QueryInfoKey(root)[0]
                            subkeys = [winreg.EnumKey(root, index) for index in range(count)]
                    except OSError:
                        continue
                    for subkey in subkeys:
                        try:
                            with winreg.OpenKey(
                                hive, uninstall_root + "\\" + subkey, 0, winreg.KEY_READ | view
                            ) as item:
                                values = {}
                                for value_name in ("DisplayName", "InstallLocation", "DisplayIcon"):
                                    try:
                                        values[value_name] = str(winreg.QueryValueEx(item, value_name)[0])
                                    except OSError:
                                        values[value_name] = ""
                        except OSError:
                            continue
                        match = _match_browser(" ".join((values["DisplayName"], subkey)))
                        if not match:
                            continue
                        browser_id, name, family = match
                        if browser_id in found:
                            continue
                        icon = _clean_windows_icon(values.get("DisplayIcon"))
                        candidates: list[Path] = []
                        if icon:
                            candidates.append(Path(icon))
                        install_location = Path(os.path.expandvars(values.get("InstallLocation") or ""))
                        if values.get("InstallLocation"):
                            candidates.extend(
                                install_location.joinpath(*relative)
                                for relative in (
                                    _WINDOWS_INSTALL_EXECUTABLES.get(browser_id, ()),
                                )
                            )
                            candidates.extend(
                                install_location.joinpath(*relative)
                                for relative in _WINDOWS_CANDIDATES.get(browser_id, ())
                            )
                        for root_path in roots:
                            candidates.extend(
                                root_path.joinpath(*relative)
                                for relative in _WINDOWS_CANDIDATES.get(browser_id, ())
                            )
                        executable = next(
                            (str(candidate.resolve()) for candidate in candidates if candidate.is_file()),
                            None,
                        )
                        if executable:
                            self._merge_browser(
                                found,
                                Browser(
                                    browser_id, name, family, executable,
                                    source="uninstall-registry", icon=icon or executable,
                                ),
                            )

    def _windows_start_menu_roots(self) -> list[Path]:
        env = {key.casefold(): value for key, value in self.environ.items()}
        roots = []
        appdata = env.get("appdata")
        programdata = env.get("programdata")
        if appdata:
            roots.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs")
        if programdata:
            roots.append(Path(programdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs")
        if not roots:
            home = Path(env.get("userprofile") or Path.home())
            roots.append(home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs")
        return [path for path in roots if path.is_dir()]

    def _detect_windows_start_menu_shortcuts(self, found: dict[str, Browser]) -> None:
        """Read Start Menu .lnk metadata through Windows Script Host, when available."""
        roots = self._windows_start_menu_roots()
        if not roots:
            return
        powershell = shutil.which("powershell.exe", path=self.environ.get("PATH"))
        if not powershell:
            powershell = shutil.which("powershell.exe")
        if not powershell:
            return

        script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$roots = ConvertFrom-Json $env:TORPROXY_START_MENU_ROOTS
$wsh = New-Object -ComObject WScript.Shell
$entries = New-Object System.Collections.Generic.List[object]
foreach ($root in $roots) {
    if (Test-Path -LiteralPath $root) {
        Get-ChildItem -LiteralPath $root -Filter '*.lnk' -File -Recurse | ForEach-Object {
            try {
                $link = $wsh.CreateShortcut($_.FullName)
                if ($link.TargetPath) {
                    $entries.Add([pscustomobject]@{
                        Name = $_.BaseName
                        TargetPath = $link.TargetPath
                        Arguments = $link.Arguments
                        IconLocation = $link.IconLocation
                        ShortcutPath = $_.FullName
                    })
                }
            } catch {}
        }
    }
}
ConvertTo-Json -InputObject @($entries) -Compress -Depth 3
"""
        env = dict(os.environ)
        env["TORPROXY_START_MENU_ROOTS"] = json.dumps([str(path) for path in roots])
        try:
            result = subprocess.run(
                [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=8,
                check=False,
                shell=False,
                env=env,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError):
            return
        if result.returncode != 0 or not result.stdout.strip():
            return
        try:
            records = json.loads(result.stdout)
        except json.JSONDecodeError:
            return
        if isinstance(records, dict):
            records = [records]
        if not isinstance(records, list):
            return

        for record in records:
            if not isinstance(record, dict):
                continue
            target = str(record.get("TargetPath") or "")
            shortcut_name = str(record.get("Name") or "")
            match = _match_browser(" ".join((shortcut_name, target)))
            if not match:
                continue
            browser_id, name, family = match
            executable = _resolve_executable(target)
            if not executable:
                continue
            arguments = tuple(
                item for item in _windows_commandline_split(str(record.get("Arguments") or ""))
                if not item.startswith("%")
            )
            icon = _clean_windows_icon(str(record.get("IconLocation") or "")) or executable
            self._merge_browser(
                found,
                Browser(
                    browser_id, name, family, executable, arguments,
                    source="start-menu-shortcut", icon=icon,
                ),
                prefer=browser_id not in found or found[browser_id].source in {
                    "known-path", "registry-app-paths", "uninstall-registry"
                },
            )

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
                    if entry.get("Type", fallback="Application").casefold() != "application":
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
                        " ".join((
                            desktop_file.name,
                            name,
                            command_text,
                            entry.get("StartupWMClass", fallback=""),
                        ))
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
                    icon_value = entry.get("Icon", fallback="").strip()
                    icon_path = _clean_windows_icon(icon_value) if os.name == "nt" else (
                        str(Path(icon_value).expanduser()) if Path(icon_value).expanduser().is_file() else icon_value or None
                    )
                    found[browser_id] = Browser(
                        browser_id,
                        canonical_name,
                        family,
                        executable,
                        arguments,
                        source="desktop-entry",
                        desktop_file=str(desktop_file),
                        icon=icon_path,
                    )
            except OSError:
                continue

        # PATH remains a useful fallback for minimal WM/package installations.
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
                    browser_id,
                    name,
                    family,
                    str(Path(executable).resolve()),
                    source="PATH",
                )
        return sorted(found.values(), key=lambda item: (item.family, item.name.casefold()))
