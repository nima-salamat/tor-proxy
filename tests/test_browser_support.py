from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from torproxy.browsers import (
    Browser,
    BrowserDetector,
    BrowserLaunchError,
    BrowserLauncher,
    BrowserProfileManager,
    CustomBrowserStore,
)
from torproxy.ports import (
    PortAllocationError,
    can_bind_loopback,
    describe_port_owner,
    can_bind_loopback_udp,
    resolve_listener_ports,
)


class MemoryConfig(dict):
    def get_config(self):
        return json.dumps(self)

    def save_config(self, value):
        self.clear()
        self.update(json.loads(value))

    def update_many(self, values):
        self.update_calls = getattr(self, "update_calls", 0) + 1
        self.update(values)


def _port_config(**overrides):
    values = {
        "proxy_port": None,
        "proxy_port_checked": False,
        "tor_port": None,
        "tor_port_checked": False,
        "control_port": None,
        "control_port_checked": False,
        "dns_port": None,
        "dns_port_checked": False,
    }
    values.update(overrides)
    return MemoryConfig(values)


def test_default_allocator_reserves_four_distinct_os_ports_and_reuses_them():
    config = _port_config()

    allocated, messages = resolve_listener_ports(config)

    assert set(allocated) == {"proxy_port", "tor_port", "control_port", "dns_port"}
    assert len(set(allocated.values())) == 4
    assert all(can_bind_loopback(port) for port in allocated.values())
    assert can_bind_loopback_udp(allocated["dns_port"])
    assert all(config[key] == value for key, value in allocated.items())
    assert sum("initialized and saved" in message for message in messages) == 4

    second, second_messages = resolve_listener_ports(config)
    assert second == allocated
    assert all("reusing saved port" in message for message in second_messages)


def test_listener_ports_are_allocated_once_and_reused():
    config = _port_config()
    candidates = iter((41001, 41002, 41003, 41004))
    first, messages = resolve_listener_ports(
        config,
        available=lambda _host, _port: True,
        udp_available=lambda _host, _port: True,
        candidate_provider=lambda: next(candidates),
    )
    second, second_messages = resolve_listener_ports(
        config,
        available=lambda _host, _port: True,
        udp_available=lambda _host, _port: True,
        candidate_provider=lambda: pytest.fail("saved ports should be reused"),
    )

    assert first == {
        "proxy_port": 41001,
        "tor_port": 41002,
        "control_port": 41003,
        "dns_port": 41004,
    }
    assert second == first
    assert all("initialized and saved" in message for message in messages)
    assert all("reusing saved port" in message for message in second_messages)
    assert config.update_calls == 1


def test_automatic_port_collision_is_replaced_and_persisted():
    config = _port_config(
        proxy_port=42001,
        tor_port=42002,
        control_port=42003,
        dns_port=42004,
    )
    candidates = iter((43001,))
    allocated, messages = resolve_listener_ports(
        config,
        available=lambda _host, port: port != 42001,
        udp_available=lambda _host, _port: True,
        candidate_provider=lambda: next(candidates),
    )

    assert allocated["proxy_port"] == 43001
    assert allocated["tor_port"] == 42002
    assert config["proxy_port"] == 43001
    assert any("switched to and saved port 43001" in message for message in messages)


def test_dns_listener_reallocates_saved_port_when_udp_is_occupied():
    config = _port_config(
        proxy_port=42001,
        tor_port=42002,
        control_port=42003,
        dns_port=42004,
    )
    allocated, messages = resolve_listener_ports(
        config,
        available=lambda _host, _port: True,
        udp_available=lambda _host, port: port != 42004,
        candidate_provider=iter((43004,)).__next__,
    )

    assert allocated["dns_port"] == 43004
    assert config["dns_port"] == 43004
    assert any("saved port 42004 is unavailable" in message for message in messages)


def test_manual_port_conflict_reports_the_process_using_the_listener(monkeypatch):
    import psutil
    from types import SimpleNamespace

    connection = SimpleNamespace(
        laddr=SimpleNamespace(port=9155),
        status=psutil.CONN_LISTEN,
        pid=4242,
    )

    class FakeProcess:
        def __init__(self, pid):
            assert pid == 4242

        def name(self):
            return "tor.exe"

        def exe(self):
            return r"C:\\TorProxy\\Tor\\tor.exe"

    monkeypatch.setattr(psutil, "net_connections", lambda kind: [connection])
    monkeypatch.setattr(psutil, "Process", FakeProcess)

    owner = describe_port_owner(9155)

    assert owner is not None
    assert "tor.exe" in owner
    assert "PID 4242" in owner
    assert "C:\\TorProxy" in owner


def test_manual_port_collision_fails_without_overwriting_user_choice():
    config = _port_config(proxy_port=9050, proxy_port_checked=True)
    with pytest.raises(PortAllocationError, match="manually selected port 9050"):
        resolve_listener_ports(
            config,
            available=lambda _host, _port: False,
            udp_available=lambda _host, _port: True,
            candidate_provider=lambda: pytest.fail("manual ports must not be silently changed"),
        )
    assert config["proxy_port"] == 9050


def test_duplicate_manual_ports_fail_closed():
    config = _port_config(
        proxy_port=9050,
        proxy_port_checked=True,
        tor_port=9050,
        tor_port_checked=True,
    )
    with pytest.raises(PortAllocationError, match="duplicates"):
        resolve_listener_ports(
            config,
            available=lambda _host, _port: True,
            udp_available=lambda _host, _port: True,
            candidate_provider=lambda: pytest.fail("duplicate manual ports must not be replaced"),
        )


def test_manual_collision_can_keep_ui_available_without_persisting_temporary_value():
    config = _port_config(proxy_port=9050, proxy_port_checked=True)
    allocated, _messages = resolve_listener_ports(
        config,
        available=lambda _host, port: port != 9050,
        udp_available=lambda _host, _port: True,
        candidate_provider=iter((44001, 44002, 44003, 44004)).__next__,
        strict_manual=False,
    )
    assert allocated["proxy_port"] == 44001
    assert config["proxy_port"] == 9050


def test_windows_standard_install_paths_find_chrome_edge_and_firefox(tmp_path, monkeypatch):
    program_files = tmp_path / "Program Files"
    local = tmp_path / "Local"
    chrome = program_files / "Google" / "Chrome" / "Application" / "chrome.exe"
    edge = program_files / "Microsoft" / "Edge" / "Application" / "msedge.exe"
    firefox = local / "Mozilla Firefox" / "firefox.exe"
    ungoogled = program_files / "Ungoogled Chromium" / "Application" / "chrome.exe"
    for executable in (chrome, edge, firefox, ungoogled):
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_text("browser", encoding="utf-8")
    if os.name != "nt":
        executable.chmod(0o755)

    monkeypatch.setitem(sys.modules, "winreg", None)
    detector = BrowserDetector(
        system="win32",
        environ={
            "PROGRAMFILES": str(program_files),
            "PROGRAMFILES(X86)": str(tmp_path / "Program Files (x86)"),
            "LOCALAPPDATA": str(local),
            "APPDATA": str(tmp_path / "NoUserStartMenu"),
            "PROGRAMDATA": str(tmp_path / "NoMachineStartMenu"),
            "PATH": "",
        },
        custom_store=CustomBrowserStore(tmp_path / "custom.json"),
    )
    browsers = {item.id: item for item in detector.detect()}
    assert browsers["chrome"].executable == str(chrome)
    assert browsers["edge"].executable == str(edge)
    assert browsers["firefox"].executable == str(firefox)
    assert browsers["ungoogled_chromium"].executable == str(ungoogled)


@pytest.mark.skipif(os.name == "nt", reason="Linux desktop-entry discovery is platform-specific")
def test_windows_commandline_split_preserves_quoted_program_files_paths():
    from torproxy.browsers.detector import _windows_commandline_split

    command = r'"C:\Program Files\Opera\launcher.exe" "%1" --profile "C:\Browser Data"'
    assert _windows_commandline_split(command) == [
        r"C:\Program Files\Opera\launcher.exe",
        "%1",
        "--profile",
        r"C:\Browser Data",
    ]


@pytest.mark.skipif(os.name != "nt", reason="Exercises the native Windows CommandLineToArgvW API")
def test_windows_native_commandline_split_uses_pointer_return_type():
    from torproxy.browsers.detector import _windows_commandline_split

    command = r'"C:\Program Files\Mozilla Firefox\firefox.exe" -osint -url "https://example.org/"'
    assert _windows_commandline_split(command) == [
        r"C:\Program Files\Mozilla Firefox\firefox.exe",
        "-osint",
        "-url",
        "https://example.org/",
    ]


def test_windows_start_menu_shortcuts_find_opera_and_firefox_and_keep_their_icons(tmp_path, monkeypatch):
    from torproxy.browsers import detector as detector_module

    appdata = tmp_path / "Roaming"
    start_menu = appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    start_menu.mkdir(parents=True)
    opera = tmp_path / "Opera GX" / "launcher.exe"
    firefox = tmp_path / "Mozilla Firefox" / "firefox.exe"
    opera_icon = tmp_path / "opera.ico"
    firefox_icon = tmp_path / "firefox.ico"
    for path in (opera, firefox, opera_icon, firefox_icon):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fixture")

    records = [
        {
            "Name": "Opera GX",
            "TargetPath": str(opera),
            "Arguments": "",
            "IconLocation": f"{opera_icon},0",
            "ShortcutPath": str(start_menu / "Opera GX.lnk"),
        },
        {
            "Name": "Firefox",
            "TargetPath": str(firefox),
            "Arguments": "",
            "IconLocation": f"{firefox_icon},0",
            "ShortcutPath": str(start_menu / "Firefox.lnk"),
        },
    ]
    monkeypatch.setattr(
        detector_module.shutil,
        "which",
        lambda command, path=None: "powershell.exe" if command.casefold() == "powershell.exe" else None,
    )
    monkeypatch.setattr(
        detector_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(records),
        ),
    )
    monkeypatch.setitem(sys.modules, "winreg", None)

    detector = BrowserDetector(
        system="win32",
        environ={
            "APPDATA": str(appdata),
            "PROGRAMDATA": str(tmp_path / "ProgramData"),
            "PROGRAMFILES": str(tmp_path / "Program Files"),
            "PROGRAMFILES(X86)": str(tmp_path / "Program Files (x86)"),
            "LOCALAPPDATA": str(tmp_path / "Local"),
            "APPDATA": str(tmp_path / "NoUserStartMenu"),
            "PROGRAMDATA": str(tmp_path / "NoMachineStartMenu"),
            "PATH": "",
        },
        custom_store=CustomBrowserStore(tmp_path / "custom.json"),
    )
    browsers = {item.id: item for item in detector.detect()}

    assert browsers["opera_gx"].executable == str(opera)
    assert browsers["opera_gx"].source == "start-menu-shortcut"
    assert browsers["opera_gx"].icon == str(opera_icon)
    assert browsers["firefox"].executable == str(firefox)
    assert browsers["firefox"].source == "start-menu-shortcut"
    assert browsers["firefox"].icon == str(firefox_icon)


def test_windows_start_menu_internet_registry_detects_opera_and_firefox(tmp_path, monkeypatch):
    opera = tmp_path / "Opera" / "launcher.exe"
    firefox = tmp_path / "Firefox" / "firefox.exe"
    for path in (opera, firefox):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fixture")

    root_path = r"Software\Clients\StartMenuInternet"
    values = {
        ("HKLM", root_path): {},
        ("HKLM", root_path + r"\Opera"): {"": "Opera"},
        ("HKLM", root_path + r"\Opera\shell\open\command"): {"": f'"{opera}" "%1"'},
        ("HKLM", root_path + r"\Firefox"): {"": "Mozilla Firefox"},
        ("HKLM", root_path + r"\Firefox\shell\open\command"): {"": f'"{firefox}" "%1"'},
    }
    children = {
        ("HKLM", root_path): ["Opera", "Firefox"],
    }

    class FakeKey:
        def __init__(self, hive, path):
            self.hive = hive
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class FakeWinreg:
        HKEY_CURRENT_USER = "HKCU"
        HKEY_LOCAL_MACHINE = "HKLM"
        KEY_READ = 1
        KEY_WOW64_64KEY = 2
        KEY_WOW64_32KEY = 4

        @staticmethod
        def OpenKey(parent, path, *_args):
            if isinstance(parent, FakeKey):
                hive, full_path = parent.hive, parent.path + "\\" + path
            else:
                hive, full_path = parent, path
            if (hive, full_path) not in values and (hive, full_path) not in children:
                raise OSError("registry key not found")
            return FakeKey(hive, full_path)

        @staticmethod
        def QueryInfoKey(key):
            return (len(children.get((key.hive, key.path), [])), 0, 0)

        @staticmethod
        def EnumKey(key, index):
            return children[(key.hive, key.path)][index]

        @staticmethod
        def QueryValueEx(key, name):
            return values[(key.hive, key.path)][name], 1

    monkeypatch.setitem(sys.modules, "winreg", FakeWinreg)
    detector = BrowserDetector(
        system="win32",
        environ={
            "PROGRAMFILES": str(tmp_path / "Program Files"),
            "PROGRAMFILES(X86)": str(tmp_path / "Program Files (x86)"),
            "LOCALAPPDATA": str(tmp_path / "Local"),
            "PATH": "",
        },
        custom_store=CustomBrowserStore(tmp_path / "custom.json"),
    )
    browsers = {item.id: item for item in detector.detect()}

    assert browsers["opera"].executable == str(opera)
    assert browsers["opera"].source == "start-menu-registration"
    assert browsers["firefox"].executable == str(firefox)
    assert browsers["firefox"].source == "start-menu-registration"


def test_linux_desktop_entries_are_parsed_without_a_shell(tmp_path):
    data_home = tmp_path / "data"
    applications = data_home / "applications"
    applications.mkdir(parents=True)
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    flatpak = binary_dir / "flatpak"
    flatpak.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    flatpak.chmod(0o755)
    opera = binary_dir / "opera"
    firefox = binary_dir / "firefox"
    for executable in (opera, firefox):
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)

    entry = applications / "google-chrome.desktop"
    entry.write_text(
        "[Desktop Entry]\n"
        "Name=Google Chrome\n"
        "Type=Application\n"
        "TryExec=flatpak\n"
        "Exec=flatpak run com.google.Chrome %U\n",
        encoding="utf-8",
    )
    opera_entry = applications / "opera.desktop"
    opera_entry.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Opera Web Browser\n"
        "TryExec=opera\n"
        "Exec=opera %U\n"
        "Icon=opera-browser\n",
        encoding="utf-8",
    )
    firefox_entry = applications / "firefox.desktop"
    firefox_entry.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Firefox Web Browser\n"
        "TryExec=firefox\n"
        "Exec=firefox %u\n"
        "Icon=firefox-browser\n",
        encoding="utf-8",
    )

    detector = BrowserDetector(
        system="linux",
        environ={
            "HOME": str(tmp_path),
            "XDG_DATA_HOME": str(data_home),
            "XDG_DATA_DIRS": "",
            "PATH": str(binary_dir),
        },
        custom_store=CustomBrowserStore(tmp_path / "custom.json"),
    )
    browsers = detector.detect()
    chrome = next(item for item in browsers if item.id == "chrome")
    assert chrome.executable == str(flatpak)
    assert chrome.arguments == ("run", "com.google.Chrome")
    assert chrome.source == "desktop-entry"

    opera_browser = next(item for item in browsers if item.id == "opera")
    firefox_browser = next(item for item in browsers if item.id == "firefox")
    assert opera_browser.executable == str(opera)
    assert opera_browser.icon == "opera-browser"
    assert firefox_browser.executable == str(firefox)
    assert firefox_browser.icon == "firefox-browser"


def test_firefox_profile_keeps_user_settings_and_replaces_managed_proxy_block(tmp_path):
    profiles = BrowserProfileManager(tmp_path)
    profile = profiles.profile_path("firefox", 45001)
    (profile / "user.js").write_text('user_pref("browser.startup.homepage", "https://example.org");\n', encoding="utf-8")

    profiles.configure_firefox("firefox", 45001)
    profiles.configure_firefox("firefox", 45001)
    content = (profile / "user.js").read_text(encoding="utf-8")
    replacement_profile = profiles.configure_firefox("firefox", 45002)
    replacement_content = (replacement_profile / "user.js").read_text(encoding="utf-8")

    assert 'user_pref("browser.startup.homepage", "https://example.org");' in content
    assert 'user_pref("network.proxy.http_port", 45001);' in content
    assert content.count("// TorProxy managed proxy settings - begin") == 1
    assert content.count("// TorProxy managed proxy settings - end") == 1
    assert 'user_pref("network.proxy.no_proxies_on", "");' in content
    assert 'user_pref("network.proxy.failover_direct", false);' in content
    assert 'user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);' in content
    assert 'user_pref("media.peerconnection.ice.no_host", true);' in content
    assert 'user_pref("media.peerconnection.ice.default_address_only", true);' in content
    assert replacement_profile != profile
    assert 'user_pref("network.proxy.http_port", 45002);' in replacement_content


def test_browser_profiles_are_separated_when_proxy_port_changes(tmp_path):
    profiles = BrowserProfileManager(tmp_path)
    old_profile = profiles.profile_path("chrome", 45101)
    new_profile = profiles.profile_path("chrome", 45102)
    assert old_profile != new_profile
    assert old_profile.parent == new_profile.parent


def test_chromium_launch_uses_isolated_profile_and_single_non_direct_proxy(tmp_path):
    executable = tmp_path / "chrome"
    executable.write_text("browser", encoding="utf-8")
    if os.name != "nt":
        executable.chmod(0o755)
    captured = {}

    class Process:
        pid = 1234

    def popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return Process()

    launcher = BrowserLauncher(
        BrowserProfileManager(tmp_path / "profiles"),
        proxy_probe=lambda host, port: (host, port) == ("127.0.0.1", 45003),
        popen=popen,
    )
    browser = Browser(
        "chrome", "Chrome", "chromium", str(executable),
        arguments=(
            "--proxy-server=direct://",
            "--no-proxy-server",
            "--proxy-bypass-list", "*",
            "--user-data-dir=/tmp/unmanaged-profile",
            "--profile-directory=Default",
        ),
    )
    assert launcher.launch(browser, 45003, "https://check.torproject.org/") == 1234

    command = captured["command"]
    assert command[0] == str(executable)
    assert command.count("--proxy-server=http://127.0.0.1:45003") == 1
    assert "--no-proxy-server" not in command
    assert "--proxy-bypass-list" not in command
    assert sum(item.startswith("--user-data-dir=") for item in command) == 1
    assert not any("unmanaged-profile" in item or "profile-directory" in item for item in command)
    assert "direct://" not in ",".join(command).lower()
    assert "--webrtc-ip-handling-policy=disable_non_proxied_udp" in command
    assert command[-1] == "https://check.torproject.org/"
    assert captured["kwargs"]["shell"] is False


def test_firefox_launch_configures_manual_proxy_without_touching_other_profile(tmp_path):
    executable = tmp_path / "firefox"
    executable.write_text("browser", encoding="utf-8")
    if os.name != "nt":
        executable.chmod(0o755)
    captured = {}

    class Process:
        pid = 5678

    def popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return Process()

    launcher = BrowserLauncher(
        BrowserProfileManager(tmp_path / "profiles"),
        proxy_probe=lambda _host, _port: True,
        popen=popen,
    )
    browser = Browser(
        "firefox", "Firefox", "firefox", str(executable),
        arguments=("--no-remote", "--profile", "/unmanaged/profile", "--new-instance"),
    )
    launcher.launch(browser, 45004)

    command = captured["command"]
    profile = Path(command[command.index("--profile") + 1])
    prefs = (profile / "user.js").read_text(encoding="utf-8")
    assert "--no-remote" not in command
    assert "--new-instance" not in command
    assert command.count("--profile") == 1
    assert "/unmanaged/profile" not in command
    assert 'user_pref("network.proxy.type", 1);' in prefs
    assert 'user_pref("network.proxy.http_port", 45004);' in prefs
    assert 'user_pref("network.proxy.failover_direct", false);' in prefs
    assert 'user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);' in prefs
    _second_executable, second_arguments = launcher.build_command(browser, 45004)
    second_profile = Path(second_arguments[second_arguments.index("--profile") + 1])
    assert second_profile == profile
    assert "--no-remote" not in command
    assert command[0] == str(executable)
    assert captured["kwargs"]["shell"] is False


def test_browser_launch_is_refused_when_proxy_is_not_listening(tmp_path):
    executable = tmp_path / "chrome"
    executable.write_text("browser", encoding="utf-8")
    if os.name != "nt":
        executable.chmod(0o755)
    launcher = BrowserLauncher(
        BrowserProfileManager(tmp_path / "profiles"),
        proxy_probe=lambda _host, _port: False,
        popen=lambda *_args, **_kwargs: pytest.fail("browser must not launch"),
    )
    browser = Browser("chrome", "Chrome", "chromium", str(executable))
    with pytest.raises(BrowserLaunchError, match="not responding"):
        launcher.launch(browser, 45005)


def test_tor_browser_is_rejected_as_a_managed_browser(tmp_path):
    executable = tmp_path / "Tor Browser" / "Browser" / "firefox"
    executable.parent.mkdir(parents=True)
    executable.write_text("browser", encoding="utf-8")
    if os.name != "nt":
        executable.chmod(0o755)
    launcher = BrowserLauncher(BrowserProfileManager(tmp_path / "profiles"))
    browser = Browser("tor-browser", "Tor Browser", "firefox", str(executable))
    with pytest.raises(BrowserLaunchError, match="own Tor stack"):
        launcher.build_command(browser, 45006)


def test_browser_url_must_be_http_or_https(tmp_path):
    executable = tmp_path / "chrome"
    executable.write_text("browser", encoding="utf-8")
    if os.name != "nt":
        executable.chmod(0o755)
    launcher = BrowserLauncher(BrowserProfileManager(tmp_path / "profiles"))
    browser = Browser("chrome", "Chrome", "chromium", str(executable))
    with pytest.raises(BrowserLaunchError, match="HTTP or HTTPS"):
        launcher.build_command(browser, 45006, "javascript:alert(1)")


def test_home_open_browser_button_requires_verified_tor_and_persistent_listener_ports():
    repository = Path(__file__).resolve().parents[1]
    home_source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    ports_source = (repository / "src/torproxy/ports.py").read_text(encoding="utf-8")
    dialog_source = (repository / "ui_/window/open_browser_dialog.py").read_text(encoding="utf-8")
    assert 'self.btn_open_browser = QPushButton' in home_source
    assert "self.btn_open_browser.clicked.connect(self.open_browser_dialog)" in home_source
    assert "self.running and self.connected" in home_source
    assert "resolve_listener_ports(" in home_source
    assert "strict_manual=False" in home_source
    assert "strict_manual=True" in home_source
    assert "reusing saved port" in ports_source
    assert "switched to and saved port" in ports_source
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    assert "network.proxy.failover_direct" not in home_source
    assert "def sync_listener_ports" in settings_source
    assert "TorProxy automatically selects and remembers distinct loopback ports." in settings_source
    assert "Enter a port between 1 and 65535" in settings_source
    assert "can_bind_loopback_udp" in ports_source
    assert "udp_available" in ports_source
    assert "Open Browser" in dialog_source
    assert "start_page_input" in dialog_source
    assert "register_custom" in dialog_source


def test_custom_browser_store_persists_and_reloads_entries(tmp_path):
    executable = tmp_path / "custom-browser"
    executable.write_text("browser", encoding="utf-8")
    if os.name != "nt":
        executable.chmod(0o755)
    store = CustomBrowserStore(tmp_path / "custom_browsers.json")
    browser = Browser("custom-test", "Custom Browser", "chromium", str(executable), source="custom")
    store.add(browser)

    reloaded = CustomBrowserStore(tmp_path / "custom_browsers.json").list()
    assert reloaded == [browser]
    if os.name != "nt":
        assert (tmp_path / "custom_browsers.json").stat().st_mode & 0o077 == 0
