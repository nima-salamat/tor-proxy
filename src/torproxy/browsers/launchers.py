"""Safe process launching for browser-specific TorProxy profiles."""
from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from .models import Browser
from .profiles import BrowserProfileManager


class BrowserLaunchError(RuntimeError):
    """A browser could not be launched through TorProxy."""


class BrowserLauncher:
    def __init__(
        self,
        profile_manager: BrowserProfileManager | None = None,
        *,
        proxy_probe=None,
        popen=None,
    ):
        self.profiles = profile_manager or BrowserProfileManager()
        self._proxy_probe = proxy_probe or self._default_proxy_probe
        self._popen = popen or subprocess.Popen

    @staticmethod
    def _default_proxy_probe(host: str, port: int, timeout: float = 0.8) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    @staticmethod
    def _validate_url(url: str | None) -> str | None:
        value = str(url or "").strip()
        if not value:
            return None
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise BrowserLaunchError("Enter a complete HTTP or HTTPS address.")
        if parsed.username or parsed.password:
            raise BrowserLaunchError("Addresses containing embedded credentials are not accepted.")
        return value

    @staticmethod
    def _chromium_base_arguments(arguments: tuple[str, ...]) -> list[str]:
        """Strip desktop-entry proxy overrides so TorProxy remains the only route."""
        value_flags = {
            "--proxy-server",
            "--proxy-pac-url",
            "--proxy-bypass-list",
            "--user-data-dir",
            "--profile-directory",
        }
        switch_flags = {"--no-proxy-server"}
        cleaned: list[str] = []
        skip_value = False
        for argument in arguments:
            value = str(argument)
            lowered = value.casefold()
            if skip_value:
                skip_value = False
                continue
            if lowered in value_flags:
                skip_value = True
                continue
            if lowered in switch_flags:
                continue
            if any(lowered.startswith(flag + "=") for flag in value_flags):
                continue
            cleaned.append(value)
        return cleaned

    @staticmethod
    def _firefox_base_arguments(arguments: tuple[str, ...]) -> list[str]:
        """Remove profile/instance overrides from desktop-entry arguments."""
        value_flags = {"--profile", "-profile", "-p"}
        switch_flags = {"--no-remote", "-no-remote", "--new-instance", "-new-instance"}
        cleaned: list[str] = []
        skip_value = False
        for argument in arguments:
            value = str(argument)
            lowered = value.casefold()
            if skip_value:
                skip_value = False
                continue
            if lowered in value_flags:
                skip_value = True
                continue
            if lowered in switch_flags:
                continue
            if any(lowered.startswith(flag + "=") for flag in value_flags):
                continue
            cleaned.append(value)
        return cleaned

    def build_command(
        self, browser: Browser, proxy_port: int, url: str | None = None
    ) -> tuple[str, list[str]]:
        if type(proxy_port) is not int or not 1 <= proxy_port <= 65535:
            raise BrowserLaunchError("The local HTTP proxy port is invalid.")
        browser_identity = " ".join((browser.id, browser.name, browser.executable)).casefold()
        if any(marker in browser_identity for marker in ("tor browser", "tor-browser", "torbrowser")):
            raise BrowserLaunchError(
                "Tor Browser is not managed by Open Browser because it ships its own Tor stack and profile."
            )
        executable = Path(browser.executable)
        if not executable.is_file() and not os.path.isabs(browser.executable):
            # Desktop entries may resolve a command from PATH during detection.
            raise BrowserLaunchError(f"Browser executable is no longer available: {browser.executable}")
        if not executable.is_file():
            raise BrowserLaunchError(f"Browser executable is no longer available: {browser.executable}")
        if os.name != "nt" and not os.access(executable, os.X_OK):
            raise BrowserLaunchError(f"Browser executable is not marked executable: {browser.executable}")

        validated_url = self._validate_url(url)
        profile = self.profiles.profile_path(browser.id, proxy_port)
        arguments = list(browser.arguments)
        if browser.family == "chromium":
            arguments = self._chromium_base_arguments(tuple(arguments))
            arguments.extend((
                f"--proxy-server=http://127.0.0.1:{proxy_port}",
                f"--user-data-dir={profile}",
                "--no-first-run",
                "--no-default-browser-check",
                "--webrtc-ip-handling-policy=disable_non_proxied_udp",
            ))
        elif browser.family == "firefox":
            arguments = self._firefox_base_arguments(tuple(arguments))
            profile = self.profiles.configure_firefox(browser.id, proxy_port)
            arguments.extend(("--profile", str(profile)))
        else:
            raise BrowserLaunchError(f"Unsupported browser family: {browser.family}")

        if validated_url:
            arguments.append(validated_url)
        return browser.executable, arguments

    def launch(self, browser: Browser, proxy_port: int, url: str | None = None) -> int | None:
        if not self._proxy_probe("127.0.0.1", proxy_port):
            raise BrowserLaunchError(
                "The TorProxy HTTP listener is not responding. Reconnect Tor before opening a browser."
            )
        executable, arguments = self.build_command(browser, proxy_port, url)
        options: dict[str, object] = {"close_fds": os.name != "nt"}
        if os.name == "nt":
            options["creationflags"] = (
                getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
            )
        else:
            options["start_new_session"] = True
        try:
            process = self._popen([executable, *arguments], shell=False, **options)
        except OSError as exc:
            raise BrowserLaunchError(f"Could not start {browser.name}: {exc}") from exc
        return getattr(process, "pid", None)
