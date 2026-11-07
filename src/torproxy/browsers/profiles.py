"""Per-user isolated browser profiles and managed Firefox proxy preferences."""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

from torproxy.paths import user_directories

_BEGIN = "// TorProxy managed proxy settings - begin"
_END = "// TorProxy managed proxy settings - end"


class BrowserProfileManager:
    def __init__(self, root: str | Path | None = None):
        self.root = Path(root) if root is not None else user_directories().data / "browser_profiles"

    @staticmethod
    def _safe_id(browser_id: str) -> str:
        value = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(browser_id)).strip(".-")
        if not value or value in {".", ".."}:
            raise ValueError("Invalid browser profile identifier.")
        return value[:80]

    def profile_path(self, browser_id: str, proxy_port: int | None = None) -> Path:
        if proxy_port is not None and (
            type(proxy_port) is not int or not 1 <= proxy_port <= 65535
        ):
            raise ValueError("The HTTP proxy port is invalid.")
        self.root.mkdir(parents=True, exist_ok=True)
        browser_root = (self.root / self._safe_id(browser_id)).resolve()
        root = self.root.resolve()
        if browser_root.parent != root:
            raise ValueError("Browser profile path escaped the TorProxy profile directory.")
        browser_root.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            try:
                browser_root.chmod(0o700)
            except OSError:
                pass
        # A port change gets a new profile directory. If an old browser process
        # still owns the previous profile, the new launch cannot silently reuse
        # its old command-line proxy settings.
        profile = browser_root / (f"port-{proxy_port}" if proxy_port is not None else "default")
        profile.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            try:
                profile.chmod(0o700)
            except OSError:
                pass
        return profile

    def configure_firefox(self, browser_id: str, proxy_port: int) -> Path:
        profile = self.profile_path(browser_id, proxy_port)
        user_js = profile / "user.js"
        existing = user_js.read_text(encoding="utf-8") if user_js.is_file() else ""
        managed = "\n".join((
            _BEGIN,
            'user_pref("network.proxy.type", 1);',
            'user_pref("network.proxy.http", "127.0.0.1");',
            f'user_pref("network.proxy.http_port", {proxy_port});',
            'user_pref("network.proxy.ssl", "127.0.0.1");',
            f'user_pref("network.proxy.ssl_port", {proxy_port});',
            'user_pref("network.proxy.share_proxy_settings", true);',
            'user_pref("network.proxy.no_proxies_on", "");',
            'user_pref("network.proxy.failover_direct", false);',
            'user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);',
            'user_pref("media.peerconnection.ice.no_host", true);',
            'user_pref("media.peerconnection.ice.default_address_only", true);',
            _END,
        ))
        if _BEGIN in existing and _END in existing:
            before = existing.split(_BEGIN, 1)[0]
            after = existing.split(_END, 1)[1]
            updated = before.rstrip() + "\n\n" + managed + after
        else:
            updated = existing.rstrip() + ("\n\n" if existing.strip() else "") + managed + "\n"

        fd, temporary_name = tempfile.mkstemp(prefix=".user-js-", suffix=".tmp", dir=profile)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(updated)
                handle.flush()
                os.fsync(handle.fileno())
            if os.name != "nt":
                os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, user_js)
        except OSError:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
            raise
        return profile
