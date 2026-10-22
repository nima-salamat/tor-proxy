"""Explicit, reversible system-proxy integration without shell interpolation."""
from __future__ import annotations

import ast
import base64
import json
import logging
import os
import platform
import shutil
import subprocess
import tempfile
import sys
from pathlib import Path
from typing import Any

SRC_ROOT = Path(__file__).resolve().parent / "src"
if SRC_ROOT.is_dir() and str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from torproxy.paths import user_directories

logger = logging.getLogger(__name__)


class Os:
    Windows = "Windows"
    Linux = "Linux"
    Mac = "Darwin"


def get_os_name():
    return platform.system()


def _snapshot_path() -> Path:
    return user_directories().state / "system-proxy-snapshot.json"


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".proxy-snapshot-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except OSError:
            pass


def _run_gsettings(*args: str) -> subprocess.CompletedProcess[str]:
    if shutil.which("gsettings") is None:
        raise RuntimeError("gsettings is not installed.")
    return subprocess.run(["gsettings", *args], check=True, capture_output=True, text=True, timeout=5)


def _gvariant_value(raw: str) -> Any:
    value = raw.strip()
    if value.startswith("@as "):
        value = value[4:].strip()
    if value in {"true", "false"}:
        return value == "true"
    try:
        return ast.literal_eval(value)
    except (ValueError, SyntaxError):
        if value.isdecimal():
            return int(value)
        # gsettings prints enum strings with quotes on many versions.
        return value.strip("'\"")


class Handler:
    WINDOWS_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    GNOME_SCHEMA = "org.gnome.system.proxy"
    GNOME_KEYS = {
        "mode": "manual",
        "autoconfig-url": "",
        "use-same-proxy": False,
        "ignore-hosts": [],
        "http.host": None,
        "http.port": None,
        "https.host": None,
        "https.port": None,
        "ftp.host": None,
        "ftp.port": None,
        "socks.host": None,
        "socks.port": None,
    }

    def __init__(self, host, port):
        self.host = str(host)
        try:
            self.port = int(port)
        except (ValueError, TypeError) as exc:
            raise ValueError("Proxy port must be an integer.") from exc
        if self.host not in {"127.0.0.1", "::1", "localhost"} or not 1 <= self.port <= 65535:
            raise ValueError("System proxy changes are restricted to a loopback host and valid port.")
        self.applied = {"enabled": 1, "server": f"{self.host}:{self.port}"}

    def _windows_values(self):
        try:
            import winreg
        except ImportError as exc:
            raise RuntimeError("Windows Registry access is unavailable.") from exc
        values = {}
        names = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect",
                 "DefaultConnectionSettings", "SavedLegacySettings")
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.WINDOWS_REG_PATH, 0, winreg.KEY_READ) as key:
            for name in names:
                try:
                    value, kind = winreg.QueryValueEx(key, name)
                    if isinstance(value, bytes):
                        value = {"base64": base64.b64encode(value).decode("ascii")}
                    values[name] = {"exists": True, "value": value, "kind": int(kind)}
                except FileNotFoundError:
                    values[name] = {"exists": False}
        return values

    def _set_windows_value(self, name, entry):
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.WINDOWS_REG_PATH, 0, winreg.KEY_SET_VALUE) as key:
            if not entry.get("exists"):
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
                return
            value, kind = entry["value"], entry["kind"]
            if isinstance(value, dict) and "base64" in value:
                value = base64.b64decode(value["base64"], validate=True)
            winreg.SetValueEx(key, name, 0, kind, value)

    def set_windows_proxy(self):
        import winreg
        path = _snapshot_path()
        if path.exists():
            try:
                previous = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                logger.error("An invalid system proxy snapshot exists; refusing to overwrite it.")
                return False
            if previous.get("platform") == "Windows" and previous.get("applied") == self.applied:
                return self._windows_is_applied()
            logger.error("An earlier proxy change has not been safely restored; refusing to replace its snapshot.")
            return False
        try:
            snapshot = {"platform": "Windows", "original": self._windows_values(), "applied": self.applied}
            _atomic_write(path, snapshot)
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.WINDOWS_REG_PATH, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, self.applied["server"])
            self._notify_windows()
            return True
        except Exception:
            logger.exception("Could not set the Windows system proxy.")
            try:
                if path.exists():
                    failed_snapshot = json.loads(path.read_text(encoding="utf-8"))
                    original = failed_snapshot.get("original", {})
                    for name in ("ProxyEnable", "ProxyServer"):
                        self._set_windows_value(name, original.get(name, {"exists": False}))
                    path.unlink(missing_ok=True)
                    self._notify_windows()
            except Exception:
                logger.exception("Automatic rollback of partial Windows proxy changes failed.")
            return False

    @staticmethod
    def _notify_windows():
        try:
            import ctypes
            ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
            ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)
        except (AttributeError, OSError):
            logger.debug("WinINet proxy notification was unavailable.")

    def _windows_is_applied(self, applied=None):
        expected = applied or self.applied
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.WINDOWS_REG_PATH, 0, winreg.KEY_READ) as key:
                enabled = winreg.QueryValueEx(key, "ProxyEnable")[0]
                server = winreg.QueryValueEx(key, "ProxyServer")[0]
            return enabled == expected["enabled"] and server == expected["server"]
        except OSError:
            return False

    def disable_windows_proxy(self):
        """Explicitly disable the operating-system proxy when the user selects Clear."""
        import winreg
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, self.WINDOWS_REG_PATH, 0, winreg.KEY_SET_VALUE
            ) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            self._notify_windows()
            snapshot = _snapshot_path()
            if snapshot.exists():
                try:
                    data = json.loads(snapshot.read_text(encoding="utf-8"))
                    if data.get("platform") == "Windows":
                        snapshot.unlink()
                except (OSError, json.JSONDecodeError):
                    logger.warning("Could not remove the old proxy restoration snapshot after explicit Clear.")
            return True
        except Exception:
            logger.exception("Could not disable the Windows system proxy.")
            return False

    def clear_windows_proxy(self):
        path = _snapshot_path()
        if not path.exists():
            logger.info("No TorProxy-owned system proxy snapshot exists; no settings were changed.")
            return False
        try:
            snapshot = json.loads(path.read_text(encoding="utf-8"))
            if snapshot.get("platform") != "Windows" or not isinstance(snapshot.get("applied"), dict):
                logger.warning("System proxy snapshot belongs to a different platform; leaving settings unchanged.")
                return False
            if not self._windows_is_applied(snapshot["applied"]):
                logger.warning("System proxy was changed externally; leaving those changes untouched.")
                return False
            original = snapshot.get("original", {})
            for name in ("ProxyEnable", "ProxyServer"):
                self._set_windows_value(name, original.get(name, {"exists": False}))
            self._notify_windows()
            path.unlink()
            return True
        except Exception:
            logger.exception("Could not restore the original Windows proxy settings.")
            return False

    def _gsettings_available_values(self):
        values = {}
        for dotted_key in self.GNOME_KEYS:
            schema, key = (self.GNOME_SCHEMA + "." + dotted_key.rsplit(".", 1)[0], dotted_key.rsplit(".", 1)[-1]) if "." in dotted_key else (self.GNOME_SCHEMA, dotted_key)
            try:
                values[dotted_key] = _run_gsettings("get", schema, key).stdout.strip()
            except (subprocess.SubprocessError, RuntimeError):
                continue
        if "mode" not in values:
            raise RuntimeError("The GNOME system-proxy schema is not available.")
        return values

    @staticmethod
    def _set_gsettings_value(dotted_key: str, value: Any) -> None:
        schema, key = (Handler.GNOME_SCHEMA + "." + dotted_key.rsplit(".", 1)[0], dotted_key.rsplit(".", 1)[-1]) if "." in dotted_key else (Handler.GNOME_SCHEMA, dotted_key)
        if isinstance(value, str):
            argument = json.dumps(value, ensure_ascii=False)
        elif isinstance(value, bool):
            argument = "true" if value else "false"
        elif isinstance(value, list):
            argument = "[" + ", ".join(json.dumps(item, ensure_ascii=False) if isinstance(item, str) else str(item) for item in value) + "]"
        elif isinstance(value, int):
            argument = str(value)
        else:
            raise ValueError(f"Unsupported GNOME proxy setting type: {type(value).__name__}")
        _run_gsettings("set", schema, key, argument)

    @staticmethod
    def _gsettings_value_arg(raw_value: str) -> Any:
        return _gvariant_value(raw_value)

    def set_linux_proxy(self):
        path = _snapshot_path()
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            logger.error("No desktop session was detected; cannot change GNOME proxy settings.")
            return False
        if path.exists():
            logger.error("A system proxy snapshot already exists; restore it before applying another change.")
            return False
        try:
            original = self._gsettings_available_values()
            snapshot = {"platform": "Linux", "original": original,
                        "applied": {"mode": "manual", "use-same-proxy": True,
                                    "http.host": self.host, "http.port": self.port,
                                    "https.host": self.host, "https.port": self.port}}
            _atomic_write(path, snapshot)
            self._set_gsettings_value("mode", "manual")
            self._set_gsettings_value("use-same-proxy", True)
            self._set_gsettings_value("http.host", self.host)
            self._set_gsettings_value("http.port", self.port)
            self._set_gsettings_value("https.host", self.host)
            self._set_gsettings_value("https.port", self.port)
            return True
        except Exception:
            logger.exception("Could not set GNOME system proxy.")
            try:
                if path.exists():
                    failed_snapshot = json.loads(path.read_text(encoding="utf-8"))
                    original = failed_snapshot.get("original", {})
                    for key in failed_snapshot.get("applied", {}):
                        if key in original:
                            self._set_gsettings_value(key, self._gsettings_value_arg(original[key]))
                    path.unlink(missing_ok=True)
            except Exception:
                logger.exception("Automatic rollback of partial GNOME proxy changes failed.")
            return False

    def disable_linux_proxy(self):
        """Explicitly select direct mode in GNOME when the user chooses Clear."""
        path = _snapshot_path()
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            logger.error("No desktop session was detected; cannot change GNOME proxy settings.")
            return False
        try:
            self._set_gsettings_value("mode", "none")
            if path.exists():
                try:
                    snapshot = json.loads(path.read_text(encoding="utf-8"))
                    if snapshot.get("platform") == "Linux":
                        path.unlink()
                except (OSError, json.JSONDecodeError):
                    logger.warning("Could not remove the old proxy restoration snapshot after explicit Clear.")
            return True
        except Exception:
            logger.exception("Could not disable the GNOME system proxy.")
            return False

    def clear_linux_proxy(self):
        path = _snapshot_path()
        if not path.exists():
            return False
        try:
            snapshot = json.loads(path.read_text(encoding="utf-8"))
            if snapshot.get("platform") != "Linux":
                return False
            applied = snapshot.get("applied", {})
            current = self._gsettings_available_values()
            externally_changed = False
            for key, expected in applied.items():
                if key not in current or _gvariant_value(current[key]) != expected:
                    externally_changed = True
                    break
            if externally_changed:
                logger.warning("GNOME proxy settings changed externally; leaving them untouched.")
                return False
            original = snapshot.get("original", {})
            for key in applied:
                if key in original:
                    self._set_gsettings_value(key, self._gsettings_value_arg(original[key]))
            path.unlink()
            return True
        except Exception:
            logger.exception("Could not restore original GNOME proxy settings.")
            return False



def has_proxy_snapshot() -> bool:
    """Return whether a prior process left a system-proxy restoration snapshot."""
    return _snapshot_path().is_file()

def manage_proxy(host, port, action="set"):
    """Apply the system proxy only after explicit user action, or restore our snapshot."""
    if action not in {"set", "clear", "disable"}:
        logger.error("Unsupported system proxy action: %s", action)
        return False
    handler = Handler(host, port)
    operating_system = get_os_name()
    if operating_system == Os.Windows:
        if action == "set":
            return handler.set_windows_proxy()
        if action == "disable":
            return handler.disable_windows_proxy()
        return handler.clear_windows_proxy()
    if operating_system == Os.Linux:
        if action == "set":
            return handler.set_linux_proxy()
        if action == "disable":
            return handler.disable_linux_proxy()
        return handler.clear_linux_proxy()
    logger.error("System proxy integration is not supported on %s.", operating_system)
    return False
