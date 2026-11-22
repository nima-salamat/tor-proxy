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

def _proxy_server_matches_endpoint(server: Any, host: str, port: int | None) -> bool:
    """Match a system proxy value against TorProxy's own loopback endpoint."""
    if not host or port is None:
        return False
    expected = f"{host.strip().lower()}:{int(port)}"
    for entry in str(server or "").replace(",", ";").split(";"):
        candidate = entry.strip()
        if not candidate:
            continue
        if "=" in candidate:
            candidate = candidate.split("=", 1)[1].strip()
        if "://" in candidate:
            candidate = candidate.split("://", 1)[1].strip()
        candidate = candidate.strip().rstrip("/")
        if candidate.lower() == expected:
            return True
    return False


def _system_proxy_result(
    state: str,
    owner: str,
    platform_name: str,
    detail: str,
) -> dict[str, str]:
    return {
        "state": state,
        "owner": owner,
        "platform": platform_name,
        "detail": detail,
    }


def get_system_proxy_status(host: str = "127.0.0.1", port: int | None = None) -> dict[str, str]:
    """Read the effective per-user system proxy state without changing OS settings.

    The returned state is enabled, disabled or unknown. Owner is torproxy only
    when the active OS proxy points at the requested loopback endpoint.
    """
    platform_name = get_os_name()
    target_host = str(host or "127.0.0.1").strip()
    try:
        target_port = int(port) if port is not None else None
        if target_port is not None and not 1 <= target_port <= 65535:
            target_port = None
    except (TypeError, ValueError):
        target_port = None

    # Use a harmless valid port when the caller has no listener port. This still
    # lets us report enabled/disabled, but never claim that TorProxy owns it.
    reader_port = target_port if target_port is not None else 1
    try:
        loopback_host = target_host if target_host in {"127.0.0.1", "::1", "localhost"} else "127.0.0.1"
        reader = Handler(loopback_host, reader_port)
        if platform_name == Os.Windows:
            values = reader._windows_values()
            proxy_enabled = bool(int(values.get("ProxyEnable", {}).get("value", 0) or 0))
            proxy_server = values.get("ProxyServer", {}).get("value", "")
            auto_config_url = str(values.get("AutoConfigURL", {}).get("value", "") or "").strip()
            auto_detect = bool(int(values.get("AutoDetect", {}).get("value", 0) or 0))
            automatic = bool(auto_config_url or auto_detect)
            if not proxy_enabled and not automatic:
                return _system_proxy_result(
                    "disabled", "none", platform_name, "Windows system proxy is disabled."
                )
            owns_proxy = (
                proxy_enabled
                and not automatic
                and _proxy_server_matches_endpoint(proxy_server, target_host, target_port)
            )
            if owns_proxy:
                detail = f"Windows system proxy is enabled at {proxy_server} (TorProxy)."
                owner = "torproxy"
            elif automatic and not proxy_enabled:
                detail = "Windows automatic proxy configuration or detection is enabled."
                owner = "other"
            else:
                detail = f"Windows system proxy is enabled at {proxy_server or 'an unspecified endpoint'}."
                owner = "other"
            return _system_proxy_result("enabled", owner, platform_name, detail)

        if platform_name == Os.Linux:
            raw_values = reader._gsettings_available_values()
            values = {
                key: _gvariant_value(value) if isinstance(value, str) else value
                for key, value in raw_values.items()
            }
            mode = str(values.get("mode", "") or "").strip().lower()
            if mode == "none":
                return _system_proxy_result(
                    "disabled", "none", platform_name, "GNOME system proxy is in direct mode."
                )
            if mode == "auto":
                url = str(values.get("autoconfig-url", "") or "").strip()
                detail = (
                    f"GNOME automatic proxy configuration is enabled ({url})."
                    if url else
                    "GNOME automatic proxy configuration is enabled."
                )
                return _system_proxy_result("enabled", "other", platform_name, detail)
            if mode != "manual":
                return _system_proxy_result(
                    "unknown",
                    "unknown",
                    platform_name,
                    f"GNOME returned an unrecognized system proxy mode: {mode or 'empty'}.",
                )

            endpoints = []
            for protocol in ("http", "https", "ftp", "socks"):
                proxy_host = str(values.get(f"{protocol}.host", "") or "").strip()
                proxy_port = values.get(f"{protocol}.port")
                try:
                    proxy_port = int(proxy_port)
                except (TypeError, ValueError):
                    proxy_port = 0
                if proxy_host and 1 <= proxy_port <= 65535:
                    endpoints.append((protocol, proxy_host, proxy_port))

            if not endpoints:
                return _system_proxy_result(
                    "disabled", "none", platform_name,
                    "GNOME is in manual mode but no protocol proxy endpoints are configured.",
                )

            http_matches = _proxy_server_matches_endpoint(
                f"{values.get('http.host', '')}:{values.get('http.port', '')}",
                target_host,
                target_port,
            )
            https_matches = _proxy_server_matches_endpoint(
                f"{values.get('https.host', '')}:{values.get('https.port', '')}",
                target_host,
                target_port,
            )
            use_same_proxy = bool(values.get("use-same-proxy", False))
            owns_proxy = bool(
                target_port is not None
                and http_matches
                and (https_matches or use_same_proxy)
            )
            if owns_proxy:
                detail = f"GNOME system proxy is enabled at {target_host}:{target_port} (TorProxy)."
                owner = "torproxy"
            else:
                summary = ", ".join(
                    f"{protocol}={proxy_host}:{proxy_port}"
                    for protocol, proxy_host, proxy_port in endpoints
                )
                detail = f"GNOME manual system proxy is enabled: {summary}."
                owner = "other"
            return _system_proxy_result("enabled", owner, platform_name, detail)

        return _system_proxy_result(
            "unknown",
            "unknown",
            platform_name,
            f"System proxy status inspection is not supported on {platform_name}.",
        )
    except Exception as exc:
        logger.debug("Could not read the system proxy status.", exc_info=True)
        return _system_proxy_result(
            "unknown",
            "unknown",
            platform_name,
            f"Could not read system proxy settings: {type(exc).__name__}: {exc}",
        )




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
