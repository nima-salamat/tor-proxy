"""Backward-compatible configuration facade using per-user, atomic storage."""
from __future__ import annotations

import json
import os
import platform
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

APP_ROOT = Path(__file__).resolve().parent
SRC_ROOT = APP_ROOT / "src"
if SRC_ROOT.is_dir() and str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from set_proxy import get_os_name, Os  # noqa: E402
from torproxy.paths import user_directories  # noqa: E402

IS_WINDOWS = get_os_name() == Os.Windows
IS_LINUX = get_os_name() == Os.Linux
IS_OTHER = not (IS_WINDOWS or IS_LINUX)
OS_NAME = get_os_name()
ARCHITECTURE = 64 if platform.architecture()[0].startswith("64") else 32
BUNDLE_DIR = str(user_directories().data / "bundles")
CHECKSUM_FILE = "sha256sums.txt"
TOR_BUNDLE_BASE_URL = "https://dist.torproject.org/torbrowser/"

DEFAULT_DATA: dict[str, Any] = {
    "schema_version": 1,
    "bridges": "",
    "bridge": False,
    "mode": "dark",
    "tor_port": None,
    "tor_port_checked": False,
    "proxy_port": None,
    "proxy_port_checked": False,
    "control_port": None,
    "control_port_checked": False,
    "dns_port": None,
    "dns_port_checked": False,
    "tor_path": None,
    "data_usage": 0,
    "MaxCircuitDirtiness": 600,
    "NewCircuitPeriod": 60,
    "newnym_interval": 0,
    "system_proxy_auto": False,
    "system_proxy_mode": "unchanged",
    "log_level": "INFO",
    "verify_tor_signatures": False,
    "confirm_exit": True,
}
LEGACY_KEYS = set(DEFAULT_DATA) | {"data_usage_bytes", "exclude_hosts", "blocked_hosts"}


class ConfigError(ValueError):
    """Configuration cannot be loaded or persisted safely."""


class Config:
    file_config = "config.json"
    default_data = DEFAULT_DATA

    def __init__(self) -> None:
        dirs = user_directories()
        self.path = dirs.config / self.file_config
        self._lock = threading.RLock()
        self.data: dict[str, Any] = dict(DEFAULT_DATA)

    def __getitem__(self, name: str) -> Any:
        with self._lock:
            return self.data[name] if name in self.data else self.default_data.get(name)

    def __setitem__(self, name: str, value: Any) -> None:
        if name not in LEGACY_KEYS:
            raise KeyError(f"Unsupported configuration setting: {name}")
        with self._lock:
            new_data = dict(self.data)
            new_data[name] = value
            self._validate(new_data)
            self._save_data(new_data)
            self.data = new_data

    def __getattr__(self, name: str) -> Any:
        if name in LEGACY_KEYS:
            return self[name]
        raise AttributeError(name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in LEGACY_KEYS:
            self[name] = value
        else:
            object.__setattr__(self, name, value)

    @staticmethod
    def _validate(data: dict[str, Any]) -> None:
        if data.get("mode", "dark") not in {"dark", "light"}:
            raise ConfigError("mode must be 'dark' or 'light'.")
        if data.get("system_proxy_mode", "unchanged") not in {"set", "unchanged", "clear"}:
            raise ConfigError("system_proxy_mode must be 'set', 'unchanged', or 'clear'.")
        for name in ("bridge", "proxy_port_checked", "tor_port_checked", "control_port_checked",
                     "dns_port_checked", "system_proxy_auto", "verify_tor_signatures", "confirm_exit"):
            if name in data and type(data[name]) is not bool:
                raise ConfigError(f"{name} must be true or false.")
        ports = []
        for name in ("proxy_port", "tor_port", "control_port", "dns_port"):
            value = data.get(name)
            if value is None or value == "":
                continue
            if type(value) is not int or not 1 <= value <= 65535:
                raise ConfigError(f"{name} must be an integer between 1 and 65535.")
            if data.get(name + "_checked"):
                ports.append(value)
        if len(ports) != len(set(ports)):
            raise ConfigError("Enabled listener ports must be distinct.")
        if not isinstance(data.get("bridges", ""), str):
            raise ConfigError("bridges must be text.")
        if type(data.get("data_usage", 0)) is not int or data.get("data_usage", 0) < 0:
            raise ConfigError("data_usage must be a non-negative byte count.")
        interval = data.get("newnym_interval", 0)
        if type(interval) is not int or not 0 <= interval <= 86400000:
            raise ConfigError("newnym_interval must be a duration in milliseconds between 0 and 86400000.")
        new_circuit_period = data.get("NewCircuitPeriod", 60)
        if type(new_circuit_period) is not int or not 10 <= new_circuit_period <= 86400:
            raise ConfigError("NewCircuitPeriod must be an integer between 10 and 86400 seconds.")

    def _save_data(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(data)
        payload["schema_version"] = 1
        fd, temp_name = tempfile.mkstemp(prefix=".config-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            if os.name != "nt":
                os.chmod(temp_name, 0o600)
            os.replace(temp_name, self.path)
        except OSError as exc:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise ConfigError(f"Could not persist configuration in {self.path}: {exc}") from exc

    def save_config(self, data: str) -> None:
        try:
            payload = json.loads(data)
            if not isinstance(payload, dict):
                raise ConfigError("Configuration root must be a JSON object.")
            with self._lock:
                merged = dict(DEFAULT_DATA)
                merged.update(payload)
                self._validate(merged)
                self._save_data(merged)
                self.data = merged
        except json.JSONDecodeError as exc:
            raise ConfigError(f"Invalid JSON configuration: {exc}") from exc

    def get_config(self) -> str:
        with self._lock:
            return json.dumps(self.data)

    def json_format(self, data: str) -> dict[str, Any]:
        try:
            value = json.loads(data)
        except json.JSONDecodeError:
            return dict(DEFAULT_DATA)
        return value if isinstance(value, dict) else dict(DEFAULT_DATA)

    @staticmethod
    def json_to_text(data: dict[str, Any]) -> str:
        return json.dumps(data, indent=2, sort_keys=True)

    def load(self) -> dict[str, Any]:
        with self._lock:
            if not self.path.exists():
                legacy_path = APP_ROOT / self.file_config
                source = legacy_path if legacy_path != self.path and legacy_path.is_file() else None
                if source:
                    try:
                        raw = json.loads(source.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError) as exc:
                        raise ConfigError(f"Could not migrate legacy config {source}: {exc}") from exc
                    if not isinstance(raw, dict):
                        raise ConfigError("Legacy configuration root must be a JSON object.")
                    merged = dict(DEFAULT_DATA)
                    merged.update({key: value for key, value in raw.items() if key in LEGACY_KEYS})
                else:
                    merged = dict(DEFAULT_DATA)
                self._validate(merged)
                self._save_data(merged)
                self.data = merged
                return dict(self.data)
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ConfigError(f"Could not read configuration {self.path}: {exc}") from exc
            if not isinstance(raw, dict):
                raise ConfigError("Configuration root must be a JSON object.")
            merged = dict(DEFAULT_DATA)
            merged.update({key: value for key, value in raw.items() if key in LEGACY_KEYS})
            self._validate(merged)
            self.data = merged
            return dict(self.data)

    def save(self) -> None:
        with self._lock:
            self._validate(self.data)
            self._save_data(self.data)

    def get(self, item: str, default=None):
        value = self[item]
        return default if value is None else value


CONFIG = Config()
