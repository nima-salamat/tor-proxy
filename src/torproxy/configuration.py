"""Versioned user configuration with validation and atomic persistence."""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .host_rules import HostRules


class ConfigurationError(ValueError):
    """Invalid configuration or failed configuration persistence."""


@dataclass(frozen=True)
class TorProxyConfig:
    schema_version: int = 1
    mode: str = "dark"
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8888
    socks_host: str = "127.0.0.1"
    socks_port: int = 9050
    control_host: str = "127.0.0.1"
    control_port: int = 9051
    bridge_enabled: bool = False
    bridges: str = ""
    blocked_hosts: tuple[str, ...] = field(default_factory=tuple)
    excluded_hosts: tuple[str, ...] = field(default_factory=tuple)
    system_proxy_auto: bool = False
    newnym_interval_seconds: int = 0
    max_circuit_dirtiness_seconds: int = 600
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ConfigurationError(f"Unsupported configuration schema: {self.schema_version}")
        if self.mode not in {"dark", "light"}:
            raise ConfigurationError("mode must be 'dark' or 'light'.")
        for name in ("proxy_host", "socks_host", "control_host"):
            if getattr(self, name) not in {"127.0.0.1", "::1", "localhost"}:
                raise ConfigurationError(f"{name} must be a loopback address.")
        ports = [self.proxy_port, self.socks_port, self.control_port]
        if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
            raise ConfigurationError("Ports must be integers in the range 1..65535.")
        if len(set(ports)) != len(ports):
            raise ConfigurationError("Proxy, SOCKS, and Control ports must be distinct.")
        if type(self.bridge_enabled) is not bool or type(self.system_proxy_auto) is not bool:
            raise ConfigurationError("Boolean configuration values must be true or false.")
        if type(self.newnym_interval_seconds) is not int or not 0 <= self.newnym_interval_seconds <= 86400:
            raise ConfigurationError("newnym_interval_seconds must be between 0 and 86400.")
        if type(self.max_circuit_dirtiness_seconds) is not int or not 10 <= self.max_circuit_dirtiness_seconds <= 86400:
            raise ConfigurationError("max_circuit_dirtiness_seconds must be between 10 and 86400.")
        if self.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ConfigurationError("log_level must be a standard logging level.")
        if not isinstance(self.bridges, str) or len(self.bridges) > 65536:
            raise ConfigurationError("bridges must be a string of at most 65536 characters.")
        HostRules.from_values(list(self.blocked_hosts))
        HostRules.from_values(list(self.excluded_hosts))


def migrate_legacy_config(raw: dict[str, Any]) -> dict[str, Any]:
    """Map supported settings from the original config.json without losing theme/bridges."""
    migrated: dict[str, Any] = {"schema_version": 1}
    field_map = {
        "mode": "mode",
        "bridge": "bridge_enabled",
        "bridges": "bridges",
        "proxy_port": "proxy_port",
        "tor_port": "socks_port",
        "control_port": "control_port",
        "newnym_interval": "newnym_interval_seconds",
        "MaxCircuitDirtiness": "max_circuit_dirtiness_seconds",
    }
    for old, new in field_map.items():
        if old in raw:
            value = raw[old]
            if old == "newnym_interval" and isinstance(value, (int, float)):
                # The original UI stores this setting in milliseconds.
                value = int(value / 1000)
            if old == "MaxCircuitDirtiness" and isinstance(value, str) and value.isdecimal():
                value = int(value)
            migrated[new] = value
    if "data_usage" in raw and isinstance(raw["data_usage"], int) and raw["data_usage"] >= 0:
        migrated["data_usage_bytes"] = raw["data_usage"]
    if isinstance(raw.get("blocked_hosts"), list):
        migrated["blocked_hosts"] = tuple(raw["blocked_hosts"])
    if isinstance(raw.get("exclude_hosts"), list):
        migrated["excluded_hosts"] = tuple(raw["exclude_hosts"])
    return migrated


class ConfigStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def load(self) -> TorProxyConfig:
        if not self.path.exists():
            config = TorProxyConfig()
            self.save(config)
            return config
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigurationError(f"Cannot read configuration at {self.path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigurationError("The configuration root must be a JSON object.")
        if "schema_version" not in raw:
            raw = migrate_legacy_config(raw)
        allowed = set(TorProxyConfig.__dataclass_fields__)
        cleaned = {key: value for key, value in raw.items() if key in allowed}
        for key in ("blocked_hosts", "excluded_hosts"):
            if key in cleaned:
                if not isinstance(cleaned[key], (list, tuple)) or not all(isinstance(x, str) for x in cleaned[key]):
                    raise ConfigurationError(f"{key} must be a list of strings.")
                cleaned[key] = tuple(cleaned[key])
        try:
            config = TorProxyConfig(**cleaned)
        except (TypeError, ValueError) as exc:
            if isinstance(exc, ConfigurationError):
                raise
            raise ConfigurationError(f"Invalid configuration: {exc}") from exc
        return config

    def save(self, config: TorProxyConfig) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(config)
        payload["blocked_hosts"] = list(config.blocked_hosts)
        payload["excluded_hosts"] = list(config.excluded_hosts)
        fd, temp_name = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent)
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
            raise ConfigurationError(f"Cannot save configuration at {self.path}: {exc}") from exc
