"""Backward-compatible configuration facade using per-user, atomic storage."""
from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
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
from torproxy.hotkeys import parse_hotkey  # noqa: E402
from torproxy.bridges import normalize_sni_hostname, parse_bridge_text  # noqa: E402

IS_WINDOWS = get_os_name() == Os.Windows
IS_LINUX = get_os_name() == Os.Linux
IS_OTHER = not (IS_WINDOWS or IS_LINUX)
OS_NAME = get_os_name()
ARCHITECTURE = 64 if platform.architecture()[0].startswith("64") else 32
BUNDLE_DIR = str(user_directories().data / "bundles")
CHECKSUM_FILE = "sha256sums.txt"
TOR_BUNDLE_BASE_URL = "https://dist.torproject.org/torbrowser/"
TOR_BUNDLE_FALLBACK_URL = "https://archive.torproject.org/tor-package-archive/torbrowser/"
CURRENT_CONFIG_SCHEMA = 3

DEFAULT_DATA: dict[str, Any] = {
    "schema_version": CURRENT_CONFIG_SCHEMA,
    "bridges": "",
    "bridge": False,
    "auto_prune_bridges": False,
    "webtunnel_sni_imitation": "",
    "webtunnel_use_default_tls": True,
    "mode": "dark",
    "theme_preference": "system",
    "tor_port": None,
    "tor_port_checked": False,
    "proxy_port": None,
    "proxy_port_checked": False,
    "http_proxy_enabled": True,
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
    "kill_switch_enabled": False,
    "confirm_exit": True,
    "global_shortcut": "Ctrl+Alt+P",
    "bridge_probe_workers": 8,
    "primary_tor_instances": 2,
    "tor_backend_selection_mode": "balanced",
    "tor_service_workers": 4,
    "tor_services": [],
    "onion_hosting_services": [],
    "developer_tor_settings": {
        "bridge_mode": "direct",
        "bridges": "",
        "webtunnel_sni_imitation": "",
        "webtunnel_use_default_tls": True,
        "max_circuit_dirtiness_seconds": 600,
        "new_circuit_period_seconds": 60,
        "startup_timeout_seconds": 180,
        "shutdown_timeout_seconds": 5,
        "client_use_ipv4": True,
        "client_use_ipv6": True,
        "upstream_proxy_type": "none",
        "upstream_proxy_host": "",
        "upstream_proxy_port": 1080,
    },
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
        if data.get("theme_preference", "system") not in {"system", "dark", "light"}:
            raise ConfigError("theme_preference must be 'system', 'dark', or 'light'.")
        if data.get("system_proxy_mode", "unchanged") not in {"set", "unchanged", "clear"}:
            raise ConfigError("system_proxy_mode must be 'set', 'unchanged', or 'clear'.")

        shortcut = data.get("global_shortcut", "Ctrl+Alt+P")
        try:
            parsed_shortcut = parse_hotkey(shortcut)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"global_shortcut is invalid: {exc}") from exc
        data["global_shortcut"] = parsed_shortcut.text
        for name in ("bridge", "proxy_port_checked", "tor_port_checked", "control_port_checked",
                     "dns_port_checked", "system_proxy_auto", "verify_tor_signatures", "confirm_exit",
                     "auto_prune_bridges", "kill_switch_enabled", "http_proxy_enabled",
                      "webtunnel_use_default_tls"):
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
        try:
            data["webtunnel_sni_imitation"] = normalize_sni_hostname(
                data.get("webtunnel_sni_imitation", "") or ""
            )
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"webtunnel_sni_imitation is invalid: {exc}") from exc
        developer_defaults = DEFAULT_DATA["developer_tor_settings"]
        developer_settings = data.get("developer_tor_settings", developer_defaults)
        if not isinstance(developer_settings, dict):
            raise ConfigError("developer_tor_settings must be an object.")
        forbidden_developer_secrets = {
            "username", "password", "upstream_proxy_username", "upstream_proxy_password",
            "private_key", "client_private_key", "tor_private_key",
        }
        if forbidden_developer_secrets.intersection(developer_settings):
            raise ConfigError(
                "Developer Tor proxy credentials and private keys must be stored outside config.json."
            )
        unknown_developer_keys = set(developer_settings).difference(developer_defaults)
        if unknown_developer_keys:
            raise ConfigError(
                "Unsupported Developer Tor settings: " + ", ".join(sorted(unknown_developer_keys))
            )
        developer_settings = {**developer_defaults, **developer_settings}
        bridge_mode = developer_settings.get("bridge_mode")
        if bridge_mode not in {"direct", "custom", "main"}:
            raise ConfigError("Developer Tor bridge_mode must be direct, custom, or main.")
        developer_bridges = developer_settings.get("bridges", "")
        if not isinstance(developer_bridges, str) or len(developer_bridges) > 65536:
            raise ConfigError("Developer Tor bridges must be text of at most 65536 characters.")
        if bridge_mode == "custom":
            parsed_developer_bridges = parse_bridge_text(developer_bridges)
            if parsed_developer_bridges.invalid_records:
                raise ConfigError(
                    "Developer Tor contains invalid Bridge records: "
                    + " ".join(parsed_developer_bridges.errors[:3])
                )
            if not parsed_developer_bridges.records:
                raise ConfigError("Custom Bridge mode requires at least one valid Bridge record.")
        try:
            developer_settings["webtunnel_sni_imitation"] = normalize_sni_hostname(
                developer_settings.get("webtunnel_sni_imitation", "") or ""
            )
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"Developer Tor WebTunnel SNI is invalid: {exc}") from exc
        for key, minimum, maximum in (
            ("max_circuit_dirtiness_seconds", 10, 86400),
            ("new_circuit_period_seconds", 10, 86400),
            ("startup_timeout_seconds", 15, 900),
            ("shutdown_timeout_seconds", 1, 60),
        ):
            value = developer_settings.get(key)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ConfigError(f"Developer Tor {key} must be an integer between {minimum} and {maximum}.")
        if type(developer_settings.get("webtunnel_use_default_tls")) is not bool:
            raise ConfigError("Developer Tor webtunnel_use_default_tls must be true or false.")
        for key in ("client_use_ipv4", "client_use_ipv6"):
            if type(developer_settings.get(key)) is not bool:
                raise ConfigError(f"Developer Tor {key} must be true or false.")
        if not developer_settings["client_use_ipv4"] and not developer_settings["client_use_ipv6"]:
            raise ConfigError("Developer Tor must allow at least one IP address family.")
        proxy_type = developer_settings.get("upstream_proxy_type")
        if proxy_type not in {"none", "socks5", "https"}:
            raise ConfigError("Developer Tor upstream_proxy_type must be none, socks5, or https.")
        proxy_host = developer_settings.get("upstream_proxy_host", "")
        if not isinstance(proxy_host, str) or len(proxy_host) > 253:
            raise ConfigError("Developer Tor upstream proxy host is invalid.")
        if proxy_type != "none":
            proxy_host = proxy_host.strip()
            if (
                not proxy_host
                or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", proxy_host)
                or ".." in proxy_host
            ):
                raise ConfigError("Developer Tor upstream proxy host must be an IP address or DNS hostname.")
        proxy_port = developer_settings.get("upstream_proxy_port")
        if type(proxy_port) is not int or not 1 <= proxy_port <= 65535:
            raise ConfigError("Developer Tor upstream proxy port must be between 1 and 65535.")
        developer_settings["upstream_proxy_host"] = proxy_host
        data["developer_tor_settings"] = developer_settings

        if type(data.get("data_usage", 0)) is not int or data.get("data_usage", 0) < 0:
            raise ConfigError("data_usage must be a non-negative byte count.")
        interval = data.get("newnym_interval", 0)
        if type(interval) is not int or not 0 <= interval <= 86400000:
            raise ConfigError("newnym_interval must be a duration in milliseconds between 0 and 86400000.")
        new_circuit_period = data.get("NewCircuitPeriod", 60)
        if type(new_circuit_period) is not int or not 10 <= new_circuit_period <= 86400:
            raise ConfigError("NewCircuitPeriod must be an integer between 10 and 86400 seconds.")

        for worker_key in ("bridge_probe_workers", "tor_service_workers"):
            workers = data.get(worker_key, 8 if worker_key == "bridge_probe_workers" else 4)
            if type(workers) is not int or not 1 <= workers <= 8:
                raise ConfigError(f"{worker_key} must be an integer between 1 and 8.")

        primary_instances = data.get("primary_tor_instances", 2)
        if type(primary_instances) is not int or not 1 <= primary_instances <= 4:
            raise ConfigError("primary_tor_instances must be an integer between 1 and 4.")

        backend_selection_mode = data.get("tor_backend_selection_mode", "balanced")
        if (
            not isinstance(backend_selection_mode, str)
            or backend_selection_mode not in {"balanced", "latency"}
        ):
            raise ConfigError("tor_backend_selection_mode must be balanced or latency.")

        services = data.get("tor_services", [])
        if not isinstance(services, list) or len(services) > 32:
            raise ConfigError("tor_services must be a list containing at most 32 profiles.")
        service_ids: set[str] = set()
        claimed_service_ports: set[int] = set()
        primary_ports = {
            data.get("tor_port"), data.get("control_port"),
            data.get("dns_port"), data.get("proxy_port"),
        } - {None, ""}
        for index, profile in enumerate(services, start=1):
            if not isinstance(profile, dict):
                raise ConfigError(f"Tor service profile #{index} must be an object.")
            service_id = profile.get("id")
            if not isinstance(service_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", service_id):
                raise ConfigError(f"Tor service profile #{index} has an invalid ID.")
            if service_id in service_ids:
                raise ConfigError(f"Tor service ID '{service_id}' is duplicated.")
            service_ids.add(service_id)
            display_name = profile.get("display_name", service_id)
            if not isinstance(display_name, str) or not display_name.strip() or len(display_name) > 80:
                raise ConfigError(f"Tor service '{service_id}' needs a display name of at most 80 characters.")
            profile_ports = []
            for port_key in ("socks_port", "control_port"):
                port_value = profile.get(port_key)
                if type(port_value) is not int or not 1 <= port_value <= 65535:
                    raise ConfigError(f"Tor service '{service_id}' has an invalid {port_key}.")
                profile_ports.append(port_value)
            dns_value = profile.get("dns_port")
            if dns_value is not None and not (type(dns_value) is int and dns_value == 0):
                if type(dns_value) is not int or not 1 <= dns_value <= 65535:
                    raise ConfigError(f"Tor service '{service_id}' has an invalid dns_port.")
                profile_ports.append(dns_value)
            if len(profile_ports) != len(set(profile_ports)):
                raise ConfigError(f"Tor service '{service_id}' listener ports must be distinct.")
            if set(profile_ports) & primary_ports:
                raise ConfigError(f"Tor service '{service_id}' conflicts with a primary application listener port.")
            if set(profile_ports) & claimed_service_ports:
                raise ConfigError(f"Tor service '{service_id}' reuses a port assigned to another profile.")
            claimed_service_ports.update(profile_ports)
            for bool_key in ("bridge_enabled", "use_primary_bridges"):
                if type(profile.get(bool_key, False)) is not bool:
                    raise ConfigError(f"Tor service '{service_id}' {bool_key} must be true or false.")
            bridges = profile.get("bridges", "")
            if not isinstance(bridges, str) or len(bridges) > 65536:
                raise ConfigError(f"Tor service '{service_id}' bridges must be text of at most 65536 characters.")
            data_directory = profile.get("data_directory")
            if data_directory is not None and (not isinstance(data_directory, str) or len(data_directory) > 4096):
                raise ConfigError(f"Tor service '{service_id}' data_directory must be a path or null.")
            # New per-profile network options remain optional for old config files.
            if {"upstream_proxy_username", "upstream_proxy_password"}.intersection(profile):
                raise ConfigError(
                    f"Tor service '{service_id}' contains proxy credentials; store them outside config.json."
                )
            proxy_type = profile.get("upstream_proxy_type", "none")
            if not isinstance(proxy_type, str) or proxy_type not in {"none", "socks5", "https"}:
                raise ConfigError(f"Tor service '{service_id}' upstream_proxy_type must be none, socks5, or https.")
            proxy_host = profile.get("upstream_proxy_host", "")
            if not isinstance(proxy_host, str) or len(proxy_host) > 253:
                raise ConfigError(f"Tor service '{service_id}' upstream_proxy_host is invalid.")
            if proxy_type != "none":
                proxy_host = proxy_host.strip()
                if (
                    not proxy_host
                    or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", proxy_host)
                    or ".." in proxy_host
                ):
                    raise ConfigError(f"Tor service '{service_id}' upstream proxy host must be an IP address or DNS hostname.")
            proxy_port = profile.get("upstream_proxy_port", 1080)
            if type(proxy_port) is not int or not 1 <= proxy_port <= 65535:
                raise ConfigError(f"Tor service '{service_id}' upstream_proxy_port must be between 1 and 65535.")
            for key, default in (("client_use_ipv4", True), ("client_use_ipv6", True)):
                if type(profile.get(key, default)) is not bool:
                    raise ConfigError(f"Tor service '{service_id}' {key} must be true or false.")
            if not profile.get("client_use_ipv4", True) and not profile.get("client_use_ipv6", True):
                raise ConfigError(f"Tor service '{service_id}' must allow IPv4, IPv6, or both.")
            for key, minimum, maximum, default in (
                ("max_circuit_dirtiness_seconds", 10, 86400, 600),
                ("new_circuit_period_seconds", 10, 86400, 60),
                ("startup_timeout_seconds", 15, 900, 180),
                ("shutdown_timeout_seconds", 1, 60, 5),
            ):
                value = profile.get(key, default)
                if type(value) is not int or not minimum <= value <= maximum:
                    raise ConfigError(
                        f"Tor service '{service_id}' {key} must be between {minimum} and {maximum}."
                    )

        onion_services = data.get("onion_hosting_services", [])
        if not isinstance(onion_services, list) or len(onion_services) > 32:
            raise ConfigError("onion_hosting_services must be a list containing at most 32 services.")
        onion_ids: set[str] = set()
        for index, service in enumerate(onion_services, start=1):
            if not isinstance(service, dict):
                raise ConfigError(f"Onion Service #{index} must be an object.")
            forbidden_secret_fields = {
                "private_key", "client_private_key", "tor_private_key",
                "private_key_base64", "client_auth_private_key",
            }
            if forbidden_secret_fields.intersection(service):
                raise ConfigError(
                    f"Onion Service #{index} contains private key material; secrets must stay outside config.json."
                )
            service_id = service.get("id")
            if not isinstance(service_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", service_id):
                raise ConfigError(f"Onion Service #{index} has an invalid ID.")
            if service_id in onion_ids:
                raise ConfigError(f"Onion Service ID '{service_id}' is duplicated.")
            onion_ids.add(service_id)
            name = service.get("display_name")
            if not isinstance(name, str) or not name.strip() or len(name) > 80:
                raise ConfigError(f"Onion Service '{service_id}' needs a name of at most 80 characters.")
            try:
                host = ipaddress.ip_address(str(service.get("local_host", "")))
            except ValueError as exc:
                raise ConfigError(f"Onion Service '{service_id}' target must be a literal loopback IP.") from exc
            if not host.is_loopback:
                raise ConfigError(f"Onion Service '{service_id}' may forward only to a loopback target.")
            for key in ("local_port", "onion_port"):
                port = service.get(key)
                if type(port) is not int or not 1 <= port <= 65535:
                    raise ConfigError(f"Onion Service '{service_id}' has an invalid {key}.")
            if "port_mappings" in service:
                mappings = service["port_mappings"]
                if not isinstance(mappings, list) or not 1 <= len(mappings) <= 16:
                    raise ConfigError(
                        f"Onion Service '{service_id}' port_mappings must contain between 1 and 16 entries."
                    )
                onion_ports: set[int] = set()
                local_targets: set[tuple[str, int]] = set()
                for mapping_index, mapping in enumerate(mappings, start=1):
                    if not isinstance(mapping, dict):
                        raise ConfigError(
                            f"Onion Service '{service_id}' port mapping #{mapping_index} must be an object."
                        )
                    mapped_onion = mapping.get("onion_port")
                    mapped_local = mapping.get("local_port")
                    mapped_host = mapping.get("local_host")
                    if type(mapped_onion) is not int or not 1 <= mapped_onion <= 65535:
                        raise ConfigError(
                            f"Onion Service '{service_id}' port mapping #{mapping_index} has an invalid onion_port."
                        )
                    if type(mapped_local) is not int or not 1 <= mapped_local <= 65535:
                        raise ConfigError(
                            f"Onion Service '{service_id}' port mapping #{mapping_index} has an invalid local_port."
                        )
                    try:
                        mapped_ip = ipaddress.ip_address(str(mapped_host))
                    except ValueError as exc:
                        raise ConfigError(
                            f"Onion Service '{service_id}' port mapping #{mapping_index} must use a literal loopback IP."
                        ) from exc
                    if not mapped_ip.is_loopback:
                        raise ConfigError(
                            f"Onion Service '{service_id}' port mapping #{mapping_index} may forward only to loopback."
                        )
                    target = (str(mapped_ip), mapped_local)
                    if mapped_onion in onion_ports or target in local_targets:
                        raise ConfigError(
                            f"Onion Service '{service_id}' port mappings must use unique Onion ports and local targets."
                        )
                    onion_ports.add(mapped_onion)
                    local_targets.add(target)
                primary_mapping = (
                    int(service["onion_port"]),
                    str(host),
                    int(service["local_port"]),
                )
                if primary_mapping not in {
                    (int(item["onion_port"]), str(ipaddress.ip_address(str(item["local_host"]))), int(item["local_port"]))
                    for item in mappings
                }:
                    raise ConfigError(
                        f"Onion Service '{service_id}' port_mappings must include its primary local_host/local_port/onion_port mapping."
                    )
            for key in ("persistent", "auto_start"):
                if type(service.get(key)) is not bool:
                    raise ConfigError(f"Onion Service '{service_id}' {key} must be true or false.")
            if service.get("access_mode") not in {"public", "private"}:
                raise ConfigError(f"Onion Service '{service_id}' access_mode must be public or private.")
            public_key = service.get("client_public_key", "")
            if service["access_mode"] == "private":
                if not isinstance(public_key, str) or not re.fullmatch(r"[a-z2-7]{52}", public_key):
                    raise ConfigError(f"Onion Service '{service_id}' has an invalid v3 client public key.")
            elif public_key not in ("", None):
                raise ConfigError(f"Public Onion Service '{service_id}' cannot keep a client authorization key.")
            onion_address = service.get("service_id", "")
            if onion_address and (
                not isinstance(onion_address, str)
                or not re.fullmatch(r"[a-z2-7]{56}", onion_address)
            ):
                raise ConfigError(f"Onion Service '{service_id}' has an invalid v3 address identifier.")

    def _save_data(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(data)
        payload["schema_version"] = CURRENT_CONFIG_SCHEMA
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

    def update_many(self, values: dict[str, Any]) -> None:
        """Validate and persist a group of settings as one locked atomic update."""
        unknown = set(values).difference(LEGACY_KEYS)
        if unknown:
            raise KeyError(f"Unsupported configuration settings: {', '.join(sorted(unknown))}")
        with self._lock:
            new_data = dict(self.data)
            new_data.update(values)
            self._validate(new_data)
            self._save_data(new_data)
            self.data = new_data

    def save_config(self, data: str) -> None:
        try:
            payload = json.loads(data)
            if not isinstance(payload, dict):
                raise ConfigError("Configuration root must be a JSON object.")
            with self._lock:
                merged = dict(DEFAULT_DATA)
                merged.update(payload)
                schema_version = payload.get("schema_version", 1)
                if "theme_preference" not in payload:
                    # Older exports stored only the effective theme. Preserve
                    # that explicit choice instead of silently switching users
                    # to system-following mode on import.
                    merged["theme_preference"] = payload.get("mode", "dark")
                if type(schema_version) is not int or schema_version < 2:
                    merged["verify_tor_signatures"] = False
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
                if source is not None:
                    legacy_schema = raw.get("schema_version", 1)
                    if "theme_preference" not in raw:
                        merged["theme_preference"] = raw.get("mode", "dark")
                    if type(legacy_schema) is not int or legacy_schema < 2:
                        merged["verify_tor_signatures"] = False
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
            schema_version = raw.get("schema_version", 1)
            migrated = "theme_preference" not in raw
            if migrated:
                merged["theme_preference"] = raw.get("mode", "dark")
            if type(schema_version) is not int or schema_version < 2:
                merged["verify_tor_signatures"] = False
                migrated = True
            if migrated or type(schema_version) is not int or schema_version < CURRENT_CONFIG_SCHEMA:
                self._validate(merged)
                self._save_data(merged)
            else:
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
