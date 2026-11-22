"""Independent Developer Tor runtime and v3 Onion Service lifecycle."""
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import re
import socket
import tempfile
import threading
import time
import uuid
from pathlib import Path
from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .onion_traffic import OnionServiceRelay, OnionTrafficStore
from .paths import user_directories
from .tor_manager import TorManager, TorSettings, TorState

LOGGER = logging.getLogger(__name__)
_SERVICE_ID_RE = re.compile(r"^[a-z2-7]{56}$")
_CLIENT_KEY_RE = re.compile(r"^[a-z2-7]{52}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_MAX_SERVICES = 32
_DEVELOPER_SETTINGS_DEFAULTS = {
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
}


class OnionHostingError(RuntimeError):
    """Developer Tor or an Onion Service operation could not be completed."""


def _b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=").lower()


def _new_client_keypair() -> tuple[str, str]:
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b32(public_raw), _b32(private_raw)


def validate_loopback_target(host: str, port: int) -> tuple[str, int]:
    """Accept only literal loopback IPs, never DNS names, wildcards, or LAN hosts."""
    try:
        address = ipaddress.ip_address(str(host).strip())
    except ValueError as exc:
        raise OnionHostingError("The local target must be a literal loopback IP (127.0.0.1 or ::1).") from exc
    if not address.is_loopback:
        raise OnionHostingError("Onion Hosting may forward only to a loopback address on this computer.")
    if type(port) is not int or not 1 <= port <= 65535:
        raise OnionHostingError("The local target port must be between 1 and 65535.")
    return str(address), port


def _normalize_port_mappings(
    local_host: str,
    local_port: int,
    onion_port: int,
    additional: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Build a bounded set of v3 Onion port forwards, all pinned to loopback."""
    host, target_port = validate_loopback_target(local_host, local_port)
    if type(onion_port) is not int or not 1 <= onion_port <= 65535:
        raise OnionHostingError("The Onion port must be between 1 and 65535.")
    if additional is None:
        additional = []
    if not isinstance(additional, list):
        raise OnionHostingError("Additional Onion port mappings must be a list.")
    if len(additional) > 15:
        raise OnionHostingError("An Onion Service can publish at most 16 port mappings.")
    result = [{"onion_port": onion_port, "local_host": host, "local_port": target_port}]
    seen_onion_ports = {onion_port}
    seen_targets = {(host, target_port)}
    for index, mapping in enumerate(additional, start=2):
        if not isinstance(mapping, dict):
            raise OnionHostingError(f"Port mapping #{index} must be an object.")
        mapped_onion = mapping.get("onion_port")
        mapped_host = mapping.get("local_host", host)
        mapped_port = mapping.get("local_port")
        mapped_host, mapped_port = validate_loopback_target(mapped_host, mapped_port)
        if type(mapped_onion) is not int or not 1 <= mapped_onion <= 65535:
            raise OnionHostingError(f"Port mapping #{index} has an invalid Onion port.")
        if mapped_onion in seen_onion_ports:
            raise OnionHostingError("Each Onion Service port mapping must use a unique Onion port.")
        target = (mapped_host, mapped_port)
        if target in seen_targets:
            raise OnionHostingError("The same local loopback target cannot be mapped more than once.")
        seen_onion_ports.add(mapped_onion)
        seen_targets.add(target)
        result.append({
            "onion_port": mapped_onion,
            "local_host": mapped_host,
            "local_port": mapped_port,
        })
    return result


class OnionHostingManager:
    """Owns a Tor process used only for publishing v3 Onion Services."""

    def __init__(
        self,
        settings_factory: Callable[[], TorSettings],
        *,
        config: Any | None = None,
        manager_factory: Callable[[TorSettings], TorManager] = TorManager,
        directories=None,
    ) -> None:
        self._settings_factory = settings_factory
        self._manager_factory = manager_factory
        self._config = config
        self._directories = directories or user_directories()
        self._lock = threading.RLock()
        self._runtime_start_lock = threading.Lock()
        self._service_lifecycle_lock = threading.RLock()
        self._runtime_cancel_event: threading.Event | None = None
        self._shutdown_requested = False
        self._manager: TorManager | None = None
        self._started_at: float | None = None
        self._temporary_services: dict[str, dict[str, Any]] = {}
        self._active_services: dict[str, str] = {}
        self._service_errors: dict[str, str] = {}
        self._temporary_keys: dict[str, dict[str, str]] = {}
        self._traffic_store = OnionTrafficStore(self._directories.data)
        self._traffic_relays: dict[str, OnionServiceRelay] = {}
        self._last_status_message = ""

    @property
    def manager(self) -> TorManager | None:
        with self._lock:
            return self._manager

    @property
    def log_path(self) -> Path:
        return self._directories.logs / "developer-tor" / "tor.log"

    @property
    def key_directory(self) -> Path:
        return self._directories.data / "developer-tor" / "keys"

    @property
    def network_credentials_path(self) -> Path:
        return self.key_directory / "network-proxy.json"

    def _config_store(self):
        if self._config is None:
            from config import CONFIG
            self._config = CONFIG
        return self._config

    def _read_network_credentials(self) -> dict[str, str]:
        path = self.network_credentials_path
        if not path.is_file():
            return {"upstream_proxy_username": "", "upstream_proxy_password": ""}
        try:
            if os.name != "nt":
                mode = path.stat().st_mode & 0o777
                if mode & 0o077:
                    path.chmod(0o600)
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise OnionHostingError(
                "Developer Tor upstream proxy credentials are unavailable or damaged. "
                "The runtime will not start with missing authentication data."
            ) from exc
        if not isinstance(value, dict):
            raise OnionHostingError("Developer Tor upstream proxy credential storage is invalid.")
        username = value.get("username", "")
        password = value.get("password", "")
        if not isinstance(username, str) or not isinstance(password, str):
            raise OnionHostingError("Developer Tor upstream proxy credentials are invalid.")
        return {
            "upstream_proxy_username": username,
            "upstream_proxy_password": password,
        }

    def _write_network_credentials(self, username: str, password: str) -> None:
        path = self.network_credentials_path
        if not username and not password:
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                raise OnionHostingError("Could not remove saved Developer Tor proxy credentials.") from exc
            return
        directory = path.parent
        directory.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            directory.chmod(0o700)
        fd, temporary = tempfile.mkstemp(prefix=".network-proxy-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump({"username": username, "password": password}, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            if os.name != "nt":
                os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            if os.name != "nt":
                path.chmod(0o600)
        except OSError as exc:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise OnionHostingError("Could not securely store Developer Tor proxy credentials.") from exc

    def network_proxy_credentials(self) -> dict[str, str]:
        return self._read_network_credentials()

    def settings_snapshot(self) -> dict[str, Any]:
        saved = dict(self._config_store()["developer_tor_settings"] or {})
        settings = {**_DEVELOPER_SETTINGS_DEFAULTS, **saved}
        try:
            credentials = self._read_network_credentials()
        except OnionHostingError:
            if settings.get("upstream_proxy_type") != "none":
                raise
            credentials = {"upstream_proxy_username": "", "upstream_proxy_password": ""}
        return {**settings, **credentials}

    def save_settings(self, values: dict[str, Any]) -> None:
        if not isinstance(values, dict):
            raise OnionHostingError("Developer Tor settings must be an object.")
        secret_keys = {"upstream_proxy_username", "upstream_proxy_password"}
        allowed = set(_DEVELOPER_SETTINGS_DEFAULTS) | secret_keys
        unknown = set(values).difference(allowed)
        if unknown:
            raise OnionHostingError("Unsupported Developer Tor setting: " + ", ".join(sorted(unknown)))
        current = self.settings_snapshot()
        merged = {**current, **values}
        username = str(merged.get("upstream_proxy_username") or "")
        password = str(merged.get("upstream_proxy_password") or "")
        if merged.get("upstream_proxy_type") == "none":
            username = password = ""
        if bool(username) != bool(password):
            raise OnionHostingError("Enter both the upstream proxy username and password, or leave both empty.")
        if username and (
            len(username) > 255 or len(password) > 255
            or any(ord(char) < 32 or ord(char) == 127 for char in username + password)
        ):
            raise OnionHostingError("Upstream proxy credentials must be 1–255 printable characters.")
        if merged.get("upstream_proxy_type") == "https" and (":" in username or ":" in password):
            raise OnionHostingError("HTTP CONNECT proxy credentials cannot contain a colon.")

        public_settings = {
            key: merged[key]
            for key in _DEVELOPER_SETTINGS_DEFAULTS
        }
        previous_credentials = self._read_network_credentials()
        self._write_network_credentials(username, password)
        try:
            self._config_store().update_many({"developer_tor_settings": public_settings})
        except Exception as exc:
            self._write_network_credentials(
                previous_credentials["upstream_proxy_username"],
                previous_credentials["upstream_proxy_password"],
            )
            raise OnionHostingError(f"Could not save Developer Tor settings: {exc}") from exc

    def _saved_services(self) -> list[dict[str, Any]]:
        services = self._config_store()["onion_hosting_services"] or []
        return [dict(item) for item in services if isinstance(item, dict)]

    def _persist_services(self, services: list[dict[str, Any]]) -> None:
        if len(services) > _MAX_SERVICES:
            raise OnionHostingError(f"At most {_MAX_SERVICES} persistent Onion Services are supported.")
        try:
            self._config_store().update_many({"onion_hosting_services": services})
        except Exception as exc:
            raise OnionHostingError(f"Could not save Onion Service settings: {exc}") from exc

    def _all_services(self) -> list[dict[str, Any]]:
        return self._saved_services() + [dict(item) for item in self._temporary_services.values()]

    def _find_service(self, service_id: str) -> dict[str, Any]:
        if service_id in self._temporary_services:
            return dict(self._temporary_services[service_id])
        for item in self._saved_services():
            if item["id"] == service_id:
                return item
        raise OnionHostingError(f"Unknown Onion Service '{service_id}'.")

    def _key_path(self, service_id: str) -> Path:
        if not _ID_RE.fullmatch(service_id):
            raise OnionHostingError("Invalid Onion Service identifier.")
        return self.key_directory / f"{service_id}.json"

    def _write_key_material(self, service_id: str, material: dict[str, str]) -> None:
        directory = self.key_directory
        directory.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            directory.chmod(0o700)
        path = self._key_path(service_id)
        fd, temporary = tempfile.mkstemp(prefix=".onion-key-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(material, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            if os.name != "nt":
                os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            if os.name != "nt":
                path.chmod(0o600)
        except OSError as exc:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise OnionHostingError(f"Could not securely store Onion Service key material: {exc}") from exc

    @staticmethod
    def _validate_tor_private_key(value: str) -> str:
        if not isinstance(value, str) or not re.fullmatch(
            r"ED25519-V3:[A-Za-z0-9+/]+={0,2}", value
        ):
            raise OnionHostingError("The stored Tor v3 identity key has an invalid format.")
        return value

    @staticmethod
    def _validate_client_authorization(service: dict[str, Any], material: dict[str, str]) -> str:
        public_key = str(service.get("client_public_key") or "")
        private_key = str(material.get("client_private_key") or "")
        if not _CLIENT_KEY_RE.fullmatch(public_key) or not _CLIENT_KEY_RE.fullmatch(private_key):
            raise OnionHostingError(
                "Private client authorization material is missing or invalid. "
                "TorProxy will not publish a private service without a usable client key."
            )
        try:
            padding = "=" * ((8 - len(private_key) % 8) % 8)
            private_raw = base64.b32decode(private_key.upper() + padding)
            derived_public = _b32(
                X25519PrivateKey.from_private_bytes(private_raw).public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )
        except (ValueError, TypeError) as exc:
            raise OnionHostingError("The private client authorization key is damaged.") from exc
        if derived_public != public_key:
            raise OnionHostingError(
                "The stored public and private client authorization keys do not match. "
                "The Onion Service was not published."
            )
        return private_key

    def _read_key_material(self, service_id: str) -> dict[str, str]:
        path = self._key_path(service_id)
        try:
            if os.name != "nt":
                mode = path.stat().st_mode & 0o777
                if mode & 0o077:
                    path.chmod(0o600)
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise OnionHostingError(
                f"Persistent key material for '{service_id}' is unavailable or damaged; "
                "TorProxy will not silently generate a replacement onion identity."
            ) from exc
        if not isinstance(value, dict):
            raise OnionHostingError(f"Persistent key material for '{service_id}' is invalid.")
        result = {str(key): str(item) for key, item in value.items()}
        if "tor_private_key" in result:
            self._validate_tor_private_key(result["tor_private_key"])
        if "client_private_key" in result and not _CLIENT_KEY_RE.fullmatch(result["client_private_key"]):
            raise OnionHostingError("The stored private client authorization key has an invalid format.")
        return result

    def _remove_key_material(self, service_id: str) -> None:
        try:
            self._key_path(service_id).unlink(missing_ok=True)
        except OSError as exc:
            raise OnionHostingError(f"Could not remove the private key file for '{service_id}': {exc}") from exc

    @staticmethod
    def _parse_control_response(response: Any) -> dict[str, str]:
        text = str(response)
        if "ServiceID=" not in text:
            content = getattr(response, "content", None)
            if callable(content):
                try:
                    parsed = content()
                    if isinstance(parsed, str):
                        text += "\n" + parsed
                    elif parsed:
                        text += "\n" + "\n".join(
                            str(item[-1] if isinstance(item, tuple) else item)
                            for item in parsed
                        )
                except Exception:
                    pass
        fields: dict[str, str] = {}
        for line in text.splitlines():
            match = re.match(r"\s*(?:250[- ]?)?([A-Za-z0-9]+)=(.*?)(?:\r)?$", line)
            if match:
                fields[match.group(1)] = match.group(2)
        for name in ("ServiceID", "PrivateKey"):
            if name not in fields:
                match = re.search(rf"\b{name}=([^\s]+)", text)
                if match:
                    fields[name] = match.group(1)
        return fields

    def _control(self, command: str):
        manager = self._manager
        if manager is None:
            raise OnionHostingError("Developer Tor is not running.")
        try:
            return manager.send_control_command(command)
        except Exception as exc:
            # Never include a command in the exception: it can contain private keys.
            raise OnionHostingError(f"Tor ControlPort rejected the Onion Service operation: {exc}") from exc

    @staticmethod
    def _manager_process_identity(manager: TorManager) -> dict[str, Any]:
        """Describe the actual Tor child; do not confuse systemd-run with Tor."""
        getter = getattr(manager, "process_identity_snapshot", None)
        if callable(getter):
            try:
                identity = getter()
            except Exception:
                return {
                    "pid": None,
                    "alive": True,
                    "verified": False,
                    "identity_unverifiable": True,
                }
            if isinstance(identity, dict) and identity:
                return identity

        # Backward compatibility for adapters that only expose their owned
        # Popen handle. A live handle is not inferred from an arbitrary PID.
        process = getattr(manager, "process", None)
        if process is None:
            return {"pid": None, "alive": False, "verified": False}
        try:
            alive = process.poll() is None
        except Exception:
            alive = True
        return {
            "pid": getattr(process, "pid", None),
            "alive": alive,
            "verified": alive,
            "identity_unverifiable": False,
        }

    def _discover_orphaned_manager(self) -> TorManager | None:
        """Reattach a manager for a live previous-session Tor PID, verified or not."""
        with self._lock:
            if self._manager is not None:
                return self._manager
        try:
            manager = self._manager_factory(self._settings_factory())
            identity_getter = getattr(manager, "process_identity_snapshot", None)
            if not callable(identity_getter):
                return None
            identity = identity_getter()
            if not bool(identity.get("alive")):
                return None
        except Exception:
            LOGGER.debug("Could not inspect a previous Developer Tor process.", exc_info=True)
            return None
        with self._lock:
            if self._manager is None:
                self._manager = manager
                if bool(identity.get("verified")):
                    self._last_status_message = (
                        f"Verified Developer Tor PID {identity.get('pid')} survived the previous TorProxy session. "
                        "Stop it to reconcile ownership before starting another runtime."
                    )
                else:
                    self._last_status_message = (
                        f"Developer Tor PID {identity.get('pid')} is still alive but its process identity "
                        "cannot be verified. TorProxy will not signal it or start a replacement until "
                        "the operating-system access/identity issue is resolved."
                    )
                return manager
            return self._manager

    def runtime_snapshot(self) -> dict[str, Any]:
        stale_relays = []
        with self._lock:
            manager = self._manager
        if manager is None:
            manager = self._discover_orphaned_manager()
        process_identity = (
            self._manager_process_identity(manager)
            if manager is not None else
            {"pid": None, "alive": False, "verified": False}
        )
        with self._lock:
            # _discover_orphaned_manager() registers the manager atomically.
            # Do not resurrect a manager reference that another thread stopped
            # and cleared between the snapshot's two lock acquisitions.
            started_at = self._started_at
            message = self._last_status_message
            process = getattr(manager, "process", None) if manager is not None else None
            manager_state = getattr(getattr(manager, "state", None), "value", "")
            manager_state = str(manager_state).lower().split(".")[-1]
            process_alive = bool(process_identity.get("alive"))
            process_verified = bool(process_identity.get("verified"))
            # During STARTING/BOOTSTRAPPING the child may not have been
            # launched or its identity record may not yet have been persisted.
            # Treating that normal window as process death races the start path.
            runtime_was_active = manager_state in {"ready", "failed", "stopping"}
            if runtime_was_active and (not process_alive or not process_verified):
                # The Tor child, not the systemd-run wrapper, is authoritative.
                # Suspend local relay endpoints when it is dead or cannot be
                # verified; retain the manager and PID record for a safe Stop.
                try:
                    manager.state = TorState.FAILED
                    manager.last_error = (
                        "Developer Tor exited unexpectedly."
                        if not process_alive else
                        "Developer Tor process identity could not be verified."
                    )
                except Exception:
                    pass
                if not process_alive:
                    self._last_status_message = (
                        "Developer Tor exited unexpectedly. Stop and restart the runtime to restore persistent services."
                    )
                else:
                    self._last_status_message = (
                        f"Developer Tor PID {process_identity.get('pid')} is alive but its identity cannot be verified. "
                        "Local relay endpoints were suspended; process ownership must be verified before stopping it."
                    )
                message = self._last_status_message
                for profile_id in self._active_services:
                    self._service_errors[profile_id] = (
                        "Developer Tor exited; this Onion Service is no longer published."
                        if not process_alive else
                        "Developer Tor process identity is unverified; this Onion Service has been suspended."
                    )
                self._active_services.clear()
                stale_relays = list(self._traffic_relays.values())
                self._traffic_relays.clear()
        for relay in stale_relays:
            relay.close()
        if manager is None:
            return {
                "state": "stopped", "progress": None, "message": "Developer Tor is stopped.",
                "version": "", "uptime_seconds": 0, "memory_bytes": 0, "pid": None,
                "process_alive": False, "process_identity_verified": False,
                "network_summary": "Saved connection settings will apply when Developer Tor starts.",
            }
        state = getattr(manager.state, "value", str(manager.state)).lower()
        process = manager.process
        identity = process_identity
        startup_in_progress = state in {"starting", "bootstrapping", "stopping"}
        orphaned = (
            process is None and bool(identity.get("alive")) and bool(identity.get("verified"))
            and not startup_in_progress
        )
        identity_unverified = (
            bool(identity.get("alive")) and not bool(identity.get("verified"))
            and not startup_in_progress
        )
        if orphaned:
            state = "orphaned"
            message = message or (
                f"Verified Developer Tor process {identity.get('pid')} survived the previous application session. "
                "Stop it to reconcile before starting another runtime."
            )
        elif identity_unverified:
            state = "process-identity-unverified"
            message = message or (
                f"PID {identity.get('pid')} is alive, but TorProxy cannot verify its executable identity with current permissions. "
                "The process will not be terminated automatically."
            )
        pid = identity.get("pid") if identity else None
        if pid is None:
            pid = getattr(process, "pid", None)
        memory = 0
        if pid:
            try:
                import psutil
                memory = int(psutil.Process(pid).memory_info().rss)
            except Exception:
                memory = 0
        version = ""
        if state == "ready":
            try:
                # Dashboard snapshots run in a background worker while service
                # actions may issue ADD_ONION/DEL_ONION on the same ControlPort.
                # Serialize this read with TorManager.send_control_command so
                # concurrent Stem requests cannot consume each other's replies.
                control_lock = getattr(manager, "_lock", None)
                if control_lock is None:
                    controller = getattr(manager, "_controller", None)
                    if controller is not None:
                        version = str(controller.get_info("version", ""))
                else:
                    with control_lock:
                        controller = getattr(manager, "_controller", None)
                        if controller is not None:
                            version = str(controller.get_info("version", ""))
            except Exception:
                version = ""
        return {
            "state": state,
            "progress": getattr(manager, "bootstrap_progress", None),
            "message": message or getattr(manager, "last_error", "") or state.title(),
            "version": version,
            "uptime_seconds": max(0, int(time.monotonic() - started_at)) if started_at else 0,
            "memory_bytes": memory,
            "pid": pid,
            "process_alive": bool(identity.get("alive", process is not None)),
            "process_identity_verified": bool(identity.get("verified", False)),
            "process_identity_unverifiable": bool(identity.get("identity_unverifiable", False)),
            "network_summary": self._network_summary(manager, state),
        }

    @staticmethod
    def _network_summary(manager: TorManager, state: str) -> str:
        settings = getattr(manager, "settings", None)
        if settings is None:
            return "Network diagnostics unavailable."
        parts: list[str] = []
        if settings.bridges_enabled:
            source = "Main" if getattr(settings, "bridge_source", "custom") == "main" else "Custom"
            try:
                records = TorManager._parse_bridges(settings.bridges)
            except Exception:
                records = []
            transports = sorted({
                transport or "vanilla"
                for transport, _record in records
            })
            bridge_summary = f"{source} bridges · {len(records)} configured"
            if transports:
                bridge_summary += " · " + ", ".join(transports)
            if state == "ready" and records:
                try:
                    active = set(manager.get_active_bridge_fingerprints())
                except Exception:
                    active = set()
                fingerprints = {
                    match.group(0).upper()
                    for _transport, record in records
                    for match in [re.search(r"\b[0-9A-Fa-f]{40}\b", record)]
                    if match
                }
                if fingerprints:
                    bridge_summary += f" · {len(active.intersection(fingerprints))}/{len(fingerprints)} first hops verified"
                else:
                    bridge_summary += " · first-hop identity unavailable"
            else:
                bridge_summary += " · waiting for a built circuit"
            parts.append(bridge_summary)
        else:
            parts.append("Direct connection")
        families = []
        if settings.client_use_ipv4:
            families.append("IPv4")
        if settings.client_use_ipv6:
            families.append("IPv6")
        parts.append(" + ".join(families))
        if settings.upstream_proxy_type == "none":
            parts.append("no upstream proxy")
        else:
            label = "SOCKS5" if settings.upstream_proxy_type == "socks5" else "HTTP CONNECT"
            parts.append(f"{label} proxy {settings.upstream_proxy_host}:{settings.upstream_proxy_port}")
        return " · ".join(parts)

    def start_runtime(self, on_status: Callable[[str, int | None, str], None] | None = None) -> None:
        """Start the dedicated Tor process; persistent auto-start services are restored after bootstrap."""
        with self._lock:
            if self._shutdown_requested:
                raise OnionHostingError("Developer Tor is shutting down and cannot be started again.")
        if not self._runtime_start_lock.acquire(blocking=False):
            raise OnionHostingError("Developer Tor is already starting, stopping, or restarting.")
        try:
            with self._lock:
                if self._shutdown_requested:
                    raise OnionHostingError("Developer Tor is shutting down and cannot be started again.")
                previous = self._manager
                if previous is not None:
                    previous_identity = self._manager_process_identity(previous)
                    if previous_identity.get("alive") and previous_identity.get("verified"):
                        if getattr(previous.state, "value", "") == "ready":
                            return
                        raise OnionHostingError("Developer Tor is already starting or stopping.")
                    if previous_identity.get("alive") and not previous_identity.get("verified"):
                        raise OnionHostingError(
                            "A previous Developer Tor PID is still alive but its identity cannot be verified. "
                            "It will not be replaced or signalled automatically."
                        )
                    # Reap the previous manager object to release its exclusive
                    # DataDirectory lock before a replacement process is created.
                    try:
                        previous.stop()
                    except Exception as exc:
                        raise OnionHostingError(
                            f"Could not release the previous Developer Tor runtime: {exc}"
                        ) from exc
                    self._manager = None

                manager = self._manager_factory(self._settings_factory())
                cancel_event = threading.Event()
                # TorManager checks this before launching and throughout bootstrap.
                # Signalling it from application shutdown prevents a late Start
                # call from creating a child after the UI has begun exiting.
                manager._start_cancel_event = cancel_event
                self._runtime_cancel_event = cancel_event
                self._manager = manager
                self._started_at = time.monotonic()

            def report(state, progress, message):
                text_state = getattr(state, "value", str(state)).lower()
                with self._lock:
                    self._last_status_message = str(message or "")
                if on_status is not None:
                    try:
                        on_status(text_state, progress, str(message or ""))
                    except Exception:
                        LOGGER.debug("Developer Tor status callback failed.", exc_info=True)

            try:
                with self._lock:
                    if self._shutdown_requested or cancel_event.is_set():
                        raise OnionHostingError("Developer Tor startup was cancelled because the runtime is stopping.")
                manager.start(on_status=report)
                with self._lock:
                    if self._shutdown_requested or cancel_event.is_set():
                        raise OnionHostingError("Developer Tor startup was cancelled because the runtime is stopping.")
                    self._started_at = time.monotonic()
            except Exception:
                with self._lock:
                    self._started_at = None
                raise

            for service in self._saved_services():
                with self._lock:
                    if self._shutdown_requested or cancel_event.is_set():
                        break
                if service.get("auto_start"):
                    try:
                        self.start_service(service["id"])
                    except Exception as exc:
                        self._service_errors[service["id"]] = str(exc)
                        LOGGER.warning("Could not auto-start Onion Service '%s': %s", service["id"], exc)
        finally:
            self._runtime_start_lock.release()

    def _stop_runtime_serialized(self, *, force: bool = False, shutdown: bool = False) -> None:
        # Signal startup before waiting for the lifecycle lock. TorManager will
        # abort an in-flight bootstrap and release its DataDirectory lock; we
        # then own the lifecycle lock before attempting final process cleanup.
        with self._lock:
            if shutdown:
                self._shutdown_requested = True
            cancel_event = self._runtime_cancel_event
            manager = self._manager
            if cancel_event is not None:
                cancel_event.set()
            manager_cancel = getattr(manager, "_start_cancel_event", None)
        if manager is None:
            manager = self._discover_orphaned_manager()
        manager_cancel = getattr(manager, "_start_cancel_event", None)
        if callable(getattr(manager_cancel, "set", None)):
            manager_cancel.set()

        if not self._runtime_start_lock.acquire(timeout=30.0):
            raise OnionHostingError(
                "Developer Tor did not finish its current start/stop operation within 30 seconds. "
                "Its process ownership is retained; retry shutdown after inspecting the runtime."
            )
        if not self._service_lifecycle_lock.acquire(timeout=30.0):
            self._runtime_start_lock.release()
            raise OnionHostingError(
                "An Onion Service operation is still active; Tor shutdown was not allowed to race it. "
                "Retry after that service operation finishes."
            )
        try:
            with self._lock:
                manager = self._manager

            if manager is not None:
                try:
                    manager.force_stop() if force else manager.stop()
                except Exception as stop_error:
                    try:
                        manager.force_stop()
                    except Exception as force_error:
                        process_identity = self._manager_process_identity(manager)
                        process_alive = bool(process_identity.get("alive"))
                        process_verified = bool(process_identity.get("verified"))
                        lock_held = getattr(manager, "_data_directory_lock_handle", None) is not None
                        raise OnionHostingError(
                            "Developer Tor could not be stopped completely. "
                            f"Process still running: {process_alive}; identity verified: {process_verified}; "
                            f"DataDirectory lock retained: {lock_held}. "
                            f"Graceful stop: {stop_error}; force-stop: {force_error}"
                        ) from force_error

                process_identity = self._manager_process_identity(manager)
                process_alive = bool(process_identity.get("alive"))
                process_verified = bool(process_identity.get("verified"))
                lock_held = getattr(manager, "_data_directory_lock_handle", None) is not None
                if process_alive or lock_held:
                    raise OnionHostingError(
                        "Developer Tor still owns a live or locked process after shutdown. "
                        "Its manager reference was retained so cleanup can be retried safely."
                    )

            with self._lock:
                relays = dict(self._traffic_relays)
            relay_errors: list[str] = []
            relay_deadline = time.monotonic() + 15.0
            for profile_id, relay in relays.items():
                try:
                    relay.close(timeout=max(0.1, relay_deadline - time.monotonic()))
                except Exception as exc:
                    relay_errors.append(f"{profile_id}: {exc}")
            if relay_errors:
                # Tor is stopped, but retain the failed relays and manager
                # reference so their socket workers can be joined on retry.
                with self._lock:
                    self._active_services.clear()
                    self._last_status_message = "Tor stopped; Onion relay cleanup is still pending."
                raise OnionHostingError(
                    "Developer Tor stopped, but one or more Onion relays remain active: "
                    + " | ".join(relay_errors)
                )

            with self._lock:
                if self._manager is manager:
                    self._manager = None
                self._started_at = None
                self._last_status_message = "Developer Tor stopped."
                temporary_ids = tuple(self._temporary_services)
                self._temporary_services.clear()
                self._temporary_keys.clear()
                self._active_services.clear()
                self._service_errors.clear()
                self._runtime_cancel_event = None
                self._traffic_relays.clear()

            for profile_id in temporary_ids:
                self._traffic_store.delete_service(profile_id)

            if shutdown:
                try:
                    self._traffic_store.close(timeout=5.0)
                except Exception as exc:
                    raise OnionHostingError(
                        "Developer Tor and its Onion relays stopped, but the traffic history writer "
                        f"could not be joined: {exc}"
                    ) from exc
        finally:
            self._service_lifecycle_lock.release()
            self._runtime_start_lock.release()

    def stop_runtime(self, *, force: bool = False) -> None:
        """Stop Developer Tor while keeping the manager available for a later restart."""
        self._stop_runtime_serialized(force=force, shutdown=False)

    def shutdown_runtime(self, *, force: bool = False) -> None:
        """Permanently close the runtime for application exit, cancelling any in-flight start."""
        self._stop_runtime_serialized(force=force, shutdown=True)

    def resume_after_cancelled_shutdown(self) -> None:
        """Allow a new runtime start if the application-level exit was rolled back."""
        if not self._runtime_start_lock.acquire(blocking=False):
            raise OnionHostingError("Developer Tor is still completing its shutdown.")
        try:
            with self._lock:
                if self._manager is not None:
                    raise OnionHostingError("Developer Tor must be fully stopped before resuming its lifecycle.")
            self._traffic_store.reopen()
            with self._lock:
                self._shutdown_requested = False
                self._runtime_cancel_event = None
                self._last_status_message = "Developer Tor is stopped."
        finally:
            self._runtime_start_lock.release()

    def create_service(
        self,
        *,
        display_name: str,
        local_host: str,
        local_port: int,
        onion_port: int = 80,
        port_mappings: list[dict[str, Any]] | None = None,
        persistent: bool = True,
        access_mode: str = "public",
        auto_start: bool = True,
    ) -> str:
        with self._service_lifecycle_lock:
            with self._lock:
                if self._shutdown_requested:
                    raise OnionHostingError("Developer Tor is shutting down; services cannot be changed.")
            return self._create_service_locked(
                display_name=display_name,
                local_host=local_host,
                local_port=local_port,
                onion_port=onion_port,
                port_mappings=port_mappings,
                persistent=persistent,
                access_mode=access_mode,
                auto_start=auto_start,
            )

    def _create_service_locked(
        self,
        *,
        display_name: str,
        local_host: str,
        local_port: int,
        onion_port: int = 80,
        port_mappings: list[dict[str, Any]] | None = None,
        persistent: bool = True,
        access_mode: str = "public",
        auto_start: bool = True,
    ) -> str:
        name = str(display_name).strip()
        if not name or len(name) > 80:
            raise OnionHostingError("Service name is required and must contain at most 80 characters.")
        host, local_port = validate_loopback_target(local_host, local_port)
        mappings = _normalize_port_mappings(host, local_port, onion_port, port_mappings)
        if type(persistent) is not bool or type(auto_start) is not bool:
            raise OnionHostingError("Persistent and Auto Start must be true or false.")
        if access_mode not in {"public", "private"}:
            raise OnionHostingError("Access mode must be Public or Private.")
        with self._lock:
            if len(self._all_services()) >= _MAX_SERVICES:
                raise OnionHostingError(f"At most {_MAX_SERVICES} Onion Services are supported.")
            used_ports = {
                (str(item["local_host"]), int(item["local_port"]), int(item["onion_port"]))
                for item in self._all_services()
            }
            if (host, local_port, onion_port) in used_ports:
                raise OnionHostingError("An Onion Service with the same target and Onion port already exists.")
        service_id = uuid.uuid4().hex[:16]
        item = {
            "id": service_id, "display_name": name, "local_host": host, "local_port": local_port,
            "onion_port": onion_port, "persistent": persistent, "access_mode": access_mode,
            "auto_start": auto_start, "service_id": "",
            "port_mappings": mappings,
        }
        key_material: dict[str, str] = {}
        if access_mode == "private":
            public_key, private_key = _new_client_keypair()
            item["client_public_key"] = public_key
            key_material["client_private_key"] = private_key
        if persistent:
            saved = self._saved_services()
            self._persist_services(saved + [item])
            if key_material:
                try:
                    self._write_key_material(service_id, key_material)
                except Exception:
                    self._persist_services(saved)
                    raise
        else:
            with self._lock:
                self._temporary_services[service_id] = item
                self._temporary_keys[service_id] = key_material
        return service_id

    def update_service(self, service_id: str, **changes) -> None:
        with self._service_lifecycle_lock:
            with self._lock:
                if self._shutdown_requested:
                    raise OnionHostingError("Developer Tor is shutting down; services cannot be changed.")
            self._update_service_locked(service_id, **changes)

    def _update_service_locked(self, service_id: str, **changes) -> None:
        allowed = {"display_name", "local_host", "local_port", "onion_port", "port_mappings", "persistent", "access_mode", "auto_start"}
        if set(changes) - allowed:
            raise OnionHostingError("Unsupported Onion Service setting.")
        with self._lock:
            if service_id in self._active_services:
                raise OnionHostingError("Stop this Onion Service before editing it.")
        current = self._find_service(service_id)
        merged = dict(current)
        merged.update(changes)
        host, port = validate_loopback_target(merged["local_host"], merged["local_port"])
        merged["local_host"], merged["local_port"] = host, port
        merged["display_name"] = str(merged["display_name"]).strip()
        if not merged["display_name"] or len(merged["display_name"]) > 80:
            raise OnionHostingError("Service name is required and must contain at most 80 characters.")
        if type(merged["onion_port"]) is not int or not 1 <= merged["onion_port"] <= 65535:
            raise OnionHostingError("The Onion port must be between 1 and 65535.")
        old_primary = (
            str(current["local_host"]), int(current["local_port"]), int(current["onion_port"])
        )
        if "port_mappings" in changes:
            additional_mappings = changes.get("port_mappings") or []
        else:
            stored_mappings = current.get("port_mappings") or [{
                "onion_port": current["onion_port"],
                "local_host": current["local_host"],
                "local_port": current["local_port"],
            }]
            additional_mappings = [
                item for item in stored_mappings
                if (
                    str(item.get("local_host", current["local_host"])),
                    int(item.get("local_port", current["local_port"])),
                    int(item.get("onion_port", current["onion_port"])),
                ) != old_primary
            ]
        mappings = _normalize_port_mappings(host, port, merged["onion_port"], additional_mappings)
        merged["port_mappings"] = mappings
        mapping_keys = {
            (item["local_host"], item["local_port"], item["onion_port"])
            for item in mappings
        }
        for other in self._all_services():
            if other["id"] == service_id:
                continue
            other_mappings = other.get("port_mappings") or [{
                "onion_port": other["onion_port"],
                "local_host": other["local_host"],
                "local_port": other["local_port"],
            }]
            other_keys = {
                (
                    str(item.get("local_host", other["local_host"])),
                    int(item.get("local_port", other["local_port"])),
                    int(item.get("onion_port", other["onion_port"])),
                )
                for item in other_mappings
            }
            if mapping_keys.intersection(other_keys):
                raise OnionHostingError("Another Onion Service already uses one of these local target and Onion port mappings.")
        if type(merged["persistent"]) is not bool or type(merged["auto_start"]) is not bool:
            raise OnionHostingError("Persistent and Auto Start must be true or false.")
        if merged["access_mode"] not in {"public", "private"}:
            raise OnionHostingError("Access mode must be Public or Private.")

        was_persistent = bool(current.get("persistent", True))
        now_persistent = bool(merged["persistent"])
        previous_access = current.get("access_mode", "public")
        key_path = self._key_path(service_id)
        if was_persistent:
            material = self._read_key_material(service_id) if key_path.is_file() else {}
            if current.get("service_id") and not material.get("tor_private_key"):
                raise OnionHostingError(
                    f"Persistent identity for '{service_id}' is missing its Tor private key; "
                    "its address cannot be safely edited or changed."
                )
        else:
            material = dict(self._temporary_keys.get(service_id, {}))
        if previous_access != merged["access_mode"]:
            if merged["access_mode"] == "private":
                public_key, private_key = _new_client_keypair()
                merged["client_public_key"] = public_key
                material["client_private_key"] = private_key
            else:
                merged.pop("client_public_key", None)
                material.pop("client_private_key", None)
        if not now_persistent:
            # Temporary services keep their key material only in this process.
            # Carry the existing Ed25519 identity across a lifetime toggle rather
            # than silently changing its address during the current app session.
            merged["persistent"] = False
            if was_persistent:
                saved = [item for item in self._saved_services() if item["id"] != service_id]
                self._persist_services(saved)
                self._remove_key_material(service_id)
            with self._lock:
                self._temporary_services[service_id] = merged
                self._temporary_keys[service_id] = material
            return

        merged["persistent"] = True
        if was_persistent:
            old_material = (
                self._read_key_material(service_id)
                if self._key_path(service_id).is_file()
                else {}
            )
            if material:
                self._write_key_material(service_id, material)
            saved = self._saved_services()
            try:
                self._persist_services([merged if item["id"] == service_id else item for item in saved])
            except Exception:
                if old_material:
                    self._write_key_material(service_id, old_material)
                else:
                    self._remove_key_material(service_id)
                raise
            with self._lock:
                self._temporary_keys.pop(service_id, None)
                self._temporary_services.pop(service_id, None)
            return

        # Temporary -> persistent: write the protected secrets before publishing
        # the profile in config.json. Roll back the key file if config persistence
        # fails so the conversion is all-or-nothing from the user's perspective.
        if material:
            self._write_key_material(service_id, material)
        saved = self._saved_services()
        try:
            self._persist_services(saved + [merged])
        except Exception:
            self._remove_key_material(service_id)
            raise
        with self._lock:
            self._temporary_services.pop(service_id, None)
            self._temporary_keys.pop(service_id, None)

    def _service_port_mappings(self, service: dict[str, Any]) -> list[dict[str, Any]]:
        mappings = service.get("port_mappings")
        if mappings:
            return _normalize_port_mappings(
                service["local_host"],
                int(service["local_port"]),
                int(service["onion_port"]),
                [
                    item for item in mappings
                    if not (
                        str(item.get("local_host", service["local_host"])) == str(service["local_host"])
                        and int(item.get("local_port", service["local_port"])) == int(service["local_port"])
                        and int(item.get("onion_port", service["onion_port"])) == int(service["onion_port"])
                    )
                ],
            )
        return _normalize_port_mappings(
            service["local_host"], int(service["local_port"]), int(service["onion_port"])
        )

    def _check_local_target(self, service: dict[str, Any]) -> None:
        for mapping in self._service_port_mappings(service):
            host, port = validate_loopback_target(mapping["local_host"], int(mapping["local_port"]))
            try:
                with socket.create_connection((host, port), timeout=2.5):
                    pass
            except OSError as exc:
                raise OnionHostingError(
                    f"Local target {host}:{port} for Onion port {mapping['onion_port']} is not accepting TCP connections. "
                    "Start every mapped local service before publishing the Onion Service."
                ) from exc

    def resolve_local_public_target(self, hostname: str, onion_port: int) -> tuple[str, int] | None:
        """Resolve this process's active public Onion address to its loopback relay.

        Private services intentionally never use this shortcut: their V3 client
        authorization must still be enforced by Tor.
        """
        normalized = str(hostname or "").strip().rstrip(".").casefold()
        if not normalized.endswith(".onion"):
            return None
        onion_id = normalized[:-6]
        if not _SERVICE_ID_RE.fullmatch(onion_id):
            return None
        if type(onion_port) is not int or not 1 <= onion_port <= 65535:
            return None

        with self._lock:
            manager = self._manager
            if (
                self._shutdown_requested
                or manager is None
                or getattr(getattr(manager, "state", None), "value", "") != "ready"
            ):
                return None
            process_identity = self._manager_process_identity(manager)
            if not process_identity.get("alive") or not process_identity.get("verified"):
                return None

            for profile_id, active_id in tuple(self._active_services.items()):
                if str(active_id).casefold() != onion_id:
                    continue
                try:
                    service = self._find_service(profile_id)
                except OnionHostingError:
                    continue
                if str(service.get("access_mode", "public")).casefold() != "public":
                    continue
                relay = self._traffic_relays.get(profile_id)
                if relay is None:
                    continue
                target = relay.local_target(onion_port)
                if target is None:
                    continue
                host, port = target
                try:
                    address = ipaddress.ip_address(str(host))
                except ValueError:
                    continue
                if not address.is_loopback or type(port) is not int or not 1 <= port <= 65535:
                    continue
                return str(address), port
        return None

    def start_service(self, profile_id: str) -> str:
        with self._service_lifecycle_lock:
            return self._start_service_locked(profile_id)

    def _start_service_locked(self, profile_id: str) -> str:
        with self._lock:
            if self._shutdown_requested:
                raise OnionHostingError("Developer Tor is shutting down; Onion Services cannot be started.")
        service = self._find_service(profile_id)
        self._check_local_target(service)
        manager = self._manager
        if manager is None or getattr(manager.state, "value", "") != "ready":
            raise OnionHostingError("Start Developer Tor and wait for bootstrap to reach 100% first.")
        process_identity = self._manager_process_identity(manager)
        if not process_identity.get("alive") or not process_identity.get("verified"):
            raise OnionHostingError(
                "Developer Tor's actual process is not alive with a verified identity; "
                "the Onion Service will not be published."
            )
        with self._lock:
            if profile_id in self._active_services:
                return self._active_services[profile_id]
        access_mode = service.get("access_mode", "public")
        flags = ["Detach"]
        command_key = "NEW:ED25519-V3"
        client_public = ""
        if access_mode == "private":
            client_public = str(service.get("client_public_key") or "")
            if not _CLIENT_KEY_RE.fullmatch(client_public):
                raise OnionHostingError("The private-access public key is missing or invalid.")
            flags.append("V3Auth")
        key_material: dict[str, str] = {}
        if service.get("persistent"):
            key_path = self._key_path(profile_id)
            key_material = self._read_key_material(profile_id) if key_path.exists() else {}
            stored_key = key_material.get("tor_private_key", "")
            if service.get("service_id") and not stored_key:
                raise OnionHostingError(
                    f"Persistent identity for '{profile_id}' is missing its Tor private key. "
                    "The service will not be recreated with a different Onion address."
                )
            if stored_key:
                command_key = self._validate_tor_private_key(stored_key)
        else:
            key_material = dict(self._temporary_keys.get(profile_id, {}))
            if key_material.get("tor_private_key"):
                command_key = key_material["tor_private_key"]
        if access_mode == "private":
            self._validate_client_authorization(service, key_material)
        mappings = self._service_port_mappings(service)
        relay = OnionServiceRelay(profile_id, mappings, self._traffic_store)
        try:
            relay_mappings = relay.start()
            port_arguments = []
            for mapping in relay_mappings:
                port_arguments.append(
                    f"Port={mapping['onion_port']},127.0.0.1:{mapping['local_port']}"
                )
            command = f"ADD_ONION {command_key} Flags={','.join(flags)} " + " ".join(port_arguments)
            if client_public:
                command += f" ClientAuthV3={client_public.upper()}"
            response = self._control(command)
            fields = self._parse_control_response(response)
            onion_id = fields.get("ServiceID", "")
            if not _SERVICE_ID_RE.fullmatch(onion_id):
                raise OnionHostingError("Tor did not return a valid v3 Onion Service address.")
            private_key = fields.get("PrivateKey", "")
            if not key_material.get("tor_private_key"):
                try:
                    private_key = self._validate_tor_private_key(private_key)
                except OnionHostingError:
                    try:
                        self._control(f"DEL_ONION {onion_id}")
                    except Exception:
                        pass
                    if service.get("persistent"):
                        raise OnionHostingError("Tor did not return a valid private key needed to preserve this Onion address.")
                    raise OnionHostingError("Tor did not return a valid temporary service identity.")
                key_material["tor_private_key"] = private_key
            try:
                if service.get("persistent"):
                    self._write_key_material(profile_id, key_material)
                    saved = self._saved_services()
                    updated = []
                    for item in saved:
                        updated.append({**item, "service_id": onion_id} if item["id"] == profile_id else item)
                    self._persist_services(updated)
                else:
                    with self._lock:
                        self._temporary_keys[profile_id] = key_material
                        self._temporary_services[profile_id]["service_id"] = onion_id
            except Exception:
                try:
                    self._control(f"DEL_ONION {onion_id}")
                except Exception:
                    LOGGER.exception("Could not roll back an Onion Service after key persistence failed.")
                raise
        except Exception:
            relay.close()
            raise
        with self._lock:
            self._active_services[profile_id] = onion_id
            self._traffic_relays[profile_id] = relay
            self._service_errors.pop(profile_id, None)
        return onion_id + ".onion"

    def stop_service(self, profile_id: str) -> None:
        with self._service_lifecycle_lock:
            self._stop_service_locked(profile_id)

    def _stop_service_locked(self, profile_id: str) -> None:
        with self._lock:
            onion_id = self._active_services.get(profile_id)
        if not onion_id:
            return
        self._control(f"DEL_ONION {onion_id}")
        with self._lock:
            self._active_services.pop(profile_id, None)
            relay = self._traffic_relays.pop(profile_id, None)
        if relay is not None:
            relay.close()

    def delete_service(self, profile_id: str) -> None:
        with self._service_lifecycle_lock:
            with self._lock:
                if self._shutdown_requested:
                    raise OnionHostingError("Developer Tor is shutting down; services cannot be changed.")
            self._delete_service_locked(profile_id)

    def _delete_service_locked(self, profile_id: str) -> None:
        self.stop_service(profile_id)
        with self._lock:
            temporary = profile_id in self._temporary_services
        if temporary:
            self._temporary_services.pop(profile_id, None)
            self._temporary_keys.pop(profile_id, None)
        else:
            saved = [item for item in self._saved_services() if item["id"] != profile_id]
            self._persist_services(saved)
            self._remove_key_material(profile_id)
        self._service_errors.pop(profile_id, None)
        self._traffic_store.delete_service(profile_id)

    def rotate_service_identity(self, profile_id: str) -> None:
        with self._service_lifecycle_lock:
            with self._lock:
                if self._shutdown_requested:
                    raise OnionHostingError("Developer Tor is shutting down; service identities cannot be changed.")
            self._rotate_service_identity_locked(profile_id)

    def _rotate_service_identity_locked(self, profile_id: str) -> None:
        """Discard the stopped service's Ed25519 identity so its next start gets a new .onion address."""
        with self._lock:
            if profile_id in self._active_services:
                raise OnionHostingError("Stop this Onion Service before generating a new .onion address.")
        current = self._find_service(profile_id)
        old_onion_id = str(current.get("service_id") or "")
        if not _SERVICE_ID_RE.fullmatch(old_onion_id):
            raise OnionHostingError("This Onion Service does not have an assigned address to rotate yet.")

        persistent = bool(current.get("persistent", True))
        if persistent:
            key_path = self._key_path(profile_id)
            if not key_path.is_file():
                raise OnionHostingError(
                    "The persistent identity key is missing; TorProxy will not silently replace it."
                )
            material = self._read_key_material(profile_id)
            if not material.get("tor_private_key"):
                raise OnionHostingError(
                    "The persistent Tor identity key is missing; the existing Onion address cannot be safely rotated."
                )
            previous_material = dict(material)
            material.pop("tor_private_key", None)
            self._write_key_material(profile_id, material)
            saved = self._saved_services()
            updated = [
                {**item, "service_id": ""} if item["id"] == profile_id else item
                for item in saved
            ]
            try:
                self._persist_services(updated)
            except Exception:
                self._write_key_material(profile_id, previous_material)
                raise
        else:
            with self._lock:
                material = dict(self._temporary_keys.get(profile_id, {}))
                material.pop("tor_private_key", None)
                self._temporary_keys[profile_id] = material
                self._temporary_services[profile_id]["service_id"] = ""

    def traffic_snapshot(self, service_id: str | None = None) -> dict[str, Any]:
        return self._traffic_store.snapshot(service_id)

    def traffic_snapshots(self, service_ids: list[str]) -> dict[str, Any]:
        """Return global and per-service counters from one short-lived SQLite read."""
        return self._traffic_store.snapshot_many(service_ids)

    def traffic_events(self, service_id: str, limit: int = 250) -> list[dict[str, Any]]:
        return self._traffic_store.events(service_id, limit=limit)

    def client_auth_private_file(self, profile_id: str) -> str:
        service = self._find_service(profile_id)
        if service.get("access_mode") != "private":
            raise OnionHostingError("This Onion Service is public and does not use client authorization.")
        onion_id = self._active_services.get(profile_id) or str(service.get("service_id") or "")
        if not _SERVICE_ID_RE.fullmatch(onion_id):
            raise OnionHostingError("Start the service once before exporting its client authorization file.")
        if service.get("persistent"):
            material = self._read_key_material(profile_id)
        else:
            material = self._temporary_keys.get(profile_id, {})
        private_key = self._validate_client_authorization(service, material)
        return f"{onion_id}:descriptor:x25519:{private_key.upper()}"

    def services_snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            active = dict(self._active_services)
            errors = dict(self._service_errors)
            temporary = {key: dict(value) for key, value in self._temporary_services.items()}
        services = self._saved_services() + list(temporary.values())
        result = []
        for item in services:
            profile_id = item["id"]
            onion_id = active.get(profile_id) or str(item.get("service_id") or "")
            result.append({
                **item,
                "address": onion_id + ".onion" if _SERVICE_ID_RE.fullmatch(onion_id) else "",
                "running": profile_id in active,
                "error": errors.get(profile_id, ""),
            })
        return result

    def close(self) -> None:
        self.shutdown_runtime()
