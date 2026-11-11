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
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .paths import user_directories
from .tor_manager import TorManager, TorManagerError, TorSettings, TorState

LOGGER = logging.getLogger(__name__)
_SERVICE_ID_RE = re.compile(r"^[a-z2-7]{56}$")
_CLIENT_KEY_RE = re.compile(r"^[a-z2-7]{52}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_MAX_SERVICES = 32


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
        self._manager: TorManager | None = None
        self._started_at: float | None = None
        self._temporary_services: dict[str, dict[str, Any]] = {}
        self._active_services: dict[str, str] = {}
        self._service_errors: dict[str, str] = {}
        self._temporary_keys: dict[str, dict[str, str]] = {}
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

    def _config_store(self):
        if self._config is None:
            from config import CONFIG
            self._config = CONFIG
        return self._config

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
        return {str(key): str(item) for key, item in value.items()}

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
        except (TorManagerError, Exception) as exc:
            # Never include a command in the exception: it can contain private keys.
            raise OnionHostingError(f"Tor ControlPort rejected the Onion Service operation: {exc}") from exc

    def runtime_snapshot(self) -> dict[str, Any]:
        with self._lock:
            manager = self._manager
            started_at = self._started_at
            message = self._last_status_message
        if manager is None:
            return {
                "state": "stopped", "progress": None, "message": "Developer Tor is stopped.",
                "version": "", "uptime_seconds": 0, "memory_bytes": 0, "pid": None,
            }
        state = getattr(manager.state, "value", str(manager.state)).lower()
        process = manager.process
        pid = getattr(process, "pid", None)
        memory = 0
        if pid:
            try:
                import psutil
                memory = int(psutil.Process(pid).memory_info().rss)
            except Exception:
                memory = 0
        version = ""
        if state == "ready" and getattr(manager, "_controller", None) is not None:
            try:
                version = str(manager._controller.get_info("version", ""))
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
        }

    def start_runtime(self, on_status: Callable[[str, int | None, str], None] | None = None) -> None:
        """Start the dedicated Tor process; persistent auto-start services are restored after bootstrap."""
        if not self._runtime_start_lock.acquire(blocking=False):
            raise OnionHostingError("Developer Tor is already starting.")
        try:
            with self._lock:
                if self._manager is not None and getattr(self._manager.state, "value", "") == "ready":
                    return
                if self._manager is not None and getattr(self._manager, "process", None) is not None:
                    if self._manager.process.poll() is None:
                        raise OnionHostingError("Developer Tor is already starting or stopping.")
                manager = self._manager_factory(self._settings_factory())
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
                manager.start(on_status=report)
            except Exception:
                with self._lock:
                    self._started_at = None
                raise
            with self._lock:
                self._started_at = time.monotonic()

            for service in self._saved_services():
                if service.get("auto_start"):
                    try:
                        self.start_service(service["id"])
                    except Exception as exc:
                        self._service_errors[service["id"]] = str(exc)
                        LOGGER.warning("Could not auto-start Onion Service '%s': %s", service["id"], exc)
        finally:
            self._runtime_start_lock.release()

    def stop_runtime(self, *, force: bool = False) -> None:
        """Remove active Onion Services, then stop only the owned Developer Tor process."""
        with self._lock:
            manager = self._manager
            active = list(self._active_services.items())
        if manager is None:
            return
        errors: list[str] = []
        for profile_id, service_id in active:
            try:
                self._control(f"DEL_ONION {service_id}")
            except Exception as exc:
                errors.append(f"{profile_id}: {exc}")
            else:
                with self._lock:
                    self._active_services.pop(profile_id, None)
        runtime_stopped = False
        try:
            manager.force_stop() if force else manager.stop()
            runtime_stopped = True
        except Exception as exc:
            errors.append(f"Tor runtime: {exc}")
        if runtime_stopped:
            # Once the child process is gone, no detached service can remain
            # published. Temporary profiles and volatile key material expire.
            with self._lock:
                self._manager = None
                self._started_at = None
                self._last_status_message = "Developer Tor stopped."
                self._temporary_services.clear()
                self._temporary_keys.clear()
                self._active_services.clear()
                self._service_errors.clear()
        if errors:
            raise OnionHostingError("; ".join(errors))

    def create_service(
        self,
        *,
        display_name: str,
        local_host: str,
        local_port: int,
        onion_port: int = 80,
        persistent: bool = True,
        access_mode: str = "public",
        auto_start: bool = True,
    ) -> str:
        name = str(display_name).strip()
        if not name or len(name) > 80:
            raise OnionHostingError("Service name is required and must contain at most 80 characters.")
        host, local_port = validate_loopback_target(local_host, local_port)
        if type(onion_port) is not int or not 1 <= onion_port <= 65535:
            raise OnionHostingError("The Onion port must be between 1 and 65535.")
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
        allowed = {"display_name", "local_host", "local_port", "onion_port", "persistent", "access_mode", "auto_start"}
        if set(changes) - allowed:
            raise OnionHostingError("Unsupported Onion Service setting.")
        with self._lock:
            if service_id in self._active_services:
                raise OnionHostingError("Stop this Onion Service before editing it.")
        current = self._find_service(service_id)
        merged = dict(current)
        merged.update(changes)
        host, port = validate_loopback_target(merged["local_host"], int(merged["local_port"]))
        merged["local_host"], merged["local_port"] = host, port
        merged["display_name"] = str(merged["display_name"]).strip()
        if not merged["display_name"] or len(merged["display_name"]) > 80:
            raise OnionHostingError("Service name is required and must contain at most 80 characters.")
        if type(merged["onion_port"]) is not int or not 1 <= merged["onion_port"] <= 65535:
            raise OnionHostingError("The Onion port must be between 1 and 65535.")
        if type(merged["persistent"]) is not bool or type(merged["auto_start"]) is not bool:
            raise OnionHostingError("Persistent and Auto Start must be true or false.")
        if merged["access_mode"] not in {"public", "private"}:
            raise OnionHostingError("Access mode must be Public or Private.")

        was_persistent = bool(current.get("persistent", True))
        now_persistent = bool(merged["persistent"])
        previous_access = current.get("access_mode", "public")
        material = (
            self._read_key_material(service_id)
            if was_persistent and self._key_path(service_id).is_file()
            else dict(self._temporary_keys.get(service_id, {}))
        )
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

    def _check_local_target(self, service: dict[str, Any]) -> None:
        host, port = validate_loopback_target(service["local_host"], int(service["local_port"]))
        try:
            with socket.create_connection((host, port), timeout=2.5):
                pass
        except OSError as exc:
            raise OnionHostingError(
                f"Local service {host}:{port} is not accepting TCP connections. "
                "Start the web server first, then retry."
            ) from exc

    def start_service(self, profile_id: str) -> str:
        service = self._find_service(profile_id)
        self._check_local_target(service)
        manager = self._manager
        if manager is None or getattr(manager.state, "value", "") != "ready":
            raise OnionHostingError("Start Developer Tor and wait for bootstrap to reach 100% first.")
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
            key_material = self._read_key_material(profile_id) if self._key_path(profile_id).exists() else {}
            stored_key = key_material.get("tor_private_key", "")
            if stored_key:
                command_key = stored_key
        else:
            key_material = dict(self._temporary_keys.get(profile_id, {}))
            if key_material.get("tor_private_key"):
                command_key = key_material["tor_private_key"]
        target_host = service["local_host"]
        target = f"[{target_host}]:{service['local_port']}" if ":" in target_host else f"{target_host}:{service['local_port']}"
        command = f"ADD_ONION {command_key} Flags={','.join(flags)} Port={service['onion_port']},{target}"
        if client_public:
            command += f" ClientAuthV3={client_public.upper()}"
        response = self._control(command)
        fields = self._parse_control_response(response)
        onion_id = fields.get("ServiceID", "")
        if not _SERVICE_ID_RE.fullmatch(onion_id):
            raise OnionHostingError("Tor did not return a valid v3 Onion Service address.")
        private_key = fields.get("PrivateKey", "")
        if not key_material.get("tor_private_key"):
            if not private_key.startswith("ED25519-V3:"):
                try:
                    self._control(f"DEL_ONION {onion_id}")
                except Exception:
                    pass
                if service.get("persistent"):
                    raise OnionHostingError("Tor did not return the private key needed to preserve this Onion address.")
                raise OnionHostingError("Tor did not return the temporary service identity.")
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
        with self._lock:
            self._active_services[profile_id] = onion_id
            self._service_errors.pop(profile_id, None)
        return onion_id + ".onion"

    def stop_service(self, profile_id: str) -> None:
        with self._lock:
            onion_id = self._active_services.get(profile_id)
        if not onion_id:
            return
        self._control(f"DEL_ONION {onion_id}")
        with self._lock:
            self._active_services.pop(profile_id, None)

    def delete_service(self, profile_id: str) -> None:
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
        private_key = str(material.get("client_private_key") or "")
        if not _CLIENT_KEY_RE.fullmatch(private_key):
            raise OnionHostingError("The client authorization private key is unavailable.")
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
        self.stop_runtime()
