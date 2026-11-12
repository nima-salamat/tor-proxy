"""Permission-restricted per-profile storage for optional Tor upstream credentials.

Credentials are deliberately kept out of config.json and out of profile metadata.
The Tor manager receives them only when constructing the profile's runtime settings.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from .paths import user_directories

_SERVICE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class ServiceCredentialError(ValueError):
    """A profile credential file is invalid or could not be safely persisted."""


def credentials_path(service_id: str, directories=None) -> Path:
    service_id = str(service_id).strip()
    if not _SERVICE_ID.fullmatch(service_id):
        raise ServiceCredentialError("Invalid Custom Tor profile ID.")
    roots = directories or user_directories()
    return Path(roots.data) / "tor-services" / "credentials" / f"{service_id}.json"


def _validate(username: Any, password: Any) -> tuple[str, str]:
    if not isinstance(username, str) or not isinstance(password, str):
        raise ServiceCredentialError("Upstream proxy credentials must be text.")
    if bool(username) != bool(password):
        raise ServiceCredentialError("Enter both upstream proxy username and password, or leave both empty.")
    if username and (
        len(username) > 255
        or len(password) > 255
        or any(ord(char) < 32 or ord(char) == 127 for char in username + password)
    ):
        raise ServiceCredentialError("Upstream proxy credentials must be 1–255 printable characters.")
    return username, password


def read_upstream_credentials(service_id: str, directories=None) -> dict[str, str]:
    path = credentials_path(service_id, directories)
    if not path.is_file():
        return {"upstream_proxy_username": "", "upstream_proxy_password": ""}
    try:
        if os.name != "nt":
            mode = path.stat().st_mode & 0o777
            if mode & 0o077:
                path.chmod(0o600)
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ServiceCredentialError(
            "Saved upstream proxy credentials are unavailable or damaged; the profile will not start with missing credentials."
        ) from exc
    if not isinstance(value, dict) or set(value).difference({"username", "password"}):
        raise ServiceCredentialError("Saved upstream proxy credential data is invalid.")
    username, password = _validate(value.get("username", ""), value.get("password", ""))
    return {"upstream_proxy_username": username, "upstream_proxy_password": password}


def write_upstream_credentials(
    service_id: str,
    username: str,
    password: str,
    directories=None,
) -> None:
    username, password = _validate(username, password)
    path = credentials_path(service_id, directories)
    if not username:
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            raise ServiceCredentialError("Could not remove saved upstream proxy credentials.") from exc
        return

    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        directory.chmod(0o700)
    fd, temporary = tempfile.mkstemp(prefix=".profile-proxy-", suffix=".tmp", dir=directory)
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
        raise ServiceCredentialError("Could not securely save upstream proxy credentials.") from exc


def delete_upstream_credentials(service_id: str, directories=None) -> None:
    path = credentials_path(service_id, directories)
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise ServiceCredentialError("Could not remove saved upstream proxy credentials.") from exc
