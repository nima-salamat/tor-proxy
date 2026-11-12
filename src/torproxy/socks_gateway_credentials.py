"""Secure per-user credentials for the Main Tor SOCKS5 gateway.

The secret is deliberately kept outside config.json. Remote clients authenticate
with RFC 1929 username/password; local loopback clients retain no-auth access.
"""
from __future__ import annotations

import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any

from .paths import user_directories


class SocksGatewayCredentialError(ValueError):
    """The Main SOCKS gateway credential file is invalid or cannot be saved."""


def credentials_path(directories=None) -> Path:
    roots = directories or user_directories()
    return Path(roots.data) / "tor-gateway" / "credentials.json"


def _validate(username: Any, password: Any) -> tuple[str, str]:
    if not isinstance(username, str) or not isinstance(password, str):
        raise SocksGatewayCredentialError("SOCKS gateway credentials must be text.")
    if not username or not password:
        raise SocksGatewayCredentialError("Both SOCKS username and password are required.")
    if (
        len(username.encode("utf-8")) > 255
        or len(password.encode("utf-8")) > 255
        or any(ord(char) < 32 or ord(char) == 127 for char in username + password)
    ):
        raise SocksGatewayCredentialError(
            "SOCKS username and password must contain 1–255 UTF-8 bytes of printable text."
        )
    return username, password


def read_socks_gateway_credentials(directories=None) -> dict[str, str]:
    path = credentials_path(directories)
    if not path.is_file():
        return {"username": "", "password": ""}
    try:
        if os.name != "nt":
            mode = path.stat().st_mode & 0o777
            if mode & 0o077:
                path.chmod(0o600)
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SocksGatewayCredentialError(
            "Saved Main SOCKS gateway credentials are unavailable or damaged; remote access was not enabled."
        ) from exc
    if not isinstance(value, dict) or set(value) != {"username", "password"}:
        raise SocksGatewayCredentialError("Saved Main SOCKS gateway credential data is invalid.")
    username, password = _validate(value.get("username"), value.get("password"))
    return {"username": username, "password": password}


def write_socks_gateway_credentials(username: str, password: str, directories=None) -> None:
    username, password = _validate(username, password)
    path = credentials_path(directories)
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        directory.chmod(0o700)
    fd, temporary = tempfile.mkstemp(prefix=".socks-gateway-", suffix=".tmp", dir=directory)
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
        raise SocksGatewayCredentialError("Could not securely save Main SOCKS gateway credentials.") from exc


def generate_socks_gateway_credentials() -> dict[str, str]:
    """Generate a unique client identity and a high-entropy password."""
    return {
        "username": "torproxy-" + secrets.token_hex(5),
        "password": secrets.token_urlsafe(32),
    }
