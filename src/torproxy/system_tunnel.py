"""System-wide TUN routing through the locally managed Tor SOCKS listener.

The sing-box executable is downloaded from an official, version-pinned release and
verified before installation. Its privileged helper is intentionally narrow: it
can only run/stop the verified sing-box binary with a validated Tor-only config.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import psutil
import requests

from .network import NetworkRouteError, create_session
from .paths import user_directories


SING_BOX_LATEST_VERSION = "1.14.4"
# Releases reviewed and shipped with TorProxy. Newer stable releases are installable
# after a warning, using the exact official GitHub asset and its published API digest.
SUPPORTED_SING_BOX_VERSIONS = ("1.14.4", "1.14.3", "1.14.2")
SING_BOX_VERSION = SING_BOX_LATEST_VERSION
SING_BOX_VERSION_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
SING_BOX_RELEASES_API = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
TUN_INTERFACE_WINDOWS = "TorProxy"
TUN_INTERFACE_LINUX = "torproxy-tun"
MAX_ENGINE_ARCHIVE_BYTES = 64 * 1024 * 1024
HELPER_START_TIMEOUT_SECONDS = 25.0
HELPER_STOP_TIMEOUT_SECONDS = 15.0

_SING_BOX_RELEASE_METADATA = {
    "1.14.4": {"published_at": "2026-10-24T01:04:25Z", "asset_sizes": {"Windows": 32891280, "Linux": 32527188}},
    "1.14.3": {"published_at": "2026-10-09T05:35:00Z", "asset_sizes": {"Windows": 32853953, "Linux": 32493273}},
    "1.14.2": {"published_at": "2026-09-24T11:47:08Z", "asset_sizes": {"Windows": 32857903, "Linux": 32500990}},
}

_ENGINE_RELEASES = {
    "1.14.4": {
        ("Windows", "amd64"): {
            "url": "https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-windows-amd64.zip",
            "sha256": "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df",
            "archive": "zip", "executable": "sing-box.exe",
        },
        ("Linux", "x86_64"): {
            "url": "https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-amd64-glibc.tar.gz",
            "sha256": "231e57c18378f780a08de832844a1ca9716e17a7bcf82964b350844d243c03ac",
            "archive": "tar.gz", "executable": "sing-box",
        },
    },
    "1.14.3": {
        ("Windows", "amd64"): {
            "url": "https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-windows-amd64.zip",
            "sha256": "d8b86ef58936dba9230ec6a57ffa4243933f3c14ef4809828b6c553440ed1518",
            "archive": "zip", "executable": "sing-box.exe",
        },
        ("Linux", "x86_64"): {
            "url": "https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-amd64-glibc.tar.gz",
            "sha256": "cadbaded70a635d0c37bf52614d8e3116542243247211e0b441328595c62acb6",
            "archive": "tar.gz", "executable": "sing-box",
        },
    },
    "1.14.2": {
        ("Windows", "amd64"): {
            "url": "https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-windows-amd64.zip",
            "sha256": "c2d8bfff918755808781dfdeeb8581b6c91eb3a243d9a7b55483cfc0c0684d32",
            "archive": "zip", "executable": "sing-box.exe",
        },
        ("Linux", "x86_64"): {
            "url": "https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-amd64-glibc.tar.gz",
            "sha256": "5c7bc18461827b28d0e5ee7e89d33b276d3ff7c818531104c8e8d26d85b0656e",
            "archive": "tar.gz", "executable": "sing-box",
        },
    },
}
_ENGINE_ASSETS = _ENGINE_RELEASES[SING_BOX_VERSION]


class SystemTunnelError(RuntimeError):
    """The system-wide Tor tunnel could not be installed, started, or stopped."""


def _normalize_upstream_asset(
    version: str,
    raw_asset: dict[str, Any],
    *,
    system: str | None = None,
    machine: str | None = None,
    require_size: bool = True,
) -> dict[str, Any]:
    """Validate an exact sing-box GitHub release asset and optional API digest."""
    if not SING_BOX_VERSION_PATTERN.fullmatch(str(version)):
        raise SystemTunnelError("The upstream sing-box release version is not a stable numeric version.")
    system = system or platform.system()
    machine = (machine or platform.machine()).lower()
    if system == "Windows" and machine in {"amd64", "x86_64"}:
        archive, executable = "zip", "sing-box.exe"
        filename = f"sing-box-{version}-windows-amd64.zip"
    elif system == "Linux" and machine in {"x86_64", "amd64"}:
        archive, executable = "tar.gz", "sing-box"
        filename = f"sing-box-{version}-linux-amd64-glibc.tar.gz"
    else:
        raise SystemTunnelError(f"Upstream sing-box releases are not packaged for {system} / {machine}.")

    url = str(raw_asset.get("url") or raw_asset.get("browser_download_url") or "")
    parsed = urlsplit(url)
    expected_path = f"/SagerNet/sing-box/releases/download/v{version}/{filename}"
    if (
        parsed.scheme != "https" or parsed.hostname != "github.com"
        or parsed.username or parsed.password or parsed.port not in (None, 443)
        or parsed.path != expected_path or parsed.query or parsed.fragment
    ):
        raise SystemTunnelError("The upstream asset URL is not the exact official SagerNet GitHub release asset.")
    if str(raw_asset.get("archive") or archive) != archive:
        raise SystemTunnelError("The upstream release archive type does not match this platform.")
    if str(raw_asset.get("filename") or filename) != filename:
        raise SystemTunnelError("The upstream release filename does not match the selected version/platform.")

    raw_digest = str(raw_asset.get("sha256") or raw_asset.get("digest") or "").strip()
    if raw_digest.startswith("sha256:"):
        raw_digest = raw_digest.split(":", 1)[1]
    if raw_digest and not SHA256_PATTERN.fullmatch(raw_digest):
        raise SystemTunnelError("GitHub returned an invalid SHA-256 digest for the sing-box asset.")
    try:
        size = int(raw_asset.get("size", 0) or 0)
    except (TypeError, ValueError) as exc:
        raise SystemTunnelError("GitHub returned an invalid sing-box asset size.") from exc
    if require_size and not 0 < size <= MAX_ENGINE_ARCHIVE_BYTES:
        raise SystemTunnelError("The GitHub release asset size is missing or exceeds the safe download limit.")

    return {
        "url": url,
        "sha256": raw_digest.lower(),
        "archive": archive,
        "executable": executable,
        "filename": filename,
        "size": size,
        "release_url": str(raw_asset.get("release_url") or f"https://github.com/SagerNet/sing-box/releases/tag/v{version}"),
        "published_at": str(raw_asset.get("published_at") or ""),
        "verification": "github-release-api-digest" if raw_digest else "github-release-https-only",
    }


def _find_upstream_platform_asset(version: str, release: dict[str, Any]) -> dict[str, Any] | None:
    """Select only the exact official Windows/Linux x64 asset from the API response."""
    if platform.system() == "Windows" and platform.machine().lower() in {"amd64", "x86_64"}:
        expected = f"sing-box-{version}-windows-amd64.zip"
    elif platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}:
        expected = f"sing-box-{version}-linux-amd64-glibc.tar.gz"
    else:
        return None
    assets = release.get("assets")
    if not isinstance(assets, list):
        return None
    for asset in assets:
        if not isinstance(asset, dict) or str(asset.get("name", "")) != expected:
            continue
        try:
            return _normalize_upstream_asset(version, {
                "url": asset.get("browser_download_url"),
                "digest": asset.get("digest"),
                "size": asset.get("size"),
                "filename": asset.get("name"),
                "release_url": release.get("html_url"),
                "published_at": release.get("published_at"),
            })
        except SystemTunnelError:
            return None
    return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_path = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(raw_path, mode)
        os.replace(raw_path, path)
    finally:
        try:
            os.unlink(raw_path)
        except OSError:
            pass


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _interface_exists(name: str) -> bool:
    if os.name == "nt":
        return any(existing.casefold() == name.casefold() for existing in psutil.net_if_addrs())
    try:
        socket.if_nametoindex(name)
        return True
    except OSError:
        return False


def _process_matches(state: dict[str, Any]) -> psutil.Process | None:
    """Return a process only when PID, image, start time and config all match."""
    try:
        pid = int(state["pid"])
        expected_created = float(state["create_time"])
        expected_exe = os.path.normcase(str(Path(state["engine"]).resolve()))
        expected_config = str(Path(state["config"]).resolve())
        process = psutil.Process(pid)
        if not process.is_running() or process.status() == psutil.STATUS_ZOMBIE:
            return None
        if abs(process.create_time() - expected_created) > 2.0:
            return None
        actual_exe = os.path.normcase(str(Path(process.exe()).resolve()))
        if actual_exe != expected_exe:
            return None
        command = process.cmdline()
        if "run" not in command or expected_config not in command:
            return None
        return process
    except (KeyError, TypeError, ValueError, OSError, psutil.Error):
        return None


class SystemTunnelManager:
    """Install and supervise sing-box without changing the user's system proxy."""

    def __init__(self, directories=None, version: str | None = None):
        self.directories = directories or user_directories()
        self.runtime_dir = self.directories.data / "system-tunnel"
        self.engine_dir = self.runtime_dir / "engine"
        self.state_dir = self.directories.state / "system-tunnel"
        self.engine_path = self.engine_dir / ("sing-box.exe" if os.name == "nt" else "sing-box")
        self.install_manifest = self.runtime_dir / "engine.json"
        self.config_path = self.state_dir / "sing-box.json"
        self.process_state_path = self.state_dir / "sing-box-process.json"
        self.log_path = self.directories.logs / "system-tunnel.log"
        manifest = _read_json(self.install_manifest)
        saved_version = str(manifest.get("version", "")) if manifest else ""
        self._release_asset: dict[str, Any] | None = None
        if manifest and saved_version not in _ENGINE_RELEASES and isinstance(manifest.get("release_asset"), dict):
            try:
                self._release_asset = _normalize_upstream_asset(saved_version, manifest["release_asset"])
            except SystemTunnelError:
                self._release_asset = None
        saved_version_is_usable = saved_version in _ENGINE_RELEASES or self._release_asset is not None
        self.version = version or (
            saved_version if saved_version_is_usable else SING_BOX_LATEST_VERSION
        )
        self.archive_path = self._archive_path_for(self.version)
        self._install_state_cache: tuple[tuple[str, int, int], ...] | None = None
        self._install_state_result = False

    def _archive_path_for(self, version: str) -> Path:
        if not SING_BOX_VERSION_PATTERN.fullmatch(str(version)):
            raise SystemTunnelError("Invalid sing-box version for an engine archive path.")
        return self.runtime_dir / f"sing-box-{version}-{platform.system().lower()}.archive"

    @property
    def installed_version(self) -> str | None:
        manifest = _read_json(self.install_manifest)
        version = str(manifest.get("version", "")) if manifest else ""
        if version in _ENGINE_RELEASES:
            return version
        archive_digest = str((manifest or {}).get("archive_sha256", ""))
        if self._release_asset is not None and version == self.version and SHA256_PATTERN.fullmatch(archive_digest):
            return version
        return None

    @property
    def installed_release_asset(self) -> dict[str, Any] | None:
        if self.installed_version and self.installed_version not in _ENGINE_RELEASES and self._release_asset:
            return dict(self._release_asset)
        return None

    @staticmethod
    def supported_versions() -> tuple[str, ...]:
        return SUPPORTED_SING_BOX_VERSIONS

    @staticmethod
    def release_metadata(version: str) -> dict[str, Any]:
        if version not in _SING_BOX_RELEASE_METADATA:
            raise SystemTunnelError(f"Unsupported sing-box version: {version}")
        return {"version": version, **_SING_BOX_RELEASE_METADATA[version]}

    def select_version(
        self,
        version: str,
        *,
        release_asset: dict[str, Any] | None = None,
        allow_unpinned: bool = False,
    ) -> None:
        version = str(version)
        if version in _ENGINE_RELEASES:
            selected_asset = None
        else:
            if not allow_unpinned or not isinstance(release_asset, dict):
                raise SystemTunnelError(
                    "That sing-box version has not been pinned in this TorProxy build. Check the official GitHub release and explicitly accept its warning first."
                )
            selected_asset = _normalize_upstream_asset(version, release_asset)
        if self.is_running() and version != self.version:
            raise SystemTunnelError("Stop the active system tunnel before changing its engine version.")
        self.version = version
        self._release_asset = selected_asset
        self.archive_path = self._archive_path_for(version)
        self._install_state_cache = None
        self._install_state_result = False

    @staticmethod
    def check_latest_release(
        proxy_url: str | None = None,
        *,
        allow_direct: bool = False,
    ) -> dict[str, Any]:
        session = None
        try:
            session = create_session(proxy_url, allow_direct=allow_direct)
            response = session.get(
                SING_BOX_RELEASES_API, timeout=(8, 12),
                headers={"Accept": "application/vnd.github+json", "User-Agent": "TorProxy-System-Tunnel"},
            )
            response.raise_for_status()
            release = response.json()
            if not isinstance(release, dict):
                raise SystemTunnelError("GitHub returned an invalid release response.")
        except NetworkRouteError as exc:
            raise SystemTunnelError(f"Could not select a safe release-check route: {exc}") from exc
        except (requests.RequestException, ValueError, AttributeError) as exc:
            raise SystemTunnelError(f"Could not check the latest sing-box release: {exc}") from exc
        finally:
            if session is not None:
                session.close()
        tag = str(release.get("tag_name", "")).removeprefix("v")
        if (
            release.get("draft") or release.get("prerelease")
            or not SING_BOX_VERSION_PATTERN.fullmatch(tag)
        ):
            raise SystemTunnelError("GitHub did not return a stable numeric sing-box release.")
        platform_asset = _find_upstream_platform_asset(tag, release)
        return {
            "version": tag,
            "published_at": str(release.get("published_at", "")),
            "url": str(release.get("html_url", "https://github.com/SagerNet/sing-box/releases")),
            "supported": tag in SUPPORTED_SING_BOX_VERSIONS,
            "platform_asset": platform_asset,
            "installable": platform_asset is not None,
        }

    @property
    def platform_asset(self) -> dict[str, Any]:
        system = platform.system()
        machine = platform.machine().lower()
        asset = _ENGINE_RELEASES.get(self.version, {}).get((system, machine))
        if asset is not None:
            return dict(asset)
        if self._release_asset is not None:
            return dict(self._release_asset)
        supported = "Windows x64 and glibc-based Linux x86_64"
        raise SystemTunnelError(
            f"System-wide TUN is currently packaged for {supported}; "
            f"this device reports {system} / {machine}. Check the latest official release to install an upstream version."
        )

    @property
    def interface_name(self) -> str:
        return TUN_INTERFACE_WINDOWS if os.name == "nt" else TUN_INTERFACE_LINUX

    def _allowed_archive_files(self) -> set[str]:
        executable = str(self.platform_asset["executable"])
        companion = "libcronet.dll" if os.name == "nt" else "libcronet.so"
        runtime_files = {executable, companion, "LICENSE", "LICENSE.txt", "COPYING"}
        if os.name == "nt":
            runtime_files.add("wintun.dll")
        return runtime_files

    @property
    def engine_sha256(self) -> str:
        manifest = _read_json(self.install_manifest)
        files = manifest.get("files", {}) if manifest else {}
        digest = files.get(self.engine_path.name) if isinstance(files, dict) else None
        if not isinstance(digest, str) or len(digest) != 64:
            raise SystemTunnelError("The installed sing-box engine manifest is missing or invalid.")
        return digest

    def is_installed(self) -> bool:
        manifest = _read_json(self.install_manifest)
        if not manifest or manifest.get("version") != self.version:
            self._install_state_cache = None
            self._install_state_result = False
            return False
        try:
            asset = self.platform_asset
            files = manifest.get("files")
            recorded_archive_digest = str(manifest.get("archive_sha256", ""))
            if (
                not SHA256_PATTERN.fullmatch(recorded_archive_digest)
                or (asset.get("sha256") and recorded_archive_digest != asset["sha256"])
                or not isinstance(files, dict)
                or self.engine_path.name not in files
                or not set(files).issubset(self._allowed_archive_files())
            ):
                self._install_state_cache = None
                self._install_state_result = False
                return False

            paths = [self.install_manifest, self.archive_path]
            paths.extend(self.engine_dir / name for name in files)
            actual_engine_files = {
                path.name for path in self.engine_dir.iterdir()
                if path.is_file() or path.is_symlink()
            }
            if actual_engine_files != set(files):
                self._install_state_cache = None
                self._install_state_result = False
                return False
            signature: list[tuple[str, int, int]] = []
            for path in paths:
                if path.is_symlink() or not path.is_file():
                    self._install_state_cache = None
                    self._install_state_result = False
                    return False
                info = path.stat()
                signature.append((str(path), info.st_size, info.st_mtime_ns))
            cache_key = tuple(signature)
            if self._install_state_cache == cache_key:
                return self._install_state_result

            if _sha256(self.archive_path) != recorded_archive_digest:
                self._install_state_cache = cache_key
                self._install_state_result = False
                return False
            for name, expected in files.items():
                if _sha256(self.engine_dir / name) != expected:
                    self._install_state_cache = cache_key
                    self._install_state_result = False
                    return False
            self._install_state_cache = cache_key
            self._install_state_result = True
            return True
        except (OSError, SystemTunnelError):
            self._install_state_cache = None
            self._install_state_result = False
            return False

    def install_engine(
        self,
        version: str | None = None,
        progress_callback=None,
        *,
        proxy_url: str | None = None,
        allow_direct: bool = False,
        release_asset: dict[str, Any] | None = None,
        allow_unpinned: bool = False,
    ) -> str:
        """Install a pinned release or a user-approved exact GitHub release asset."""
        if version is not None:
            self.select_version(version, release_asset=release_asset, allow_unpinned=allow_unpinned)
        if self.is_running():
            raise SystemTunnelError("Stop the active system tunnel before updating its engine.")
        asset = self.platform_asset
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        staged_archive = self.runtime_dir / f".sing-box-{uuid.uuid4().hex}.archive"
        staged_dir = self.runtime_dir / f".engine-stage-{uuid.uuid4().hex}"
        backup_dir = self.runtime_dir / f".engine-backup-{uuid.uuid4().hex}"
        session = None
        try:
            session = create_session(proxy_url, allow_direct=allow_direct)
            total = 0
            digest = hashlib.sha256()
            if progress_callback:
                progress_callback("download", 0, 0, f"Downloading sing-box {self.version}…")
            with session.get(
                asset["url"], stream=True, timeout=(15, 45),
                headers={"User-Agent": "TorProxy-System-Tunnel"},
            ) as response:
                response.raise_for_status()
                declared = response.headers.get("Content-Length")
                if declared and int(declared) > MAX_ENGINE_ARCHIVE_BYTES:
                    raise SystemTunnelError("The sing-box release archive is larger than expected.")
                with staged_archive.open("wb") as output:
                    for chunk in response.iter_content(1024 * 1024):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > MAX_ENGINE_ARCHIVE_BYTES:
                            raise SystemTunnelError("The sing-box release archive exceeded the size limit.")
                        digest.update(chunk)
                        output.write(chunk)
                        if progress_callback:
                            progress_callback("download", total, int(declared or 0), "Downloading official sing-box archive…")
                    output.flush()
                    os.fsync(output.fileno())
            archive_digest = digest.hexdigest()
            if asset.get("sha256") and archive_digest != asset["sha256"]:
                raise SystemTunnelError("sing-box archive SHA-256 does not match the digest published by GitHub.")
            if progress_callback:
                progress_callback("verify", total, total, "Archive SHA-256 verified; checking runtime files…")

            staged_dir.mkdir(mode=0o700)
            if asset["archive"] == "zip":
                files = self._extract_zip_runtime(staged_archive, staged_dir, asset["executable"])
            else:
                files = self._extract_tar_runtime(staged_archive, staged_dir, asset["executable"])

            staged_executable = staged_dir / asset["executable"]
            if os.name != "nt":
                staged_executable.chmod(0o700)
            version = subprocess.run(
                [str(staged_executable), "version"], cwd=staged_dir,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=10, check=False,
            )
            version_text = (version.stdout or "").strip()
            if version.returncode != 0 or self.version not in version_text:
                raise SystemTunnelError(
                    f"The downloaded engine did not report the expected version {self.version}: "
                    f"{version_text[:240]}"
                )
            if progress_callback:
                progress_callback("install", total, total, f"Verified sing-box {self.version}; installing engine files…")

            if self.engine_dir.exists():
                os.replace(self.engine_dir, backup_dir)
            try:
                os.replace(staged_dir, self.engine_dir)
                os.replace(staged_archive, self.archive_path)
                _atomic_json(
                    self.install_manifest,
                    {
                        "version": self.version,
                        "archive_sha256": archive_digest,
                        "source": asset["url"],
                        "release_asset": asset if self.version not in _ENGINE_RELEASES else None,
                        "verification_method": (
                            "torproxy-pinned-sha256" if self.version in _ENGINE_RELEASES
                            else "github-api-sha256" if asset.get("sha256")
                            else "github-release-https-only"
                        ),
                        "files": files,
                    },
                )
            except Exception:
                if self.engine_dir.exists():
                    shutil.rmtree(self.engine_dir, ignore_errors=True)
                if backup_dir.exists():
                    os.replace(backup_dir, self.engine_dir)
                raise
            if backup_dir.exists():
                shutil.rmtree(backup_dir, ignore_errors=True)
            self._install_state_cache = None
            self._install_state_result = False
            if progress_callback:
                progress_callback("complete", total, total, f"sing-box {self.version} installed and verified.")
            return f"sing-box {self.version} installed; archive and runtime files verified."
        except NetworkRouteError as exc:
            raise SystemTunnelError(f"Could not select a safe sing-box download route: {exc}") from exc
        except requests.RequestException as exc:
            raise SystemTunnelError(f"Could not download sing-box: {exc}") from exc
        finally:
            if session is not None:
                session.close()
            staged_archive.unlink(missing_ok=True)
            if staged_dir.exists():
                shutil.rmtree(staged_dir, ignore_errors=True)
            if backup_dir.exists():
                shutil.rmtree(backup_dir, ignore_errors=True)

    @staticmethod
    def _safe_archive_member(name: str) -> PurePosixPath:
        path = PurePosixPath(name)
        if path.is_absolute() or not path.parts or ".." in path.parts or "\\" in name:
            raise SystemTunnelError("The sing-box archive contains an unsafe member path.")
        return path

    @classmethod
    def _extract_zip_runtime(cls, archive: Path, destination: Path, filename: str) -> dict[str, str]:
        allowed = {filename, "libcronet.dll", "wintun.dll", "LICENSE", "LICENSE.txt", "COPYING"}
        found_executable = 0
        hashes: dict[str, str] = {}
        with zipfile.ZipFile(archive) as bundle:
            for info in bundle.infolist():
                if info.is_dir():
                    continue
                name = cls._safe_archive_member(info.filename).name
                if name not in allowed:
                    continue
                mode = (info.external_attr >> 16) & 0o170000
                if mode not in {0, stat.S_IFREG} or info.file_size <= 0:
                    raise SystemTunnelError(f"The sing-box archive member {name} is not a safe regular file.")
                if info.file_size > (100 * 1024 * 1024 if name == filename else 32 * 1024 * 1024):
                    raise SystemTunnelError(f"The sing-box archive member {name} is larger than expected.")
                if name == filename:
                    found_executable += 1
                if name in hashes:
                    raise SystemTunnelError(f"The sing-box archive contains duplicate runtime file {name}.")
                target = destination / name
                with bundle.open(info) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                hashes[name] = _sha256(target)
        if found_executable != 1:
            raise SystemTunnelError(f"The official Windows archive must contain exactly one {filename}.")
        return hashes

    @classmethod
    def _extract_tar_runtime(cls, archive: Path, destination: Path, filename: str) -> dict[str, str]:
        allowed = {filename, "libcronet.so", "LICENSE", "LICENSE.txt", "COPYING"}
        found_executable = 0
        hashes: dict[str, str] = {}
        with tarfile.open(archive, "r:gz") as bundle:
            for item in bundle.getmembers():
                name = cls._safe_archive_member(item.name).name
                if not item.isfile() or name not in allowed:
                    continue
                if item.issym() or item.islnk() or item.size <= 0:
                    raise SystemTunnelError(f"The sing-box archive member {name} is not a safe regular file.")
                if item.size > (100 * 1024 * 1024 if name == filename else 32 * 1024 * 1024):
                    raise SystemTunnelError(f"The sing-box archive member {name} is larger than expected.")
                if name == filename:
                    found_executable += 1
                if name in hashes:
                    raise SystemTunnelError(f"The sing-box archive contains duplicate runtime file {name}.")
                source = bundle.extractfile(item)
                if source is None:
                    raise SystemTunnelError(f"Could not read sing-box archive member {name}.")
                target = destination / name
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                hashes[name] = _sha256(target)
        if found_executable != 1:
            raise SystemTunnelError(f"The official Linux archive must contain exactly one {filename}.")
        return hashes

    @classmethod
    def _archive_runtime_file_hashes(
        cls, archive: Path, archive_type: str, filename: str
    ) -> dict[str, str]:
        """Hash all supported runtime/license files inside a pinned archive."""
        if archive_type == "zip":
            allowed = {filename, "libcronet.dll", "wintun.dll", "LICENSE", "LICENSE.txt", "COPYING"}
        elif archive_type == "tar.gz":
            allowed = {filename, "libcronet.so", "LICENSE", "LICENSE.txt", "COPYING"}
        else:
            raise SystemTunnelError("Unsupported pinned sing-box archive type.")
        hashes: dict[str, str] = {}
        executable_count = 0

        def consume(name: str, source, *, size: int) -> None:
            nonlocal executable_count
            if name not in allowed:
                return
            if size <= 0 or size > (100 * 1024 * 1024 if name == filename else 32 * 1024 * 1024):
                raise SystemTunnelError(f"The pinned archive member {name} has an unsafe size.")
            if name in hashes:
                raise SystemTunnelError(f"The pinned archive contains duplicate runtime file {name}.")
            digest = hashlib.sha256()
            total = 0
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                total += len(chunk)
                if total > size or total > (100 * 1024 * 1024 if name == filename else 32 * 1024 * 1024):
                    raise SystemTunnelError(f"The pinned archive member {name} exceeded its declared size.")
                digest.update(chunk)
            if total != size:
                raise SystemTunnelError(f"The pinned archive member {name} was truncated.")
            hashes[name] = digest.hexdigest()
            if name == filename:
                executable_count += 1

        if archive_type == "zip":
            with zipfile.ZipFile(archive) as bundle:
                for info in bundle.infolist():
                    if info.is_dir():
                        continue
                    name = cls._safe_archive_member(info.filename).name
                    if name not in allowed:
                        continue
                    mode = (info.external_attr >> 16) & 0o170000
                    if mode not in {0, stat.S_IFREG}:
                        raise SystemTunnelError(f"The pinned archive member {name} is not a regular file.")
                    with bundle.open(info) as source:
                        consume(name, source, size=info.file_size)
        elif archive_type == "tar.gz":
            with tarfile.open(archive, "r:gz") as bundle:
                for item in bundle.getmembers():
                    name = cls._safe_archive_member(item.name).name
                    if name not in allowed:
                        continue
                    if not item.isfile() or item.issym() or item.islnk():
                        raise SystemTunnelError(f"The pinned archive member {name} is not a regular file.")
                    source = bundle.extractfile(item)
                    if source is None:
                        raise SystemTunnelError(f"The pinned archive member {name} could not be read.")
                    with source:
                        consume(name, source, size=item.size)
        else:
            raise SystemTunnelError("Unsupported pinned sing-box archive type.")

        if executable_count != 1:
            raise SystemTunnelError("The pinned archive must contain exactly one engine executable.")
        return hashes

    @classmethod
    def _archive_executable_sha256(cls, archive: Path, archive_type: str, filename: str) -> str:
        """Compatibility helper for tests and diagnostics."""
        return cls._archive_runtime_file_hashes(archive, archive_type, filename)[filename]

    def build_config(
        self,
        socks_port: int,
        *,
        tor_executables: list[str | Path],
        tun_stack: str | None = None,
    ) -> dict[str, Any]:
        """Create a fail-closed TCP-only TUN config with Tor bootstrap bypasses."""
        if type(socks_port) is not int or not 1 <= socks_port <= 65535:
            raise SystemTunnelError("The local Tor SOCKS port is invalid.")
        bypass_paths = {str(self.engine_path.resolve())}
        for raw_path in tor_executables:
            if raw_path:
                path = Path(raw_path).expanduser().resolve()
                if path.is_file():
                    bypass_paths.add(str(path))
        if not any(Path(path).name.casefold() in {"tor", "tor.exe"} for path in bypass_paths):
            raise SystemTunnelError("A validated Tor executable path is required to prevent a tunnel loop.")

        tun = {
            "type": "tun",
            "tag": "torproxy-tun-in",
            "interface_name": self.interface_name,
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "dns_address": ["172.19.0.2", "fdfe:dcba:9876::2"],
            "mtu": 1400,
            "auto_route": True,
            "strict_route": True,
            "dns_mode": "hijack",
        }
        if platform.system() == "Linux":
            tun["auto_redirect"] = True
        elif platform.system() == "Windows":
            version_parts = tuple(int(part) for part in self.version.split("."))
            if version_parts < (1, 15, 0):
                selected_stack = tun_stack or "gvisor"
                if selected_stack not in {"gvisor", "system", "mixed"}:
                    raise SystemTunnelError("Unsupported Windows TUN stack.")
                tun["stack"] = selected_stack
            elif tun_stack is not None:
                raise SystemTunnelError(
                    "sing-box 1.15 and newer use the new native TUN stack; the legacy stack option must be omitted."
                )

        return {
            "log": {"level": "warn", "timestamp": True},
            "dns": {
                "servers": [
                    {
                        "type": "https",
                        "tag": "tor-doh",
                        "server": "1.1.1.1",
                        "server_port": 443,
                        "path": "/dns-query",
                        "tls": {"enabled": True, "server_name": "cloudflare-dns.com"},
                        "detour": "tor-socks",
                    }
                ],
                "final": "tor-doh",
            },
            "inbounds": [tun],
            "outbounds": [
                {
                    "type": "socks",
                    "tag": "tor-socks",
                    "server": "127.0.0.1",
                    "server_port": socks_port,
                    "version": "5",
                    "network": "tcp",
                },
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
            ],
            "route": {
                "auto_detect_interface": True,
                "rules": [
                    {
                        "process_name": sorted({Path(path).name.casefold() for path in bypass_paths}),
                        "action": "route",
                        "outbound": "direct",
                    },
                    {
                        "process_path": sorted(bypass_paths),
                        "action": "route",
                        "outbound": "direct",
                    },
                    {"action": "hijack-dns"},
                    {"network": "udp", "action": "reject", "method": "default"},
                ],
                "final": "tor-socks",
            },
        }

    def _write_and_check_config(
        self,
        socks_port: int,
        tor_executables: list[str | Path],
        *,
        tun_stack: str | None = None,
    ) -> None:
        """Validate the generated config before crossing the privileged boundary."""
        config = self.build_config(
            socks_port, tor_executables=tor_executables, tun_stack=tun_stack
        )
        self.state_dir.mkdir(parents=True, exist_ok=True)
        _atomic_json(self.config_path, config)
        if os.name != "nt":
            self.config_path.chmod(0o600)
        check = subprocess.run(
            [str(self.engine_path), "check", "-c", str(self.config_path)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if check.returncode != 0:
            detail = (check.stderr or check.stdout or "sing-box rejected the generated config").strip()
            raise SystemTunnelError(detail[-1200:])

    def is_running(self) -> bool:
        state = _read_json(self.process_state_path)
        if not state:
            return False
        return _process_matches(state) is not None

    def status(self) -> dict[str, Any]:
        state = _read_json(self.process_state_path)
        if not state:
            if _interface_exists(self.interface_name):
                return {
                    "active": False,
                    "verified": False,
                    "detail": f"An untracked {self.interface_name} adapter exists; refusing to assume it is safe to reuse.",
                }
            return {"active": False, "verified": True, "detail": "System tunnel is stopped."}
        process = _process_matches(state)
        if process is None:
            return {
                "active": False,
                "verified": False,
                "detail": "A stale or unverified tunnel process record exists; use Stop to reconcile it.",
            }
        if not _interface_exists(self.interface_name):
            return {
                "active": False,
                "verified": False,
                "pid": process.pid,
                "detail": "The sing-box process is alive but its TUN interface is missing; use Stop to reconcile it.",
            }
        return {
            "active": True,
            "verified": True,
            "pid": process.pid,
            "detail": f"System tunnel is active on {self.interface_name}.",
        }

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            block = sock.recv(size - len(chunks))
            if not block:
                raise OSError("Tor SOCKS closed the connection during its handshake.")
            chunks.extend(block)
        return bytes(chunks)

    @classmethod
    def _socks5_connect_probe(
        cls,
        socks_port: int,
        target_ip: str,
        target_port: int,
        *,
        server_name: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        """Verify Tor SOCKS TCP/TLS reachability for the explicit traffic diagnostic."""
        with socket.create_connection(("127.0.0.1", socks_port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"\x05\x01\x00")
            greeting = cls._recv_exact(sock, 2)
            if greeting != b"\x05\x00":
                raise OSError(f"Tor SOCKS authentication negotiation failed: {greeting!r}")
            request = b"\x05\x01\x00\x01" + socket.inet_aton(target_ip) + struct.pack("!H", target_port)
            sock.sendall(request)
            header = cls._recv_exact(sock, 4)
            if header[0] != 5 or header[1] != 0:
                raise OSError(f"Tor SOCKS could not reach {target_ip}:{target_port} (reply={header[1]}).")
            address_size = {1: 4, 4: 16}.get(header[3])
            if address_size is None:
                address_size = cls._recv_exact(sock, 1)[0]
            cls._recv_exact(sock, address_size + 2)
            if server_name:
                # A successful SOCKS CONNECT alone does not prove that the exit
                # can carry application TLS. Complete TLS before changing routes.
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=server_name) as verified:
                    if not verified.getpeercert():
                        raise ssl.SSLError("The TLS peer did not provide a certificate.")

    @classmethod
    def _probe_targets(cls) -> tuple[tuple[str, str], ...]:
        return (
            ("1.1.1.1", "cloudflare-dns.com"),
            ("8.8.8.8", "dns.google"),
            ("9.9.9.9", "dns.quad9.net"),
        )

    @classmethod
    def _verify_tunnel_tcp_tls(
        cls,
        target: tuple[str, str],
        *,
        timeout: float = 15.0,
    ) -> None:
        """Verify a TLS flow through the active TUN."""
        address, server_name = target
        try:
            with socket.create_connection((address, 443), timeout=timeout) as raw:
                raw.settimeout(timeout)
                with ssl.create_default_context().wrap_socket(
                    raw, server_hostname=server_name
                ) as verified:
                    if not verified.getpeercert():
                        raise ssl.SSLError("The TLS peer did not provide a certificate.")
        except (OSError, ssl.SSLError) as exc:
            raise SystemTunnelError(
                f"TUN TCP/TLS test failed for {address} ({server_name}): {exc}"
            ) from exc

    def start(self, socks_port: int, *, tor_executables: list[str | Path]) -> str:
        """Start sing-box once; connectivity checks are an explicit, separate action."""
        current = self.status()
        if current.get("active"):
            return str(current.get("detail") or "System tunnel is already active.")
        if not current.get("verified", True):
            raise SystemTunnelError(
                str(current.get("detail") or "The previous tunnel state must be reconciled before starting.")
            )
        if not self.is_installed():
            raise SystemTunnelError("Install the verified sing-box engine first.")
        if _interface_exists(self.interface_name):
            raise SystemTunnelError(
                f"The {self.interface_name} interface already exists outside TorProxy; refusing to take it over."
            )

        # For Windows versions before 1.15 the default is gvisor, which is
        # also the first/default choice in v2rayN. Do not trial-run other stacks:
        # each start/stop crosses UAC and a network probe is not a TUN health check.
        self._write_and_check_config(socks_port, tor_executables)
        result = self._invoke_helper("start")
        if not result.get("ok") or not result.get("active"):
            raise SystemTunnelError(
                str(result.get("error") or result.get("detail") or "Tunnel start failed.")
            )
        return (
            "System tunnel started; the sing-box process and TUN interface are active. "
            "Use Test traffic to verify end-to-end connectivity separately."
        )

    def test_connection(self, socks_port: int, *, timeout: float = 8.0) -> str:
        """Run explicit network diagnostics without restarting or elevating the tunnel."""
        current = self.status()
        if not current.get("active") or not current.get("verified"):
            raise SystemTunnelError(
                str(current.get("detail") or "Start and verify the system tunnel before testing traffic.")
            )

        failures: list[str] = []
        for target_ip, server_name in self._probe_targets():
            try:
                self._socks5_connect_probe(
                    socks_port,
                    target_ip,
                    443,
                    server_name=server_name,
                    timeout=timeout,
                )
            except (OSError, ssl.SSLError, SystemTunnelError) as exc:
                failures.append(f"Tor SOCKS {target_ip}: {exc}")
                continue

            try:
                self._verify_tunnel_tcp_tls((target_ip, server_name), timeout=timeout)
                return (
                    f"Tunnel traffic verified: TLS to {server_name} passed through "
                    "the active TUN and Tor SOCKS outbound."
                )
            except SystemTunnelError as exc:
                failures.append(str(exc))

        raise SystemTunnelError(
            "The TUN process and interface are active, but end-to-end traffic could not be verified. "
            "The tunnel was left running for inspection; no automatic restart or route change was attempted. "
            + " | ".join(failures)
        )

    def stop(self) -> str:
        result = self._invoke_helper("stop", timeout=HELPER_STOP_TIMEOUT_SECONDS + 20)
        if not result.get("ok") or result.get("active"):
            raise SystemTunnelError(str(result.get("error") or result.get("detail") or "Tunnel stop failed."))
        return str(result.get("detail") or "System tunnel stopped.")

    def _helper_base(self) -> list[str]:
        if getattr(sys, "frozen", False):
            return [sys.executable, "--system-tunnel-helper"]
        main_script = Path(__file__).resolve().parents[2] / "main.py"
        return [sys.executable, str(main_script), "--system-tunnel-helper"]

    def _helper_action_arguments(self, action: str, result_path: Path) -> list[str]:
        """Build one identical, parser-compatible argument list for Linux and Windows."""
        manifest = _read_json(self.install_manifest) or {}
        asset = self.platform_asset
        return [
            action,
            "--version", self.version,
            "--engine", str(self.engine_path),
            "--config", str(self.config_path),
            "--state", str(self.process_state_path),
            "--log", str(self.log_path),
            "--sha256", self.engine_sha256 if action == "start" else "",
            "--archive", str(self.archive_path),
            "--archive-sha256", str(manifest.get("archive_sha256") or asset.get("sha256") or ""),
            "--release-sha256", str(asset.get("sha256") or ""),
            "--source-url", str(asset["url"]),
            "--archive-type", str(asset["archive"]),
            *(["--unverified-release"] if self.version not in _ENGINE_RELEASES else []),
            "--interface", self.interface_name,
            "--result", str(result_path),
        ]

    def _invoke_helper(self, action: str, timeout: float = HELPER_START_TIMEOUT_SECONDS + 20) -> dict[str, Any]:
        if os.name == "nt":
            return self._invoke_windows_helper(action, timeout)
        pkexec = shutil.which("pkexec")
        if not pkexec:
            raise SystemTunnelError("PolicyKit pkexec is required to create the Linux TUN interface.")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        result_path = self.state_dir / f"helper-result-{uuid.uuid4().hex}.json"
        command = [
            pkexec,
            *self._helper_base(),
            *self._helper_action_arguments(action, result_path),
        ]
        try:
            completed = subprocess.run(
                command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                timeout=timeout, check=False,
            )
            result = _read_json(result_path)
            if result is None:
                output = (completed.stderr or completed.stdout or "PolicyKit helper returned no result.").strip()
                raise SystemTunnelError(output[-1200:])
            if completed.returncode != 0 and result.get("ok"):
                raise SystemTunnelError("The privileged tunnel helper exited unexpectedly.")
            return result
        except subprocess.TimeoutExpired as exc:
            raise SystemTunnelError("The privileged tunnel helper timed out; the tunnel state must be checked.") from exc
        finally:
            result_path.unlink(missing_ok=True)

    def _invoke_windows_helper(self, action: str, timeout: float) -> dict[str, Any]:
        from ctypes import wintypes

        self.state_dir.mkdir(parents=True, exist_ok=True)
        result_path = self.state_dir / f"helper-result-{uuid.uuid4().hex}.json"
        result_path.unlink(missing_ok=True)
        command = self._helper_action_arguments(action, result_path)
        base = self._helper_base()
        if getattr(sys, "frozen", False):
            executable, params = base[0], subprocess.list2cmdline([*base[1:], *command])
        else:
            executable, params = base[0], subprocess.list2cmdline([*base[1:], *command])

        class SHELLEXECUTEINFOW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
                ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR),
                ("hkeyClass", wintypes.HANDLE), ("dwHotKey", wintypes.DWORD),
                ("hIcon", wintypes.HANDLE), ("hProcess", wintypes.HANDLE),
            ]

        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
        shell32.ShellExecuteExW.restype = wintypes.BOOL
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        info = SHELLEXECUTEINFOW()
        info.cbSize = ctypes.sizeof(info)
        info.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
        info.lpVerb = "runas"
        info.lpFile = executable
        info.lpParameters = params
        info.lpDirectory = str(Path(executable).resolve().parent)
        info.nShow = 0
        try:
            if not shell32.ShellExecuteExW(ctypes.byref(info)):
                error = ctypes.get_last_error()
                if error == 1223:
                    raise SystemTunnelError("Administrator approval was cancelled.")
                raise SystemTunnelError(f"Could not request administrator privileges (error {error}).")
            wait = kernel32.WaitForSingleObject(info.hProcess, int(timeout * 1000))
            if wait == 0x00000102:
                raise SystemTunnelError("The elevated tunnel helper timed out; check the tunnel status before retrying.")
            if wait != 0:
                raise SystemTunnelError(f"Waiting for the elevated tunnel helper failed (code {wait}).")
            exit_code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(exit_code)):
                raise SystemTunnelError("Could not read the elevated tunnel helper exit code.")
            result = _read_json(result_path)
            if result is None:
                raise SystemTunnelError(f"The elevated tunnel helper returned no result (exit code {exit_code.value}).")
            return result
        finally:
            if info.hProcess:
                kernel32.CloseHandle(info.hProcess)
            result_path.unlink(missing_ok=True)


def _require_elevation() -> None:
    if os.name == "nt":
        try:
            elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError) as exc:
            raise SystemTunnelError("Could not verify Windows administrator privileges.") from exc
        if not elevated:
            raise SystemTunnelError("The system TUN helper must run as Administrator.")
    elif hasattr(os, "geteuid") and os.geteuid() != 0:
        raise SystemTunnelError("The system TUN helper must run as root through pkexec.")


def _helper_start(args: Any) -> dict[str, Any]:
    engine = Path(args.engine).resolve()
    config_path = Path(args.config).resolve()
    state_path = Path(args.state).resolve()
    log_path = Path(args.log).resolve()
    version = str(getattr(args, "version", ""))
    expected_asset = _ENGINE_RELEASES.get(version, {}).get(
        (platform.system(), platform.machine().lower())
    )
    unpinned = bool(getattr(args, "unverified_release", False))
    if expected_asset is None:
        if not unpinned:
            raise SystemTunnelError("The privileged helper rejected an upstream release without explicit user approval.")
        expected_asset = _normalize_upstream_asset(
            version,
            {
                "url": getattr(args, "source_url", ""),
                "sha256": getattr(args, "release_sha256", ""),
                "archive": getattr(args, "archive_type", ""),
            },
            require_size=False,
        )
        if args.release_sha256 and args.archive_sha256 != args.release_sha256:
            raise SystemTunnelError("The downloaded archive does not match the GitHub API asset digest.")
    else:
        if (
            unpinned
            or str(getattr(args, "source_url", "")) != expected_asset["url"]
            or args.archive_sha256 != expected_asset["sha256"]
            or args.archive_type != expected_asset["archive"]
        ):
            raise SystemTunnelError("The privileged helper rejected modified pinned release metadata.")
    expected_executable = expected_asset["executable"]
    expected_interface = TUN_INTERFACE_WINDOWS if os.name == "nt" else TUN_INTERFACE_LINUX
    if args.interface != expected_interface or engine.name != expected_executable or engine.parent.name != "engine":
        raise SystemTunnelError("The privileged helper rejected an unexpected engine or interface path.")
    archive = Path(args.archive).resolve()
    expected_archive_name = f"sing-box-{version}-{platform.system().lower()}.archive"
    if archive.name != expected_archive_name or not archive.is_file():
        raise SystemTunnelError("The privileged helper rejected an unexpected sing-box archive path.")
    if not SHA256_PATTERN.fullmatch(str(args.archive_sha256)) or _sha256(archive) != args.archive_sha256:
        raise SystemTunnelError("The privileged helper rejected the sing-box archive checksum.")
    archive_files = SystemTunnelManager._archive_runtime_file_hashes(
        archive, expected_asset["archive"], expected_executable
    )
    archive_engine_hash = archive_files[expected_executable]
    if not engine.is_file() or engine.is_symlink() or _sha256(engine) != archive_engine_hash:
        raise SystemTunnelError("The privileged helper rejected the engine: it does not match the downloaded archive.")
    if args.sha256 != archive_engine_hash:
        raise SystemTunnelError("The privileged helper rejected the engine SHA-256 argument.")
    actual_engine_files = {path.name for path in engine.parent.iterdir() if path.is_file() or path.is_symlink()}
    if actual_engine_files != set(archive_files):
        raise SystemTunnelError("The privileged helper rejected extra or missing runtime files beside sing-box.")
    for name, expected_hash in archive_files.items():
        runtime_file = engine.parent / name
        if runtime_file.is_symlink() or not runtime_file.is_file() or _sha256(runtime_file) != expected_hash:
            raise SystemTunnelError(f"The privileged helper rejected modified runtime file {name}.")
    config = _read_json(config_path)
    if not isinstance(config, dict) or set(config) != {"log", "dns", "inbounds", "outbounds", "route"}:
        raise SystemTunnelError("The privileged helper rejected unexpected top-level tunnel configuration.")
    if config.get("log") != {"level": "warn", "timestamp": True}:
        raise SystemTunnelError("The privileged helper rejected unexpected logging options.")
    if not isinstance(config.get("inbounds"), list) or len(config["inbounds"]) != 1:
        raise SystemTunnelError("The privileged helper rejected the tunnel inbounds.")
    inbound = config["inbounds"][0]
    if not isinstance(inbound, dict): 
        raise SystemTunnelError("The privileged helper rejected a malformed TUN inbound.")
    if inbound.get("type") != "tun" or inbound.get("interface_name") != args.interface:
        raise SystemTunnelError("The privileged helper rejected the TUN interface configuration.")
    if inbound.get("auto_route") is not True or inbound.get("strict_route") is not True:
        raise SystemTunnelError("The privileged helper requires strict automatic routing.")
    if inbound.get("dns_mode") != "hijack" or inbound.get("dns_address") != [
        "172.19.0.2", "fdfe:dcba:9876::2"
    ]:
        raise SystemTunnelError("The privileged helper requires the pinned TUN DNS addresses.")
    version_parts = tuple(int(part) for part in str(args.version).split("."))
    legacy_windows_stack = (
        platform.system() == "Windows" and version_parts < (1, 15, 0)
    )
    expected_tun_fields = {
        "type", "tag", "interface_name", "address", "dns_address", "mtu",
        "auto_route", "strict_route", "dns_mode",
    } | ({"auto_redirect"} if platform.system() == "Linux" else set()) | (
        {"stack"} if legacy_windows_stack else set()
    )
    if set(inbound) != expected_tun_fields:
        raise SystemTunnelError("The privileged helper rejected unexpected TUN options.")
    if inbound.get("tag") != "torproxy-tun-in" or inbound.get("address") != [
        "172.19.0.1/30", "fdfe:dcba:9876::1/126"
    ] or inbound.get("mtu") != 1400:
        raise SystemTunnelError("The privileged helper rejected the TUN interface addresses.")
    if platform.system() == "Linux" and inbound.get("auto_redirect") is not True:
        raise SystemTunnelError("Linux TUN must use the verified auto-redirect mode.")
    if platform.system() == "Windows":
        if "auto_redirect" in inbound:
            raise SystemTunnelError("The privileged helper rejected unsupported Windows TUN options.")
        if legacy_windows_stack and inbound.get("stack") not in {"gvisor", "system", "mixed"}:
            raise SystemTunnelError("Windows TUN must use a supported legacy TCP/IP stack.")
        if not legacy_windows_stack and "stack" in inbound:
            raise SystemTunnelError("sing-box 1.15+ must use its built-in native TUN stack.")
    outbounds = {item.get("tag"): item for item in config.get("outbounds", [])}
    proxy = outbounds.get("tor-socks")
    if not proxy or proxy.get("type") != "socks" or proxy.get("network") != "tcp":
        raise SystemTunnelError("The privileged helper requires the TCP-only Tor SOCKS outbound.")
    if proxy.get("server") != "127.0.0.1" or type(proxy.get("server_port")) is not int:
        raise SystemTunnelError("The privileged helper only permits the local Tor SOCKS listener.")
    if set(outbounds) != {"tor-socks", "direct", "block"}:
        raise SystemTunnelError("The privileged helper rejected unexpected outbound definitions.")
    if set(proxy) != {"type", "tag", "server", "server_port", "version", "network"}:
        raise SystemTunnelError("The privileged helper rejected extra SOCKS outbound options.")
    if proxy.get("version") != "5" or outbounds.get("direct") != {"type": "direct", "tag": "direct"} or outbounds.get("block") != {"type": "block", "tag": "block"}:
        raise SystemTunnelError("The privileged helper rejected an unexpected outbound configuration.")
    dns = config.get("dns", {})
    servers = dns.get("servers", [])
    if set(dns) != {"servers", "final"} or dns.get("final") != "tor-doh" or len(servers) != 1:
        raise SystemTunnelError("The privileged helper rejected the DNS configuration.")
    if servers[0] != {
        "type": "https", "tag": "tor-doh", "server": "1.1.1.1", "server_port": 443,
        "path": "/dns-query",
        "tls": {"enabled": True, "server_name": "cloudflare-dns.com"},
        "detour": "tor-socks",
    }:
        raise SystemTunnelError("DNS must use the pinned HTTPS resolver through Tor SOCKS.")
    route = config.get("route", {})
    if set(route) != {"auto_detect_interface", "rules", "final"} or route.get("auto_detect_interface") is not True or route.get("final") != "tor-socks":
        raise SystemTunnelError("The privileged helper rejected the routing defaults.")
    route_rules = route.get("rules", [])
    if (
        len(route_rules) != 4
        or route_rules[2] != {"action": "hijack-dns"}
        or route_rules[3] != {"network": "udp", "action": "reject", "method": "default"}
    ):
        raise SystemTunnelError("The privileged helper rejected the DNS/UDP route ordering.")

    name_rule = route_rules[0]
    process_names = name_rule.get("process_name") if isinstance(name_rule, dict) else None
    if (
        set(name_rule) != {"process_name", "action", "outbound"}
        or name_rule.get("action") != "route"
        or name_rule.get("outbound") != "direct"
        or not isinstance(process_names, list)
        or not process_names or process_names != sorted(set(process_names))
    ):
        raise SystemTunnelError("The privileged helper rejected the process-name bypass route.")
    allowed_names = {"tor", "tor.exe", "lyrebird", "lyrebird.exe", engine.name.casefold()}
    if (
        any(not isinstance(name, str) or name.casefold() not in allowed_names for name in process_names)
        or engine.name.casefold() not in {name.casefold() for name in process_names}
        or not any(name.casefold() in {"tor", "tor.exe"} for name in process_names)
    ):
        raise SystemTunnelError("Tor and sing-box must have explicit process-name TUN bypasses.")

    direct_rule = route_rules[1]
    process_paths = direct_rule.get("process_path")
    if (
        set(direct_rule) != {"process_path", "action", "outbound"}
        or direct_rule.get("action") != "route"
        or direct_rule.get("outbound") != "direct"
        or not isinstance(process_paths, list)
        or len(process_paths) not in {2, 3}
        or process_paths != sorted(set(process_paths))
    ):
        raise SystemTunnelError("The privileged helper rejected the process-path bypass route.")
    normalized_paths = []
    for raw_path in process_paths:
        if not isinstance(raw_path, str) or not Path(raw_path).is_absolute() or not Path(raw_path).is_file():
            raise SystemTunnelError("The privileged helper rejected a missing or relative bypass executable.")
        normalized_paths.append(str(Path(raw_path).resolve()))
    if str(engine) not in normalized_paths or not any(Path(p).name.casefold() in {"tor", "tor.exe"} for p in normalized_paths):
        raise SystemTunnelError("The Tor and sing-box executable paths must be excluded from TUN routing.")
    if any(Path(p).name.casefold() not in allowed_names for p in normalized_paths):
        raise SystemTunnelError("The privileged helper rejected an unexpected direct-route executable.")

    state = _read_json(state_path)
    if state:
        existing = _process_matches(state)
        if existing is not None:
            return {"ok": True, "active": True, "pid": existing.pid, "detail": "System tunnel is already active."}
        try:
            stale_pid = int(state.get("pid", 0))
        except (TypeError, ValueError):
            stale_pid = 0
        if stale_pid > 0 and psutil.pid_exists(stale_pid):
            raise SystemTunnelError("The saved tunnel PID still identifies another process; refusing to take it over.")
        state_path.unlink(missing_ok=True)
    if _interface_exists(args.interface):
        raise SystemTunnelError("The requested TUN interface already exists; refusing to take over an unrelated adapter.")

    check = subprocess.run(
        [str(engine), "check", "-c", str(config_path)],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20, check=False,
    )
    if check.returncode != 0:
        detail = (check.stderr or check.stdout or "sing-box rejected the tunnel configuration").strip()
        raise SystemTunnelError(detail[-1200:])

    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("ab", buffering=0) as log_handle:
        kwargs: dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": log_handle,
            "stderr": subprocess.STDOUT,
            "close_fds": True,
        }
        if os.name == "nt":
            # Keep the console/process relationship so the elevated helper can
            # send a shutdown control event later. Hide the console instead of
            # detaching the process from it; DETACHED_PROCESS breaks TUN cleanup.
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE
            kwargs["startupinfo"] = startupinfo
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        else:
            kwargs["start_new_session"] = True
        process = subprocess.Popen([str(engine), "run", "-c", str(config_path)], **kwargs)

    deadline = time.monotonic() + HELPER_START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        code = process.poll()
        if code is not None:
            try:
                tail = log_path.read_text(encoding="utf-8", errors="replace")[-1800:]
            except OSError:
                tail = ""
            raise SystemTunnelError(f"sing-box exited during TUN startup ({code}). {tail.strip()}")
        if _interface_exists(args.interface):
            if process.poll() is not None:
                raise SystemTunnelError("sing-box exited while its TUN interface was being created.")
            state_path.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "pid": process.pid,
                "create_time": psutil.Process(process.pid).create_time(),
                "engine": str(engine),
                "config": str(config_path),
                "interface": args.interface,
                "sha256": args.sha256,
            }
            _atomic_json(state_path, record, mode=0o644)
            time.sleep(0.2)
            if process.poll() is not None or _process_matches(record) is None:
                state_path.unlink(missing_ok=True)
                raise SystemTunnelError("sing-box did not remain healthy after creating its TUN interface.")
            return {"ok": True, "active": True, "pid": process.pid, "detail": "System TUN interface is active."}
        time.sleep(0.25)

    try:
        process.terminate()
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except OSError:
            pass
    raise SystemTunnelError(f"sing-box did not create the {args.interface} interface in time.")


def _send_windows_ctrl_break(pid: int) -> bool:
    """Ask a console-attached sing-box process to shut down and release Wintun cleanly."""
    if os.name != "nt":
        return False
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.AttachConsole.argtypes = [wintypes.DWORD]
    kernel32.AttachConsole.restype = wintypes.BOOL
    kernel32.GenerateConsoleCtrlEvent.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.GenerateConsoleCtrlEvent.restype = wintypes.BOOL
    kernel32.SetConsoleCtrlHandler.argtypes = [ctypes.c_void_p, wintypes.BOOL]
    kernel32.SetConsoleCtrlHandler.restype = wintypes.BOOL
    kernel32.FreeConsole.argtypes = []
    kernel32.FreeConsole.restype = wintypes.BOOL

    if not kernel32.AttachConsole(pid):
        return False
    ignored = False
    try:
        ignored = bool(kernel32.SetConsoleCtrlHandler(None, True))
        # CTRL_BREAK_EVENT to all processes in the child's console. The helper
        # ignores it; sing-box receives the same graceful shutdown event.
        return bool(kernel32.GenerateConsoleCtrlEvent(1, 0))
    finally:
        kernel32.FreeConsole()
        if ignored:
            kernel32.SetConsoleCtrlHandler(None, False)


def _stop_verified_process(process: psutil.Process, state: dict[str, Any]) -> None:
    """Stop only the exact recorded sing-box process, preferring graceful cleanup."""
    if os.name == "nt":
        _send_windows_ctrl_break(process.pid)
        try:
            process.wait(timeout=8)
            return
        except psutil.TimeoutExpired:
            pass

        # This is the same non-/F Windows shutdown path used by desktop launchers
        # when the child has no visible console window.
        taskkill = shutil.which("taskkill.exe") or shutil.which("taskkill")
        if taskkill:
            try:
                subprocess.run(
                    [taskkill, "/PID", str(process.pid)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=8,
                    check=False,
                )
                process.wait(timeout=5)
                return
            except (OSError, subprocess.TimeoutExpired, psutil.TimeoutExpired, psutil.NoSuchProcess):
                pass
    else:
        try:
            process.terminate()
            process.wait(timeout=HELPER_STOP_TIMEOUT_SECONDS)
            return
        except psutil.TimeoutExpired:
            pass
        except psutil.NoSuchProcess:
            return

    # Last resort is deliberately identity-checked and followed by a TUN
    # interface disappearance check before reporting the tunnel stopped.
    current = _process_matches(state)
    if current is None or current.pid != process.pid:
        raise SystemTunnelError("The tunnel process identity changed while stopping; refusing to terminate it.")
    try:
        current.kill()
        current.wait(timeout=5)
    except psutil.NoSuchProcess:
        return
    except psutil.TimeoutExpired as exc:
        raise SystemTunnelError("The verified sing-box process could not be stopped.") from exc


def _helper_stop(state_path: Path, interface_name: str) -> dict[str, Any]:
    state = _read_json(state_path)
    if not state:
        if _interface_exists(interface_name):
            raise SystemTunnelError(
                f"The {interface_name} interface exists without a verified sing-box process record. "
                "The helper refused to claim that the system routes were restored."
            )
        return {"ok": True, "active": False, "detail": "No system tunnel process or TUN interface is recorded."}
    process = _process_matches(state)
    if process is None:
        try:
            saved_pid = int(state.get("pid", 0))
        except (TypeError, ValueError):
            saved_pid = 0
        if saved_pid <= 0 or psutil.pid_exists(saved_pid):
            raise SystemTunnelError("The saved tunnel PID still identifies another process; refusing to terminate it.")
        if _interface_exists(interface_name):
            raise SystemTunnelError(
                f"The {interface_name} adapter remains after its process exited. "
                "The helper retained the stale record instead of claiming that routes were restored."
            )
        state_path.unlink(missing_ok=True)
        return {"ok": True, "active": False, "detail": "Removed a stale tunnel record; its process has already exited."}
    try:
        _stop_verified_process(process, state)
    except psutil.NoSuchProcess:
        pass
    deadline = time.monotonic() + 5.0
    while _interface_exists(interface_name) and time.monotonic() < deadline:
        time.sleep(0.1)
    if _interface_exists(interface_name):
        raise SystemTunnelError(
            f"sing-box stopped, but the {interface_name} adapter is still present. "
            "TorProxy retained the process record because route removal could not be verified."
        )
    state_path.unlink(missing_ok=True)
    return {"ok": True, "active": False, "detail": "System tunnel stopped; sing-box released its TUN routes."}


def system_tunnel_helper_main(argv: list[str] | None = None) -> int:
    """Narrow privileged entry point; called before Qt starts in main.py."""
    import argparse

    parser = argparse.ArgumentParser(prog="torproxy-system-tunnel-helper")
    parser.add_argument("action", choices=("start", "stop"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--engine", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--release-sha256", default="")
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--unverified-release", action="store_true")
    parser.add_argument("--archive-type", choices=("zip", "tar.gz"), required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args(argv)
    result: dict[str, Any]
    try:
        _require_elevation()
        if args.action == "start":
            result = _helper_start(args)
        else:
            result = _helper_stop(Path(args.state).resolve(), args.interface)
    except Exception as exc:
        result = {"ok": False, "active": False, "error": f"{type(exc).__name__}: {exc}"}
    try:
        _atomic_json(Path(args.result).resolve(), result, mode=0o644)
    except OSError:
        pass
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result.get("ok") else 1
