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
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

import psutil
import requests

from .network import NetworkRouteError, create_session
from .paths import user_directories


SING_BOX_LATEST_VERSION = "1.14.4"
# Only stable releases with reviewed platform SHA-256 digests can be installed.
# New upstream versions remain visible in the UI but cannot execute until pinned here.
SUPPORTED_SING_BOX_VERSIONS = ("1.14.4", "1.14.3", "1.14.2")
SING_BOX_VERSION = SING_BOX_LATEST_VERSION
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
        self.version = version or (
            saved_version if saved_version in SUPPORTED_SING_BOX_VERSIONS else SING_BOX_LATEST_VERSION
        )
        self.archive_path = self._archive_path_for(self.version)
        self._install_state_cache: tuple[tuple[str, int, int], ...] | None = None
        self._install_state_result = False

    def _archive_path_for(self, version: str) -> Path:
        return self.runtime_dir / f"sing-box-{version}-{platform.system().lower()}.archive"

    @property
    def installed_version(self) -> str | None:
        manifest = _read_json(self.install_manifest)
        version = str(manifest.get("version", "")) if manifest else ""
        return version if version in SUPPORTED_SING_BOX_VERSIONS else None

    @staticmethod
    def supported_versions() -> tuple[str, ...]:
        return SUPPORTED_SING_BOX_VERSIONS

    @staticmethod
    def release_metadata(version: str) -> dict[str, Any]:
        if version not in _SING_BOX_RELEASE_METADATA:
            raise SystemTunnelError(f"Unsupported sing-box version: {version}")
        return {"version": version, **_SING_BOX_RELEASE_METADATA[version]}

    def select_version(self, version: str) -> None:
        if version not in SUPPORTED_SING_BOX_VERSIONS:
            raise SystemTunnelError(
                "That sing-box version has not been pinned and verified by this TorProxy release."
            )
        if self.is_running() and version != self.version:
            raise SystemTunnelError("Stop the active system tunnel before changing its engine version.")
        self.version = version
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
        if release.get("draft") or release.get("prerelease") or not tag:
            raise SystemTunnelError("GitHub did not return a stable sing-box release.")
        return {
            "version": tag,
            "published_at": str(release.get("published_at", "")),
            "url": str(release.get("html_url", "https://github.com/SagerNet/sing-box/releases")),
            "supported": tag in SUPPORTED_SING_BOX_VERSIONS,
        }

    @property
    def platform_asset(self) -> dict[str, str]:
        system = platform.system()
        machine = platform.machine().lower()
        asset = _ENGINE_RELEASES.get(self.version, {}).get((system, machine))
        if asset is None:
            supported = "Windows x64 and glibc-based Linux x86_64"
            raise SystemTunnelError(
                f"System-wide TUN is currently packaged for {supported}; "
                f"this device reports {system} / {machine}."
            )
        return asset

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
            if (
                manifest.get("archive_sha256") != asset["sha256"]
                or not isinstance(files, dict)
                or self.engine_path.name not in files
                or not set(files).issubset(self._allowed_archive_files())
                or self.engine_path.name not in files
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

            if _sha256(self.archive_path) != asset["sha256"]:
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
    ) -> str:
        """Download a pinned release through Tor or an explicitly authorized direct route."""
        if version is not None:
            self.select_version(version)
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
            if archive_digest != asset["sha256"]:
                raise SystemTunnelError("sing-box archive SHA-256 verification failed.")
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
        self, socks_port: int, tor_executables: list[str | Path]
    ) -> None:
        config = self.build_config(socks_port, tor_executables=tor_executables)
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

    def start(self, socks_port: int, *, tor_executables: list[str | Path]) -> str:
        if not self.is_installed():
            raise SystemTunnelError("Install the verified sing-box engine first.")
        if _interface_exists(self.interface_name):
            raise SystemTunnelError(
                f"The {self.interface_name} interface already exists outside TorProxy; refusing to take it over."
            )
        try:
            with socket.create_connection(("127.0.0.1", socks_port), timeout=2):
                pass
        except OSError as exc:
            raise SystemTunnelError("The local Tor SOCKS listener is not accepting connections.") from exc
        self._write_and_check_config(socks_port, tor_executables)
        result = self._invoke_helper("start")
        if not result.get("ok") or not result.get("active"):
            raise SystemTunnelError(str(result.get("error") or result.get("detail") or "Tunnel start failed."))
        return str(result.get("detail") or "System tunnel started.")

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
            action,
            "--version", self.version,
            "--engine", str(self.engine_path),
            "--config", str(self.config_path),
            "--state", str(self.process_state_path),
            "--log", str(self.log_path),
            "--sha256", self.engine_sha256 if action == "start" else "",
            "--archive", str(self.archive_path),
            "--archive-sha256", self.platform_asset["sha256"],
            "--archive-type", self.platform_asset["archive"],
            "--interface", self.interface_name,
            "--result", str(result_path),
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
        command = [
            action,
            "--version", self.version,
            "--engine", str(self.engine_path),
            "--config", str(self.config_path),
            "--state", str(self.process_state_path),
            "--log", str(self.log_path),
            "--sha256", self.engine_sha256 if action == "start" else "",
            "--archive", str(self.archive_path),
            "--archive-sha256", self.platform_asset["sha256"],
            "--archive-type", self.platform_asset["archive"],
            "--interface", self.interface_name,
            "--result", str(result_path),
        ]
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
    expected_asset = _ENGINE_RELEASES.get(str(getattr(args, "version", "")), {}).get(
        (platform.system(), platform.machine().lower())
    )
    if expected_asset is None:
        raise SystemTunnelError("The privileged helper rejected an unsupported or unpinned sing-box version/platform.")
    expected_executable = expected_asset["executable"]
    expected_interface = TUN_INTERFACE_WINDOWS if os.name == "nt" else TUN_INTERFACE_LINUX
    if args.interface != expected_interface or engine.name != expected_executable or engine.parent.name != "engine":
        raise SystemTunnelError("The privileged helper rejected an unexpected engine or interface path.")
    if args.archive_type != expected_asset["archive"] or args.archive_sha256 != expected_asset["sha256"]:
        raise SystemTunnelError("The privileged helper rejected unpinned archive metadata.")
    archive = Path(args.archive).resolve()
    expected_archive_name = f"sing-box-{args.version}-{platform.system().lower()}.archive"
    if archive.name != expected_archive_name or not archive.is_file():
        raise SystemTunnelError("The privileged helper rejected an unexpected sing-box archive path.")
    if _sha256(archive) != expected_asset["sha256"]:
        raise SystemTunnelError("The privileged helper rejected the sing-box archive checksum.")
    archive_files = SystemTunnelManager._archive_runtime_file_hashes(
        archive, expected_asset["archive"], expected_executable
    )
    archive_engine_hash = archive_files[expected_executable]
    if not engine.is_file() or engine.is_symlink() or _sha256(engine) != archive_engine_hash:
        raise SystemTunnelError("The privileged helper rejected the engine: it does not match the pinned archive.")
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
    expected_tun_fields = {
        "type", "tag", "interface_name", "address", "dns_address", "mtu",
        "auto_route", "strict_route", "dns_mode",
    } | ({"auto_redirect"} if platform.system() == "Linux" else set())
    if set(inbound) != expected_tun_fields:
        raise SystemTunnelError("The privileged helper rejected unexpected TUN options.")
    if inbound.get("tag") != "torproxy-tun-in" or inbound.get("address") != [
        "172.19.0.1/30", "fdfe:dcba:9876::1/126"
    ] or inbound.get("mtu") != 1400:
        raise SystemTunnelError("The privileged helper rejected the TUN interface addresses.")
    if platform.system() == "Linux" and inbound.get("auto_redirect") is not True:
        raise SystemTunnelError("Linux TUN must use the verified auto-redirect mode.")
    if platform.system() == "Windows" and "auto_redirect" in inbound:
        raise SystemTunnelError("The privileged helper rejected unsupported Windows TUN options.")
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
    if len(route_rules) != 3 or route_rules[1] != {"action": "hijack-dns"}:
        raise SystemTunnelError("DNS packets must be hijacked into the Tor-routed DNS module.")
    if route_rules[2] != {"network": "udp", "action": "reject", "method": "default"}:
        raise SystemTunnelError("UDP must be rejected to prevent traffic from bypassing Tor.")
    direct_rule = route_rules[0]
    process_paths = direct_rule.get("process_path")
    if (
        set(direct_rule) != {"process_path", "action", "outbound"}
        or direct_rule.get("action") != "route"
        or direct_rule.get("outbound") != "direct"
        or not isinstance(process_paths, list)
        or len(process_paths) not in {2, 3}
        or process_paths != sorted(set(process_paths))
    ):
        raise SystemTunnelError("The privileged helper rejected the process-bypass route.")
    normalized_paths = []
    for raw_path in process_paths:
        if not isinstance(raw_path, str) or not Path(raw_path).is_absolute() or not Path(raw_path).is_file():
            raise SystemTunnelError("The privileged helper rejected a missing or relative bypass executable.")
        normalized_paths.append(str(Path(raw_path).resolve()))
    if str(engine) not in normalized_paths or not any(Path(p).name.casefold() in {"tor", "tor.exe"} for p in normalized_paths):
        raise SystemTunnelError("The Tor and sing-box executables must be excluded from TUN routing.")
    if any(Path(p).name.casefold() not in {"tor", "tor.exe", "lyrebird", "lyrebird.exe", engine.name.casefold()} for p in normalized_paths):
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
