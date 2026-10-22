"""Tor Expert Bundle discovery and fail-closed signed installation."""
from __future__ import annotations

import glob
import logging
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

from config import ARCHITECTURE, BUNDLE_DIR, OS_NAME, TOR_BUNDLE_BASE_URL
from torproxy.bundle import (
    ALLOWED_DISTRIBUTION_HOSTS,
    BundleVerificationError,
    download_verified_bundle,
    verify_tor_signature,
)
from utils import resource_path

logger = logging.getLogger(__name__)
REQUEST_TIMEOUT = (8.0, 20.0)
STABLE_VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def bundle_path(filename: str) -> Path:
    root = Path(resource_path(BUNDLE_DIR)).resolve()
    candidate = Path(filename)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError("Bundle path must remain within the configured bundle directory.")
    return candidate


def create_bundle_dir() -> None:
    Path(resource_path(BUNDLE_DIR)).mkdir(parents=True, exist_ok=True)


def _fetch_listing(url: str) -> BeautifulSoup:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_DISTRIBUTION_HOSTS:
        raise BundleVerificationError("Refusing to query an untrusted Tor distribution host.")
    with requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False) as response:
        if 300 <= response.status_code < 400:
            raise BundleVerificationError("Redirects are refused when discovering Tor releases.")
        final = urlsplit(response.url)
        if final.scheme != "https" or final.hostname not in ALLOWED_DISTRIBUTION_HOSTS:
            raise BundleVerificationError("Tor distribution listing redirected to an untrusted host.")
        response.raise_for_status()
        return BeautifulSoup(response.text, "html.parser")


def get_tor_versions(url: str = TOR_BUNDLE_BASE_URL) -> list[str]:
    """Return stable numeric release directory names; never download side files as a side effect."""
    try:
        soup = _fetch_listing(url)
        versions = set()
        for link in soup.find_all("a", href=True):
            name = link.get("href", "").strip("/")
            if STABLE_VERSION.fullmatch(name):
                versions.add(name)
        # Keep UI discovery bounded: checking every historical release can require hundreds of requests.
        return [version + "/" for version in sorted(versions, key=lambda v: tuple(map(int, v.split("."))), reverse=True)[:12]]
    except (requests.RequestException, BundleVerificationError, ValueError):
        logger.exception("Could not retrieve the official Tor Expert Bundle release list.")
        return []


def _platform_name() -> str:
    if OS_NAME == "Windows":
        return "windows"
    if OS_NAME == "Linux":
        return "linux"
    raise BundleVerificationError(f"Tor bundle downloads are not configured for {OS_NAME}.")


def _architecture_name() -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"} and ARCHITECTURE == 64:
        return "x86_64"
    if machine in {"i386", "i486", "i586", "i686", "x86"} and ARCHITECTURE == 32:
        return "i686"
    # Python may be a 32-bit process on a 64-bit machine.
    if ARCHITECTURE == 32:
        return "i686"
    raise BundleVerificationError(f"Unsupported CPU architecture for an Expert Bundle: {machine}.")


def get_bundle_links(version: str, base_url: str = TOR_BUNDLE_BASE_URL) -> list[str]:
    release = str(version).strip().strip("/")
    if not STABLE_VERSION.fullmatch(release):
        return []
    try:
        soup = _fetch_listing(urljoin(base_url.rstrip("/") + "/", release + "/"))
        prefix = f"tor-expert-bundle-{_platform_name()}-{_architecture_name()}-{release}.tar.gz"
        return [link["href"] for link in soup.find_all("a", href=True)
                if link.get("href", "") == prefix]
    except (requests.RequestException, BundleVerificationError, ValueError):
        logger.exception("Could not list Tor bundles for release %s.", release)
        return []


def get_version_by_bundle(filename: str, with_slash: bool = False) -> str:
    name = Path(filename).name
    match = re.search(r"-(\d+\.\d+\.\d+)\.tar\.gz$", name)
    if not match:
        raise ValueError(f"Not a stable Tor Expert Bundle filename: {name}")
    version = match.group(1)
    return version + "/" if with_slash else version


def download_file(filename: str, version: str, base_url: str = TOR_BUNDLE_BASE_URL) -> Path:
    """Download only the current-OS/CPU bundle and require its detached signature."""
    release = str(version).strip().strip("/")
    if not STABLE_VERSION.fullmatch(release):
        raise BundleVerificationError("Only stable numeric Tor versions can be downloaded.")
    expected = f"tor-expert-bundle-{_platform_name()}-{_architecture_name()}-{release}.tar.gz"
    if Path(filename).name != expected:
        raise BundleVerificationError(f"Bundle name does not match the selected platform/version: {expected}")
    create_bundle_dir()
    archive = bundle_path(expected)
    if archive.exists() and check_hash(archive):
        return archive
    archive.parent.mkdir(parents=True, exist_ok=True)
    result = download_verified_bundle(release, _platform_name(), _architecture_name(), archive, base_url)
    logger.info("Downloaded and signature-verified Tor Expert Bundle %s.", expected)
    return result


def save_checksum(file, version: str) -> None:
    """Legacy compatibility only; unsigned checksum lists are not a trust source."""
    raise BundleVerificationError(
        "Unsigned checksum files are not accepted. Verify the artifact's detached OpenPGP signature instead."
    )


def get_checksum(version: str, base_url: str = TOR_BUNDLE_BASE_URL) -> None:
    """Legacy compatibility only: do not save an unverified checksum list."""
    raise BundleVerificationError(
        "Unsigned checksum download is disabled; Tor Expert Bundles must have a valid pinned-key signature."
    )


def check_hash(filename, base_url: str = TOR_BUNDLE_BASE_URL, go_online: bool = False) -> bool:
    """Return true only when a detached signature verifies against the pinned Tor key."""
    del base_url
    path = Path(filename)
    if not path.is_absolute():
        path = bundle_path(path)
    if path.is_dir() or not path.is_file():
        return False
    signature = path.with_name(path.name + ".asc")
    if not signature.is_file() and go_online:
        try:
            version = get_version_by_bundle(path.name)
            expected = f"tor-expert-bundle-{_platform_name()}-{_architecture_name()}-{version}.tar.gz"
            if path.name != expected:
                return False
            sig_url = urljoin(TOR_BUNDLE_BASE_URL.rstrip("/") + "/", f"{version}/{path.name}.asc")
            with requests.get(sig_url, timeout=REQUEST_TIMEOUT, allow_redirects=False) as response:
                if 300 <= response.status_code < 400:
                    return False
                final = urlsplit(response.url)
                if final.scheme != "https" or final.hostname not in ALLOWED_DISTRIBUTION_HOSTS:
                    return False
                response.raise_for_status()
                if not response.content or len(response.content) > 1024 * 1024:
                    return False
            signature.write_bytes(response.content)
        except Exception:
            logger.exception("Could not retrieve a detached signature for %s.", path.name)
            return False
    if not signature.is_file():
        return False
    try:
        verify_tor_signature(path, signature)
        return True
    except (BundleVerificationError, OSError):
        logger.warning("Tor bundle signature verification failed: %s", path.name)
        return False


def list_downloaded_bundles() -> list[str]:
    return [str(path) for path in Path(resource_path(BUNDLE_DIR)).glob("*.tar.gz")]


def _verification_marker(bundle_dir: Path) -> Path:
    return bundle_dir / ".torproxy-verified.json"


def check_bundle_compatibility(filename: str) -> bool:
    """Only verified extracted bundles qualify as managed/default bundles."""
    path = Path(filename).resolve()
    name = path.name
    if not path.is_dir() or not name.startswith("tor-expert-bundle-"):
        return False
    try:
        marker = _verification_marker(path)
        metadata = __import__("json").loads(marker.read_text(encoding="utf-8"))
        if metadata.get("signature_verified") is not True:
            return False
        expected_digest = metadata.get("archive_sha256", "")
        if not re.fullmatch(r"[a-f0-9]{64}", expected_digest):
            return False
        archive = path.with_name(path.name + ".tar.gz")
        if not archive.is_file() or sha256_file(archive) != expected_digest:
            return False
        if not archive.with_name(archive.name + ".asc").is_file():
            return False
    except (OSError, ValueError, AttributeError):
        return False
    try:
        platform_name = _platform_name()
        arch = _architecture_name()
    except BundleVerificationError:
        return False
    if not name.startswith(f"tor-expert-bundle-{platform_name}-{arch}-"):
        return False
    executable = path / "tor" / ("tor.exe" if platform_name == "windows" else "tor")
    if not executable.is_file():
        return False
    return os.name == "nt" or os.access(executable, os.X_OK)


def get_own_bundles() -> list[str]:
    root = Path(resource_path(BUNDLE_DIR))
    if not root.is_dir():
        return []
    return [str(path) for path in sorted(root.glob("tor-expert-bundle-*"))
            if path.is_dir() and check_bundle_compatibility(str(path))]


def delete_bundle(name: str) -> None:
    path = bundle_path(name)
    root = Path(resource_path(BUNDLE_DIR)).resolve()
    if path == root or root not in path.parents:
        raise ValueError("Refusing to delete outside the local bundle directory.")
    archive = path.with_name(path.name + ".tar.gz") if path.is_dir() else path
    if path.is_dir():
        shutil.rmtree(path)
    elif path.is_file():
        path.unlink()
    else:
        logger.info("Bundle path does not exist: %s", path)
    for sidecar in (archive, archive.with_name(archive.name + ".asc")):
        try:
            sidecar.unlink()
        except FileNotFoundError:
            pass
