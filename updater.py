"""Tor Expert Bundle discovery and fail-closed signed installation."""
from __future__ import annotations

import json
import logging
import os
import platform
import re
import shutil
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

from config import ARCHITECTURE, BUNDLE_DIR, OS_NAME, TOR_BUNDLE_BASE_URL
from torproxy.bundle import (
    ALLOWED_DISTRIBUTION_HOSTS,
    BundleProgress,
    BundleVerificationError,
    download_verified_bundle,
    sha256_file,
    verify_tor_signature,
)
from utils import resource_path

logger = logging.getLogger(__name__)
REQUEST_TIMEOUT = (8.0, 20.0)

# Tor currently publishes stable versions as X.Y.Z and alpha releases as X.YaN.
# A future naming convention must be added deliberately rather than accepted generically.
STABLE_VERSION = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
ALPHA_VERSION = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?a(0|[1-9]\d*)$"
)


def parse_tor_version(version: str) -> tuple[int, int, int, str, int]:
    """Validate a supported release name and return sortable numeric components.

    Sort policy: stable channel first; prereleases are shown separately afterwards.
    Within each channel, numeric components are sorted descending by callers.
    """
    value = str(version).strip().strip("/")
    stable = STABLE_VERSION.fullmatch(value)
    if stable:
        major, minor, patch = (int(part) for part in stable.groups())
        return major, minor, patch, "stable", 0
    alpha = ALPHA_VERSION.fullmatch(value)
    if alpha:
        major, minor, patch, alpha_number = alpha.groups()
        return int(major), int(minor), int(patch or 0), "alpha", int(alpha_number)
    raise ValueError("Unsupported Tor release version: {!r}".format(value))


def tor_version_sort_key(version: str) -> tuple[int, int, int, int, int]:
    """Natural numeric sort key with stable releases ranked before all alphas."""
    major, minor, patch, channel, prerelease = parse_tor_version(version)
    return (1 if channel == "stable" else 0, major, minor, patch, prerelease)


def tor_version_channel(version: str) -> str:
    """Return the validated UI channel label for a release."""
    return "Stable" if parse_tor_version(version)[3] == "stable" else "Alpha · prerelease"


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
    """Return every recognized release directory, sorted stables first then alphas.

    Artifact availability is checked lazily when a user selects a release. This
    avoids firing one network request for every historical release at startup.
    """
    try:
        soup = _fetch_listing(url)
        versions: set[str] = set()
        for link in soup.find_all("a", href=True):
            href = unquote(str(link.get("href", "")).strip())
            if not href or href.startswith(("../", "#")):
                continue
            parsed = urlsplit(href)
            if parsed.scheme or parsed.netloc:
                continue
            path = parsed.path.strip("/")
            if not path or "/" in path:
                continue
            try:
                parse_tor_version(path)
            except ValueError:
                continue
            versions.add(path)
        return [version + "/" for version in sorted(versions, key=tor_version_sort_key, reverse=True)]
    except (requests.RequestException, BundleVerificationError, ValueError):
        logger.exception("Could not retrieve the official Tor Expert Bundle release list.")
        return []


def _platform_name() -> str:
    if OS_NAME == "Windows":
        return "windows"
    if OS_NAME == "Linux":
        return "linux"
    raise BundleVerificationError("Tor bundle downloads are not configured for {}.".format(OS_NAME))


def _architecture_name() -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"} and ARCHITECTURE == 64:
        return "x86_64"
    if machine in {"i386", "i486", "i586", "i686", "x86"} and ARCHITECTURE == 32:
        return "i686"
    # A 32-bit Python process can run on a 64-bit x86 OS.
    if ARCHITECTURE == 32 and machine in {"x86_64", "amd64", "i386", "i486", "i586", "i686", "x86"}:
        return "i686"
    raise BundleVerificationError("Unsupported CPU architecture for an Expert Bundle: {}.".format(machine))


def get_bundle_links(version: str, base_url: str = TOR_BUNDLE_BASE_URL) -> list[str]:
    """Return the exact platform artifact only when both archive and .asc are listed."""
    release = str(version).strip().strip("/")
    try:
        parse_tor_version(release)
        soup = _fetch_listing(urljoin(base_url.rstrip("/") + "/", release + "/"))
        expected = "tor-expert-bundle-{}-{}-{}.tar.gz".format(
            _platform_name(), _architecture_name(), release
        )
        names = {
            Path(urlsplit(str(link.get("href", ""))).path).name
            for link in soup.find_all("a", href=True)
        }
        if expected in names and expected + ".asc" in names:
            return [expected]
        return []
    except (requests.RequestException, BundleVerificationError, ValueError):
        logger.exception("Could not list signed Tor bundles for release %s.", release)
        return []


def get_version_by_bundle(filename: str, with_slash: bool = False) -> str:
    name = Path(filename).name
    match = re.search(r"-((?:\d+\.\d+\.\d+)|(?:\d+\.\d+(?:\.\d+)?a\d+))\.tar\.gz$", name)
    if not match:
        raise ValueError("Not a supported Tor Expert Bundle filename: {}".format(name))
    version = match.group(1)
    parse_tor_version(version)
    return version + "/" if with_slash else version


def download_file(
    filename: str,
    version: str,
    base_url: str = TOR_BUNDLE_BASE_URL,
    progress_callback=None,
    cancel_event=None,
) -> Path:
    """Download only a matching OS/CPU bundle and require its detached signature."""
    release = str(version).strip().strip("/")
    try:
        parse_tor_version(release)
    except ValueError as exc:
        raise BundleVerificationError(str(exc)) from exc
    expected = "tor-expert-bundle-{}-{}-{}.tar.gz".format(
        _platform_name(), _architecture_name(), release
    )
    if Path(filename).name != expected:
        raise BundleVerificationError("Bundle name does not match the selected platform/version: {}".format(expected))
    create_bundle_dir()
    archive = bundle_path(expected)
    if archive.exists() and check_hash(archive):
        if progress_callback:
            progress_callback(BundleProgress(
                version=release, operation="install", stage="already_verified",
                message="Existing archive signature verified.",
            ))
        return archive
    archive.parent.mkdir(parents=True, exist_ok=True)
    result = download_verified_bundle(
        release, _platform_name(), _architecture_name(), archive, base_url,
        progress_callback=progress_callback, cancel_event=cancel_event,
    )
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
            expected = "tor-expert-bundle-{}-{}-{}.tar.gz".format(
                _platform_name(), _architecture_name(), version
            )
            if path.name != expected:
                return False
            sig_url = urljoin(TOR_BUNDLE_BASE_URL.rstrip("/") + "/", "{}/{}.asc".format(version, path.name))
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
        metadata = json.loads(_verification_marker(path).read_text(encoding="utf-8"))
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
    if not name.startswith("tor-expert-bundle-{}-{}-".format(platform_name, arch)):
        return False
    executable = path / "tor" / ("tor.exe" if platform_name == "windows" else "tor")
    if not executable.is_file():
        return False
    return os.name == "nt" or os.access(executable, os.X_OK)


def get_own_bundles() -> list[str]:
    root = Path(resource_path(BUNDLE_DIR))
    if not root.is_dir():
        return []
    return [
        str(path) for path in sorted(root.glob("tor-expert-bundle-*"))
        if path.is_dir() and check_bundle_compatibility(str(path))
    ]


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
