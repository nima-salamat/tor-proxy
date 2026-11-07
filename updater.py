"""Tor Expert Bundle discovery and fail-closed signed installation."""
from __future__ import annotations

import json
import logging
import os
import platform
import re
import shutil
import uuid
from pathlib import Path
from threading import Event
from urllib.parse import unquote, urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

from config import ARCHITECTURE, BUNDLE_DIR, OS_NAME, TOR_BUNDLE_BASE_URL, TOR_BUNDLE_FALLBACK_URL
from torproxy.bundle import (
    ALLOWED_DISTRIBUTION_HOSTS,
    BundleProgress,
    BundleVerificationError,
    MAX_BUNDLE_BYTES,
    download_verified_bundle,
    sha256_file,
    verify_tor_signature,
)
from torproxy.network import NetworkRouteError, create_session, network_error_message
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


def _distribution_base_urls(base_url: str = TOR_BUNDLE_BASE_URL) -> tuple[str, ...]:
    """Return a selected official source and the other Tor endpoint as fallback."""
    primary = str(base_url).rstrip("/") + "/"
    official = {
        TOR_BUNDLE_BASE_URL.rstrip("/") + "/",
        TOR_BUNDLE_FALLBACK_URL.rstrip("/") + "/",
    }
    if primary not in official:
        return (primary,)
    secondary = (
        TOR_BUNDLE_FALLBACK_URL.rstrip("/") + "/"
        if primary == TOR_BUNDLE_BASE_URL.rstrip("/") + "/"
        else TOR_BUNDLE_BASE_URL.rstrip("/") + "/"
    )
    return (primary, secondary)


def _raise_distribution_failure(
    purpose: str, failures: list[str], *, proxy_url: str | None, allow_direct: bool
) -> BundleVerificationError:
    route = "TOR_SOCKS" if proxy_url else "DIRECT_BOOTSTRAP" if allow_direct else "NO_ROUTE"
    return BundleVerificationError(
        f"{purpose} could not be completed using {route}. "
        + " | ".join(failures)
        + " The application did not change network routes. "
        "Check connectivity or try Import .tar.gz with a locally downloaded Expert Bundle."
    )


def _fetch_listing(
    url: str, proxy_url: str | None = None, *, allow_direct: bool = False
) -> BeautifulSoup:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_DISTRIBUTION_HOSTS:
        raise BundleVerificationError("Refusing to query an untrusted Tor distribution host.")
    try:
        with create_session(proxy_url, allow_direct=allow_direct) as session:
            with session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False) as response:
                if 300 <= response.status_code < 400:
                    raise BundleVerificationError("Redirects are refused when discovering Tor releases.")
                final = urlsplit(response.url)
                if final.scheme != "https" or final.hostname not in ALLOWED_DISTRIBUTION_HOSTS:
                    raise BundleVerificationError("Tor distribution listing redirected to an untrusted host.")
                response.raise_for_status()
                return BeautifulSoup(response.text, "html.parser")
    except NetworkRouteError as exc:
        raise BundleVerificationError(str(exc)) from exc


def get_tor_versions(
    url: str = TOR_BUNDLE_BASE_URL, *, proxy_url: str | None = None, allow_direct: bool = False
) -> list[str]:
    """Return every recognized release directory, sorted stables first then alphas.

    Artifact availability is checked lazily when a user selects a release. This
    avoids firing one network request for every historical release at startup.
    """
    failures: list[str] = []
    saw_listing = False
    for source_base in _distribution_base_urls(url):
        try:
            soup = _fetch_listing(source_base, proxy_url, allow_direct=allow_direct)
        except requests.RequestException as exc:
            message = network_error_message(
                exc, purpose="Tor release discovery",
                proxy_url=proxy_url, allow_direct=allow_direct,
            )
            failures.append(f"{urlsplit(source_base).hostname}: {message}")
            logger.warning(
                "Tor release endpoint %s failed; trying the next official endpoint: %s",
                urlsplit(source_base).hostname, message,
            )
            continue

        saw_listing = True
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
        if versions:
            return [
                version + "/"
                for version in sorted(versions, key=tor_version_sort_key, reverse=True)
            ]
        logger.warning(
            "Tor release endpoint %s returned no recognized versions; trying the next official endpoint.",
            urlsplit(source_base).hostname,
        )

    if failures:
        raise _raise_distribution_failure(
            "Tor release discovery", failures,
            proxy_url=proxy_url, allow_direct=allow_direct,
        )
    raise BundleVerificationError(
        "The official Tor release listings returned no recognizable stable or supported alpha release directories."
    )


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


def get_bundle_links(
    version: str,
    base_url: str = TOR_BUNDLE_BASE_URL,
    *,
    require_signature: bool = True,
    proxy_url: str | None = None,
    allow_direct: bool = False,
) -> list[str]:
    """Return the exact platform artifact, requiring .asc only when signature checks are enabled."""
    release = str(version).strip().strip("/")
    parse_tor_version(release)
    platform_name = _platform_name()
    architecture = _architecture_name()
    expected = f"tor-expert-bundle-{platform_name}-{architecture}-{release}.tar.gz"
    failures: list[str] = []
    sources = _distribution_base_urls(base_url)
    for source_base in sources:
        listing_url = urljoin(source_base, release + "/")
        try:
            soup = _fetch_listing(listing_url, proxy_url, allow_direct=allow_direct)
        except requests.RequestException as exc:
            message = network_error_message(
                exc,
                purpose=f"Artifact availability check for Tor release {release}",
                proxy_url=proxy_url,
                allow_direct=allow_direct,
            )
            failures.append(f"{urlsplit(source_base).hostname}: {message}")
            logger.warning(
                "Tor artifact listing %s failed; trying the next official endpoint: %s",
                urlsplit(source_base).hostname, message,
            )
            continue

        anchors = soup.find_all("a", href=True)
        if not anchors:
            logger.warning(
                "Tor artifact listing for %s at %s was empty; trying its official mirror.",
                release, urlsplit(source_base).hostname,
            )
            continue
        names = {
            Path(urlsplit(str(link.get("href", ""))).path).name
            for link in anchors
        }
        if expected in names and (not require_signature or expected + ".asc" in names):
            return [expected]

    if failures:
        raise _raise_distribution_failure(
            f"Artifact availability check for Tor release {release}", failures,
            proxy_url=proxy_url, allow_direct=allow_direct,
        )
    return []

def get_version_by_bundle(filename: str, with_slash: bool = False) -> str:
    name = Path(filename).name
    match = re.fullmatch(r"tor-expert-bundle-(?:windows|linux)-(?:x86_64|i686)-((?:\d+\.\d+\.\d+)|(?:\d+\.\d+(?:\.\d+)?a\d+))\.tar\.gz", name)
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
    verify_signature: bool = True,
    proxy_url: str | None = None,
    allow_direct: bool = False,
) -> Path:
    """Download the exact current-platform Expert Bundle using an explicit network route."""
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
    signature = archive.with_name(archive.name + ".asc")
    if verify_signature and archive.is_file() and signature.is_file():
        if progress_callback:
            progress_callback(BundleProgress(
                version=release, operation="verify", stage="verifying_signature",
                message="Checking the cached archive signature before reuse.",
            ))
        try:
            verify_tor_signature(
                archive, signature, progress_callback=progress_callback,
                cancel_event=cancel_event, version=release,
                proxy_url=proxy_url, allow_direct=allow_direct,
            )
        except BundleVerificationError as exc:
            message = str(exc).lower()
            if cancel_event is not None and cancel_event.is_set():
                raise
            if any(term in message for term in ("gnupg", "timed out", "download failed", "could not be retrieved")):
                raise
            logger.warning("Cached Tor archive failed signature verification; re-downloading it.")
        else:
            if progress_callback:
                progress_callback(BundleProgress(
                    version=release, operation="install", stage="already_verified",
                    message="Existing archive signature verified; safe extraction is still required.",
                ))
            return archive
    # An unsigned cache has no authenticated publisher identity. Always fetch a
    # fresh archive for installation when OpenPGP verification is disabled.
    archive.parent.mkdir(parents=True, exist_ok=True)
    source_urls = _distribution_base_urls(base_url)
    source_failures: list[str] = []
    result = None
    for source_index, source_base in enumerate(source_urls):
        try:
            result = download_verified_bundle(
                release, _platform_name(), _architecture_name(), archive, source_base,
                progress_callback=progress_callback, cancel_event=cancel_event,
                verify_signature=verify_signature, proxy_url=proxy_url, allow_direct=allow_direct,
            )
            break
        except BundleVerificationError as exc:
            message = str(exc).lower()
            retryable_source_error = (
                "download failed" in message
                and any(
                    marker in message
                    for marker in (
                        "connection", "timed out", "refused", "dns resolution",
                        "tls certificate", "http 403", "http 404", "http 408",
                        "http 429", "http 500", "http 502", "http 503", "http 504",
                    )
                )
            )
            if not retryable_source_error:
                raise
            source_failures.append(f"{urlsplit(source_base).hostname}: {exc}")
            if source_index + 1 >= len(source_urls):
                if len(source_urls) > 1:
                    raise _raise_distribution_failure(
                        f"Tor bundle download for release {release}",
                        source_failures,
                        proxy_url=proxy_url,
                        allow_direct=allow_direct,
                    ) from exc
                raise
            logger.warning(
                "Tor bundle download from %s failed; trying official archive mirror %s: %s",
                urlsplit(source_base).hostname,
                urlsplit(source_urls[source_index + 1]).hostname,
                exc,
            )

    if result is None:
        raise BundleVerificationError("Tor bundle download failed without a result.")
    if verify_signature:
        logger.info("Downloaded and signature-verified Tor Expert Bundle %s.", expected)
    else:
        logger.warning("Downloaded Tor Expert Bundle %s via HTTPS without authenticating its OpenPGP signature.", expected)
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


def check_hash(
    filename, base_url: str = TOR_BUNDLE_BASE_URL, go_online: bool = False, *,
    proxy_url: str | None = None, allow_direct: bool = False,
) -> bool:
    """Return true only when a detached signature verifies against the pinned Tor key."""
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
            parsed_base = urlsplit(base_url)
            if parsed_base.scheme != "https" or parsed_base.hostname not in ALLOWED_DISTRIBUTION_HOSTS:
                return False
            sig_url = urljoin(base_url.rstrip("/") + "/", "{}/{}.asc".format(version, path.name))
            with create_session(proxy_url, allow_direct=allow_direct) as session:
                with session.get(sig_url, timeout=REQUEST_TIMEOUT, allow_redirects=False) as response:
                    if 300 <= response.status_code < 400:
                        return False
                    final = urlsplit(response.url)
                    if final.scheme != "https" or final.hostname not in ALLOWED_DISTRIBUTION_HOSTS:
                        return False
                    response.raise_for_status()
                    if not response.content or len(response.content) > 1024 * 1024:
                        return False
                    signature.write_bytes(response.content)
        except (requests.RequestException, BundleVerificationError, NetworkRouteError, OSError, ValueError) as exc:
            logger.warning(
                "Could not retrieve a detached signature for %s: %s",
                path.name,
                exc,
            )
            return False
    if not signature.is_file():
        return False
    try:
        verify_tor_signature(path, signature, proxy_url=proxy_url, allow_direct=allow_direct)
        return True
    except (BundleVerificationError, NetworkRouteError, OSError):
        logger.warning("Tor bundle signature verification failed: %s", path.name)
        return False


def list_downloaded_bundles() -> list[str]:
    return [str(path) for path in Path(resource_path(BUNDLE_DIR)).glob("*.tar.gz")]


def _verification_marker(bundle_dir: Path) -> Path:
    return bundle_dir / ".torproxy-verified.json"


def check_bundle_compatibility(filename: str) -> bool:
    """Accept intact managed installs with signed, HTTPS-only, or local-unverified provenance."""
    path = Path(filename).resolve()
    name = path.name
    if not path.is_dir() or not name.startswith("tor-expert-bundle-"):
        return False
    try:
        metadata = json.loads(_verification_marker(path).read_text(encoding="utf-8"))
        signature_verified = (
            metadata.get("signature_verified") is True
            and metadata.get("verification_method", "openpgp") == "openpgp"
        )
        https_only = (
            metadata.get("signature_verified") is False
            and metadata.get("verification_method") == "https_only"
        )
        local_unverified = (
            metadata.get("signature_verified") is False
            and metadata.get("verification_method") == "local_unverified"
        )
        if not (signature_verified or https_only or local_unverified):
            return False
        expected_digest = metadata.get("archive_sha256", "")
        if not re.fullmatch(r"[a-f0-9]{64}", expected_digest):
            return False
        archive = path.with_name(path.name + ".tar.gz")
        if not archive.is_file() or sha256_file(archive) != expected_digest:
            return False
        if signature_verified and not archive.with_name(archive.name + ".asc").is_file():
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



def _copy_limited_local_file(
    source: Path,
    destination: Path,
    *,
    max_bytes: int,
    expected_size: int,
    cancel_event: Event | None = None,
) -> int:
    """Copy a local archive/sidecar atomically into a temporary file with size and cancel checks."""
    total = 0
    with source.open("rb") as input_file, destination.open("xb") as output_file:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise BundleVerificationError("Local Tor bundle import was cancelled.")
            chunk = input_file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise BundleVerificationError("The selected local file exceeds its configured size limit.")
            output_file.write(chunk)
        output_file.flush()
        os.fsync(output_file.fileno())
    if total != expected_size:
        raise BundleVerificationError("The selected local file changed while it was being imported.")
    return total


def import_local_bundle(
    filename: str | os.PathLike[str],
    *,
    verify_signature: bool = True,
    proxy_url: str | None = None,
    allow_direct: bool = False,
    progress_callback=None,
    cancel_event: Event | None = None,
) -> Path:
    """Import a user-selected Expert Bundle into managed storage using safe extraction."""
    from utils import extract_tar_gz_file

    source = Path(filename).expanduser().resolve()
    if not source.is_file():
        raise BundleVerificationError("The selected local Tor bundle archive does not exist.")
    try:
        version = get_version_by_bundle(source.name)
    except ValueError as exc:
        raise BundleVerificationError(str(exc)) from exc
    expected = "tor-expert-bundle-{}-{}-{}.tar.gz".format(
        _platform_name(), _architecture_name(), version
    )
    if source.name != expected:
        raise BundleVerificationError(
            "The selected archive does not match this device. Expected filename: {}".format(expected)
        )
    size = source.stat().st_size
    if size <= 0 or size > MAX_BUNDLE_BYTES:
        raise BundleVerificationError(
            "The local archive is empty or exceeds the {} MiB size limit.".format(
                MAX_BUNDLE_BYTES // (1024 * 1024)
            )
        )

    signature_source = source.with_name(source.name + ".asc")
    if verify_signature and not signature_source.is_file():
        raise BundleVerificationError(
            "OpenPGP verification is enabled, but the matching .asc file is missing beside the archive."
        )
    if signature_source.is_file() and signature_source.stat().st_size > 1024 * 1024:
        raise BundleVerificationError("The detached signature file exceeds the 1 MiB size limit.")

    create_bundle_dir()
    archive = bundle_path(expected)
    destination = bundle_path(expected[:-len(".tar.gz")])
    signature = archive.with_name(archive.name + ".asc")
    if archive.exists() or destination.exists() or signature.exists():
        raise BundleVerificationError(
            "A bundle with this version already exists in managed storage. Rescan installed bundles first."
        )
    archive.parent.mkdir(parents=True, exist_ok=True)
    temporary_archive = archive.with_name(".{}.{}.import".format(archive.name, uuid.uuid4().hex))
    temporary_signature = signature.with_name(".{}.{}.import".format(signature.name, uuid.uuid4().hex))
    archive_published = False
    signature_published = False
    try:
        if cancel_event is not None and cancel_event.is_set():
            raise BundleVerificationError("Local Tor bundle import was cancelled.")
        if progress_callback:
            progress_callback(BundleProgress(
                version, "import", "copying_local_archive",
                total_bytes=size, percentage=0,
                message="Copying the selected local archive into managed storage.",
            ))
        _copy_limited_local_file(
            source, temporary_archive, max_bytes=MAX_BUNDLE_BYTES,
            expected_size=size, cancel_event=cancel_event,
        )
        if signature_source.is_file():
            _copy_limited_local_file(
                signature_source, temporary_signature, max_bytes=1024 * 1024,
                expected_size=signature_source.stat().st_size, cancel_event=cancel_event,
            )
        if cancel_event is not None and cancel_event.is_set():
            raise BundleVerificationError("Local Tor bundle import was cancelled.")
        os.replace(temporary_archive, archive)
        archive_published = True
        if temporary_signature.is_file():
            os.replace(temporary_signature, signature)
            signature_published = True
        installed = extract_tar_gz_file(
            archive,
            destination,
            progress_callback=progress_callback,
            cancel_event=cancel_event,
            version=version,
            verify_signature=verify_signature,
            verification_method="openpgp" if verify_signature else "local_unverified",
            proxy_url=proxy_url,
            allow_direct=allow_direct,
        )
        logger.info(
            "Imported local Tor Expert Bundle %s (OpenPGP verification=%s).",
            expected, verify_signature,
        )
        return installed
    except Exception:
        if archive_published:
            try:
                archive.unlink()
            except FileNotFoundError:
                pass
        if signature_published:
            try:
                signature.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        for temporary in (temporary_archive, temporary_signature):
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
