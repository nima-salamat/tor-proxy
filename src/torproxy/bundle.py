"""Pinned-signature verification, bounded downloads, progress events, and safe tar extraction."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from threading import Event
from urllib.parse import urlsplit

import requests


TOR_SIGNING_FINGERPRINT = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"
TOR_PUBLIC_KEY_URL = "https://keys.openpgp.org/vks/v1/by-fingerprint/" + TOR_SIGNING_FINGERPRINT
ALLOWED_DISTRIBUTION_HOSTS = {"dist.torproject.org", "archive.torproject.org"}
MAX_BUNDLE_BYTES = 300 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024
PROGRESS_MIN_INTERVAL_SECONDS = 0.12
SUPPORTED_VERSION = re.compile(
    r"^(?:(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)|"
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))?a(?:0|[1-9]\d*))$"
)


@dataclass(frozen=True)
class BundleProgress:
    """Immutable transfer/install event safe to send through a Qt queued signal."""

    version: str
    operation: str
    stage: str
    bytes_received: int = 0
    total_bytes: int | None = None
    percentage: int | None = None
    speed_bytes_per_second: float | None = None
    eta_seconds: int | None = None
    message: str = ""


class BundleVerificationError(RuntimeError):
    """A Tor release could not be authenticated or safely installed."""


def _progress(callback, event: BundleProgress) -> None:
    if callback is not None:
        callback(event)


def _check_cancelled(cancel_event: Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise BundleVerificationError("Tor bundle operation was cancelled.")


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(
    url: str,
    destination: Path,
    allowed_hosts: set[str],
    timeout: tuple[float, float] = (10.0, 30.0),
    max_bytes: int = MAX_BUNDLE_BYTES,
    *,
    version: str = "",
    operation: str = "download",
    stage: str = "downloading_archive",
    progress_callback=None,
    cancel_event: Event | None = None,
) -> None:
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in allowed_hosts
            or parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise BundleVerificationError("Refusing a non-HTTPS or non-authoritative download URL.")
    total = 0
    started = time.monotonic()
    last_report = 0.0
    total_bytes = None
    try:
        _check_cancelled(cancel_event)
        with requests.get(url, stream=True, timeout=timeout, allow_redirects=False) as response:
            if 300 <= response.status_code < 400:
                raise BundleVerificationError(
                    "Download redirects are refused; use the published Tor distribution URL."
                )
            final = urlsplit(response.url)
            if (final.scheme != "https" or final.hostname not in allowed_hosts
                    or final.username or final.password or final.port not in (None, 443)):
                raise BundleVerificationError(
                    "The download redirected outside the approved Tor distribution hosts."
                )
            response.raise_for_status()
            raw_length = response.headers.get("Content-Length")
            try:
                declared = int(raw_length) if raw_length is not None else 0
                total_bytes = declared if declared > 0 else None
            except (TypeError, ValueError):
                total_bytes = None
            if total_bytes is not None and total_bytes > max_bytes:
                raise BundleVerificationError("The server file exceeds the configured size limit.")
            _progress(progress_callback, BundleProgress(
                version, operation, stage, 0, total_bytes, 0 if total_bytes else None,
                None, None, "Connecting to the official Tor distribution.",
            ))
            with destination.open("wb") as output:
                for chunk in response.iter_content(chunk_size=256 * 1024):
                    _check_cancelled(cancel_event)
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > max_bytes:
                        raise BundleVerificationError("The downloaded file exceeds the configured size limit.")
                    if total_bytes is not None and total > total_bytes:
                        raise BundleVerificationError(
                            "The server sent more bytes than its declared Content-Length."
                        )
                    output.write(chunk)
                    now = time.monotonic()
                    elapsed = max(now - started, 0.001)
                    speed = total / elapsed
                    percentage = int(total * 100 / total_bytes) if total_bytes else None
                    eta = int(max(total_bytes - total, 0) / speed) if total_bytes and speed > 0 else None
                    if now - last_report >= PROGRESS_MIN_INTERVAL_SECONDS:
                        _progress(progress_callback, BundleProgress(
                            version, operation, stage, total, total_bytes, percentage, speed, eta,
                            f"Received {total} bytes",
                        ))
                        last_report = now
                output.flush()
                os.fsync(output.fileno())
    except requests.RequestException as exc:
        raise BundleVerificationError(f"Download failed: {exc}") from exc
    except OSError:
        # The caller owns the temporary destination and removes it on all failure paths.
        raise
    if total == 0:
        raise BundleVerificationError("The server returned an empty file.")
    if total_bytes is not None and total != total_bytes:
        raise BundleVerificationError(
            "The transfer ended before the declared Content-Length was received."
        )
    elapsed = max(time.monotonic() - started, 0.001)
    _progress(progress_callback, BundleProgress(
        version, operation, stage, total, total_bytes, 100 if total_bytes and total == total_bytes else None,
        total / elapsed, 0, "Transfer finished; validation is still required.",
    ))


def _find_gpg_executable() -> Path:
    """Find and smoke-test an installed GnuPG runtime without invoking a shell."""
    import shutil as _shutil

    candidates: list[Path] = []
    configured = os.environ.get("TORPROXY_GPG_EXECUTABLE", "").strip()
    if configured:
        candidates.append(Path(configured).expanduser())
    for command in ("gpg", "gpg2"):
        found = _shutil.which(command)
        if found:
            candidates.append(Path(found))
    if os.name == "nt":
        roots = [
            os.environ.get("ProgramFiles", ""),
            os.environ.get("ProgramFiles(x86)", ""),
            os.environ.get("LOCALAPPDATA", ""),
        ]
        for root in roots:
            if root:
                base = Path(root)
                candidates.extend([
                    base / "GnuPG" / "bin" / "gpg.exe",
                    base / "Programs" / "GnuPG" / "bin" / "gpg.exe",
                ])
    else:
        candidates.extend([
            Path("/usr/bin/gpg"),
            Path("/usr/local/bin/gpg"),
            Path("/opt/homebrew/bin/gpg"),
        ])
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            key = os.path.normcase(str(resolved))
            if key in seen or not resolved.is_file():
                continue
            seen.add(key)
            checked = subprocess.run(
                [str(resolved), "--version"], stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=5, check=False,
            )
            if checked.returncode == 0 and "gpg" in (checked.stdout + checked.stderr).lower():
                return resolved
        except (OSError, subprocess.TimeoutExpired):
            continue
    raise BundleVerificationError(
        "Tor's signature was not checked because GnuPG could not be found or started. "
        "Install GnuPG from https://gnupg.org/download/ and restart TorProxy, or set "
        "TORPROXY_GPG_EXECUTABLE to the full path of gpg.exe/gpg. Verification remains mandatory."
    )


def verify_tor_signature(
    artifact: str | Path,
    signature: str | Path,
    public_key_url: str = TOR_PUBLIC_KEY_URL,
    expected_fingerprint: str = TOR_SIGNING_FINGERPRINT,
    *,
    progress_callback=None,
    cancel_event: Event | None = None,
    version: str = "",
) -> None:
    """Verify a detached OpenPGP signature against the independently pinned Tor key."""
    artifact = Path(artifact)
    signature = Path(signature)
    if not artifact.is_file():
        raise BundleVerificationError("The downloaded Tor archive is missing.")
    if not signature.is_file():
        raise BundleVerificationError("The detached Tor signature (.asc) is missing.")
    expected = re.sub(r"\s+", "", expected_fingerprint).upper()
    if not re.fullmatch(r"[A-F0-9]{40}", expected):
        raise BundleVerificationError("The trusted OpenPGP fingerprint is not a full 40-character fingerprint.")
    gpg = _find_gpg_executable()
    try:
        with tempfile.TemporaryDirectory(prefix="torproxy-gpg-") as home:
            home_path = Path(home)
            key_file = home_path / "tor-signing-key.asc"
            _download(
                public_key_url, key_file,
                {"keys.openpgp.org", "openpgpkey.torproject.org"},
                max_bytes=2 * 1024 * 1024, version=version, operation="verify",
                stage="downloading_signing_key", progress_callback=progress_callback,
                cancel_event=cancel_event,
            )
            env = os.environ.copy()
            env["GNUPGHOME"] = str(home_path)
            imported = subprocess.run(
                [str(gpg), "--batch", "--no-tty", "--import", str(key_file)],
                env=env, stdin=subprocess.DEVNULL, capture_output=True,
                text=True, timeout=20, check=False,
            )
            if imported.returncode != 0:
                raise BundleVerificationError("The Tor OpenPGP signing key could not be imported.")
            listing = subprocess.run(
                [str(gpg), "--batch", "--with-colons", "--fingerprint", "--list-keys"],
                env=env, stdin=subprocess.DEVNULL, capture_output=True,
                text=True, timeout=20, check=False,
            )
            fingerprints = {
                line.split(":")[9].upper()
                for line in listing.stdout.splitlines()
                if line.startswith("fpr:") and len(line.split(":")) > 9
            }
            if listing.returncode != 0 or expected not in fingerprints:
                raise BundleVerificationError(
                    "The downloaded OpenPGP key does not match the independently pinned fingerprint."
                )
            verified = subprocess.run(
                [str(gpg), "--batch", "--no-tty", "--status-fd", "1",
                 "--verify", str(signature), str(artifact)],
                env=env, stdin=subprocess.DEVNULL, capture_output=True,
                text=True, timeout=30, check=False,
            )
            valid_lines = [
                line.split() for line in verified.stdout.splitlines()
                if line.startswith("[GNUPG:] VALIDSIG ")
            ]
            if verified.returncode != 0 or not valid_lines:
                raise BundleVerificationError("The Tor release signature is missing or invalid.")
            signers = {
                part.upper()
                for line in valid_lines
                for part in line[2:]
                if re.fullmatch(r"[A-Fa-f0-9]{40}", part)
            }
            if expected not in signers:
                raise BundleVerificationError(
                    "The release signature was not made by the pinned Tor signing key."
                )
    except FileNotFoundError as exc:
        raise BundleVerificationError(
            "GnuPG disappeared or could not be started during verification; installation was refused."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise BundleVerificationError("GnuPG timed out while verifying the Tor release.") from exc


def safe_extract_tar_gz(archive_path: str | Path, destination: str | Path) -> Path:
    """Extract regular files/directories only; reject links, special files, and path escapes."""
    archive_path = Path(archive_path)
    destination = Path(destination)
    destination_parent = destination.parent.resolve()
    destination_parent.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix=f".{destination.name}.extract-", dir=destination_parent))
    try:
        root = temp_dir.resolve()
        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            total_size = 0
            for member in members:
                name = PurePosixPath(member.name)
                if name.is_absolute() or ".." in name.parts:
                    raise BundleVerificationError(f"Unsafe path in archive: {member.name!r}")
                target = (root / Path(*name.parts)).resolve()
                if target != root and root not in target.parents:
                    raise BundleVerificationError(f"Archive path escapes extraction directory: {member.name!r}")
                if not (member.isdir() or member.isfile()):
                    raise BundleVerificationError(
                        f"Unsupported link or special archive entry: {member.name!r}"
                    )
                if member.isfile():
                    total_size += member.size
                    if total_size > MAX_EXTRACTED_BYTES:
                        raise BundleVerificationError(
                            "Archive expands beyond the configured extraction-size limit."
                        )
            for member in members:
                name = PurePosixPath(member.name)
                target = root / Path(*name.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise BundleVerificationError(f"Could not read archive member: {member.name!r}")
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                if os.name != "nt":
                    os.chmod(target, member.mode & 0o755)
        if destination.exists():
            raise BundleVerificationError(f"Destination already exists; refusing to overwrite: {destination}")
        os.replace(temp_dir, destination)
        return destination
    except BundleVerificationError:
        raise
    except (tarfile.TarError, OSError) as exc:
        raise BundleVerificationError(f"Tor archive extraction failed: {exc}") from exc
    finally:
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)


def download_verified_bundle(
    version: str,
    platform_name: str,
    architecture: str,
    destination: str | Path,
    base_url: str = "https://dist.torproject.org/torbrowser/",
    *,
    progress_callback=None,
    cancel_event: Event | None = None,
) -> Path:
    """Download archive + signature, verify them, then publish the complete archive atomically."""
    if not SUPPORTED_VERSION.fullmatch(version):
        raise BundleVerificationError("Unsupported Tor release version.")
    if platform_name not in {"windows", "linux"} or architecture not in {"x86_64", "i686"}:
        raise BundleVerificationError(
            "This application currently supports only Windows/Linux x86 Expert Bundles."
        )
    parsed = urlsplit(base_url)
    if (parsed.scheme != "https" or parsed.hostname not in ALLOWED_DISTRIBUTION_HOSTS
            or parsed.username or parsed.password
            or parsed.path.rstrip("/") not in {"/torbrowser", "/tor-package-archive/torbrowser"}):
        raise BundleVerificationError("The bundle base URL is not an approved Tor distribution endpoint.")
    filename = f"tor-expert-bundle-{platform_name}-{architecture}-{version}.tar.gz"
    _progress(progress_callback, BundleProgress(
        version, "verify", "checking_verification_runtime",
        message="Checking that the required OpenPGP verification runtime is available before downloading.",
    ))
    # Fail early on a clean machine without GnuPG so users do not download a large archive first.
    _find_gpg_executable()
    _check_cancelled(cancel_event)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="torproxy-download-", dir=destination.parent) as work:
        work_path = Path(work)
        archive_tmp = work_path / filename
        signature_tmp = work_path / (filename + ".asc")
        base = base_url.rstrip("/") + "/" + version + "/"
        _download(
            base + filename, archive_tmp, ALLOWED_DISTRIBUTION_HOSTS,
            version=version, operation="download", stage="downloading_archive",
            progress_callback=progress_callback, cancel_event=cancel_event,
        )
        _download(
            base + filename + ".asc", signature_tmp, ALLOWED_DISTRIBUTION_HOSTS,
            max_bytes=1024 * 1024, version=version, operation="download",
            stage="downloading_signature", progress_callback=progress_callback,
            cancel_event=cancel_event,
        )
        _check_cancelled(cancel_event)
        _progress(progress_callback, BundleProgress(
            version, "verify", "verifying_signature", message="Checking the detached OpenPGP signature."
        ))
        verify_tor_signature(
            archive_tmp, signature_tmp, progress_callback=progress_callback,
            cancel_event=cancel_event, version=version,
        )
        _check_cancelled(cancel_event)
        _progress(progress_callback, BundleProgress(
            version, "verify", "signature_verified", message="The archive signature matches the pinned Tor key."
        ))
        # Publish both final files only after successful signature verification.
        signature_destination = destination.with_name(destination.name + ".asc")
        signature_copy = signature_destination.with_name("." + signature_destination.name + ".tmp")
        try:
            shutil.copyfile(signature_tmp, signature_copy)
            with signature_copy.open("rb+") as handle:
                os.fsync(handle.fileno())
            os.replace(archive_tmp, destination)
            os.replace(signature_copy, signature_destination)
        finally:
            try:
                signature_copy.unlink()
            except FileNotFoundError:
                pass
        _progress(progress_callback, BundleProgress(
            version, "download", "archive_validated", message="Signed archive saved; installation is not complete yet."
        ))
    return destination
