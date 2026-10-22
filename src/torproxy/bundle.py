"""Pinned-signature verification, bounded downloads, and safe tar extraction."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

import requests


TOR_SIGNING_FINGERPRINT = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"
TOR_PUBLIC_KEY_URL = "https://keys.openpgp.org/vks/v1/by-fingerprint/" + TOR_SIGNING_FINGERPRINT
ALLOWED_DISTRIBUTION_HOSTS = {"dist.torproject.org", "archive.torproject.org"}
MAX_BUNDLE_BYTES = 300 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024


class BundleVerificationError(RuntimeError):
    """A Tor release could not be authenticated or safely installed."""


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, destination: Path, allowed_hosts: set[str],
              timeout: tuple[float, float] = (10.0, 30.0), max_bytes: int = MAX_BUNDLE_BYTES) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in allowed_hosts or parsed.username or parsed.password:
        raise BundleVerificationError("Refusing a non-HTTPS or non-authoritative download URL.")
    total = 0
    try:
        with requests.get(url, stream=True, timeout=timeout, allow_redirects=False) as response:
            if 300 <= response.status_code < 400:
                raise BundleVerificationError("Download redirects are refused; use the published Tor distribution URL.")
            final = urlsplit(response.url)
            if final.scheme != "https" or final.hostname not in allowed_hosts:
                raise BundleVerificationError("The download redirected outside the approved Tor distribution hosts.")
            response.raise_for_status()
            with destination.open("wb") as output:
                for chunk in response.iter_content(chunk_size=1024 * 256):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > max_bytes:
                        raise BundleVerificationError("The downloaded file exceeds the configured size limit.")
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
    except requests.RequestException as exc:
        raise BundleVerificationError(f"Download failed: {exc}") from exc
    if total == 0:
        raise BundleVerificationError("The server returned an empty file.")


def verify_tor_signature(artifact: str | Path, signature: str | Path,
                         public_key_url: str = TOR_PUBLIC_KEY_URL,
                         expected_fingerprint: str = TOR_SIGNING_FINGERPRINT) -> None:
    """Verify a detached OpenPGP signature using a pinned Tor Browser Developers key."""
    artifact = Path(artifact)
    signature = Path(signature)
    expected = re.sub(r"\s+", "", expected_fingerprint).upper()
    if not re.fullmatch(r"[A-F0-9]{40}", expected):
        raise BundleVerificationError("The trusted OpenPGP fingerprint is not a full 40-character fingerprint.")
    try:
        with tempfile.TemporaryDirectory(prefix="torproxy-gpg-") as home:
            home_path = Path(home)
            key_file = home_path / "tor-signing-key.asc"
            _download(public_key_url, key_file, {"keys.openpgp.org", "openpgpkey.torproject.org"},
                      max_bytes=2 * 1024 * 1024)
            env = os.environ.copy()
            env["GNUPGHOME"] = str(home_path)
            imported = subprocess.run(
                ["gpg", "--batch", "--no-tty", "--import", str(key_file)],
                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=20, check=False,
            )
            if imported.returncode != 0:
                raise BundleVerificationError("Could not import the Tor signing key.")
            listing = subprocess.run(
                ["gpg", "--batch", "--with-colons", "--fingerprint", "--list-keys"],
                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=20, check=False,
            )
            fingerprints = {line.split(":")[9].upper() for line in listing.stdout.splitlines()
                            if line.startswith("fpr:") and len(line.split(":")) > 9}
            if listing.returncode != 0 or expected not in fingerprints:
                raise BundleVerificationError("The downloaded OpenPGP key does not match the pinned fingerprint.")
            verified = subprocess.run(
                ["gpg", "--batch", "--no-tty", "--status-fd", "1", "--verify", str(signature), str(artifact)],
                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=30, check=False,
            )
            valid_lines = [line.split() for line in verified.stdout.splitlines()
                           if line.startswith("[GNUPG:] VALIDSIG ")]
            if verified.returncode != 0 or not valid_lines:
                raise BundleVerificationError("Tor release signature is missing or invalid.")
            signers = {part.upper() for line in valid_lines for part in line[2:] if re.fullmatch(r"[A-Fa-f0-9]{40}", part)}
            if expected not in signers:
                raise BundleVerificationError("The release signature was not made by the pinned Tor signing key.")
    except FileNotFoundError as exc:
        raise BundleVerificationError("GnuPG is required to verify Tor releases; installation was refused.") from exc
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
                    raise BundleVerificationError(f"Unsupported link or special archive entry: {member.name!r}")
                if member.isfile():
                    total_size += member.size
                    if total_size > MAX_EXTRACTED_BYTES:
                        raise BundleVerificationError("Archive expands beyond the configured extraction-size limit.")
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


def download_verified_bundle(version: str, platform_name: str, architecture: str,
                             destination: str | Path,
                             base_url: str = "https://dist.torproject.org/torbrowser/") -> Path:
    """Download and verify a stable official Expert Bundle before returning its archive path."""
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise BundleVerificationError("Only stable numeric release versions are accepted.")
    if platform_name not in {"windows", "linux"} or architecture not in {"x86_64", "i686"}:
        raise BundleVerificationError("This application currently supports only Windows/Linux x86 Expert Bundles.")
    parsed = urlsplit(base_url)
    if (parsed.scheme != "https" or parsed.hostname not in ALLOWED_DISTRIBUTION_HOSTS
            or parsed.path.rstrip("/") not in {"/torbrowser", "/tor-package-archive/torbrowser"}):
        raise BundleVerificationError("The bundle base URL is not an approved Tor distribution endpoint.")
    filename = f"tor-expert-bundle-{platform_name}-{architecture}-{version}.tar.gz"
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="torproxy-download-", dir=destination.parent) as work:
        work_path = Path(work)
        archive_tmp = work_path / filename
        signature_tmp = work_path / (filename + ".asc")
        base = base_url.rstrip("/") + "/" + version + "/"
        _download(base + filename, archive_tmp, ALLOWED_DISTRIBUTION_HOSTS)
        _download(base + filename + ".asc", signature_tmp, ALLOWED_DISTRIBUTION_HOSTS, max_bytes=1024 * 1024)
        verify_tor_signature(archive_tmp, signature_tmp)
        signature_destination = destination.with_name(destination.name + ".asc")
        signature_copy = signature_destination.with_name("." + signature_destination.name + ".tmp")
        shutil.copyfile(signature_tmp, signature_copy)
        os.replace(signature_copy, signature_destination)
        os.replace(archive_tmp, destination)
    return destination
