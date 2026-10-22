"""Resource path helpers and verified Tor Expert Bundle extraction."""
from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import uuid
from threading import Event
from datetime import datetime, timezone
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parent / "src"
if SRC_ROOT.is_dir() and str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from torproxy.bundle import (  # noqa: E402
    TOR_SIGNING_FINGERPRINT,
    BundleProgress,
    BundleVerificationError,
    safe_extract_tar_gz,
    sha256_file,
    verify_tor_signature,
)

logger = logging.getLogger(__name__)


def resource_path(relative_path):
    """Resolve read-only packaged resources; runtime data belongs in user directories."""
    if getattr(sys, "_MEIPASS", False):
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, relative_path)


def extract_tar_gz_file(
    filename,
    dst,
    *,
    progress_callback=None,
    cancel_event: Event | None = None,
    version: str = "",
    verify_signature: bool = True,
):
    """Safely extract and atomically publish a bundle, recording whether OpenPGP was checked."""
    archive = Path(filename).expanduser().resolve()
    destination = Path(dst).expanduser().resolve()
    signature = archive.with_name(archive.name + ".asc")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = destination.with_name(".{}.verified-{}".format(destination.name, uuid.uuid4().hex))
    try:
        if destination.exists():
            raise BundleVerificationError(
                "Destination already exists; refusing to overwrite: {}".format(destination)
            )
        if not archive.is_file():
            raise BundleVerificationError("The Tor archive is missing.")
        if verify_signature:
            if not signature.is_file():
                raise BundleVerificationError("A detached .asc signature is required when OpenPGP verification is enabled.")
            if progress_callback:
                progress_callback(BundleProgress(
                    version, "verify", "verifying_signature",
                    message="Rechecking the archive signature before extraction.",
                ))
            verify_tor_signature(
                archive, signature, progress_callback=progress_callback,
                cancel_event=cancel_event, version=version,
            )
            if progress_callback:
                progress_callback(BundleProgress(
                    version, "verify", "signature_verified",
                    message="The detached signature matches the pinned Tor signing key.",
                ))
        elif progress_callback:
            progress_callback(BundleProgress(
                version, "verify", "signature_verification_skipped",
                message="OpenPGP is disabled in Settings. Extraction safeguards and SHA-256 bookkeeping remain enabled, but the publisher signature is unauthenticated.",
            ))
        if cancel_event is not None and cancel_event.is_set():
            raise BundleVerificationError("Tor bundle installation was cancelled before extraction.")
        if progress_callback:
            progress_callback(BundleProgress(
                version, "install", "extracting_archive",
                message=(
                    "Signature verified. Safely extracting into an isolated staging directory."
                    if verify_signature else
                    "Safely extracting the HTTPS-downloaded archive into an isolated staging directory; signature was not checked."
                ),
            ))
        extracted = safe_extract_tar_gz(archive, staging)
        marker = extracted / ".torproxy-verified.json"
        marker_tmp = extracted / ".torproxy-verified.json.tmp"
        metadata = {
            "signature_verified": bool(verify_signature),
            "verification_method": "openpgp" if verify_signature else "https_only",
            "signing_key_fingerprint": TOR_SIGNING_FINGERPRINT if verify_signature else None,
            "archive_sha256": sha256_file(archive),
            "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        with marker_tmp.open("x", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            marker_tmp.chmod(0o600)
        os.replace(marker_tmp, marker)
        if destination.exists():
            raise BundleVerificationError(
                "Destination appeared during installation; refusing to overwrite: {}".format(destination)
            )
        os.replace(extracted, destination)
        return destination
    except Exception as exc:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        logger.error("Tor bundle extraction/installation failed: %s", exc)
        raise
def extract_tar_gz_file(
    filename,
    dst,
    *,
    progress_callback=None,
    cancel_event: Event | None = None,
    version: str = "",
):
    """Verify, extract and publish one complete bundle atomically with its trust marker."""
    archive = Path(filename).expanduser().resolve()
    destination = Path(dst).expanduser().resolve()
    signature = archive.with_name(archive.name + ".asc")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = destination.with_name(".{}.verified-{}".format(destination.name, uuid.uuid4().hex))
    try:
        if destination.exists():
            raise BundleVerificationError(
                "Destination already exists; refusing to overwrite: {}".format(destination)
            )
        if not archive.is_file() or not signature.is_file():
            raise BundleVerificationError("A Tor archive and its detached .asc signature are both required.")
        if progress_callback:
            progress_callback(BundleProgress(
                version, "verify", "verifying_signature",
                message="Rechecking the archive signature before extraction.",
            ))
        verify_tor_signature(
            archive, signature, progress_callback=progress_callback,
            cancel_event=cancel_event, version=version,
        )
        if progress_callback:
            progress_callback(BundleProgress(
                version, "verify", "signature_verified",
                message="The detached signature matches the pinned Tor signing key.",
            ))
        if cancel_event is not None and cancel_event.is_set():
            raise BundleVerificationError("Tor bundle installation was cancelled before extraction.")
        if progress_callback:
            progress_callback(BundleProgress(
                version, "install", "extracting_archive",
                message="Signature verified. Safely extracting into an isolated staging directory.",
            ))
        extracted = safe_extract_tar_gz(archive, staging)
        marker = extracted / ".torproxy-verified.json"
        marker_tmp = extracted / ".torproxy-verified.json.tmp"
        metadata = {
            "signature_verified": True,
            "signing_key_fingerprint": TOR_SIGNING_FINGERPRINT,
            "archive_sha256": sha256_file(archive),
            "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        with marker_tmp.open("x", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            marker_tmp.chmod(0o600)
        os.replace(marker_tmp, marker)
        # The final name becomes visible only after extraction and verification metadata exist.
        if destination.exists():
            raise BundleVerificationError(
                "Destination appeared during installation; refusing to overwrite: {}".format(destination)
            )
        os.replace(extracted, destination)
        return destination
    except Exception as exc:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        logger.error("Verified Tor extraction failed: %s", exc)
        raise
