"""Resource path helpers and verified Tor Expert Bundle extraction."""
from __future__ import annotations

import json
import logging
import os
import sys
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
):
    """Verify the exact archive again, report each stage, then safely extract and mark it."""
    archive = Path(filename).expanduser().resolve()
    destination = Path(dst).expanduser().resolve()
    signature = archive.with_name(archive.name + ".asc")
    try:
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
                message="Signature verified. Safely extracting into an atomic temporary directory.",
            ))
        extracted = safe_extract_tar_gz(archive, destination)
        marker = extracted / ".torproxy-verified.json"
        marker.write_text(json.dumps({
            "signature_verified": True,
            "signing_key_fingerprint": TOR_SIGNING_FINGERPRINT,
            "archive_sha256": sha256_file(archive),
            "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        }, indent=2) + "\n", encoding="utf-8")
        if os.name != "nt":
            marker.chmod(0o600)
        return extracted
    except Exception as exc:
        logger.error("Verified Tor extraction failed: %s", exc)
        raise
