"""Fetch exactly one newest compatible, signed Tor Expert Bundle for a release build."""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import updater  # noqa: E402
from torproxy.bundle import BundleVerificationError  # noqa: E402
from utils import extract_tar_gz_file  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "release-bundle",
        help="Temporary build directory that will contain bundles/.",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    bundle_root = args.output_dir.expanduser().resolve() / "bundles"
    bundle_root.mkdir(parents=True, exist_ok=True)

    # Reuse the application's exact platform, version-priority, download,
    # OpenPGP pinning, and safe-extraction code. The output stays in the
    # disposable GitHub Actions workspace, never in a developer's user data.
    updater.BUNDLE_DIR = str(bundle_root)
    versions = updater.get_tor_versions(allow_direct=True)
    selected: tuple[str, str] | None = None

    for entry in versions:
        version = entry.rstrip("/")
        try:
            candidates = updater.get_bundle_links(
                version,
                require_signature=True,
                allow_direct=True,
            )
        except BundleVerificationError:
            # A listing/network failure means we cannot safely establish which
            # release is newest; do not silently fall back to an older version.
            raise
        if candidates:
            if len(candidates) != 1:
                raise BundleVerificationError(
                    f"Expected one exact platform bundle for Tor {version}, got {len(candidates)}."
                )
            selected = (version, candidates[0])
            break

    if selected is None:
        raise BundleVerificationError(
            "No stable/alpha release listed a signed Expert Bundle for this runner's OS and CPU."
        )

    version, filename = selected
    archive = updater.download_file(
        filename,
        version,
        verify_signature=True,
        allow_direct=True,
    )
    signature = archive.with_name(archive.name + ".asc")
    if not signature.is_file():
        raise BundleVerificationError("The downloaded Expert Bundle has no detached signature sidecar.")

    destination = bundle_root / filename.removesuffix(".tar.gz")
    if destination.exists():
        raise BundleVerificationError(f"Refusing to replace an existing build bundle: {destination}")

    extract_tar_gz_file(
        archive,
        destination,
        version=version,
        verify_signature=True,
        verification_method="openpgp",
        allow_direct=True,
    )
    if not updater.check_bundle_compatibility(str(destination)):
        raise BundleVerificationError(
            "The extracted Tor bundle failed the same integrity/platform checks used by the application."
        )

    print(f"Selected Tor release: {version}")
    print(f"Selected artifact: {filename}")
    print("Trust: detached OpenPGP signature verified with TorProxy's pinned Tor signing key.")
    print(f"Packaged directory: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
