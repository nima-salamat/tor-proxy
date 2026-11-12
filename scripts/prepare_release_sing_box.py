"""Download and verify the pinned sing-box engine for a portable release package."""
from __future__ import annotations

import argparse
import hashlib
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import requests

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from torproxy.system_tunnel import (  # noqa: E402
    MAX_ENGINE_ARCHIVE_BYTES,
    SING_BOX_LATEST_VERSION,
    SystemTunnelError,
    SystemTunnelManager,
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "release-sing-box",
        help="Directory that will contain the platform-specific pinned sing-box archive.",
    )
    args = parser.parse_args()

    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    directories = SimpleNamespace(
        data=output_dir / "temporary-data",
        state=output_dir / "temporary-state",
        logs=output_dir / "temporary-logs",
        config=output_dir / "temporary-config",
        cache=output_dir / "temporary-cache",
    )
    manager = SystemTunnelManager(directories=directories, version=SING_BOX_LATEST_VERSION)
    asset = manager.platform_asset
    destination = output_dir / (
        f"sing-box-{manager.version}-{platform.system().lower()}.archive"
    )
    if destination.exists():
        raise SystemTunnelError(f"Refusing to overwrite an existing release asset: {destination}")

    staged = output_dir / f".{destination.name}.download"
    session = requests.Session()
    session.trust_env = False
    total = 0
    digest = hashlib.sha256()
    try:
        with session.get(
            asset["url"],
            stream=True,
            timeout=(15, 45),
            headers={"User-Agent": "TorProxy-Release-Builder"},
        ) as response:
            response.raise_for_status()
            declared = response.headers.get("Content-Length")
            if declared and int(declared) > MAX_ENGINE_ARCHIVE_BYTES:
                raise SystemTunnelError("The official sing-box archive exceeds the configured size limit.")
            with staged.open("xb") as output:
                for chunk in response.iter_content(1024 * 1024):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > MAX_ENGINE_ARCHIVE_BYTES:
                        raise SystemTunnelError("The official sing-box archive exceeded the size limit.")
                    output.write(chunk)
                    digest.update(chunk)
                output.flush()
                os.fsync(output.fileno())

        actual_digest = digest.hexdigest()
        if actual_digest != asset["sha256"]:
            raise SystemTunnelError("The downloaded sing-box archive does not match its pinned SHA-256.")

        # Parse the archive using the same strict member allowlist as the runtime installer,
        # then execute the extracted binary before allowing it into a published package.
        with tempfile.TemporaryDirectory(prefix="torproxy-sing-box-release-") as temporary:
            extraction = Path(temporary) / "engine"
            extraction.mkdir()
            if asset["archive"] == "zip":
                files = manager._extract_zip_runtime(staged, extraction, asset["executable"])
            else:
                files = manager._extract_tar_runtime(staged, extraction, asset["executable"])
            executable = extraction / asset["executable"]
            if os.name != "nt":
                executable.chmod(0o700)
            result = subprocess.run(
                [str(executable), "version"],
                cwd=extraction,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15,
                check=False,
            )
            version_output = (result.stdout or "").strip()
            if result.returncode != 0 or manager.version not in version_output:
                raise SystemTunnelError(
                    "The official sing-box archive failed its executable version check: "
                    f"{version_output[:240]}"
                )

        os.replace(staged, destination)
        print(f"Platform: {platform.system()} / {platform.machine()}")
        print(f"Selected sing-box version: {manager.version}")
        print(f"Verified SHA-256: {actual_digest}")
        print(f"Verified runtime files: {', '.join(sorted(files))}")
        print(f"Packaged archive: {destination}")
        return 0
    finally:
        session.close()
        staged.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
