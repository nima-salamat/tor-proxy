"""Verify a frozen package discovers and can execute its bundled Tor binary."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path, help="Frozen TorProxy executable in its package root.")
    args = parser.parse_args()
    app = args.executable.expanduser().resolve()
    if not app.is_file():
        parser.error(f"application executable not found: {app}")

    bundle_root = app.parent / "bundles"
    if not bundle_root.is_dir():
        print(f"Smoke test failed: packaged bundles directory is missing: {bundle_root}", file=sys.stderr)
        return 2

    # Exercise the same frozen-app branch and auto-selection path used at runtime.
    sys.frozen = True
    sys.executable = str(app)
    import tor
    import updater

    with tempfile.TemporaryDirectory(prefix="torproxy-package-smoke-") as temporary:
        user_bundle_root = Path(temporary) / "user-bundles"
        user_bundle_root.mkdir(parents=True)
        updater.BUNDLE_DIR = str(user_bundle_root)
        updater.resource_path = lambda _path: str(user_bundle_root)
        tor.BUNDLE_DIR = str(user_bundle_root)
        tor.resource_path = lambda _path: str(user_bundle_root)

        selected, selected_root = tor._find_executable(None)
        if selected is None or selected_root is None:
            print("Smoke test failed: no verified packaged Tor executable was auto-discovered.", file=sys.stderr)
            return 1
        expected_name = "tor.exe" if os.name == "nt" else "tor"
        expected = (selected_root / "tor" / expected_name).resolve()
        if selected.resolve() != expected or bundle_root.resolve() not in selected.parents:
            print(
                f"Smoke test failed: unexpected Tor executable selection: {selected}",
                file=sys.stderr,
            )
            return 1

        try:
            result = subprocess.run(
                [str(selected), "--version"],
                cwd=str(selected.parent),
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"Smoke test failed to run the bundled Tor executable: {exc}", file=sys.stderr)
            return 1
        if result.returncode != 0:
            print((result.stdout + result.stderr).strip(), file=sys.stderr)
            print(f"Smoke test failed: bundled Tor exited with code {result.returncode}.", file=sys.stderr)
            return 1
        version_line = next(
            (line.strip() for line in (result.stdout + result.stderr).splitlines() if "Tor version " in line),
            "Tor executable returned successfully.",
        )
        print(f"Smoke test passed: auto-selected packaged Tor ({version_line}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
