"""Smoke-test the native Qt launcher UI in an offscreen platform session."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    executable = args.executable.expanduser().resolve()
    if not executable.is_file():
        print(f"Launcher smoke test failed: executable not found: {executable}", file=sys.stderr)
        return 2

    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment.setdefault("QT_LOGGING_RULES", "qt.qpa.*=false")

    try:
        result = subprocess.run(
            [str(executable), "--self-test"],
            cwd=str(executable.parent),
            env=environment,
            capture_output=True,
            text=True,
            timeout=max(3.0, args.timeout),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"Launcher smoke test could not complete: {exc}", file=sys.stderr)
        return 1

    if result.returncode != 0:
        details = "\n".join(part for part in (result.stdout, result.stderr) if part.strip())
        print(details or "(launcher returned no diagnostic output)", file=sys.stderr)
        print(f"Launcher smoke test failed with exit code {result.returncode}.", file=sys.stderr)
        return 1

    print(f"Launcher smoke test passed: {executable.name} created and displayed its splash UI.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
