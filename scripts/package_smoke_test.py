"""Launch a frozen desktop build offscreen and ensure initialization survives."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _read_log(handle) -> str:
    handle.flush()
    handle.seek(0)
    return handle.read().decode("utf-8", errors="replace").strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    executable = args.executable.expanduser().resolve()
    if not executable.is_file():
        print(f"Smoke test failed: executable not found: {executable}", file=sys.stderr)
        return 2

    env = os.environ.copy()
    env["QT_QPA_PLATFORM"] = "offscreen"
    env.setdefault("QT_LOGGING_RULES", "qt.qpa.*=false")

    with tempfile.TemporaryFile() as output:
        try:
            process = subprocess.Popen(
                [str(executable)],
                cwd=str(executable.parent),
                env=env,
                stdout=output,
                stderr=subprocess.STDOUT,
            )
        except OSError as exc:
            print(f"Smoke test failed to launch {executable}: {exc}", file=sys.stderr)
            return 2

        try:
            deadline = time.monotonic() + max(2.0, args.timeout)
            while time.monotonic() < deadline:
                return_code = process.poll()
                if return_code is not None:
                    details = _read_log(output)
                    print(details or "(the app produced no stdout/stderr)", file=sys.stderr)
                    print(
                        f"Smoke test failed: process exited early with code {return_code}.",
                        file=sys.stderr,
                    )
                    return 1
                time.sleep(0.2)

            print(f"Smoke test passed: {executable.name} remained alive for {args.timeout:.1f}s.")
            return 0
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
