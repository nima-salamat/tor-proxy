"""Smoke-test the native TorProxy launcher and its startup theme selection."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def run_case(
    executable: Path,
    environment: dict[str, str],
    timeout: float,
    arguments: list[str],
    label: str,
) -> bool:
    try:
        result = subprocess.run(
            [str(executable), *arguments],
            cwd=str(executable.parent),
            env=environment,
            capture_output=True,
            text=True,
            timeout=max(3.0, timeout),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"Launcher smoke test could not complete ({label}): {exc}", file=sys.stderr)
        return False

    if result.returncode != 0:
        details = "\n".join(part for part in (result.stdout, result.stderr) if part.strip())
        print(details or "(launcher returned no diagnostic output)", file=sys.stderr)
        print(
            f"Launcher smoke test failed for {label} with exit code {result.returncode}.",
            file=sys.stderr,
        )
        return False

    print(f"Launcher smoke test passed: {label}.")
    return True


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

    if os.name == "nt":
        # The native Win32 launcher reads the same per-user config file as the
        # Python application. Isolate APPDATA so the CI runner's own settings
        # cannot influence these checks. Opposite mode values verify that the
        # explicit preference, rather than the effective-mode cache, wins.
        cases = (
            ("dark preference", {"theme_preference": "dark", "mode": "light"}, "dark"),
            ("light preference", {"theme_preference": "light", "mode": "dark"}, "light"),
            ("legacy mode fallback", {"mode": "light"}, "light"),
        )
        with tempfile.TemporaryDirectory(prefix="torproxy-launcher-theme-") as temporary:
            for name, configuration, expected_theme in cases:
                app_data = Path(temporary) / name.replace(" ", "-")
                config_directory = app_data / "TorProxy"
                config_directory.mkdir(parents=True, exist_ok=True)
                (config_directory / "config.json").write_text(
                    json.dumps(configuration),
                    encoding="utf-8",
                )
                case_environment = environment.copy()
                case_environment["APPDATA"] = str(app_data)
                if not run_case(
                    executable,
                    case_environment,
                    args.timeout,
                    ["--self-test", f"--expect-theme={expected_theme}"],
                    name,
                ):
                    return 1
        return 0

    # Linux uses the Qt splash implementation, which reads the XDG config
    # directory. Keep the same preference/legacy cases as the native Windows
    # launcher so both front ends are checked against the application setting.
    cases = (
        ("dark preference", {"theme_preference": "dark", "mode": "light"}, "dark"),
        ("light preference", {"theme_preference": "light", "mode": "dark"}, "light"),
        ("legacy mode fallback", {"mode": "light"}, "light"),
    )
    with tempfile.TemporaryDirectory(prefix="torproxy-launcher-theme-") as temporary:
        for name, configuration, expected_theme in cases:
            config_root = Path(temporary) / name.replace(" ", "-")
            config_directory = config_root / "torproxy"
            config_directory.mkdir(parents=True, exist_ok=True)
            (config_directory / "config.json").write_text(
                json.dumps(configuration),
                encoding="utf-8",
            )
            case_environment = environment.copy()
            case_environment["XDG_CONFIG_HOME"] = str(config_root)
            if not run_case(
                executable,
                case_environment,
                args.timeout,
                ["--self-test", f"--expect-theme={expected_theme}"],
                name,
            ):
                return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
