from __future__ import annotations

import re
from pathlib import Path


def test_release_version_is_consistent_across_python_and_native_launchers():
    repository = Path(__file__).resolve().parents[1]
    expected = "1.6.0"

    pyproject = (repository / "pyproject.toml").read_text(encoding="utf-8")
    package_init = (repository / "src/torproxy/__init__.py").read_text(encoding="utf-8")
    cmake = (repository / "launcher/CMakeLists.txt").read_text(encoding="utf-8")
    splash = (repository / "launcher/src/splash_window.cpp").read_text(encoding="utf-8")
    light_installer = (repository / "packaging/torproxy.iss").read_text(encoding="utf-8")
    full_installer = (repository / "packaging/torproxy-full.iss").read_text(encoding="utf-8")

    assert re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE).group(1) == expected
    assert re.search(r'^__version__ = "([^"]+)"$', package_init, re.MULTILINE).group(1) == expected
    assert f"project(TorProxyLauncher VERSION {expected} LANGUAGES CXX)" in cmake
    assert re.search(r'^#define TORPROXY_VERSION "([^"]+)"$', splash, re.MULTILINE).group(1) == expected

    assert re.search(r'^\s*#define AppVersion "([^"]+)"$', light_installer, re.MULTILINE).group(1) == expected
    assert 'Source: "..\\dist\\TorProxy\\*"' in light_installer
    assert '"{app}\\TorProxyLauncher.exe"' in light_installer

    assert re.search(r'^\s*#define AppVersion "([^"]+)"$', full_installer, re.MULTILINE).group(1) == expected
    assert "TorProxy-Full-Setup-windows-x64" in full_installer
    assert 'Source: "..\\dist\\TorProxy-Full\\*"' in full_installer
    assert '"{app}\\bundles' not in full_installer


def test_release_workflow_builds_and_preserves_complete_windows_installer():
    repository = Path(__file__).resolve().parents[1]
    workflow = (repository / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "Build and smoke-test complete Windows installer" in workflow
    assert "packaging/torproxy-full.iss" in workflow
    assert "TorProxy-Full-Setup-windows-x64.exe" in workflow
    assert "torproxy-full-installer-windows" in workflow
    assert "python scripts/package_bundle_smoke_test.py (Join-Path $fullInstallRoot" in workflow
    assert "if ($LASTEXITCODE -ne 0) { throw " in workflow

    assert "prepare_release_bundle.py --output-dir release-bundle" in workflow
    assert "prepare_release_sing_box.py --output-dir release-sing-box" in workflow
    assert 'Copy-Item -Path "release-sing-box/*" -Destination $singBoxDestination' in workflow
    assert 'cp -a release-sing-box/. "$stage_root/TorProxy/bundles/sing-box/"' in workflow

    # The follow-up release upload must not replace any previously published
    # ZIP, the lightweight installer, or the original checksum manifest.
    asset_block = workflow.split("          files: |", 1)[1].split("          generate_release_notes:", 1)[0]
    assert "TorProxy-Full-Setup-windows-x64.exe" in asset_block
    assert "SHA256-TorProxy-Full-Setup.txt" in asset_block
    assert "cat SHA256-TorProxy-Full-Setup.txt" in workflow
    assert "TorProxy-windows-x64.zip" not in asset_block
    assert "TorProxy-Setup-windows-x64.exe" not in asset_block
    assert "SHA256SUMS.txt" not in asset_block
