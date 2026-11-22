from __future__ import annotations

import re
from pathlib import Path


def test_release_version_is_consistent_across_python_and_native_launcher():
    repository = Path(__file__).resolve().parents[1]
    expected = "1.6.0"

    pyproject = (repository / "pyproject.toml").read_text(encoding="utf-8")
    package_init = (repository / "src/torproxy/__init__.py").read_text(encoding="utf-8")
    cmake = (repository / "launcher/CMakeLists.txt").read_text(encoding="utf-8")
    splash = (repository / "launcher/src/splash_window.cpp").read_text(encoding="utf-8")
    installer = (repository / "packaging/torproxy.iss").read_text(encoding="utf-8")
    full_installer = (repository / "packaging/torproxy-full.iss").read_text(encoding="utf-8")

    assert re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE).group(1) == expected
    assert re.search(r'^__version__ = "([^"]+)"$', package_init, re.MULTILINE).group(1) == expected
    assert f"project(TorProxyLauncher VERSION {expected} LANGUAGES CXX)" in cmake
    assert re.search(r'^#define TORPROXY_VERSION "([^"]+)"$', splash, re.MULTILINE).group(1) == expected
    assert re.search(r'^\s*#define AppVersion "([^"]+)"$', installer, re.MULTILINE).group(1) == expected
    assert 'Source: "..\\dist\\TorProxy\\*"' in installer
    assert '"{app}\\TorProxyLauncher.exe"' in installer
    assert re.search(r'^#define AppVersion "([^"]+)"


def test_release_workflow_publishes_tagged_versions_after_both_builds():
    repository = Path(__file__).resolve().parents[1]
    workflow = (repository / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "if: startsWith(github.ref, 'refs/tags/v')" in workflow
    assert "startsWith(github.event.head_commit.message, 'Publish TorProxy v')" in workflow
    assert "endsWith(github.event.head_commit.message, 'to GitHub Releases')" in workflow
    assert "steps.release_version.outputs.tag" in workflow
    assert "needs: build" in workflow
    assert "TorProxy-windows-x64.zip" in workflow
    assert "TorProxy-Setup-windows-x64.exe" in workflow
    assert "TorProxy-Full-Setup-windows-x64.exe" in workflow
    assert "Build and smoke-test complete Windows installer" in workflow
    assert "torproxy-full-installer-windows" in workflow
    assert "ISCC.exe" in workflow
    assert "TorProxy-linux-x64.tar.gz" in workflow
    assert "prepare_release_sing_box.py --output-dir release-sing-box" in workflow
    assert 'Copy-Item -Path "release-sing-box/*" -Destination $singBoxDestination' in workflow
    assert 'cp -a release-sing-box/. "$stage_root/TorProxy/bundles/sing-box/"' in workflow
    assert "package_bundle_smoke_test.py" in workflow
, full_installer, re.MULTILINE).group(1) == expected
    assert "TorProxy-Full-Setup-windows-x64" in full_installer
    assert 'Source: "..\\dist\\TorProxy-Full\\*"' in full_installer
    assert '"{app}\\bundles"' not in full_installer


def test_release_workflow_publishes_tagged_versions_after_both_builds():
    repository = Path(__file__).resolve().parents[1]
    workflow = (repository / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "if: startsWith(github.ref, 'refs/tags/v')" in workflow
    assert "startsWith(github.event.head_commit.message, 'Publish TorProxy v')" in workflow
    assert "endsWith(github.event.head_commit.message, 'to GitHub Releases')" in workflow
    assert "steps.release_version.outputs.tag" in workflow
    assert "needs: build" in workflow
    assert "TorProxy-windows-x64.zip" in workflow
    assert "TorProxy-Setup-windows-x64.exe" in workflow
    assert "ISCC.exe" in workflow
    assert "TorProxy-linux-x64.tar.gz" in workflow
    assert "prepare_release_sing_box.py --output-dir release-sing-box" in workflow
    assert 'Copy-Item -Path "release-sing-box/*" -Destination $singBoxDestination' in workflow
    assert 'cp -a release-sing-box/. "$stage_root/TorProxy/bundles/sing-box/"' in workflow
    assert "package_bundle_smoke_test.py" in workflow
