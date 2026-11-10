from __future__ import annotations

import re
from pathlib import Path


def test_release_version_is_consistent_across_python_and_native_launcher():
    repository = Path(__file__).resolve().parents[1]
    expected = "1.1.0"

    pyproject = (repository / "pyproject.toml").read_text(encoding="utf-8")
    package_init = (repository / "src/torproxy/__init__.py").read_text(encoding="utf-8")
    cmake = (repository / "launcher/CMakeLists.txt").read_text(encoding="utf-8")
    splash = (repository / "launcher/src/splash_window.cpp").read_text(encoding="utf-8")

    assert re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE).group(1) == expected
    assert re.search(r'^__version__ = "([^"]+)"$', package_init, re.MULTILINE).group(1) == expected
    assert re.search(r'^project\\(TorProxyLauncher VERSION ([^ ]+) LANGUAGES CXX\\)$', cmake, re.MULTILINE).group(1) == expected
    assert re.search(r'^#define TORPROXY_VERSION "([^"]+)"$', splash, re.MULTILINE).group(1) == expected


def test_release_workflow_publishes_tagged_versions_after_both_builds():
    repository = Path(__file__).resolve().parents[1]
    workflow = (repository / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "if: startsWith(github.ref, 'refs/tags/v')" in workflow
    assert "tag_name: ${{ github.ref_name }}" in workflow
    assert "needs: build" in workflow
    assert "TorProxy-windows-x64.zip" in workflow
    assert "TorProxy-linux-x64.tar.gz" in workflow
