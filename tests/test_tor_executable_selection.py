from __future__ import annotations

import os
from pathlib import Path



def _make_executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"test tor executable")
    if os.name != "nt":
        path.chmod(0o755)
    return path


def test_auto_discovery_ignores_unverified_managed_bundle(tmp_path, monkeypatch):
    import tor

    root = tmp_path / "bundles"
    executable = _make_executable(root / "tor-expert-bundle-linux-x86_64-15.0.26" / "tor" / "tor")
    monkeypatch.setattr(tor, "resource_path", lambda _path: str(root))
    monkeypatch.setattr(tor, "IS_WINDOWS", os.name == "nt")
    monkeypatch.setattr(tor, "_verified_managed_bundles", lambda _root: [])

    resolved, bundle_root = tor._find_executable(None)
    assert resolved is None
    assert bundle_root is None
    assert executable.is_file()


def test_configured_managed_bundle_must_be_verified(tmp_path, monkeypatch):
    import tor

    root = tmp_path / "bundles"
    bundle = root / "tor-expert-bundle-linux-x86_64-15.0.26"
    _make_executable(bundle / "tor" / ("tor.exe" if os.name == "nt" else "tor"))
    monkeypatch.setattr(tor, "resource_path", lambda _path: str(root))
    monkeypatch.setattr(tor, "IS_WINDOWS", os.name == "nt")
    monkeypatch.setattr(tor, "_verified_managed_bundles", lambda _root: [])

    executable, resolved_root = tor._find_executable(bundle)
    assert executable is None
    assert resolved_root == bundle


def test_configured_verified_managed_bundle_resolves_executable(tmp_path, monkeypatch):
    import tor

    root = tmp_path / "bundles"
    bundle = root / "tor-expert-bundle-linux-x86_64-15.0.26"
    executable_name = "tor.exe" if os.name == "nt" else "tor"
    executable = _make_executable(bundle / "tor" / executable_name)
    monkeypatch.setattr(tor, "resource_path", lambda _path: str(root))
    monkeypatch.setattr(tor, "IS_WINDOWS", os.name == "nt")
    monkeypatch.setattr(tor, "_verified_managed_bundles", lambda _root: [bundle.resolve()])

    resolved, resolved_root = tor._find_executable(bundle)
    assert resolved == executable.resolve()
    assert resolved_root == bundle.resolve()


def test_unverified_managed_executable_cannot_bypass_bundle_check(tmp_path, monkeypatch):
    import tor

    root = tmp_path / "bundles"
    executable = _make_executable(
        root / "tor-expert-bundle-linux-x86_64-15.0.26" / "tor" /
        ("tor.exe" if os.name == "nt" else "tor")
    )
    monkeypatch.setattr(tor, "resource_path", lambda _path: str(root))
    monkeypatch.setattr(tor, "IS_WINDOWS", os.name == "nt")
    monkeypatch.setattr(tor, "_verified_managed_bundles", lambda _root: [])

    resolved, bundle_root = tor._find_executable(executable)
    assert resolved is None
    assert bundle_root is not None


def test_frozen_app_auto_selects_verified_packaged_tor_bundle(tmp_path, monkeypatch):
    import hashlib
    import json
    import sys

    import updater
    import tor

    platform_name = updater._platform_name()
    architecture = updater._architecture_name()
    app_root = tmp_path / "portable"
    executable = app_root / ("TorProxy.exe" if platform_name == "windows" else "TorProxy")
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"frozen app")
    user_data = tmp_path / "user-data" / "bundles"
    user_data.mkdir(parents=True)

    bundle = app_root / "bundles" / (
        f"tor-expert-bundle-{platform_name}-{architecture}-16.0"
    )
    tor_executable = bundle / "tor" / ("tor.exe" if platform_name == "windows" else "tor")
    _make_executable(tor_executable)
    archive = bundle.with_name(bundle.name + ".tar.gz")
    archive.write_bytes(b"verified release archive")
    archive.with_name(archive.name + ".asc").write_text(
        "detached signature sidecar", encoding="utf-8"
    )
    marker = {
        "signature_verified": True,
        "verification_method": "openpgp",
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    }
    (bundle / ".torproxy-verified.json").write_text(
        json.dumps(marker), encoding="utf-8"
    )

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setattr(updater, "BUNDLE_DIR", str(user_data))
    monkeypatch.setattr(updater, "resource_path", lambda _path: str(user_data))
    monkeypatch.setattr(tor, "BUNDLE_DIR", str(user_data))
    monkeypatch.setattr(tor, "resource_path", lambda _path: str(user_data))

    resolved, resolved_root = tor._find_executable(None)

    assert resolved == tor_executable.resolve()
    assert resolved_root == bundle.resolve()


def test_packaged_bundle_discovery_is_disabled_for_source_runs(tmp_path, monkeypatch):
    import sys

    import updater

    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python.exe"))
    assert updater.get_packaged_bundles() == []
