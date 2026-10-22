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
