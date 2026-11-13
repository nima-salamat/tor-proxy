from __future__ import annotations

import os
from pathlib import Path

import pytest



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



def test_verified_bundle_inventory_lists_compatible_versions_and_prefers_user_copy(monkeypatch, tmp_path):
    import updater

    user_stable = tmp_path / "user" / "tor-expert-bundle-windows-x86_64-16.0"
    user_alpha = tmp_path / "user" / "tor-expert-bundle-windows-x86_64-16.0a14"
    packaged_stable = tmp_path / "app" / "bundles" / "tor-expert-bundle-windows-x86_64-16.0"
    packaged_older = tmp_path / "app" / "bundles" / "tor-expert-bundle-windows-x86_64-15.0.26"
    monkeypatch.setattr(
        updater, "get_own_bundles", lambda: [str(user_stable), str(user_alpha)]
    )
    monkeypatch.setattr(
        updater, "get_packaged_bundles", lambda: [str(packaged_stable), str(packaged_older)]
    )

    inventory = updater.get_verified_bundle_inventory()
    by_version = {item["version"]: item for item in inventory}

    assert set(by_version) == {"16.0", "16.0a14", "15.0.26"}
    assert by_version["16.0"]["path"] == str(user_stable.resolve())
    assert by_version["16.0"]["source"] == "user"
    assert by_version["15.0.26"]["source"] == "packaged"


def test_resolve_verified_bundle_rechecks_selected_install_and_executable_layout(monkeypatch, tmp_path):
    import tor
    import updater

    bundle = tmp_path / "tor-expert-bundle-windows-x86_64-16.0"
    executable = bundle / "tor" / "tor.exe"
    monkeypatch.setattr(
        updater,
        "get_verified_bundle_inventory",
        lambda: [{"version": "16.0", "path": str(bundle), "source": "user"}],
    )
    monkeypatch.setattr(updater, "check_bundle_compatibility", lambda _path: True)
    monkeypatch.setattr(tor, "_find_executable", lambda _path: (executable, bundle))

    resolved_executable, resolved_root = updater.resolve_verified_bundle("16.0")

    assert resolved_executable == executable.resolve()
    assert resolved_root == bundle.resolve()


def test_resolve_verified_bundle_rejects_missing_or_untrusted_version(monkeypatch):
    import updater
    from torproxy.bundle import BundleVerificationError

    monkeypatch.setattr(updater, "get_verified_bundle_inventory", lambda: [])

    with pytest.raises(BundleVerificationError, match="not installed"):
        updater.resolve_verified_bundle("99.0")



def test_fast_bundle_discovery_defers_only_the_archive_digest(tmp_path, monkeypatch):
    import hashlib
    import json

    import updater

    platform_name = updater._platform_name()
    architecture = updater._architecture_name()
    root = tmp_path / "bundles"
    bundle = root / f"tor-expert-bundle-{platform_name}-{architecture}-16.0"
    _make_executable(
        bundle / "tor" / ("tor.exe" if platform_name == "windows" else "tor")
    )
    archive = bundle.with_name(bundle.name + ".tar.gz")
    archive.write_bytes(b"archive contents do not match the saved digest")
    marker = {
        "signature_verified": False,
        "verification_method": "https_only",
        "archive_sha256": hashlib.sha256(b"original archive contents").hexdigest(),
    }
    (bundle / ".torproxy-verified.json").write_text(json.dumps(marker), encoding="utf-8")

    monkeypatch.setattr(updater, "BUNDLE_DIR", str(root))
    monkeypatch.setattr(updater, "resource_path", lambda _path: str(root))
    hash_calls = []
    real_hash = updater.sha256_file

    def recording_hash(path):
        hash_calls.append(Path(path))
        return real_hash(path)

    monkeypatch.setattr(updater, "sha256_file", recording_hash)

    assert updater.get_own_bundles(verify=False) == [str(bundle)]
    assert hash_calls == []
    # Strict discovery still rejects a mismatched archive digest.
    assert updater.get_own_bundles() == []
    assert hash_calls == [archive]
