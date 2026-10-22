from __future__ import annotations

import json
import os
import tarfile
from pathlib import Path

import pytest

from torproxy import bundle as bundle_module
from torproxy.bundle import BundleVerificationError
import utils


def _archive(path: Path) -> Path:
    payload = path.parent / "payload"
    payload.mkdir()
    tor_dir = payload / "tor"
    tor_dir.mkdir()
    executable = tor_dir / ("tor.exe" if os.name == "nt" else "tor")
    executable.write_bytes(b"verified tor test payload")
    if os.name != "nt":
        executable.chmod(0o755)
    with tarfile.open(path, "w:gz") as tar:
        tar.add(tor_dir, arcname="tor")
    payload_dir = payload
    import shutil
    shutil.rmtree(payload_dir)
    path.with_name(path.name + ".asc").write_bytes(b"mock signature sidecar")
    return path


def test_bundle_install_publishes_marker_and_directory_together(tmp_path, monkeypatch):
    archive = _archive(tmp_path / "tor-expert-bundle-test.tar.gz")
    destination = tmp_path / "tor-expert-bundle-test"
    monkeypatch.setattr(utils, "verify_tor_signature", lambda *_args, **_kwargs: None)

    events = []
    installed = utils.extract_tar_gz_file(
        archive, destination, progress_callback=events.append, version="16.0a14"
    )

    assert installed == destination
    marker = json.loads((destination / ".torproxy-verified.json").read_text(encoding="utf-8"))
    assert marker["signature_verified"] is True
    assert marker["signing_key_fingerprint"] == bundle_module.TOR_SIGNING_FINGERPRINT
    assert marker["archive_sha256"] == bundle_module.sha256_file(archive)
    assert (destination / "tor" / ("tor.exe" if os.name == "nt" else "tor")).is_file()
    assert events[0].stage == "verifying_signature"
    assert events[-1].stage == "extracting_archive"
    assert not list(tmp_path.glob(".tor-expert-bundle-test.verified-*"))


def test_install_failure_cleans_staging_and_does_not_publish(tmp_path, monkeypatch):
    archive = _archive(tmp_path / "tor-expert-bundle-test.tar.gz")
    destination = tmp_path / "tor-expert-bundle-test"
    monkeypatch.setattr(utils, "verify_tor_signature", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        utils, "sha256_file",
        lambda _path: (_ for _ in ()).throw(OSError("injected digest failure")),
    )

    with pytest.raises(OSError, match="injected digest failure"):
        utils.extract_tar_gz_file(archive, destination)

    assert not destination.exists()
    assert not list(tmp_path.glob(".tor-expert-bundle-test.verified-*"))


def test_install_does_not_overwrite_existing_destination(tmp_path, monkeypatch):
    archive = _archive(tmp_path / "tor-expert-bundle-test.tar.gz")
    destination = tmp_path / "tor-expert-bundle-test"
    destination.mkdir()
    (destination / "keep.txt").write_text("preserve", encoding="utf-8")
    monkeypatch.setattr(
        utils, "verify_tor_signature",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must reject existing target first")),
    )

    with pytest.raises(BundleVerificationError, match="already exists"):
        utils.extract_tar_gz_file(archive, destination)

    assert (destination / "keep.txt").read_text(encoding="utf-8") == "preserve"


def test_install_can_explicitly_skip_openpgp_and_records_that_choice(tmp_path, monkeypatch):
    archive = _archive(tmp_path / "tor-expert-bundle-test.tar.gz")
    archive.with_name(archive.name + ".asc").unlink()
    destination = tmp_path / "tor-expert-bundle-test"
    monkeypatch.setattr(
        utils, "verify_tor_signature",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("OpenPGP should be skipped")),
    )

    events = []
    installed = utils.extract_tar_gz_file(
        archive, destination, progress_callback=events.append,
        version="16.0a14", verify_signature=False,
    )

    marker = json.loads((installed / ".torproxy-verified.json").read_text(encoding="utf-8"))
    assert marker["signature_verified"] is False
    assert marker["verification_method"] == "https_only"
    assert marker["signing_key_fingerprint"] is None
    assert marker["archive_sha256"] == bundle_module.sha256_file(archive)
    assert events[0].stage == "signature_verification_skipped"
    assert events[-1].stage == "extracting_archive"
