from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from torproxy import bundle as bundle_module
from torproxy.bundle import BundleVerificationError


FINGERPRINT = bundle_module.TOR_SIGNING_FINGERPRINT
OTHER_FINGERPRINT = "0123456789ABCDEF0123456789ABCDEF01234567"


def _verification_files(tmp_path: Path, archive_bytes: bytes = b"trusted archive"):
    archive = tmp_path / "tor-expert-bundle-windows-x86_64-16.0a14.tar.gz"
    signature = archive.with_name(archive.name + ".asc")
    archive.write_bytes(archive_bytes)
    signature.write_bytes(b"mock detached signature")
    return archive, signature


def _configure_gpg_mocks(monkeypatch, tmp_path, *, key_fingerprint=FINGERPRINT, signature_fingerprint=FINGERPRINT,
                         signature_valid=True, timeout=False, import_ok=True, archive_bytes=b"trusted archive"):
    archive, signature = _verification_files(tmp_path, archive_bytes)
    monkeypatch.setattr(bundle_module, "_find_gpg_executable", lambda: Path("mock-gpg.exe"))

    def download_key(_url, destination, _allowed_hosts, **_kwargs):
        Path(destination).write_bytes(b"mock public key")

    monkeypatch.setattr(bundle_module, "_download", download_key)

    def run(command, **_kwargs):
        if "--import" in command:
            return SimpleNamespace(returncode=0 if import_ok else 2, stdout="", stderr="")
        if "--list-keys" in command:
            listing = f"fpr:::::::::{key_fingerprint}:\n"
            return SimpleNamespace(returncode=0, stdout=listing, stderr="")
        if "--verify" in command:
            if timeout:
                raise subprocess.TimeoutExpired(command, timeout=30)
            actual_archive = Path(command[-1]).read_bytes()
            valid = signature_valid and actual_archive == archive_bytes
            status = (
                f"[GNUPG:] VALIDSIG {signature_fingerprint} 2026-10-14 1791936000 0 4 0 1 10 00\n"
                if valid else "[GNUPG:] BADSIG 1234 invalid\n"
            )
            return SimpleNamespace(returncode=0 if valid else 1, stdout=status, stderr="")
        raise AssertionError(f"Unexpected GnuPG call: {command}")

    monkeypatch.setattr(bundle_module.subprocess, "run", run)
    return archive, signature


def test_gpg_runtime_unavailable_fails_closed(tmp_path, monkeypatch):
    archive, signature = _verification_files(tmp_path)
    monkeypatch.setattr(
        bundle_module, "_find_gpg_executable",
        lambda: (_ for _ in ()).throw(BundleVerificationError("GnuPG could not be found")),
    )
    with pytest.raises(BundleVerificationError, match="GnuPG could not be found"):
        bundle_module.verify_tor_signature(archive, signature)


def test_configured_gpg_executable_is_discovered_and_smoke_tested(tmp_path, monkeypatch):
    candidate = tmp_path / ("gpg.exe" if os.name == "nt" else "gpg")
    candidate.write_bytes(b"test stub")
    monkeypatch.setenv("TORPROXY_GPG_EXECUTABLE", str(candidate))
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    monkeypatch.setattr(
        bundle_module.subprocess, "run",
        lambda command, **_kwargs: SimpleNamespace(
            returncode=0, stdout="gpg (GnuPG) 2.4.5", stderr=""
        ),
    )
    assert bundle_module._find_gpg_executable() == candidate.resolve()


def test_valid_detached_signature_requires_pinned_key_and_validsig(tmp_path, monkeypatch):
    archive, signature = _configure_gpg_mocks(monkeypatch, tmp_path)
    assert bundle_module.verify_tor_signature(archive, signature) is None


def test_downloaded_key_with_another_fingerprint_is_rejected(tmp_path, monkeypatch):
    archive, signature = _configure_gpg_mocks(
        monkeypatch, tmp_path, key_fingerprint=OTHER_FINGERPRINT
    )
    with pytest.raises(BundleVerificationError, match="does not match"):
        bundle_module.verify_tor_signature(archive, signature)


def test_signature_from_unexpected_signer_is_rejected(tmp_path, monkeypatch):
    archive, signature = _configure_gpg_mocks(
        monkeypatch, tmp_path, signature_fingerprint=OTHER_FINGERPRINT
    )
    with pytest.raises(BundleVerificationError, match="pinned Tor signing key"):
        bundle_module.verify_tor_signature(archive, signature)


def test_invalid_signature_is_rejected(tmp_path, monkeypatch):
    archive, signature = _configure_gpg_mocks(
        monkeypatch, tmp_path, signature_valid=False
    )
    with pytest.raises(BundleVerificationError, match="missing or invalid"):
        bundle_module.verify_tor_signature(archive, signature)


def test_modified_archive_fails_signature_verification(tmp_path, monkeypatch):
    archive, signature = _configure_gpg_mocks(monkeypatch, tmp_path)
    archive.write_bytes(b"modified after signing")
    with pytest.raises(BundleVerificationError, match="missing or invalid"):
        bundle_module.verify_tor_signature(archive, signature)


def test_gpg_timeout_fails_closed(tmp_path, monkeypatch):
    archive, signature = _configure_gpg_mocks(monkeypatch, tmp_path, timeout=True)
    with pytest.raises(BundleVerificationError, match="timed out"):
        bundle_module.verify_tor_signature(archive, signature)


def test_gpg_import_failure_is_not_reported_as_signature_success(tmp_path, monkeypatch):
    archive, signature = _configure_gpg_mocks(monkeypatch, tmp_path, import_ok=False)
    with pytest.raises(BundleVerificationError, match="could not be imported"):
        bundle_module.verify_tor_signature(archive, signature)


def test_unsupported_signature_packets_fail_without_validsig(tmp_path, monkeypatch):
    archive, signature = _configure_gpg_mocks(monkeypatch, tmp_path, signature_valid=False)
    with pytest.raises(BundleVerificationError, match="missing or invalid"):
        bundle_module.verify_tor_signature(archive, signature)

def test_missing_gpg_is_detected_before_downloading_bundle(monkeypatch, tmp_path):
    def missing_runtime():
        raise BundleVerificationError("GnuPG could not be found")

    def unexpected_request(*_args, **_kwargs):
        raise AssertionError("the large Tor archive must not be downloaded without a verifier")

    monkeypatch.setattr(bundle_module, "_find_gpg_executable", missing_runtime)
    monkeypatch.setattr(bundle_module.requests, "get", unexpected_request)
    events = []

    with pytest.raises(BundleVerificationError, match="GnuPG could not be found"):
        bundle_module.download_verified_bundle(
            "16.0a14", "windows", "x86_64", tmp_path / "tor-expert-bundle-windows-x86_64-16.0a14.tar.gz",
            progress_callback=events.append,
        )

    assert events[0].stage == "checking_verification_runtime"
    assert not list(tmp_path.glob("*.tar.gz"))

