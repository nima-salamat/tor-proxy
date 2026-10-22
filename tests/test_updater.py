import pytest

import updater
from torproxy.bundle import BundleVerificationError


def test_missing_signature_fails_closed(tmp_path, monkeypatch):
    archive = tmp_path / "tor-expert-bundle-linux-x86_64-15.0.26.tar.gz"
    archive.write_bytes(b"unverified archive")
    monkeypatch.setattr(updater, "_platform_name", lambda: "linux")
    monkeypatch.setattr(updater, "_architecture_name", lambda: "x86_64")
    assert updater.check_hash(archive, go_online=False) is False


def test_unsigned_checksum_helpers_are_disabled():
    with pytest.raises(BundleVerificationError, match="Unsigned checksum"):
        updater.get_checksum("15.0.26")
    with pytest.raises(BundleVerificationError, match="Unsigned checksum"):
        updater.save_checksum(None, "15.0.26")
