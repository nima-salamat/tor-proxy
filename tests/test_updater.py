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



def test_unsigned_cached_archive_is_not_reused(monkeypatch, tmp_path):
    archive = tmp_path / "tor-expert-bundle-linux-x86_64-15.0.26.tar.gz"
    archive.write_bytes(b"old cached archive")
    calls = []

    monkeypatch.setattr(updater, "BUNDLE_DIR", str(tmp_path))
    monkeypatch.setattr(updater, "resource_path", lambda value: value)
    monkeypatch.setattr(updater, "_platform_name", lambda: "linux")
    monkeypatch.setattr(updater, "_architecture_name", lambda: "x86_64")

    def fresh_download(*args, **kwargs):
        calls.append((args, kwargs))
        archive.write_bytes(b"fresh network archive")
        return archive

    monkeypatch.setattr(updater, "download_verified_bundle", fresh_download)
    result = updater.download_file(
        archive.name, "15.0.26", verify_signature=False, allow_direct=True
    )
    assert result == archive
    assert len(calls) == 1
    assert archive.read_bytes() == b"fresh network archive"



def test_check_hash_uses_the_supplied_tor_route_for_signature_and_key(monkeypatch, tmp_path):
    import updater

    archive = tmp_path / "tor-expert-bundle-linux-x86_64-15.0.26.tar.gz"
    archive.write_bytes(b"archive")
    route_calls = []
    verify_calls = []

    class Response:
        status_code = 200
        url = "https://dist.torproject.org/torbrowser/15.0.26/" + archive.name + ".asc"
        content = b"detached signature"

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def raise_for_status(self):
            return None

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get(self, *_args, **_kwargs):
            return Response()

    def factory(proxy_url, *, allow_direct):
        route_calls.append((proxy_url, allow_direct))
        return Session()

    def verify(path, signature, **kwargs):
        verify_calls.append((path, signature, kwargs))

    monkeypatch.setattr(updater, "create_session", factory)
    monkeypatch.setattr(updater, "_platform_name", lambda: "linux")
    monkeypatch.setattr(updater, "_architecture_name", lambda: "x86_64")
    monkeypatch.setattr(updater, "verify_tor_signature", verify)

    proxy = "socks5h://127.0.0.1:19050"
    assert updater.check_hash(archive, go_online=True, proxy_url=proxy)
    assert route_calls == [(proxy, False)]
    assert verify_calls[0][2]["proxy_url"] == proxy
    assert verify_calls[0][2]["allow_direct"] is False
    assert archive.with_name(archive.name + ".asc").read_bytes() == b"detached signature"
