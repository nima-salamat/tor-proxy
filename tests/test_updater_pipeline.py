from __future__ import annotations

import os
from pathlib import Path
from threading import Event

import pytest
import requests
from bs4 import BeautifulSoup

import updater
from torproxy import bundle as bundle_module
from torproxy.bundle import BundleProgress, BundleVerificationError


def _listing(*names: str) -> BeautifulSoup:
    links = "".join(f'<a href="{name}">{name}</a>' for name in names)
    return BeautifulSoup(f"<html><body>{links}</body></html>", "html.parser")


def test_version_parser_recognizes_stable_and_alpha():
    assert updater.parse_tor_version("15.0.26") == (15, 0, 26, "stable", 0)
    assert updater.parse_tor_version("16.0a14") == (16, 0, 0, "alpha", 14)
    assert updater.tor_version_channel("16.0a14").startswith("Alpha")


@pytest.mark.parametrize("name", [
    "", "latest", "15.0", "16.0b3", "../16.0a14", "15.0.20/evil",
    "15.0.26.tar.gz", "16.0a", "016.0a14",
])
def test_version_parser_rejects_unrecognized_names(name):
    with pytest.raises(ValueError):
        updater.parse_tor_version(name)


def test_release_sorting_is_numeric_and_stables_are_prioritized():
    versions = ["15.0.9", "15.0.25", "15.0.26", "16.0a14", "15.0.20"]
    assert sorted(versions, key=updater.tor_version_sort_key, reverse=True) == [
        "15.0.26", "15.0.25", "15.0.20", "15.0.9", "16.0a14"
    ]


@pytest.mark.parametrize(("filename", "expected"), [
    ("tor-expert-bundle-windows-x86_64-16.0a14.tar.gz", "16.0a14"),
    ("tor-expert-bundle-linux-x86_64-15.0.26.tar.gz", "15.0.26"),
])
def test_version_extraction_from_bundle_name(filename, expected):
    assert updater.get_version_by_bundle(filename) == expected
    assert updater.get_version_by_bundle(filename, with_slash=True) == expected + "/"


def test_version_extraction_rejects_wrong_artifact():
    with pytest.raises(ValueError):
        updater.get_version_by_bundle("tor-browser-windows-x86_64-16.0a14.tar.gz")


def test_release_directory_discovery_includes_alpha_and_does_not_truncate(monkeypatch):
    monkeypatch.setattr(
        updater, "_fetch_listing",
        lambda _url, *_args, **_kwargs: _listing("15.0.20/", "15.0.25/", "15.0.26/", "16.0a14/",
                              "not-a-version/", "../", "tor-browser-16.0a14.exe"),
    )
    assert updater.get_tor_versions() == [
        "15.0.26/", "15.0.25/", "15.0.20/", "16.0a14/"
    ]


def test_bundle_discovery_requires_exact_archive_and_sidecar(monkeypatch):
    expected = "tor-expert-bundle-windows-x86_64-16.0a14.tar.gz"
    monkeypatch.setattr(updater, "_platform_name", lambda: "windows")
    monkeypatch.setattr(updater, "_architecture_name", lambda: "x86_64")
    monkeypatch.setattr(updater, "_fetch_listing", lambda _url, *_args, **_kwargs: _listing(expected, expected + ".asc"))
    assert updater.get_bundle_links("16.0a14") == [expected]

    monkeypatch.setattr(updater, "_fetch_listing", lambda _url, *_args, **_kwargs: _listing(expected))
    assert updater.get_bundle_links("16.0a14") == []
    assert updater.get_bundle_links("16.0a14", require_signature=False) == [expected]


def test_bundle_discovery_ignores_browser_updates_and_other_archives(monkeypatch):
    expected = "tor-expert-bundle-windows-x86_64-15.0.20.tar.gz"
    monkeypatch.setattr(updater, "_platform_name", lambda: "windows")
    monkeypatch.setattr(updater, "_architecture_name", lambda: "x86_64")
    monkeypatch.setattr(
        updater, "_fetch_listing",
        lambda _url, *_args, **_kwargs: _listing(
            "tor-browser-windows-x86_64-15.0.20.exe",
            "tor-expert-bundle-windows-i686-15.0.20.tar.gz",
            "tor-expert-bundle-windows-x86_64-15.0.20.tar.gz.mar",
            expected + ".asc",
        ),
    )
    assert updater.get_bundle_links("15.0.20") == []


class _FakeResponse:
    def __init__(self, chunks, *, length=None, status=200, url="https://dist.torproject.org/test"):
        self._chunks = chunks
        self.status_code = status
        self.url = url
        self.headers = {} if length is None else {"Content-Length": str(length)}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size):
        yield from self._chunks


class _FakeSession:
    def __init__(self, response):
        self.response = response

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def get(self, *_args, **_kwargs):
        return self.response


def _patch_bundle_session(monkeypatch, response):
    monkeypatch.setattr(
        bundle_module, "create_session",
        lambda *_args, **_kwargs: _FakeSession(response),
    )


def test_stream_download_reports_known_size_without_false_unknown(monkeypatch, tmp_path):
    events: list[BundleProgress] = []
    _patch_bundle_session(monkeypatch, _FakeResponse([b"abc"], length=3))
    destination = tmp_path / "bundle.tar.gz"
    bundle_module._download(
        "https://dist.torproject.org/test", destination, {"dist.torproject.org"},
        version="15.0.26", progress_callback=events.append, allow_direct=True,
    )
    assert destination.read_bytes() == b"abc"
    assert events[0].total_bytes == 3
    assert events[-1].bytes_received == 3
    assert events[-1].percentage == 100


def test_stream_download_uses_indeterminate_progress_without_content_length(monkeypatch, tmp_path):
    events: list[BundleProgress] = []
    _patch_bundle_session(monkeypatch, _FakeResponse([b"", b"abcd"]))
    bundle_module._download(
        "https://dist.torproject.org/test", tmp_path / "bundle.tar.gz",
        {"dist.torproject.org"}, progress_callback=events.append, allow_direct=True,
    )
    assert events[0].total_bytes is None
    assert events[-1].total_bytes is None
    assert events[-1].percentage is None
    assert events[-1].bytes_received == 4


def test_stream_download_fails_on_http_error(monkeypatch, tmp_path):
    _patch_bundle_session(monkeypatch, _FakeResponse([], status=503))
    with pytest.raises(BundleVerificationError, match="Download failed"):
        bundle_module._download(
            "https://dist.torproject.org/test", tmp_path / "bundle.tar.gz",
            {"dist.torproject.org"}, allow_direct=True,
        )


def test_stream_download_observes_cancellation_before_network(monkeypatch, tmp_path):
    cancelled = Event()
    cancelled.set()

    def unexpected_request(*_args, **_kwargs):
        raise AssertionError("network should not be started when cancellation is already requested")

    monkeypatch.setattr(bundle_module, "create_session", unexpected_request)
    with pytest.raises(BundleVerificationError, match="cancelled"):
        bundle_module._download(
            "https://dist.torproject.org/test", tmp_path / "bundle.tar.gz",
            {"dist.torproject.org"}, cancel_event=cancelled, allow_direct=True,
        )


def test_download_verified_bundle_requires_supported_channel_and_platform(tmp_path):
    with pytest.raises(BundleVerificationError, match="Unsupported Tor release"):
        bundle_module.download_verified_bundle("latest", "windows", "x86_64", tmp_path / "x.tar.gz")
    with pytest.raises(BundleVerificationError, match="supports only"):
        bundle_module.download_verified_bundle("16.0a14", "macos", "arm64", tmp_path / "x.tar.gz")


def test_cancelled_or_unsigned_archive_is_not_reported_as_installed():
    # A missing detached signature must fail before invoking GnuPG.
    with pytest.raises(BundleVerificationError, match="missing"):
        bundle_module.verify_tor_signature("/no/such/archive.tar.gz", "/no/such/archive.tar.gz.asc")

def test_stream_download_rejects_mismatched_content_length(monkeypatch, tmp_path):
    _patch_bundle_session(monkeypatch, _FakeResponse([b"short"], length=99))
    with pytest.raises(BundleVerificationError, match="declared Content-Length"):
        bundle_module._download(
            "https://dist.torproject.org/test", tmp_path / "bundle.tar.gz",
            {"dist.torproject.org"}, allow_direct=True,
        )

@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("TORPROXY_ONLINE_SIGNATURE_TEST") != "1",
    reason="set TORPROXY_ONLINE_SIGNATURE_TEST=1 to download and verify a real official bundle",
)
def test_live_official_expert_bundle_download_and_signature(tmp_path):
    """Opt-in integration test: download a recent compatible release and verify its real .asc."""
    versions = updater.get_tor_versions(allow_direct=True)
    stable = [version.rstrip("/") for version in versions
              if updater.tor_version_channel(version.rstrip("/")) == "Stable"][:6]
    alpha = [version.rstrip("/") for version in versions
             if updater.tor_version_channel(version.rstrip("/")).startswith("Alpha")][:4]

    candidate = None
    for version in stable + alpha:
        links = updater.get_bundle_links(version, allow_direct=True)
        if links:
            candidate = (version, links[0])
            break
    if candidate is None:
        pytest.skip("No compatible signed Expert Bundle was listed in the recent release window.")

    version, filename = candidate
    archive = bundle_module.download_verified_bundle(
        version,
        updater._platform_name(),
        updater._architecture_name(),
        tmp_path / filename,
        allow_direct=True,
    )
    assert archive.is_file() and archive.stat().st_size > 0
    assert archive.with_name(archive.name + ".asc").is_file()

def test_empty_release_listing_is_not_reported_as_no_versions(monkeypatch):
    monkeypatch.setattr(updater, "_fetch_listing", lambda _url, *_args, **_kwargs: _listing())
    with pytest.raises(BundleVerificationError, match="no recognizable"):
        updater.get_tor_versions()


def test_unsupported_platform_is_reported_before_artifact_query(monkeypatch):
    monkeypatch.setattr(updater, "_platform_name", lambda: (_ for _ in ()).throw(
        BundleVerificationError("Tor bundle downloads are not configured for macOS.")
    ))
    monkeypatch.setattr(
        updater, "_fetch_listing",
        lambda _url, *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unsupported platforms must not query artifacts")),
    )
    with pytest.raises(BundleVerificationError, match="not configured for macOS"):
        updater.get_bundle_links("16.0a14")


def test_unreachable_release_listing_is_not_treated_as_empty(monkeypatch):
    monkeypatch.setattr(
        updater, "_fetch_listing",
        lambda _url, *_args, **_kwargs: (_ for _ in ()).throw(requests.Timeout("network timeout")),
    )
    with pytest.raises(BundleVerificationError, match="Check the network connection"):
        updater.get_bundle_links("16.0a14")



def test_https_only_install_marker_is_accepted_with_digest_and_safe_executable(tmp_path, monkeypatch):
    import json

    bundle_name = "tor-expert-bundle-linux-x86_64-15.0.26"
    bundle = tmp_path / bundle_name
    # This fixture deliberately mocks the Linux platform regardless of the CI host.
    executable = bundle / "tor" / "tor"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"explicitly unsigned test tor")
    if os.name != "nt":
        executable.chmod(0o755)
    archive = bundle.with_name(bundle.name + ".tar.gz")
    archive.write_bytes(b"archive downloaded over HTTPS")
    marker = {
        "signature_verified": False,
        "verification_method": "https_only",
        "signing_key_fingerprint": None,
        "archive_sha256": bundle_module.sha256_file(archive),
    }
    (bundle / ".torproxy-verified.json").write_text(json.dumps(marker), encoding="utf-8")
    monkeypatch.setattr(updater, "_platform_name", lambda: "linux")
    monkeypatch.setattr(updater, "_architecture_name", lambda: "x86_64")

    assert updater.check_bundle_compatibility(str(bundle))
    marker["verification_method"] = "unknown"
    (bundle / ".torproxy-verified.json").write_text(json.dumps(marker), encoding="utf-8")
    assert not updater.check_bundle_compatibility(str(bundle))


def test_download_verified_bundle_https_only_skips_gpg_and_signature_request(monkeypatch, tmp_path):
    requests_made = []
    events = []

    def unexpected_gpg():
        raise AssertionError("GnuPG must not be queried when signature verification is disabled")

    class RecordingSession(_FakeSession):
        def get(self, url, **kwargs):
            requests_made.append(url)
            return super().get(url, **kwargs)

    monkeypatch.setattr(
        bundle_module, "create_session",
        lambda *_args, **_kwargs: RecordingSession(
            _FakeResponse([b"test archive bytes"], length=len(b"test archive bytes"))
        ),
    )
    monkeypatch.setattr(bundle_module, "_find_gpg_executable", unexpected_gpg)
    destination = tmp_path / "tor-expert-bundle-linux-x86_64-15.0.26.tar.gz"

    result = bundle_module.download_verified_bundle(
        "15.0.26",
        "linux",
        "x86_64",
        destination,
        progress_callback=events.append,
        verify_signature=False,
        allow_direct=True,
    )

    assert result == destination
    assert destination.read_bytes() == b"test archive bytes"
    assert len(requests_made) == 1
    assert requests_made[0].endswith("/15.0.26/" + destination.name)
    assert not destination.with_name(destination.name + ".asc").exists()
    assert events[0].stage == "signature_verification_skipped"
    assert any(event.stage == "archive_downloaded_https_only" for event in events)



def test_stream_download_refuses_implicit_direct_connection(tmp_path):
    with pytest.raises(BundleVerificationError, match="No Tor route is available"):
        bundle_module._download(
            "https://dist.torproject.org/test",
            tmp_path / "bundle.tar.gz",
            {"dist.torproject.org"},
        )



def test_fetch_listing_uses_explicit_tor_session(monkeypatch):
    import updater

    calls = []

    class Response:
        status_code = 200
        url = "https://dist.torproject.org/torbrowser/"

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def raise_for_status(self):
            return None

        @property
        def text(self):
            return "<html><a href='15.0.26/'>15.0.26</a></html>"

    class Session:
        def __init__(self):
            self.trust_env = True

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get(self, url, **kwargs):
            calls.append((url, kwargs))
            return Response()

    def session_factory(proxy_url, *, allow_direct):
        calls.append((proxy_url, allow_direct))
        return Session()

    monkeypatch.setattr(updater, "create_session", session_factory)
    soup = updater._fetch_listing(
        "https://dist.torproject.org/torbrowser/",
        "socks5h://127.0.0.1:19050",
    )
    assert soup.find("a") is not None
    assert calls[0] == ("socks5h://127.0.0.1:19050", False)
    assert calls[1][1]["allow_redirects"] is False


def test_get_bundle_links_passes_tor_route_to_listing(monkeypatch):
    import updater

    expected = "tor-expert-bundle-linux-x86_64-15.0.26.tar.gz"
    calls = []
    monkeypatch.setattr(updater, "_platform_name", lambda: "linux")
    monkeypatch.setattr(updater, "_architecture_name", lambda: "x86_64")

    def listing(url, proxy_url=None, *, allow_direct=False):
        calls.append((url, proxy_url, allow_direct))
        return _listing(expected, expected + ".asc")

    monkeypatch.setattr(updater, "_fetch_listing", listing)
    assert updater.get_bundle_links(
        "15.0.26", proxy_url="socks5h://127.0.0.1:19050"
    ) == [expected]
    assert calls[0][1:] == ("socks5h://127.0.0.1:19050", False)


def _make_local_expert_bundle(path):
    import shutil
    import tarfile

    payload_root = path.parent / (path.name + "-payload")
    tor_dir = payload_root / "tor"
    tor_dir.mkdir(parents=True)
    executable = tor_dir / ("tor.exe" if os.name == "nt" else "tor")
    executable.write_bytes(b"local test tor executable")
    if os.name != "nt":
        executable.chmod(0o755)
    with tarfile.open(path, "w:gz") as archive:
        archive.add(tor_dir, arcname="tor")
    shutil.rmtree(payload_root)
    return path


def test_manual_bundle_import_installs_and_records_local_trust(tmp_path, monkeypatch):
    import json
    import utils
    import updater

    platform_name = "windows" if os.name == "nt" else "linux"
    executable_name = "tor.exe" if os.name == "nt" else "tor"
    filename = f"tor-expert-bundle-{platform_name}-x86_64-15.0.26.tar.gz"
    source = _make_local_expert_bundle(tmp_path / filename)
    managed = tmp_path / "managed"
    monkeypatch.setattr(updater, "BUNDLE_DIR", str(managed))
    monkeypatch.setattr(updater, "resource_path", lambda value: value)
    monkeypatch.setattr(updater, "_platform_name", lambda: platform_name)
    monkeypatch.setattr(updater, "_architecture_name", lambda: "x86_64")
    monkeypatch.setattr(
        utils, "verify_tor_signature",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unsigned local import must not fetch GPG")),
    )

    installed = updater.import_local_bundle(source, verify_signature=False)
    marker = json.loads((installed / ".torproxy-verified.json").read_text(encoding="utf-8"))
    assert marker["signature_verified"] is False
    assert marker["verification_method"] == "local_unverified"
    assert (installed / "tor" / executable_name).is_file()
    assert (managed / filename).is_file()
    assert updater.check_bundle_compatibility(str(installed))


def test_manual_bundle_import_checks_adjacent_signature(tmp_path, monkeypatch):
    import updater
    import utils

    platform_name = "windows" if os.name == "nt" else "linux"
    filename = f"tor-expert-bundle-{platform_name}-x86_64-15.0.26.tar.gz"
    source = _make_local_expert_bundle(tmp_path / filename)
    source.with_name(source.name + ".asc").write_bytes(b"detached signature")
    managed = tmp_path / "managed"
    calls = []
    monkeypatch.setattr(updater, "BUNDLE_DIR", str(managed))
    monkeypatch.setattr(updater, "resource_path", lambda value: value)
    monkeypatch.setattr(updater, "_platform_name", lambda: platform_name)
    monkeypatch.setattr(updater, "_architecture_name", lambda: "x86_64")

    def verified(archive, signature, **kwargs):
        calls.append((Path(archive).name, Path(signature).name, kwargs))

    monkeypatch.setattr(utils, "verify_tor_signature", verified)
    installed = updater.import_local_bundle(
        source, verify_signature=True, proxy_url="socks5h://127.0.0.1:19050"
    )
    assert calls
    assert calls[0][0] == filename
    assert calls[0][1] == filename + ".asc"
    assert calls[0][2]["proxy_url"] == "socks5h://127.0.0.1:19050"
    assert updater.check_bundle_compatibility(str(installed))


def test_manual_bundle_import_rejects_wrong_platform(tmp_path, monkeypatch):
    import updater

    source = _make_local_expert_bundle(
        tmp_path / "tor-expert-bundle-windows-x86_64-15.0.26.tar.gz"
    )
    monkeypatch.setattr(updater, "BUNDLE_DIR", str(tmp_path / "managed"))
    monkeypatch.setattr(updater, "resource_path", lambda value: value)
    monkeypatch.setattr(updater, "_platform_name", lambda: "linux")
    monkeypatch.setattr(updater, "_architecture_name", lambda: "x86_64")
    with pytest.raises(BundleVerificationError, match="does not match this device"):
        updater.import_local_bundle(source, verify_signature=False)


def test_manual_bundle_import_does_not_overwrite_existing_archive(tmp_path, monkeypatch):
    import updater

    platform_name = "windows" if os.name == "nt" else "linux"
    source = _make_local_expert_bundle(
        tmp_path / f"tor-expert-bundle-{platform_name}-x86_64-15.0.26.tar.gz"
    )
    managed = tmp_path / "managed"
    managed.mkdir()
    (managed / source.name).write_bytes(b"preserve existing archive")
    monkeypatch.setattr(updater, "BUNDLE_DIR", str(managed))
    monkeypatch.setattr(updater, "resource_path", lambda value: value)
    monkeypatch.setattr(updater, "_platform_name", lambda: platform_name)
    monkeypatch.setattr(updater, "_architecture_name", lambda: "x86_64")
    with pytest.raises(BundleVerificationError, match="already exists"):
        updater.import_local_bundle(source, verify_signature=False)
    assert (managed / source.name).read_bytes() == b"preserve existing archive"
