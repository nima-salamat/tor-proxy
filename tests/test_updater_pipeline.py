from __future__ import annotations

from threading import Event

import pytest
import requests
from bs4 import BeautifulSoup

import updater
from torproxy import bundle as bundle_module
from torproxy.bundle import BundleProgress, BundleVerificationError


def _listing(*names: str) -> BeautifulSoup:
    return BeautifulSoup(
        "<html><body>{}</body></html>".format(
            "".join('<a href="{}">{}</a>'.format(name, name) for name in names)
        ),
        "html.parser",
    )


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
        lambda _url: _listing("15.0.20/", "15.0.25/", "15.0.26/", "16.0a14/",
                              "not-a-version/", "../", "tor-browser-16.0a14.exe"),
    )
    assert updater.get_tor_versions() == [
        "15.0.26/", "15.0.25/", "15.0.20/", "16.0a14/"
    ]


def test_bundle_discovery_requires_exact_archive_and_sidecar(monkeypatch):
    expected = "tor-expert-bundle-windows-x86_64-16.0a14.tar.gz"
    monkeypatch.setattr(updater, "_platform_name", lambda: "windows")
    monkeypatch.setattr(updater, "_architecture_name", lambda: "x86_64")
    monkeypatch.setattr(updater, "_fetch_listing", lambda _url: _listing(expected, expected + ".asc"))
    assert updater.get_bundle_links("16.0a14") == [expected]

    monkeypatch.setattr(updater, "_fetch_listing", lambda _url: _listing(expected))
    assert updater.get_bundle_links("16.0a14") == []


def test_bundle_discovery_ignores_browser_updates_and_other_archives(monkeypatch):
    expected = "tor-expert-bundle-windows-x86_64-15.0.20.tar.gz"
    monkeypatch.setattr(updater, "_platform_name", lambda: "windows")
    monkeypatch.setattr(updater, "_architecture_name", lambda: "x86_64")
    monkeypatch.setattr(
        updater, "_fetch_listing",
        lambda _url: _listing(
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
            raise requests.HTTPError("HTTP {}".format(self.status_code))

    def iter_content(self, chunk_size):
        yield from self._chunks


def test_stream_download_reports_known_size_without_false_unknown(monkeypatch, tmp_path):
    events: list[BundleProgress] = []
    monkeypatch.setattr(
        bundle_module.requests, "get",
        lambda *_args, **_kwargs: _FakeResponse([b"abc"], length=3),
    )
    destination = tmp_path / "bundle.tar.gz"
    bundle_module._download(
        "https://dist.torproject.org/test", destination, {"dist.torproject.org"},
        version="15.0.26", progress_callback=events.append,
    )
    assert destination.read_bytes() == b"abc"
    assert events[0].total_bytes == 3
    assert events[-1].bytes_received == 3
    assert events[-1].percentage == 100


def test_stream_download_uses_indeterminate_progress_without_content_length(monkeypatch, tmp_path):
    events: list[BundleProgress] = []
    monkeypatch.setattr(
        bundle_module.requests, "get",
        lambda *_args, **_kwargs: _FakeResponse([b"", b"abcd"]),
    )
    bundle_module._download(
        "https://dist.torproject.org/test", tmp_path / "bundle.tar.gz",
        {"dist.torproject.org"}, progress_callback=events.append,
    )
    assert events[0].total_bytes is None
    assert events[-1].total_bytes is None
    assert events[-1].percentage is None
    assert events[-1].bytes_received == 4


def test_stream_download_fails_on_http_error(monkeypatch, tmp_path):
    monkeypatch.setattr(
        bundle_module.requests, "get",
        lambda *_args, **_kwargs: _FakeResponse([], status=503),
    )
    with pytest.raises(BundleVerificationError, match="Download failed"):
        bundle_module._download(
            "https://dist.torproject.org/test", tmp_path / "bundle.tar.gz",
            {"dist.torproject.org"},
        )


def test_stream_download_observes_cancellation_before_network(monkeypatch, tmp_path):
    cancelled = Event()
    cancelled.set()

    def unexpected_request(*_args, **_kwargs):
        raise AssertionError("network should not be started when cancellation is already requested")

    monkeypatch.setattr(bundle_module.requests, "get", unexpected_request)
    with pytest.raises(BundleVerificationError, match="cancelled"):
        bundle_module._download(
            "https://dist.torproject.org/test", tmp_path / "bundle.tar.gz",
            {"dist.torproject.org"}, cancel_event=cancelled,
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
    monkeypatch.setattr(
        bundle_module.requests, "get",
        lambda *_args, **_kwargs: _FakeResponse([b"short"], length=99),
    )
    with pytest.raises(BundleVerificationError, match="declared Content-Length"):
        bundle_module._download(
            "https://dist.torproject.org/test", tmp_path / "bundle.tar.gz",
            {"dist.torproject.org"},
        )

