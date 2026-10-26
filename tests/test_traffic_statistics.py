from __future__ import annotations

import queue
import threading

import pytest


@pytest.fixture(scope="module")
def qt_app():
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def test_record_bytes_preserves_aggregate_queue_and_tracks_upload_download(monkeypatch):
    pytest.importorskip("socks")
    import proxy

    received = queue.Queue()
    totals = {"upload": 0, "download": 0}
    monkeypatch.setattr(proxy, "queue_bytes", received)
    monkeypatch.setattr(proxy, "_traffic_direction_totals", totals)
    monkeypatch.setattr(proxy, "_traffic_direction_lock", threading.Lock())

    proxy._record_bytes(12, "upload")
    proxy._record_bytes(29, "download")
    proxy._record_bytes(4)
    proxy._record_bytes(0, "upload")
    proxy._record_bytes(-8, "download")

    assert [received.get_nowait() for _ in range(received.qsize())] == [12, 29, 4]
    assert proxy.get_traffic_direction_snapshot() == {"upload": 12, "download": 29}


def test_statistics_sampling_tracks_session_deltas_rate_and_peak(qt_app, monkeypatch):
    pytest.importorskip("qtawesome")
    import ui_.window.statistics_window as statistics

    counters = {"upload": 0, "download": 0}
    monkeypatch.setattr(statistics, "CONFIG", {"mode": "dark", "data_usage": 4096})
    monkeypatch.setattr(statistics, "get_traffic_direction_snapshot", lambda: dict(counters))

    page = statistics.StatisticsWindow(proxy_widget=type("ProxyState", (), {"running": True, "connected": True})())
    page.timer.stop()
    first = page._last_sample_at + 1.0
    counters.update(upload=100, download=300)
    page.sample_once(now=first, total_bytes=5000)
    assert page._session_upload == 100
    assert page._session_download == 300
    assert page.metric_values["session"].text() == "400 B"
    assert page.metric_values["current"].text() == "400 B/s"
    assert page._peak_rate == 400

    counters.update(upload=140, download=1060)
    page.sample_once(now=first + 2.0, total_bytes=6000)
    assert page._session_upload == 140
    assert page._session_download == 1060
    assert page.metric_values["session"].text() == "1.17 KiB"
    assert page._current_rate == 400
    assert page._peak_rate == 400
    assert len(page._samples) == 3
    assert len(page.rate_chart._samples) == 3
    assert len(page.volume_chart._samples) == 3

    page.deleteLater()
    qt_app.processEvents()
