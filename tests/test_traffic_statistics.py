from __future__ import annotations

import os
import queue
import threading
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def qt_app():
    pytest.importorskip("PySide6")
    try:
        from PySide6.QtWidgets import QApplication
    except (ImportError, OSError) as exc:
        pytest.skip(f"Qt native libraries are unavailable in this environment: {exc}")

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

    events = [received.get_nowait() for _ in range(received.qsize())]
    assert [(amount, direction) for _timestamp, amount, direction in events] == [
        (12, "upload"),
        (29, "download"),
        (4, None),
    ]
    assert proxy.get_traffic_direction_snapshot() == {"upload": 12, "download": 29}


def test_traffic_history_persists_totals_directional_counters_and_minute_buckets(tmp_path):
    from torproxy.traffic_history import TrafficHistoryStore

    database_path = tmp_path / "traffic-history.sqlite3"
    minute = int(time.time() // 60) * 60
    store = TrafficHistoryStore(database_path, initial_total_bytes=1000)
    result = store.record_batch(
        total_delta=30,
        upload_delta=10,
        download_delta=20,
        minute_deltas={minute: (30, 10, 20)},
        total_floor=1000,
        now=minute + 30,
    )
    assert result["total_bytes"] == 1030
    assert result["upload_bytes"] == 10
    assert result["download_bytes"] == 20

    buckets = store.load_buckets(minute, minute + 60, bucket_count=1)
    assert buckets == [{
        "timestamp": minute,
        "total_bytes": 30,
        "upload_bytes": 10,
        "download_bytes": 20,
    }]
    store.close()

    restarted = TrafficHistoryStore(database_path, initial_total_bytes=900)
    assert restarted.get_totals()["total_bytes"] == 1030
    assert restarted.get_totals()["upload_bytes"] == 10
    assert restarted.get_totals()["download_bytes"] == 20
    restarted.close()


def test_statistics_sampling_tracks_session_deltas_rate_and_peak(qt_app, monkeypatch):
    pytest.importorskip("qtawesome")
    import ui_.window.statistics_window as statistics

    counters = {"upload": 0, "download": 0}
    monkeypatch.setattr(statistics, "CONFIG", {"mode": "dark", "data_usage": 4096})
    monkeypatch.setattr(statistics, "get_traffic_direction_snapshot", lambda: dict(counters))

    class FakeHistoryStore:
        def get_totals(self):
            return {"total_bytes": 4096, "upload_bytes": 0, "download_bytes": 0, "updated_at": 0}

        def load_buckets(self, start, end, *, bucket_count=60):
            del start, end
            return [
                {"timestamp": index * 60, "total_bytes": 0, "upload_bytes": 0, "download_bytes": 0}
                for index in range(bucket_count)
            ]

    page = statistics.StatisticsWindow(
        proxy_widget=type("ProxyState", (), {"running": True, "connected": True})(),
        history_store=FakeHistoryStore(),
    )
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
