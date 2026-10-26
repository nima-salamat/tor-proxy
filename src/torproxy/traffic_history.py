"""Persistent minute-level proxy traffic history backed by SQLite."""
from __future__ import annotations

import logging
import math
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Mapping

from torproxy.paths import user_directories

logger = logging.getLogger(__name__)

DEFAULT_DATABASE_NAME = "traffic-history.sqlite3"
DEFAULT_RETENTION_DAYS = 180


def _non_negative_int(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


class TrafficHistoryStore:
    """Persist aggregate byte totals and minute buckets without storing host data.

    The proxy accounting worker owns a writer instance. The statistics page uses a
    separate read instance, so database writes never run on a request-handler thread.
    """

    def __init__(
        self,
        database_path: str | Path | None = None,
        *,
        initial_total_bytes: int = 0,
        initialize: bool = True,
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> None:
        default_path = user_directories().data / DEFAULT_DATABASE_NAME
        self.path = Path(database_path) if database_path is not None else default_path
        self._writer_enabled = bool(initialize)
        self._initial_total_bytes = _non_negative_int(initial_total_bytes)
        self._retention_days = max(30, int(retention_days))
        self._connection: sqlite3.Connection | None = None
        self._lock = threading.RLock()
        self._last_prune_day: int | None = None
        if self._writer_enabled:
            self._connect(create=True)

    def _connect(self, *, create: bool) -> sqlite3.Connection | None:
        if self._connection is not None:
            return self._connection
        if not self.path.exists() and not create:
            return None
        if create:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if os.name != "nt":
                try:
                    self.path.parent.chmod(0o700)
                except OSError:
                    pass
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=2.0 if create else 0.15,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 2000" if create else "PRAGMA busy_timeout = 150")
            if create:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("PRAGMA synchronous = NORMAL")
                self._initialize_schema(connection)
                if os.name != "nt":
                    try:
                        self.path.chmod(0o600)
                    except OSError:
                        pass
            self._connection = connection
            return connection
        except Exception:
            if connection is not None:
                connection.close()
            raise

    def _initialize_schema(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS traffic_minutes (
                bucket_start INTEGER PRIMARY KEY,
                total_bytes INTEGER NOT NULL CHECK (total_bytes >= 0),
                upload_bytes INTEGER NOT NULL CHECK (upload_bytes >= 0),
                download_bytes INTEGER NOT NULL CHECK (download_bytes >= 0)
            );
            CREATE TABLE IF NOT EXISTS traffic_totals (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                total_bytes INTEGER NOT NULL CHECK (total_bytes >= 0),
                upload_bytes INTEGER NOT NULL CHECK (upload_bytes >= 0),
                download_bytes INTEGER NOT NULL CHECK (download_bytes >= 0),
                updated_at INTEGER NOT NULL
            );
            """
        )
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                """
                INSERT OR IGNORE INTO traffic_totals
                    (id, total_bytes, upload_bytes, download_bytes, updated_at)
                VALUES (1, ?, 0, 0, ?)
                """,
                (self._initial_total_bytes, int(time.time())),
            )
            row = connection.execute(
                "SELECT total_bytes FROM traffic_totals WHERE id = 1"
            ).fetchone()
            current_total = _non_negative_int(row["total_bytes"] if row else 0)
            if current_total < self._initial_total_bytes:
                connection.execute(
                    """
                    UPDATE traffic_totals
                    SET total_bytes = ?, updated_at = ?
                    WHERE id = 1
                    """,
                    (self._initial_total_bytes, int(time.time())),
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def get_totals(self) -> dict[str, int]:
        """Read the persistent all-time counters, returning zeros if no database exists."""
        with self._lock:
            try:
                connection = self._connect(create=self._writer_enabled)
                if connection is None:
                    return {"total_bytes": 0, "upload_bytes": 0, "download_bytes": 0, "updated_at": 0}
                row = connection.execute(
                    """
                    SELECT total_bytes, upload_bytes, download_bytes, updated_at
                    FROM traffic_totals WHERE id = 1
                    """
                ).fetchone()
                if row is None:
                    return {"total_bytes": 0, "upload_bytes": 0, "download_bytes": 0, "updated_at": 0}
                return {
                    "total_bytes": _non_negative_int(row["total_bytes"]),
                    "upload_bytes": _non_negative_int(row["upload_bytes"]),
                    "download_bytes": _non_negative_int(row["download_bytes"]),
                    "updated_at": _non_negative_int(row["updated_at"]),
                }
            except sqlite3.Error:
                if self._writer_enabled:
                    raise
                logger.debug("Persistent traffic totals are not available yet.", exc_info=True)
                return {"total_bytes": 0, "upload_bytes": 0, "download_bytes": 0, "updated_at": 0}

    def record_batch(
        self,
        *,
        total_delta: int,
        upload_delta: int,
        download_delta: int,
        minute_deltas: Mapping[int, tuple[int, int, int]],
        total_floor: int = 0,
        now: int | None = None,
    ) -> dict[str, int]:
        """Commit a batch of events and minute aggregates in one short transaction.

        total_floor reconciles the legacy JSON counter after an interrupted write;
        it prevents either the JSON counter or this database from lowering lifetime usage.
        """
        if not self._writer_enabled:
            raise RuntimeError("This traffic history instance is read-only.")
        total_delta = _non_negative_int(total_delta)
        upload_delta = _non_negative_int(upload_delta)
        download_delta = _non_negative_int(download_delta)
        total_floor = _non_negative_int(total_floor)
        timestamp = int(time.time()) if now is None else _non_negative_int(now)
        buckets: list[tuple[int, int, int, int]] = []
        for raw_start, raw_values in minute_deltas.items():
            bucket_start = _non_negative_int(raw_start)
            bucket_start -= bucket_start % 60
            try:
                values = tuple(_non_negative_int(value) for value in raw_values)
            except (TypeError, ValueError):
                continue
            if len(values) != 3:
                continue
            bucket_total, bucket_upload, bucket_download = values
            bucket_total = max(bucket_total, bucket_upload + bucket_download)
            if bucket_total or bucket_upload or bucket_download:
                buckets.append((bucket_start, bucket_total, bucket_upload, bucket_download))

        with self._lock:
            connection = self._connect(create=True)
            if connection is None:
                raise RuntimeError("Could not open the traffic history database.")
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    UPDATE traffic_totals
                    SET total_bytes = MAX(total_bytes, ?) + ?,
                        upload_bytes = upload_bytes + ?,
                        download_bytes = download_bytes + ?,
                        updated_at = ?
                    WHERE id = 1
                    """,
                    (total_floor, total_delta, upload_delta, download_delta, timestamp),
                )
                for bucket_start, bucket_total, bucket_upload, bucket_download in buckets:
                    connection.execute(
                        """
                        INSERT INTO traffic_minutes
                            (bucket_start, total_bytes, upload_bytes, download_bytes)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(bucket_start) DO UPDATE SET
                            total_bytes = traffic_minutes.total_bytes + excluded.total_bytes,
                            upload_bytes = traffic_minutes.upload_bytes + excluded.upload_bytes,
                            download_bytes = traffic_minutes.download_bytes + excluded.download_bytes
                        """,
                        (bucket_start, bucket_total, bucket_upload, bucket_download),
                    )
                day = timestamp // 86400
                if self._last_prune_day != day:
                    cutoff = max(0, timestamp - self._retention_days * 86400)
                    connection.execute(
                        "DELETE FROM traffic_minutes WHERE bucket_start < ?", (cutoff,)
                    )
                    self._last_prune_day = day
                row = connection.execute(
                    """
                    SELECT total_bytes, upload_bytes, download_bytes, updated_at
                    FROM traffic_totals WHERE id = 1
                    """
                ).fetchone()
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        if row is None:
            raise RuntimeError("The traffic totals row is missing.")
        return {
            "total_bytes": _non_negative_int(row["total_bytes"]),
            "upload_bytes": _non_negative_int(row["upload_bytes"]),
            "download_bytes": _non_negative_int(row["download_bytes"]),
            "updated_at": _non_negative_int(row["updated_at"]),
        }

    def load_buckets(
        self,
        start_timestamp: int,
        end_timestamp: int,
        *,
        bucket_count: int = 60,
    ) -> list[dict[str, int]]:
        """Load time-aligned graph buckets, filling intervals with zero traffic."""
        count = max(1, min(1200, int(bucket_count)))
        start = max(0, int(start_timestamp))
        end = max(0, int(end_timestamp))
        if end <= start:
            return []
        start_aligned = start - start % 60
        end_aligned = end - end % 60
        if end > end_aligned:
            end_aligned += 60
        if end_aligned <= start_aligned:
            end_aligned = start_aligned + 60
        span = end_aligned - start_aligned
        step = max(60, int(math.ceil(span / (count * 60)) * 60))
        actual_count = min(count, max(1, int(math.ceil(span / step))))
        buckets = [
            {
                "timestamp": start_aligned + index * step,
                "total_bytes": 0,
                "upload_bytes": 0,
                "download_bytes": 0,
            }
            for index in range(actual_count)
        ]

        with self._lock:
            try:
                connection = self._connect(create=self._writer_enabled)
                if connection is None:
                    return buckets
                rows = connection.execute(
                    """
                    SELECT CAST((bucket_start - ?) / ? AS INTEGER) AS bucket_index,
                           SUM(total_bytes) AS total_bytes,
                           SUM(upload_bytes) AS upload_bytes,
                           SUM(download_bytes) AS download_bytes
                    FROM traffic_minutes
                    WHERE bucket_start >= ? AND bucket_start < ?
                    GROUP BY bucket_index
                    ORDER BY bucket_index
                    """,
                    (start_aligned, step, start_aligned, end_aligned),
                ).fetchall()
            except sqlite3.Error:
                if self._writer_enabled:
                    raise
                logger.debug("Persistent traffic history is not available yet.", exc_info=True)
                return buckets
        for row in rows:
            index = int(row["bucket_index"])
            if 0 <= index < actual_count:
                buckets[index]["total_bytes"] = _non_negative_int(row["total_bytes"])
                buckets[index]["upload_bytes"] = _non_negative_int(row["upload_bytes"])
                buckets[index]["download_bytes"] = _non_negative_int(row["download_bytes"])
        return buckets

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None


__all__ = (
    "DEFAULT_DATABASE_NAME",
    "DEFAULT_RETENTION_DAYS",
    "TrafficHistoryStore",
)
