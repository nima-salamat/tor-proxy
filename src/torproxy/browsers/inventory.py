"""SQLite-backed cache of installed browser launch targets."""
from __future__ import annotations

import json
import os
import sqlite3
import time
from collections.abc import Iterable
from pathlib import Path

from torproxy.paths import user_directories

from .models import Browser


class BrowserInventoryStore:
    """Persist the last known browser inventory for instant dialog startup.

    Each operation opens its own short-lived SQLite connection. This keeps the
    store safe to use from the UI thread and a discovery worker concurrently.
    """

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else user_directories().data / "browser_inventory.sqlite3"

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            try:
                self.path.parent.chmod(0o700)
            except OSError:
                pass
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS browser_inventory (
                browser_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                family TEXT NOT NULL,
                executable TEXT NOT NULL,
                arguments_json TEXT NOT NULL DEFAULT '[]',
                source TEXT NOT NULL DEFAULT 'detected',
                desktop_file TEXT,
                icon TEXT,
                last_seen REAL NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_browser_inventory_name "
            "ON browser_inventory(name COLLATE NOCASE)"
        )
        if os.name != "nt":
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
        return connection

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Browser:
        try:
            arguments = json.loads(row["arguments_json"] or "[]")
        except (TypeError, json.JSONDecodeError):
            arguments = []
        if not isinstance(arguments, list):
            arguments = []
        return Browser(
            id=str(row["browser_id"]),
            name=str(row["name"]),
            family=str(row["family"]),
            executable=str(row["executable"]),
            arguments=tuple(str(value) for value in arguments),
            source=str(row["source"] or "detected"),
            desktop_file=row["desktop_file"],
            icon=row["icon"],
        )

    @staticmethod
    def _values(browser: Browser, timestamp: float) -> tuple:
        return (
            browser.id,
            browser.name,
            browser.family,
            browser.executable,
            json.dumps(list(browser.arguments), ensure_ascii=False),
            browser.source,
            browser.desktop_file,
            browser.icon,
            timestamp,
        )

    @staticmethod
    def _is_available(browser: Browser) -> bool:
        executable = Path(browser.executable).expanduser()
        if not executable.is_file():
            return False
        return os.name == "nt" or os.access(executable, os.X_OK)

    def load(self) -> list[Browser]:
        """Load the saved snapshot quickly; availability is rechecked asynchronously."""
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT browser_id, name, family, executable, arguments_json,
                       source, desktop_file, icon
                FROM browser_inventory
                ORDER BY family COLLATE NOCASE, name COLLATE NOCASE
                """
            ).fetchall()
            browsers: list[Browser] = []
            for row in rows:
                try:
                    browsers.append(self._from_row(row))
                except (TypeError, ValueError, KeyError):
                    continue
            return browsers
        finally:
            connection.close()

    def replace_snapshot(self, browsers: Iterable[Browser]) -> list[Browser]:
        """Atomically refresh detections while retaining valid user-added entries."""
        latest = {browser.id: browser for browser in browsers if self._is_available(browser)}
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            # A custom browser can be added while discovery is running. Preserve
            # that latest user action even if the worker's detector snapshot
            # started just before the user saved it.
            rows = connection.execute(
                """
                SELECT browser_id, name, family, executable, arguments_json,
                       source, desktop_file, icon
                FROM browser_inventory
                WHERE source = 'custom'
                """
            ).fetchall()
            for row in rows:
                try:
                    custom = self._from_row(row)
                except (TypeError, ValueError, KeyError):
                    continue
                if self._is_available(custom):
                    latest.setdefault(custom.id, custom)

            connection.execute("DELETE FROM browser_inventory")
            timestamp = time.time()
            connection.executemany(
                """
                INSERT INTO browser_inventory (
                    browser_id, name, family, executable, arguments_json,
                    source, desktop_file, icon, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [self._values(browser, timestamp) for browser in latest.values()],
            )
            connection.commit()
            return sorted(latest.values(), key=lambda item: (item.family, item.name.casefold()))
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def upsert(self, browser: Browser) -> None:
        """Immediately persist a user-added or corrected browser record."""
        if not self._is_available(browser):
            raise FileNotFoundError(f"Browser executable is no longer available: {browser.executable}")
        connection = self._connect()
        try:
            connection.execute(
                """
                INSERT INTO browser_inventory (
                    browser_id, name, family, executable, arguments_json,
                    source, desktop_file, icon, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(browser_id) DO UPDATE SET
                    name=excluded.name,
                    family=excluded.family,
                    executable=excluded.executable,
                    arguments_json=excluded.arguments_json,
                    source=excluded.source,
                    desktop_file=excluded.desktop_file,
                    icon=excluded.icon,
                    last_seen=excluded.last_seen
                """,
                self._values(browser, time.time()),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def remove(self, browser_id: str, executable: str | None = None) -> bool:
        """Remove a stale record without deleting a newer record with the same ID."""
        connection = self._connect()
        try:
            if executable is None:
                cursor = connection.execute(
                    "DELETE FROM browser_inventory WHERE browser_id = ?",
                    (str(browser_id),),
                )
            else:
                cursor = connection.execute(
                    "DELETE FROM browser_inventory WHERE browser_id = ? AND executable = ?",
                    (str(browser_id), str(executable)),
                )
            connection.commit()
            return cursor.rowcount > 0
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
