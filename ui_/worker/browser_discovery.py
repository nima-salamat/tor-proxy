"""Background browser discovery worker; never touches Qt widgets."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, Signal, Slot

from torproxy.browsers import Browser, BrowserDetector, BrowserInventoryStore

logger = logging.getLogger(__name__)


class BrowserDiscoverySignals(QObject):
    completed = Signal(object)
    failed = Signal(str)


class BrowserDiscoveryWorker(QRunnable):
    """Run the potentially slow OS scan and persist its complete snapshot."""

    def __init__(self, detector: BrowserDetector, inventory: BrowserInventoryStore):
        super().__init__()
        self.detector = detector
        self.inventory = inventory
        self.signals = BrowserDiscoverySignals()

    @staticmethod
    def _still_installed(browser: Browser) -> bool:
        executable = Path(browser.executable).expanduser()
        if not executable.is_file():
            return False
        return os.name == "nt" or os.access(executable, os.X_OK)

    @Slot()
    def run(self) -> None:
        try:
            # Windows registry/Start Menu and Linux .desktop traversal can take
            # noticeable time, so this method is only called by QThreadPool.
            detected = self.detector.detect()
            current = [browser for browser in detected if self._still_installed(browser)]
            snapshot = self.inventory.replace_snapshot(current)
            self.signals.completed.emit(snapshot)
        except Exception as exc:
            logger.exception("Background browser discovery failed.")
            try:
                self.signals.failed.emit(f"{type(exc).__name__}: {exc}")
            except RuntimeError:
                logger.exception("Could not notify the browser dialog about scan failure.")
