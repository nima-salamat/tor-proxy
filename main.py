"""TorProxy desktop entry point."""
from __future__ import annotations

import logging
import signal
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent
SRC_ROOT = APP_ROOT / "src"
if SRC_ROOT.is_dir() and str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

import portalocker
import qdarkstyle
from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QMessageBox
from qdarkstyle.dark.palette import DarkPalette
from qdarkstyle.light.palette import LightPalette

from config import CONFIG
from torproxy.paths import user_directories
from ui import Window
from utils import resource_path

LOGGER = logging.getLogger(__name__)


def configure_logging() -> None:
    directories = user_directories().ensure()
    level_name = str(CONFIG["log_level"] or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    if root.handlers:
        return
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    file_handler = RotatingFileHandler(
        directories.logs / "torproxy.log", maxBytes=2 * 1024 * 1024, backupCount=4, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(file_handler)
    root.addHandler(console)


def main() -> int:
    # Preserve each display's actual DPI ratio when moving between monitors.
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    try:
        CONFIG.load()
    except Exception as exc:
        QMessageBox.critical(None, "TorProxy configuration error", str(exc))
        return 2
    configure_logging()
    app.setApplicationName("TorProxy")
    app.setApplicationDisplayName("TorProxy")

    directories = user_directories().ensure()
    lock_path = directories.state / "application.lock"
    try:
        with portalocker.Lock(str(lock_path), mode="a", timeout=0):
            if CONFIG["mode"] == "light":
                app.setStyleSheet(qdarkstyle.load_stylesheet(palette=LightPalette()))
            else:
                app.setStyleSheet(qdarkstyle.load_stylesheet(palette=DarkPalette()))
            app.setWindowIcon(QIcon(resource_path("assets/icon.png")))
            win = Window()
            # Keep the normal Windows DWM presentation path. Display-affinity
            # restrictions are not needed for Tor operation and can interfere
            # with capture/restore behavior for frameless Qt windows.
            win.show()
            signal.signal(signal.SIGINT, lambda *_: QTimer.singleShot(0, app.quit))
            try:
                return app.exec()
            finally:
                try:
                    win.proxyWidget._stop_services()
                except Exception:
                    LOGGER.exception("Error during application shutdown.")
    except portalocker.exceptions.LockException:
        QMessageBox.information(None, "TorProxy is already running", "Close the existing TorProxy instance first.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
