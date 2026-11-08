"""TorProxy desktop entry point."""
from __future__ import annotations

import faulthandler
import logging
import os
import signal
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent
SRC_ROOT = APP_ROOT / "src"
if SRC_ROOT.is_dir() and str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

# PyInstaller invokes this dedicated entry point for the elevated Linux firewall helper.
if sys.platform.startswith("linux") and sys.argv[1:2] == ["--killswitch-helper"]:
    # Windowed PyInstaller builds may not initialize console streams. The
    # privileged helper's JSON response must still reach pkexec's pipe.
    if sys.stdout is None:
        sys.stdout = open("/dev/stdout", "w", encoding="utf-8", buffering=1)
    if sys.stderr is None:
        sys.stderr = open("/dev/stderr", "w", encoding="utf-8", buffering=1)
    from torproxy.firewall.linux_helper import main as killswitch_helper_main
    raise SystemExit(killswitch_helper_main(sys.argv[2:]))

# The TUN helper runs before Qt imports and uses only the pinned sing-box engine.
if sys.argv[1:2] == ["--system-tunnel-helper"]:
    if sys.stdout is None:
        sys.stdout = open("/dev/stdout" if os.name != "nt" else os.devnull, "w", encoding="utf-8", buffering=1)
    if sys.stderr is None:
        sys.stderr = open("/dev/stderr" if os.name != "nt" else os.devnull, "w", encoding="utf-8", buffering=1)
    from torproxy.system_tunnel import system_tunnel_helper_main
    raise SystemExit(system_tunnel_helper_main(sys.argv[2:]))

_STARTUP_STREAM = None


def configure_launcher_streams() -> None:
    """Capture early Python startup errors for the native launcher, if present."""
    global _STARTUP_STREAM
    log_path = os.environ.get("TORPROXY_LAUNCHER_LOG", "").strip()
    if not log_path:
        return
    try:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        _STARTUP_STREAM = Path(log_path).open("a", encoding="utf-8", buffering=1)
        sys.stdout = _STARTUP_STREAM
        sys.stderr = _STARTUP_STREAM
    except OSError:
        # Log redirection is diagnostic only and must not block application startup.
        return


configure_launcher_streams()

# A dependency-free heartbeat lets the native Windows splash acknowledge that
# Python has begun executing, even while PySide6 is still importing.
try:
    from torproxy.launcher_ipc import notify_launcher as _notify_launcher

    if os.environ.get("TORPROXY_LAUNCHER_STATUS_FILE"):
        _notify_launcher("starting", "Starting the Python runtime…")
except Exception:
    _notify_launcher = None

LOGGER = logging.getLogger(__name__)
_CRASH_LOG_HANDLE = None


def enable_crash_reporting() -> None:
    """Keep a faulthandler file open so native crashes leave a diagnostic trace."""
    global _CRASH_LOG_HANDLE
    if _CRASH_LOG_HANDLE is not None:
        return
    try:
        from torproxy.paths import user_directories

        directories = user_directories().ensure()
        handle = (directories.logs / "torproxy-crash.log").open("ab", buffering=0)
        faulthandler.enable(file=handle, all_threads=True)
        _CRASH_LOG_HANDLE = handle
    except Exception:
        # Crash reporting must never prevent TorProxy from starting.
        if sys.stderr is not None:
            sys.stderr.write("TorProxy: could not enable native crash diagnostics.\n")


def _log_uncaught_exception(exc_type, exc_value, exc_traceback) -> None:
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    LOGGER.critical(
        "Uncaught exception on the main thread.",
        exc_info=(exc_type, exc_value, exc_traceback),
    )
    sys.__excepthook__(exc_type, exc_value, exc_traceback)


def configure_logging() -> None:
    from config import CONFIG
    from torproxy.paths import user_directories

    directories = user_directories().ensure()
    level_name = str(CONFIG["log_level"] or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    sys.excepthook = _log_uncaught_exception
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
    # Keep the splash informed while dependencies and the application UI load.
    from torproxy.launcher_ipc import notify_launcher

    notify_launcher("starting", "Loading Python and desktop components…")
    import portalocker
    import qdarkstyle
    from PySide6.QtCore import QTimer, Qt
    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication
    from qdarkstyle.dark.palette import DarkPalette
    from qdarkstyle.light.palette import LightPalette

    from config import CONFIG
    from torproxy.paths import user_directories
    from ui import Window
    from ui_.window.dialogs import QMessageBox
    from utils import resource_path

    enable_crash_reporting()
    # Preserve each display's actual DPI ratio when moving between monitors.
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    try:
        CONFIG.load()
    except Exception as exc:
        message = f"Configuration error: {exc}"
        if not notify_launcher("failed", message):
            QMessageBox.critical(None, "TorProxy configuration error", str(exc))
        return 2
    configure_logging()
    notify_launcher("starting", "Preparing TorProxy settings…")
    app.setApplicationName("TorProxy")
    app.setApplicationDisplayName("TorProxy")
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("TorProxy.Desktop")
        except (AttributeError, OSError):
            LOGGER.debug("Could not set the Windows taskbar application identity.", exc_info=True)

    directories = user_directories().ensure()
    lock_path = directories.state / "application.lock"
    try:
        with portalocker.Lock(str(lock_path), mode="a", timeout=0):
            if CONFIG["mode"] == "light":
                app.setStyleSheet(qdarkstyle.load_stylesheet(palette=LightPalette()))
            else:
                app.setStyleSheet(qdarkstyle.load_stylesheet(palette=DarkPalette()))
            app.setWindowIcon(QIcon(resource_path("assets/icon.png")))
            notify_launcher("starting", "Building the TorProxy window…")
            win = Window()
            # Keep the normal Windows DWM presentation path. Display-affinity
            # restrictions are not needed for Tor operation and can interfere
            # with capture/restore behavior for frameless Qt windows.
            win.show()
            # Process the initial show/paint events before closing the external splash.
            app.processEvents()
            launcher_expected = bool(
                os.environ.get("TORPROXY_LAUNCHER_STATUS_FILE")
                or os.environ.get("TORPROXY_LAUNCHER_SERVER")
            )
            if launcher_expected and not notify_launcher("ready"):
                LOGGER.error("The launcher readiness signal could not be delivered; the application will continue running.")
            signal.signal(signal.SIGINT, lambda *_: QTimer.singleShot(0, app.quit))
            try:
                return app.exec()
            finally:
                try:
                    win.proxyWidget._stop_services()
                except Exception:
                    LOGGER.exception("Error during application shutdown.")
    except portalocker.exceptions.LockException:
        message = "TorProxy is already running. Close the existing instance first."
        if not notify_launcher("failed", message):
            QMessageBox.information(None, "TorProxy is already running", message)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
