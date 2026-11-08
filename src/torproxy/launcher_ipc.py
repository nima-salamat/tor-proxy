"""Small authenticated IPC bridge used by the optional native startup launcher."""

from __future__ import annotations

import json
import os


def notify_launcher(status: str, message: str = "") -> bool:
    """Notify the native launcher that TorProxy is ready or failed to start.

    Direct Python launches have no launcher environment and are intentionally
    unaffected. The socket name is random per attempt and the token prevents
    unrelated same-user local clients from spoofing startup state.
    """
    server_name = os.environ.get("TORPROXY_LAUNCHER_SERVER", "").strip()
    token = os.environ.get("TORPROXY_LAUNCHER_TOKEN", "").strip()
    if not server_name or not token or status not in {"ready", "failed"}:
        return False

    try:
        from PySide6.QtCore import QEventLoop, QIODevice, QTimer
        from PySide6.QtNetwork import QLocalSocket

        socket = QLocalSocket()
        socket.connectToServer(server_name, QIODevice.OpenModeFlag.WriteOnly)
        if not socket.waitForConnected(1200):
            return False

        payload = {
            "token": token,
            "status": status,
            "message": str(message or "")[:1800],
        }
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        message = encoded + b"\n"
        loop = QEventLoop()
        timer = QTimer()
        timer.setSingleShot(True)

        def finish_after_write(_written=0):
            if socket.bytesToWrite() == 0:
                loop.quit()

        def finish_after_error(_error):
            loop.quit()

        socket.bytesWritten.connect(finish_after_write)
        socket.errorOccurred.connect(finish_after_error)
        try:
            if socket.write(message) != len(message):
                return False
            socket.flush()
            if socket.bytesToWrite() > 0:
                timer.timeout.connect(loop.quit)
                timer.start(1200)
                loop.exec(QEventLoop.ProcessEventsFlag.ExcludeUserInputEvents)
            return socket.bytesToWrite() == 0 and socket.isValid()
        finally:
            timer.stop()
            try:
                socket.bytesWritten.disconnect(finish_after_write)
                socket.errorOccurred.disconnect(finish_after_error)
            except (RuntimeError, TypeError):
                pass
    except Exception:
        # Reporting is best-effort; a failed launcher channel must never stop
        # the actual application from starting or running.
        return False
