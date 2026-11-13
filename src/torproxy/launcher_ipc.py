"""Small authenticated startup-status bridge used by the native launcher."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path


def _write_status_file(path_value: str, token: str, status: str, message: str) -> bool:
    """Atomically publish a tiny status record for the native splash launchers."""
    path = Path(path_value)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Hex keeps this wire format line-oriented and trivial to parse from Win32.
        payload = f"{token}\n{status}\n{str(message or '').encode('utf-8').hex()}\n"
        with temporary.open("x", encoding="ascii", newline="\n") as stream:
            if os.name != "nt":
                os.chmod(temporary, 0o600)
            stream.write(payload)
            stream.flush()
        # This file contains transient launch progress, not durable user data.
        # Atomic replacement protects readers from partial records without
        # forcing the Python startup thread to wait for a storage flush.
        os.replace(temporary, path)
        return True
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        return False


def notify_launcher(status: str, message: str = "") -> bool:
    """Notify the native launcher about startup progress, readiness, or failure.

    Direct Python launches have no launcher environment and are intentionally
    unaffected. Both native launchers can use an authenticated atomic status
    file without waiting for a Qt local-socket handshake during Python imports.
    QLocalSocket remains available as the Linux retry fallback.
    """
    if status not in {"starting", "ready", "failed"}:
        return False

    token = os.environ.get("TORPROXY_LAUNCHER_TOKEN", "").strip()
    if not token:
        return False

    status_file = os.environ.get("TORPROXY_LAUNCHER_STATUS_FILE", "").strip()
    if status_file:
        if _write_status_file(status_file, token, status, str(message or "")[:1800]):
            return True

    server_name = os.environ.get("TORPROXY_LAUNCHER_SERVER", "").strip()
    if not server_name:
        return False

    try:
        from PySide6.QtCore import QEventLoop, QIODevice, QTimer
        from PySide6.QtNetwork import QLocalSocket

        socket = QLocalSocket()
        socket.connectToServer(server_name, QIODevice.OpenModeFlag.ReadWrite)
        if not socket.waitForConnected(2500):
            return False

        payload = {
            "token": token,
            "status": status,
            "message": str(message or "")[:1800],
        }
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        wire_message = encoded + b"\n"
        loop = QEventLoop()
        timer = QTimer()
        timer.setSingleShot(True)

        def finish_after_ack():
            if socket.canReadLine():
                loop.quit()

        def finish_after_error(_error):
            loop.quit()

        socket.readyRead.connect(finish_after_ack)
        socket.errorOccurred.connect(finish_after_error)
        try:
            if socket.write(wire_message) != len(wire_message):
                return False
            socket.flush()
            if not socket.canReadLine():
                timer.timeout.connect(loop.quit)
                timer.start(3000)
                loop.exec(QEventLoop.ProcessEventsFlag.ExcludeUserInputEvents)
            acknowledgement = bytes(socket.readAll()).strip()
            return acknowledgement == b"ACK"
        finally:
            timer.stop()
            try:
                socket.readyRead.disconnect(finish_after_ack)
                socket.errorOccurred.disconnect(finish_after_error)
            except (RuntimeError, TypeError):
                pass
    except Exception:
        # Reporting is diagnostic only and must never prevent app startup.
        return False
