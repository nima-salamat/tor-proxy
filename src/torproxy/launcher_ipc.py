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
        from PySide6.QtCore import QIODevice
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
        if socket.write(encoded + b"\n") < 0:
            return False
        return bool(socket.waitForBytesWritten(1200))
    except Exception:
        # Reporting is best-effort; a failed launcher channel must never stop
        # the actual application from starting or running.
        return False
