"""Helpers for starting child processes without flashing console windows."""
from __future__ import annotations

import os
import subprocess


def hidden_subprocess_kwargs() -> dict[str, object]:
    """Return Windows flags that suppress console windows for CLI child processes.

    Keep stdout/stderr redirection and process lifetime under each caller's
    control. CREATE_NO_WINDOW prevents a console host from being created;
    STARTF_USESHOWWINDOW is an additional SW_HIDE hint for Windows runtimes.
    """
    if os.name != "nt":
        return {}

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0  # SW_HIDE
    return {
        "creationflags": subprocess.CREATE_NO_WINDOW,
        "startupinfo": startupinfo,
    }
