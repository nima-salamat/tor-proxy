"""Resolve the OS appearance used by TorProxy's system-following theme."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QPalette


def resolve_system_theme(app=None) -> str:
    """Return dark or light using Qt's native platform color scheme.

    Qt 6.5+ reports desktop appearance through QStyleHints and emits
    colorSchemeChanged when the OS theme changes. If a platform plugin cannot
    report a scheme, use its current window palette as a conservative fallback.
    """
    app = app or QGuiApplication.instance()
    if app is None:
        return "light"

    try:
        scheme = app.styleHints().colorScheme()
        if scheme == Qt.ColorScheme.Dark:
            return "dark"
        if scheme == Qt.ColorScheme.Light:
            return "light"
    except (AttributeError, RuntimeError, TypeError):
        pass

    try:
        window_color = app.palette().color(QPalette.ColorRole.Window)
        return "dark" if window_color.lightness() < 128 else "light"
    except (AttributeError, RuntimeError, TypeError):
        return "light"
