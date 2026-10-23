"""Compact animated light/dark switch used by Settings."""
from __future__ import annotations

import qtawesome as qta
from PySide6.QtCore import Qt, Signal, QRectF
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QWidget


class ThemeSwitch(QWidget):
    """A rounded track with a sliding icon-bearing circular thumb."""

    modeChanged = Signal(str)

    def __init__(self, mode: str = "dark", parent=None):
        super().__init__(parent)
        self._mode = "light" if mode == "light" else "dark"
        self.setObjectName("themeSwitch")
        self.setFixedSize(92, 40)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAccessibleName("Color theme")
        self.setToolTip("Switch between dark and light themes")
        self.set_mode(self._mode)

    @property
    def mode(self) -> str:
        return self._mode

    def set_mode(self, mode: str) -> None:
        if mode not in {"dark", "light"}:
            return
        changed = mode != self._mode
        self._mode = mode
        self.setAccessibleDescription("Dark theme" if mode == "dark" else "Light theme")
        self.update()
        if changed:
            # The parent may explicitly sync the switch after changing theme
            # elsewhere; no signal is emitted here to avoid recursive updates.
            pass

    def toggle(self) -> None:
        self._mode = "light" if self._mode == "dark" else "dark"
        self.update()
        self.modeChanged.emit(self._mode)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.toggle()
            event.accept()
            return
        super().mousePressEvent(event)

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key.Key_Space, Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.toggle()
            event.accept()
            return
        super().keyPressEvent(event)

    def paintEvent(self, event):
        del event
        dark = self._mode == "dark"
        track = QColor("#354152" if dark else "#d8e4ef")
        border = QColor("#526175" if dark else "#c3d1df")
        thumb = QColor("#eaf0f7" if dark else "#ffffff")
        icon_color = "#263449" if dark else "#c07a16"

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(border)
        painter.setBrush(track)
        # A rounded-rectangle track rather than a full ellipse keeps the
        # contemporary soft-capsule look while preserving clear end stops.
        painter.drawRoundedRect(QRectF(1, 1, self.width() - 2, self.height() - 2), 13, 13)

        diameter = 30
        x = 5 if dark else self.width() - diameter - 5
        y = (self.height() - diameter) / 2
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(thumb)
        painter.drawEllipse(QRectF(x, y, diameter, diameter))

        icon_name = "fa6s.moon" if dark else "fa6s.sun"
        pixmap = qta.icon(icon_name, color=icon_color).pixmap(16, 16)
        painter.drawPixmap(int(x + (diameter - pixmap.width()) / 2),
                           int(y + (diameter - pixmap.height()) / 2), pixmap)
        painter.end()
