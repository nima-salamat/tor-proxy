"""Compact animated light/dark switch used by Settings."""
from __future__ import annotations

import qtawesome as qta
from PySide6.QtCore import Qt, Signal, QRect, QRectF, QVariantAnimation, QEasingCurve
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QWidget


class ThemeSwitch(QWidget):
    """A rounded track with a sliding icon-bearing circular thumb."""

    modeChanged = Signal(str)

    def __init__(self, mode: str = "dark", parent=None):
        super().__init__(parent)
        self._mode = "light" if mode == "light" else "dark"
        self._thumb_progress = 1.0 if self._mode == "light" else 0.0
        self._animation = QVariantAnimation(self)
        self._animation.setDuration(180)
        self._animation.setEasingCurve(QEasingCurve.Type.InOutCubic)
        self._animation.valueChanged.connect(self._set_thumb_progress)
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

    def set_mode(self, mode: str, *, animate: bool = False) -> None:
        if mode not in {"dark", "light"}:
            return
        changed = mode != self._mode
        self._mode = mode
        self.setAccessibleDescription("Dark theme" if mode == "dark" else "Light theme")
        if not changed:
            # Do not interrupt an animation when the parent synchronizes the
            # modeChanged signal emitted by a click on this very control.
            return
        target = 1.0 if mode == "light" else 0.0
        self._animation.stop()
        if animate and abs(self._thumb_progress - target) > 0.01:
            self._animation.setStartValue(self._thumb_progress)
            self._animation.setEndValue(target)
            self._animation.start()
        else:
            self._thumb_progress = target
            self.update()

    def _set_thumb_progress(self, value) -> None:
        self._thumb_progress = float(value)
        self.update()

    def toggle(self) -> None:
        new_mode = "light" if self._mode == "dark" else "dark"
        self.set_mode(new_mode, animate=True)
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
        left = 5
        right = self.width() - diameter - 5
        x = left + (right - left) * self._thumb_progress
        y = (self.height() - diameter) / 2
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(thumb)
        painter.drawEllipse(QRectF(x, y, diameter, diameter))

        icon_name = "fa6s.moon" if dark else "fa6s.sun"
        icon = qta.icon(icon_name, color=icon_color)
        # Paint the QIcon into a fixed logical-pixel square. Drawing a raw
        # pixmap can look off-center on high-DPI displays because its physical
        # pixel size/device-pixel-ratio differs from the intended logical size.
        icon_size = 18
        icon_rect = QRect(
            round(x + (diameter - icon_size) / 2),
            round(y + (diameter - icon_size) / 2),
            icon_size,
            icon_size,
        )
        icon.paint(painter, icon_rect, Qt.AlignmentFlag.AlignCenter)
        painter.end()
