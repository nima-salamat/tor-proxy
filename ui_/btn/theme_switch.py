"""Compact animated light/dark switch used by Settings."""
from __future__ import annotations

import qtawesome as qta
from PySide6.QtCore import (
    QAbstractAnimation,
    QEasingCurve,
    QRect,
    QRectF,
    Qt,
    Signal,
    QVariantAnimation,
)
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QWidget


class ThemeSwitch(QWidget):
    """A rounded track with a sliding icon-bearing circular thumb."""

    modeChanged = Signal(str)

    def __init__(self, mode: str = "dark", parent=None):
        super().__init__(parent)
        self._mode = "light" if mode == "light" else "dark"
        self._thumb_progress = 1.0 if self._mode == "light" else 0.0
        self._deferred_mode = None
        self._icons = {
            "dark": qta.icon("fa6s.moon", color="#263449"),
            "light": qta.icon("fa6s.sun", color="#c07a16"),
        }
        self._animation = QVariantAnimation(self)
        self._animation.setDuration(220)
        self._animation.setEasingCurve(QEasingCurve.Type.InOutCubic)
        self._animation.valueChanged.connect(self._on_animation_value)
        self._animation.finished.connect(self._finish_animation)
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

    @property
    def is_animating(self) -> bool:
        return self._animation.state() == QAbstractAnimation.State.Running

    def set_mode(self, mode: str, *, animate: bool = False) -> None:
        """Synchronize a mode chosen elsewhere; clicked changes commit at mid-slide."""
        if mode not in {"dark", "light"}:
            return
        changed = mode != self._mode
        if not changed:
            # During a click-driven transition the owner sends this same mode
            # back from the mid-slide signal. Keep the running thumb animation.
            return

        self._animation.stop()
        self._deferred_mode = None
        self._mode = mode
        self.setAccessibleDescription("Dark theme" if mode == "dark" else "Light theme")
        target = 1.0 if mode == "light" else 0.0
        if animate and abs(self._thumb_progress - target) > 0.01:
            self._animation.setStartValue(self._thumb_progress)
            self._animation.setEndValue(target)
            self._animation.start()
        else:
            self._thumb_progress = target
            self.update()

    def _on_animation_value(self, value) -> None:
        self._thumb_progress = float(value)
        self.update()

        if (
            self._deferred_mode is not None
            and self._deferred_mode != self._mode
            and self._animation.currentTime() >= self._animation.duration() / 2
        ):
            # Change the icon/theme semantic at the visual midpoint. Emitting
            # here starts the circular reveal while the thumb keeps sliding.
            mode = self._deferred_mode
            self._deferred_mode = None
            self._mode = mode
            self.setAccessibleDescription("Dark theme" if mode == "dark" else "Light theme")
            self.update()
            self.modeChanged.emit(mode)

    def _finish_animation(self) -> None:
        end_value = self._animation.endValue()
        if end_value is not None:
            self._thumb_progress = float(end_value)
        if self._deferred_mode is not None and self._deferred_mode != self._mode:
            mode = self._deferred_mode
            self._deferred_mode = None
            self._mode = mode
            self.setAccessibleDescription("Dark theme" if mode == "dark" else "Light theme")
            self.modeChanged.emit(mode)
        self.update()

    def _set_thumb_progress(self, value) -> None:
        # Kept as a small compatibility helper for integrations using the
        # switch's animation progress directly.
        self._thumb_progress = float(value)
        self.update()

    def toggle(self) -> None:
        running = self.is_animating
        base_mode = (
            self._deferred_mode
            if running and self._deferred_mode is not None
            else self._mode
        )
        new_mode = "light" if base_mode == "dark" else "dark"
        self._animation.stop()

        target = 1.0 if new_mode == "light" else 0.0
        self._deferred_mode = new_mode if new_mode != self._mode else None
        self._animation.setStartValue(self._thumb_progress)
        self._animation.setEndValue(target)
        if abs(self._thumb_progress - target) <= 0.01:
            self._thumb_progress = target
            if self._deferred_mode is not None:
                mode = self._deferred_mode
                self._deferred_mode = None
                self._mode = mode
                self.setAccessibleDescription("Dark theme" if mode == "dark" else "Light theme")
                self.modeChanged.emit(mode)
            self.update()
            return
        self._animation.start()

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

        # Icons are created once in __init__; do not build a new QIcon on
        # every paint while the thumb animation is ticking.
        icon = self._icons[self._mode]
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
