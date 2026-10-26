"""Opaque two-frame circular reveal for the application's color-theme transition."""
from __future__ import annotations

import math

from PySide6.QtCore import (
    QAbstractAnimation,
    QEvent,
    QEasingCurve,
    QPointF,
    Qt,
    QVariantAnimation,
    Signal,
)
from PySide6.QtGui import QPainter, QPainterPath, QPixmap
from PySide6.QtWidgets import QWidget


class CircularThemeReveal(QWidget):
    """Reveal a new widget snapshot inside a growing circle over the old snapshot.

    Both frames are opaque pixmaps captured from the real widget tree. Drawing the
    new frame underneath and clipping the old frame outside the circle makes the
    individual widgets themselves change as the circular reveal passes over them.
    It does not rely on translucent child-window composition.
    """

    finished = Signal()

    def __init__(
        self,
        parent: QWidget,
        old_snapshot: QPixmap,
        new_snapshot: QPixmap,
        center,
        duration_ms: int = 460,
    ) -> None:
        super().__init__(parent)
        self._old_snapshot = old_snapshot
        self._new_snapshot = new_snapshot
        self._center = QPointF(center)
        self._radius = 0.0
        self._duration_ms = max(1, int(duration_ms))

        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)
        self.setAutoFillBackground(False)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setStyleSheet("border: none;")
        self.setGeometry(parent.rect())
        parent.installEventFilter(self)

        self._animation = QVariantAnimation(self)
        self._animation.setDuration(self._duration_ms)
        self._animation.setStartValue(0.0)
        self._animation.setEndValue(self._maximum_radius())
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._animation.valueChanged.connect(self._set_radius)
        self._animation.finished.connect(self._finish)

    @property
    def radius(self) -> float:
        return self._radius

    def _maximum_radius(self) -> float:
        width = max(0.0, float(self.width()))
        height = max(0.0, float(self.height()))
        x = self._center.x()
        y = self._center.y()
        return max(
            math.hypot(x, y),
            math.hypot(width - x, y),
            math.hypot(x, height - y),
            math.hypot(width - x, height - y),
        ) + 2.0

    def start(self) -> None:
        self._animation.setEndValue(self._maximum_radius())
        self._animation.start()

    def cancel(self) -> None:
        self._animation.stop()
        self.hide()
        self.deleteLater()

    def _set_radius(self, value) -> None:
        self._radius = max(0.0, float(value))
        self.update()

    def _finish(self) -> None:
        self._radius = self._maximum_radius()
        self.update()
        self.hide()
        self.finished.emit()
        self.deleteLater()

    def eventFilter(self, watched, event) -> bool:
        if watched is self.parent() and event.type() == QEvent.Type.Resize:
            self.setGeometry(self.parent().rect())
            if self._animation.state() == QAbstractAnimation.State.Running:
                self._animation.setEndValue(self._maximum_radius())
        return super().eventFilter(watched, event)

    def paintEvent(self, event) -> None:
        del event
        painter = QPainter(self)
        if not painter.isActive():
            return

        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        # The base layer is always the actual new-theme UI frame and is fully
        # opaque. The old frame is drawn over it only outside the reveal circle.
        painter.drawPixmap(self.rect(), self._new_snapshot)

        old_frame_region = QPainterPath()
        old_frame_region.addRect(self.rect())
        if self._radius > 0:
            reveal_region = QPainterPath()
            reveal_region.addEllipse(self._center, self._radius, self._radius)
            old_frame_region = old_frame_region.subtracted(reveal_region)

        painter.setClipPath(old_frame_region)
        painter.drawPixmap(self.rect(), self._old_snapshot)
        painter.end()
