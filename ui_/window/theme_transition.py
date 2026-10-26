"""Circular reveal transition used when switching the application color theme."""
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
from PySide6.QtGui import QColor, QPainter, QPixmap
from PySide6.QtWidgets import QWidget


class CircularThemeReveal(QWidget):
    """Keep a snapshot of the old theme visible outside an expanding clear circle."""

    finished = Signal()

    def __init__(
        self,
        parent: QWidget,
        snapshot: QPixmap,
        center,
        duration_ms: int = 460,
    ) -> None:
        super().__init__(parent)
        self._snapshot = snapshot
        self._center = QPointF(center)
        self._radius = 0.0
        self._duration_ms = max(1, int(duration_ms))

        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)
        self.setAutoFillBackground(False)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setStyleSheet("background-color: transparent; border: none;")
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
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Source)
        painter.fillRect(self.rect(), QColor(0, 0, 0, 0))
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)
        painter.drawPixmap(self.rect(), self._snapshot)

        if self._radius > 0:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(0, 0, 0, 0))
            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Clear)
            painter.drawEllipse(self._center, self._radius, self._radius)
        painter.end()
