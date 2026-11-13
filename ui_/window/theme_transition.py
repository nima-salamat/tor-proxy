"""Single-snapshot circular reveal for the application's color-theme transition."""
from __future__ import annotations

import logging
import math
import time

from PySide6.QtCore import (
    QAbstractAnimation,
    QEvent,
    QEasingCurve,
    QPoint,
    QPointF,
    Qt,
    QVariantAnimation,
    Signal,
)
from PySide6.QtGui import QPainter, QPainterPath, QPixmap, QRegion, QRectF
from PySide6.QtWidgets import QWidget

logger = logging.getLogger(__name__)


class CircularThemeReveal(QWidget):
    """Reveal the live new theme through a growing hole in one old-frame snapshot.

    The window is already themed when this overlay appears. It therefore needs
    only one captured pixmap: draw that old frame outside the animated circle and
    let the live themed widgets show through inside it. This avoids the second
    full-window grab and halves the full-frame image blits per animation frame.
    """

    finished = Signal()

    def __init__(
        self,
        parent: QWidget,
        old_snapshot: QPixmap,
        center,
        duration_ms: int = 300,
        live_widgets=(),
    ) -> None:
        super().__init__(parent)
        self._old_snapshot = old_snapshot
        self._center = QPointF(center)
        self._radius = 0.0
        self._duration_ms = max(1, int(duration_ms))
        self._live_widgets = tuple(widget for widget in live_widgets if widget is not None)
        self._paint_frames = 0
        self._paint_total_ms = 0.0
        self._paint_max_ms = 0.0

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
        if self._paint_frames:
            average_ms = self._paint_total_ms / self._paint_frames
            if self._paint_max_ms >= 16.0:
                logger.info(
                    "Theme reveal rendered %d frames; average paint %.1f ms, max %.1f ms.",
                    self._paint_frames,
                    average_ms,
                    self._paint_max_ms,
                )
            else:
                logger.debug(
                    "Theme reveal rendered %d frames; average paint %.1f ms, max %.1f ms.",
                    self._paint_frames,
                    average_ms,
                    self._paint_max_ms,
                )
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
        started = time.perf_counter()
        painter = QPainter(self)
        if not painter.isActive():
            return

        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        # Odd-even fill creates a hole in the full-window clip. Only the old
        # snapshot is painted, so the updated widgets remain live underneath.
        old_frame_region = QPainterPath()
        old_frame_region.setFillRule(Qt.FillRule.OddEvenFill)
        old_frame_region.addRect(QRectF(self.rect()))
        if self._radius > 0:
            old_frame_region.addEllipse(self._center, self._radius, self._radius)
        painter.setClipPath(old_frame_region)
        painter.drawPixmap(self.rect(), self._old_snapshot)
        painter.setClipping(False)

        # Keep explicitly requested controls live above the old-frame overlay.
        for widget in self._live_widgets:
            if not widget.isVisible():
                continue
            offset = widget.mapTo(self.parentWidget(), QPoint(0, 0))
            widget.render(
                painter,
                offset,
                QRegion(),
                QWidget.RenderFlag.DrawWindowBackground | QWidget.RenderFlag.DrawChildren,
            )
        painter.end()

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        self._paint_frames += 1
        self._paint_total_ms += elapsed_ms
        self._paint_max_ms = max(self._paint_max_ms, elapsed_ms)
