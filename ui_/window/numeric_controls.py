"""Numeric Qt inputs that never consume mouse-wheel events."""
from __future__ import annotations

from PySide6.QtGui import QWheelEvent
from PySide6.QtWidgets import QDoubleSpinBox, QSpinBox


class _IgnoreWheelMixin:
    """Leave wheel gestures to the surrounding scroll area, not numeric fields."""

    def wheelEvent(self, event: QWheelEvent) -> None:  # noqa: N802 - Qt virtual
        event.ignore()


class NoWheelSpinBox(_IgnoreWheelMixin, QSpinBox):
    """Integer input whose value changes only through deliberate input."""


class NoWheelDoubleSpinBox(_IgnoreWheelMixin, QDoubleSpinBox):
    """Floating-point input whose value changes only through deliberate input."""
