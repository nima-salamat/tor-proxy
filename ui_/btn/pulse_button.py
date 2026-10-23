from PySide6.QtWidgets import QPushButton
from PySide6.QtCore import Qt, QEasingCurve, QPropertyAnimation, Property
from PySide6.QtGui import QPainter, QColor, QBrush, QPen, QRadialGradient


class PulseButton(QPushButton):
    """Fixed-circle, animated Tor connect control; the controller owns its state."""

    def __init__(self, text="Connect"):
        super().__init__(text)
        self.setFixedSize(264, 264)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.connected = False
        self.hovered = False
        self._pulse_radius = 103.0
        self._halo_radius = 115.0

        self.outer_anim = QPropertyAnimation(self, b"pulseRadius", self)
        self.outer_anim.setStartValue(101)
        self.outer_anim.setEndValue(124)
        self.outer_anim.setDuration(1800)
        self.outer_anim.setLoopCount(-1)
        self.outer_anim.setEasingCurve(QEasingCurve.Type.InOutSine)

        self.halo_anim = QPropertyAnimation(self, b"haloRadius", self)
        self.halo_anim.setStartValue(108)
        self.halo_anim.setEndValue(127)
        self.halo_anim.setDuration(2600)
        self.halo_anim.setLoopCount(-1)
        self.halo_anim.setEasingCurve(QEasingCurve.Type.InOutSine)

        self.outer_anim.start()
        self.halo_anim.start()

    def set_connected(self, connected):
        self.connected = bool(connected)
        self.setText("DISCONNECT" if self.connected else "CONNECT")
        self.update()

    def enterEvent(self, event):
        self.hovered = True
        super().enterEvent(event)
        self.update()

    def leaveEvent(self, event):
        self.hovered = False
        super().leaveEvent(event)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        center = self.rect().center()
        base_color = QColor("#ff526d" if self.connected else "#2eae69")
        highlight = QColor("#ff91a2" if self.connected else "#82e8ae")
        if self.hovered:
            highlight = highlight.lighter(108)

        # Animated rings are circular, low-alpha, and outside the main button face.
        for radius, alpha, width in (
            (self._halo_radius, 32, 2.0),
            (self._pulse_radius, 72, 2.4),
        ):
            ring_color = QColor(base_color)
            ring_color.setAlpha(alpha)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(ring_color, width))
            painter.drawEllipse(center, int(radius), int(radius))

        main_radius = 100
        gradient = QRadialGradient(center.x() - 30, center.y() - 37, main_radius * 2.0)
        gradient.setColorAt(0.0, highlight)
        gradient.setColorAt(0.62, base_color)
        gradient.setColorAt(1.0, QColor("#176942" if not self.connected else "#9d2941"))
        painter.setPen(QPen(base_color.lighter(128), 1.4))
        painter.setBrush(QBrush(gradient))
        painter.drawEllipse(center, main_radius, main_radius)

        outline = QColor("#ffffff")
        outline.setAlpha(45)
        painter.setPen(QPen(outline, 1.2))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(center, 78, 78)

        painter.setPen(QColor("#ffffff"))
        font = painter.font()
        font.setBold(True)
        font.setPointSize(14)
        painter.setFont(font)
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self.text())
        painter.end()

    def getPulseRadius(self):
        return float(self._pulse_radius)

    def setPulseRadius(self, value):
        self._pulse_radius = float(value)
        self.update()

    pulseRadius = Property(float, getPulseRadius, setPulseRadius)

    def getHaloRadius(self):
        return float(self._halo_radius)

    def setHaloRadius(self, value):
        self._halo_radius = float(value)
        self.update()

    haloRadius = Property(float, getHaloRadius, setHaloRadius)
