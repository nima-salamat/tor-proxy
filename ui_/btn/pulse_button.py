from PySide6.QtWidgets import QPushButton
from PySide6.QtCore import Qt, QEasingCurve, QPropertyAnimation, Property, QTimer
from PySide6.QtGui import QPainter, QColor, QBrush, QPen, QRadialGradient


class PulseButton(QPushButton):
    """Circular, animated Connect button synchronized with Tor's actual lifecycle."""

    def __init__(self, text="CONNECT"):
        super().__init__(text)
        self.setFixedSize(264, 264)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._state = "disconnected"
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

        self._connected_feedback_timer = QTimer(self)
        self._connected_feedback_timer.setSingleShot(True)
        self._connected_feedback_timer.timeout.connect(self._finish_connected_feedback)
        self.outer_anim.start()
        self.halo_anim.start()

    @property
    def state(self):
        return self._state

    def _set_state(self, state, text):
        self._connected_feedback_timer.stop()
        self._state = state
        self.connected = state in {"connected", "disconnect", "stopping"}
        # Give startup a quicker, more noticeable pulse while keeping the
        # connected/disconnected idle animation calm.
        animation_speeds = {
            "disconnected": (1800, 2600),
            "connecting": (760, 1280),
            "connected": (1350, 2100),
            "disconnect": (2050, 2900),
            "stopping": (980, 1550),
        }
        outer_duration, halo_duration = animation_speeds.get(state, (1800, 2600))
        self.outer_anim.setDuration(outer_duration)
        self.halo_anim.setDuration(halo_duration)
        self.setText(text)
        self.update()

    def set_connecting(self):
        self._set_state("connecting", "CONNECTING…")
        self.setToolTip("Starting Tor and waiting for bootstrap to complete.")

    def set_connected(self, connected):
        """Show a brief success acknowledgement, then leave a red Disconnect button."""
        if not connected:
            self._set_state("disconnected", "CONNECT")
            self.setToolTip("Connect to Tor.")
            return
        self._set_state("connected", "CONNECTED")
        self.setToolTip("Tor is connected. Disconnect from Tor.")
        self._connected_feedback_timer.start(1000)

    def _finish_connected_feedback(self):
        if self._state == "connected":
            self._state = "disconnect"
            self.connected = True
            self.setText("DISCONNECT")
            self.update()

    def set_disconnecting(self):
        self._set_state("stopping", "DISCONNECTING…")
        self.setToolTip("Stopping Tor and the local proxy.")

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
        colors = {
            "disconnected": ("#2eae69", "#82e8ae", "#176942"),
            "connecting": ("#328bd4", "#9bd1ff", "#1d4e89"),
            "connected": ("#2cbb88", "#a6f4d3", "#146953"),
            "disconnect": ("#ff526d", "#ff9caa", "#9d2941"),
            "stopping": ("#e58a44", "#ffd0a5", "#8a4321"),
        }
        base, highlight, edge = colors.get(self._state, colors["disconnected"])
        base_color = QColor(base)
        highlight_color = QColor(highlight)
        if self.hovered:
            highlight_color = highlight_color.lighter(108)

        # During startup the outer rings move faster and use a cool blue color.
        for radius, alpha, width, low, high in (
            (self._halo_radius, 36, 2.0, 108.0, 127.0),
            (self._pulse_radius, 78, 2.4, 101.0, 124.0),
        ):
            ring_color = QColor(base_color)
            progress = min(1.0, max(0.0, (radius - low) / (high - low)))
            ring_color.setAlpha(int(alpha * (1.0 - 0.78 * progress)))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(ring_color, width))
            painter.drawEllipse(center, int(radius), int(radius))

        main_radius = 100
        gradient = QRadialGradient(center.x() - 30, center.y() - 37, main_radius * 2.0)
        gradient.setColorAt(0.0, highlight_color)
        gradient.setColorAt(0.62, base_color)
        gradient.setColorAt(1.0, QColor(edge))
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
        font.setPointSize(13 if self._state in {"connecting", "stopping"} else 14)
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
