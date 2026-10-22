from PySide6.QtWidgets import QPushButton, QSizePolicy
from PySide6.QtCore import Qt, QEasingCurve, QPropertyAnimation, Property, QTimer
from PySide6.QtGui import QPainter, QColor, QBrush, QPen

import logging
logger = logging.getLogger(__name__)

class PulseButton(QPushButton):
    def __init__(self, text):
        super().__init__(text)
        self.setMinimumSize(180, 180)
        self.setMaximumSize(250, 250)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        self.connected = False
        self.hovered = False

        # primary pulse (main circle)
        self._pulse_radius = 0
        self._pulse_color = "#2ecc71"
        self.outer_anim = QPropertyAnimation(self, b"pulseRadius")
        self.outer_anim.setStartValue(0)
        self.outer_anim.setEndValue(104)
        self.outer_anim.setDuration(800)
        self.outer_anim.setLoopCount(-1)
        self.outer_anim.setEasingCurve(QEasingCurve.Type.OutQuad)

        # secondary pulse (soft halo)
        self._halo_radius = 0
        self.halo_anim = QPropertyAnimation(self, b"haloRadius")
        self.halo_anim.setStartValue(0)
        self.halo_anim.setEndValue(132)
        self.halo_anim.setDuration(1500)
        self.halo_anim.setLoopCount(-1)
        self.halo_anim.setEasingCurve(QEasingCurve.Type.InOutQuad)

        # inner breathe (for disconnected state)
        self._inner_radius = 0
        self.inner_anim = QPropertyAnimation(self, b"innerRadius")
        self.inner_anim.setStartValue(0)
        self.inner_anim.setEndValue(30)
        self.inner_anim.setDuration(1200)
        self.inner_anim.setLoopCount(-1)
        self.inner_anim.setEasingCurve(QEasingCurve.Type.InOutQuad)

        self.updateStyle()
        self.clicked.connect(self.toggle_state)

        # keep event loop alive
        self._idle_timer = QTimer(self)
        self._idle_timer.setInterval(1000)
        self._idle_timer.timeout.connect(lambda: None)
        self._idle_timer.start()

    # --------------------
    # hover events
    # --------------------
    def enterEvent(self, event):
        self.hovered = True
        if self.connected:
            self.outer_anim.setDuration(500)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.hovered = False
        if self.connected:
            self.outer_anim.setDuration(800)
        super().leaveEvent(event)

    # --------------------
    # Style / state
    # --------------------
    def updateStyle(self):
        if self.connected:
            self.setText("DISCONNECT")
            self._pulse_color = "#e74c3c"
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: #b03a2e;
                    color: white;
                    font-size: 20px;
                    font-weight: 700;
                    border-radius: {min(self.width(), self.height()) // 2}px;
                    border: none;
                }}
                QPushButton:hover {{
                    background-color: #96281b;
                }}
            """)
            self.inner_anim.stop()
            self.outer_anim.start()
            self.halo_anim.start()
        else:
            self.setText("CONNECT")
            self._pulse_color = "#2ecc71"
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: #27ae60;
                    color: white;
                    font-size: 20px;
                    font-weight: 700;
                    border-radius: 125px;
                    border: none;
                }}
                QPushButton:hover {{
                    background-color: #199441;
                }}
            """)
            self.outer_anim.stop()
            self.halo_anim.stop()
            self._pulse_radius = 0
            self._halo_radius = 0
            self.inner_anim.start()
        self.update()

    def toggle_state(self):
        self.connected = not self.connected
        self.updateStyle()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        diameter = max(1, min(self.width(), self.height()))
        self.outer_anim.setEndValue(int(diameter * 0.43))
        self.halo_anim.setEndValue(int(diameter * 0.54))
        self.inner_anim.setEndValue(int(diameter * 0.13))
        self.updateStyle()

    # --------------------
    # Painting
    # --------------------
    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        center = self.rect().center()

        # inner breathe
        if self._inner_radius and not self.connected:
            color = QColor(self._pulse_color)
            color.setAlphaF(0.55 * (1 - self._inner_radius / max(1, float(self.inner_anim.endValue()))))
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(center, int(self._inner_radius), int(self._inner_radius))

        # outer pulse (connected)
        if self._pulse_radius and self.connected:
            color = QColor(self._pulse_color)
            color.setAlphaF(0.6 * (1 - self._pulse_radius / max(1, float(self.outer_anim.endValue()))))
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(center, int(self._pulse_radius), int(self._pulse_radius))

        # halo (big outer circle)
        if self._halo_radius and self.connected:
            color = QColor(self._pulse_color)
            color.setAlphaF(0.2 * (1 - self._halo_radius / max(1, float(self.halo_anim.endValue()))))
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(center, int(self._halo_radius), int(self._halo_radius))

        painter.end()

    # --------------------
    # Properties
    # --------------------
    def getPulseRadius(self):
        return int(self._pulse_radius)
    def setPulseRadius(self, value):
        self._pulse_radius = float(value)
        self.update()
    pulseRadius = Property(int, getPulseRadius, setPulseRadius)

    def getHaloRadius(self):
        return int(self._halo_radius)
    def setHaloRadius(self, value):
        self._halo_radius = float(value)
        self.update()
    haloRadius = Property(int, getHaloRadius, setHaloRadius)

    def getInnerRadius(self):
        return int(self._inner_radius)
    def setInnerRadius(self, value):
        self._inner_radius = float(value)
        self.update()
    innerRadius = Property(int, getInnerRadius, setInnerRadius)
