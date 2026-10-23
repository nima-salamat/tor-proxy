"""Compact Windows title bar with native multi-monitor window dragging."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QWidget, QHBoxLayout, QPushButton, QSizePolicy
import qtawesome as qta


class CustomTitleBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_ = parent
        self.setObjectName("customTitleBar")
        self.setFixedHeight(40)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        self.title = QLabel("TorProxy", self)
        self.title.setObjectName("windowTitle")
        self.title.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

        self.btn_min = QPushButton(self)
        self.btn_max = QPushButton(self)
        self.btn_close = QPushButton(self)
        self._icon_color = "#eff1f4"
        self.btn_min.setIcon(qta.icon("fa6s.window-minimize", color=self._icon_color))
        self.btn_max.setIcon(qta.icon("fa6s.window-maximize", color=self._icon_color))
        self.btn_close.setIcon(qta.icon("fa6s.xmark", color=self._icon_color))
        self.btn_min.setObjectName("titleBarButton")
        self.btn_max.setObjectName("titleBarButton")
        self.btn_close.setObjectName("titleBarCloseButton")
        self.btn_min.setToolTip("Minimize")
        self.btn_max.setToolTip("Maximize / restore")
        self.btn_close.setToolTip("Hide TorProxy to the system tray")
        for button in (self.btn_min, self.btn_max, self.btn_close):
            button.setFixedSize(36, 30)
            button.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        self.btn_min.clicked.connect(parent.showMinimized)
        self.btn_max.clicked.connect(self._toggle_maximized)
        self.btn_close.clicked.connect(parent.hide_to_tray)
        self.btn_close.setAccessibleName("Hide TorProxy to the system tray")
        self.btn_min.setAccessibleName("Minimize window")
        self.btn_max.setAccessibleName("Maximize or restore window")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 5, 7, 5)
        layout.setSpacing(5)
        layout.addWidget(self.title)
        layout.addStretch(1)
        layout.addWidget(self.btn_min)
        layout.addWidget(self.btn_max)
        layout.addWidget(self.btn_close)
        self._start_pos = None

    def _toggle_maximized(self):
        if self.parent_.isMaximized():
            self.parent_.showNormal()
        else:
            self.parent_.showMaximized()
        self._sync_maximize_button()

    def update_theme(self, color):
        self._icon_color = color
        self.btn_min.setIcon(qta.icon("fa6s.window-minimize", color=color))
        self.btn_close.setIcon(qta.icon("fa6s.xmark", color=color))
        self._sync_maximize_button()

    def _sync_maximize_button(self):
        maximized = self.parent_.isMaximized()
        icon_name = "fa6s.window-restore" if maximized else "fa6s.window-maximize"
        self.btn_max.setIcon(qta.icon(icon_name, color=self._icon_color))
        self.btn_max.setToolTip("Restore" if maximized else "Maximize")

    def showEvent(self, event):
        super().showEvent(event)
        self._sync_maximize_button()

    def mousePressEvent(self, event):
        if event.button() != Qt.MouseButton.LeftButton:
            super().mousePressEvent(event)
            return
        handle = self.parent_.windowHandle()
        if handle is not None:
            try:
                if handle.startSystemMove():
                    event.accept()
                    return
            except (AttributeError, RuntimeError):
                pass
        # Fallback for window systems that do not implement startSystemMove.
        # Use global coordinates; the main window's moveEvent applies a
        # multi-monitor-aware visibility clamp after each fallback move.
        self._start_pos = event.globalPosition().toPoint()
        event.accept()

    def mouseMoveEvent(self, event):
        if self._start_pos is not None and event.buttons() & Qt.MouseButton.LeftButton:
            current = event.globalPosition().toPoint()
            self.parent_.move(self.parent_.pos() + current - self._start_pos)
            self._start_pos = current
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        self._start_pos = None
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._toggle_maximized()
            event.accept()
            return
        super().mouseDoubleClickEvent(event)
