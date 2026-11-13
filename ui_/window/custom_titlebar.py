"""Compact Windows title bar with native multi-monitor window dragging."""
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QLabel, QWidget, QHBoxLayout, QPushButton, QSizePolicy
import qtawesome as qta

from utils import resource_path


_TITLE_BAR_HEIGHT = 40
_WINDOW_CONTROL_BUTTON_WIDTH = 46


class CustomTitleBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_ = parent
        self.setObjectName("customTitleBar")
        self.setFixedHeight(_TITLE_BAR_HEIGHT)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        # Keep the app identity anchored to the left, using the high-resolution
        # PNG rather than scaling the small Windows ICO.
        self.app_icon = QLabel(self)
        self.app_icon.setObjectName("customTitleBarAppIcon")
        self.app_icon.setAccessibleName("TorProxy application icon")
        self.app_icon.setToolTip("TorProxy")
        self.app_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.app_icon.setFixedSize(24, 24)
        self.app_icon.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self._source_app_icon = QPixmap(resource_path("assets/icon.png"))

        self.title = QLabel("TorProxy", self)
        self.title.setObjectName("windowTitle")
        self.title.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

        # Keep the window controls in their own edge-to-edge strip. Its zero-
        # margin layout makes the buttons meet one another and the titlebar edges.
        self.window_controls = QWidget(self)
        self.window_controls.setObjectName("titleBarWindowControls")
        self.window_controls.setFixedSize(
            3 * _WINDOW_CONTROL_BUTTON_WIDTH, _TITLE_BAR_HEIGHT
        )
        self.window_controls_layout = QHBoxLayout(self.window_controls)
        self.window_controls_layout.setContentsMargins(0, 0, 0, 0)
        self.window_controls_layout.setSpacing(0)

        self.btn_min = QPushButton(self.window_controls)
        self.btn_max = QPushButton(self.window_controls)
        self.btn_close = QPushButton(self.window_controls)
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
            button.setFixedSize(_WINDOW_CONTROL_BUTTON_WIDTH, _TITLE_BAR_HEIGHT)
            button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            button.setAutoDefault(False)
            button.setDefault(False)

        self.window_controls_layout.addWidget(self.btn_min)
        self.window_controls_layout.addWidget(self.btn_max)
        self.window_controls_layout.addWidget(self.btn_close)

        self.btn_min.clicked.connect(parent.showMinimized)
        self.btn_max.clicked.connect(self._toggle_maximized)
        self.btn_close.clicked.connect(parent.hide_to_tray)
        self.btn_close.setAccessibleName("Hide TorProxy to the system tray")
        self.btn_min.setAccessibleName("Minimize window")
        self.btn_max.setAccessibleName("Maximize or restore window")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 0, 0)
        layout.setSpacing(5)
        layout.addWidget(self.app_icon, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.title, 0, Qt.AlignmentFlag.AlignVCenter)
        # The flexible gap belongs between the left-aligned branding and
        # right-aligned window controls, not before the branding.
        layout.addStretch(1)
        layout.addWidget(self.window_controls, 0, Qt.AlignmentFlag.AlignRight)
        self._start_pos = None
        self._screen_signal_connected = False

        self._refresh_app_icon()

    def _refresh_app_icon(self, *_args):
        """Render the PNG at the current screen's device-pixel ratio."""
        if self._source_app_icon.isNull():
            self.app_icon.clear()
            return

        ratio = max(1.0, float(self.devicePixelRatioF()))
        physical_size = QSize(round(20 * ratio), round(20 * ratio))
        pixmap = self._source_app_icon.scaled(
            physical_size,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        pixmap.setDevicePixelRatio(ratio)
        self.app_icon.setPixmap(pixmap)

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
        self._refresh_app_icon()
        if not self._screen_signal_connected:
            handle = self.window().windowHandle()
            if handle is not None:
                handle.screenChanged.connect(self._refresh_app_icon)
                self._screen_signal_connected = True
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
