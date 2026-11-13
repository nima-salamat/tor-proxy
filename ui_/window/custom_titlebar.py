"""Compact Windows title bar with native multi-monitor window dragging."""
from PySide6.QtCore import QEvent, Qt, QSize, QPoint, QRect, QTimer
from PySide6.QtGui import QGuiApplication, QPixmap
from PySide6.QtWidgets import QLabel, QWidget, QHBoxLayout, QPushButton, QSizePolicy, QMenu
import qtawesome as qta

from utils import resource_path


SNAP_LAYOUT_HOVER_DELAY_MS = 650


def _snap_layout_rect(work_area: QRect, layout: str) -> QRect:
    """Return one snap region inside a screen's available work area."""
    x, y = work_area.x(), work_area.y()
    width, height = work_area.width(), work_area.height()
    half_width = width // 2
    half_height = height // 2
    two_thirds = (width * 2) // 3

    regions = {
        "left_half": QRect(x, y, half_width, height),
        "right_half": QRect(x + half_width, y, width - half_width, height),
        "left_two_thirds": QRect(x, y, two_thirds, height),
        "right_two_thirds": QRect(x + width - two_thirds, y, two_thirds, height),
        "top_left": QRect(x, y, half_width, half_height),
        "top_right": QRect(x + half_width, y, width - half_width, half_height),
        "bottom_left": QRect(x, y + half_height, half_width, height - half_height),
        "bottom_right": QRect(
            x + half_width, y + half_height,
            width - half_width, height - half_height
        ),
    }
    try:
        return QRect(regions[layout])
    except KeyError as exc:
        raise ValueError(f"Unknown snap layout: {layout}") from exc


class CustomTitleBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_ = parent
        self.setObjectName("customTitleBar")
        self.setFixedHeight(40)
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
        layout.addWidget(self.app_icon, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.title, 0, Qt.AlignmentFlag.AlignVCenter)
        # The flexible gap belongs between the left-aligned branding and
        # right-aligned window controls, not before the branding.
        layout.addStretch(1)
        layout.addWidget(self.btn_min)
        layout.addWidget(self.btn_max)
        layout.addWidget(self.btn_close)
        self._start_pos = None
        self._screen_signal_connected = False

        # Do not return HTMAXBUTTON for this Qt-drawn button: it makes Windows
        # paint a second non-client maximize control at a different screen rect.
        # Use a delayed Qt flyout so the actual button remains clickable.
        self.snap_menu = QMenu(self.btn_max)
        self.snap_menu.setObjectName("snapLayoutMenu")
        self.snap_menu.addSection("Split 50 / 50")
        self._snap_actions = {}
        for label, placement in (
            ("Left half", "left_half"),
            ("Right half", "right_half"),
        ):
            action = self.snap_menu.addAction(label)
            action.triggered.connect(
                lambda _checked=False, target=placement: self._apply_snap_layout(target)
            )
            self._snap_actions[placement] = action

        self.snap_menu.addSection("Split 2 / 3 + 1 / 3")
        for label, placement in (
            ("Left two-thirds", "left_two_thirds"),
            ("Right two-thirds", "right_two_thirds"),
        ):
            action = self.snap_menu.addAction(label)
            action.triggered.connect(
                lambda _checked=False, target=placement: self._apply_snap_layout(target)
            )
            self._snap_actions[placement] = action

        self.snap_menu.addSection("Four corners")
        for label, placement in (
            ("Top-left quarter", "top_left"),
            ("Top-right quarter", "top_right"),
            ("Bottom-left quarter", "bottom_left"),
            ("Bottom-right quarter", "bottom_right"),
        ):
            action = self.snap_menu.addAction(label)
            action.triggered.connect(
                lambda _checked=False, target=placement: self._apply_snap_layout(target)
            )
            self._snap_actions[placement] = action

        self._snap_hover_timer = QTimer(self)
        self._snap_hover_timer.setSingleShot(True)
        self._snap_hover_timer.setInterval(SNAP_LAYOUT_HOVER_DELAY_MS)
        self._snap_hover_timer.timeout.connect(self._show_snap_menu)
        self.btn_max.installEventFilter(self)
        self.btn_max.pressed.connect(self._cancel_snap_hover)
        self._apply_snap_menu_theme()
        self._refresh_app_icon()

    def eventFilter(self, watched, event):
        if watched is self.btn_max:
            if event.type() == QEvent.Type.Enter:
                if not self.snap_menu.isVisible():
                    self._snap_hover_timer.start()
            elif event.type() == QEvent.Type.Leave:
                self._snap_hover_timer.stop()
            elif event.type() == QEvent.Type.MouseButtonPress:
                self._cancel_snap_hover()
        return super().eventFilter(watched, event)

    def _cancel_snap_hover(self):
        self._snap_hover_timer.stop()

    def _show_snap_menu(self):
        if (
            not self.btn_max.underMouse()
            or not self.parent_.isVisible()
            or self.parent_.isMinimized()
        ):
            return

        self.snap_menu.ensurePolished()
        menu_size = self.snap_menu.sizeHint()
        button_bottom_right = self.btn_max.mapToGlobal(
            QPoint(self.btn_max.width(), self.btn_max.height() + 6)
        )
        screen = (
            QGuiApplication.screenAt(button_bottom_right)
            or QGuiApplication.primaryScreen()
        )
        if screen is None:
            return

        available = screen.availableGeometry()
        x = button_bottom_right.x() - menu_size.width()
        y = button_bottom_right.y()
        if y + menu_size.height() > available.bottom() + 1:
            y = self.btn_max.mapToGlobal(QPoint(0, -menu_size.height() - 6)).y()
        x = min(max(x, available.left()), available.right() - menu_size.width() + 1)
        y = min(max(y, available.top()), available.bottom() - menu_size.height() + 1)
        self.snap_menu.popup(QPoint(x, y))

    def _apply_snap_menu_theme(self):
        dark = self._icon_color.lower() not in {"#243143", "#202832", "#253246"}
        if dark:
            surface, border, foreground, hover, muted = (
                "#171e29", "#303b4c", "#e8edf6", "#29384d", "#94a2b5"
            )
        else:
            surface, border, foreground, hover, muted = (
                "#ffffff", "#dfe6ef", "#253246", "#edf3fb", "#7b8798"
            )
        self.snap_menu.setStyleSheet(f"""
            QMenu#snapLayoutMenu {{
                background-color: {surface};
                color: {foreground};
                border: 1px solid {border};
                border-radius: 10px;
                padding: 6px;
            }}
            QMenu#snapLayoutMenu::item {{
                padding: 7px 18px;
                margin: 1px 4px;
                border-radius: 6px;
            }}
            QMenu#snapLayoutMenu::item:selected {{
                background-color: {hover};
                color: {foreground};
            }}
            QMenu#snapLayoutMenu::item:disabled {{
                color: {muted};
            }}
            QMenu#snapLayoutMenu::separator {{
                height: 1px;
                background-color: {border};
                margin: 4px 8px;
            }}
            QMenu#snapLayoutMenu::item:section {{
                color: {muted};
                font-size: 8pt;
                font-weight: 700;
            }}
        """)

    def _apply_snap_layout(self, placement):
        window = self.parent_
        if window is None:
            return
        center = window.frameGeometry().center()
        screen = QGuiApplication.screenAt(center) or QGuiApplication.primaryScreen()
        if screen is None:
            return

        target = _snap_layout_rect(screen.availableGeometry(), placement)
        if window.isMaximized() or window.isFullScreen():
            window.showNormal()
        window.setGeometry(target)
        window.raise_()
        window.activateWindow()

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
        self._apply_snap_menu_theme()

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
