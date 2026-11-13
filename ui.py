from collections import deque
from contextlib import contextmanager
import ctypes
import time
from ctypes import wintypes

from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QMenu,
    QStackedWidget,
    QWidget,
    QLabel,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QToolButton,
    QButtonGroup,
    QFrame,
    QSystemTrayIcon,
    QWidgetAction
)
from PySide6.QtGui import (
    QAction,
    QActionGroup,
    QColor,
    QCursor,
    QGuiApplication,
    QIcon,
    QKeySequence,
    QPainter,
    QPainterPath,
    QPen,
    QMouseEvent,
)
import qdarkstyle
from qdarkstyle.dark.palette import DarkPalette
from qdarkstyle.light.palette import LightPalette
from PySide6.QtCore import QEvent, QTimer, Qt, Signal, QSize, QPoint, QPointF, QRect
import qtawesome as qta
from ui_.window.theme_transition import CircularThemeReveal
from ui_.window.theme import resolve_system_theme
from utils import resource_path
import logging
from config import CONFIG, IS_WINDOWS
from torproxy.hotkeys import HotkeyManager, parse_hotkey
from ui_.worker.worker import Worker
from ui_.window.proxy_window import ProxyWindow
from ui_.window.custom_titlebar import CustomTitleBar
from ui_.window.dialogs import QMessageBox, ExitConfirmDialog
logger = logging.getLogger(__name__)

_THEME_STYLESHEET_CACHE = {}


# Native hit-test values used by custom Windows title bars and resize borders.
_HTCLIENT = 1
_HTCAPTION = 2
_HTMAXBUTTON = 9
_HTLEFT = 10
_HTRIGHT = 11
_HTTOP = 12
_HTTOPLEFT = 13
_HTTOPRIGHT = 14
_HTBOTTOM = 15
_HTBOTTOMLEFT = 16
_HTBOTTOMRIGHT = 17
_WM_NCCALCSIZE = 0x0083
_WM_NCHITTEST = 0x0084
_WM_SYSKEYDOWN = 0x0104
_WM_SYSCOMMAND = 0x0112
_WM_NCRBUTTONUP = 0x00A5
_SC_KEYMENU = 0xF100
_SC_MOVE = 0xF010
_SC_SIZE = 0xF000
_SC_CLOSE = 0xF060
_VK_SPACE = 0x20
_WM_DPICHANGED = 0x02E0
_WM_NCMOUSEMOVE = 0x00A0
_WM_NCMOUSEMOVE = 0x00A0
_WM_NCLBUTTONDOWN = 0x00A1
_WM_NCLBUTTONUP = 0x00A2
_WM_NCLBUTTONDBLCLK = 0x00A3
_WM_MOUSEMOVE = 0x0200
_WM_LBUTTONUP = 0x0202
_WM_CAPTURECHANGED = 0x0215
_WM_NCMOUSELEAVE = 0x02A2
_WM_MOVING = 0x0216
_WM_ENTERSIZEMOVE = 0x0231
_WM_EXITSIZEMOVE = 0x0232

# A custom Qt title bar still needs an overlapped top-level HWND on Windows.
# These styles let the shell perform native minimize/restore and taskbar effects.
_WS_POPUP = 0x80000000
_WS_CAPTION = 0x00C00000
_WS_SYSMENU = 0x00080000
_WS_THICKFRAME = 0x00040000
_WS_MINIMIZEBOX = 0x00020000
_WS_MAXIMIZEBOX = 0x00010000
_WS_OVERLAPPEDWINDOW = (
    _WS_CAPTION | _WS_SYSMENU | _WS_THICKFRAME
    | _WS_MINIMIZEBOX | _WS_MAXIMIZEBOX
)



class _MONITORINFO(ctypes.Structure):
    _fields_ = (
        ("cbSize", wintypes.DWORD),
        ("rcMonitor", wintypes.RECT),
        ("rcWork", wintypes.RECT),
        ("dwFlags", wintypes.DWORD),
    )


def _native_resize_hit_test(point, window_rect, border=8):
    """Return the Win32 resize hit-test code for an edge or corner."""
    if border <= 0 or not window_rect.contains(point):
        return None

    on_left = point.x() < window_rect.left() + border
    on_right = point.x() > window_rect.right() - border
    on_top = point.y() < window_rect.top() + border
    on_bottom = point.y() > window_rect.bottom() - border

    if on_top and on_left:
        return _HTTOPLEFT
    if on_top and on_right:
        return _HTTOPRIGHT
    if on_bottom and on_left:
        return _HTBOTTOMLEFT
    if on_bottom and on_right:
        return _HTBOTTOMRIGHT
    if on_left:
        return _HTLEFT
    if on_right:
        return _HTRIGHT
    if on_top:
        return _HTTOP
    if on_bottom:
        return _HTBOTTOM
    return None


def _native_titlebar_hit_test(point, titlebar_rect, maximize_rect, other_button_rects):
    """Use Windows' native maximize hit target while keeping other Qt controls client-side."""
    if maximize_rect.contains(point):
        # This Win32 hit code enables the operating system's own Snap Layouts flyout.
        return _HTMAXBUTTON
    if any(rect.contains(point) for rect in other_button_rects):
        return _HTCLIENT
    if titlebar_rect.contains(point):
        # Blank caption space supports native dragging and the Alt+Space system menu.
        return _HTCAPTION
    return None


def _clamp_window_rect_to_work_area(
    window_rect, work_area, visible_width=88, visible_titlebar=28
):
    """Keep a useful grab area visible without issuing another window move."""
    width = max(1, int(window_rect.width()))
    height = max(1, int(window_rect.height()))
    visible_width = min(max(1, int(visible_width)), width, max(1, work_area.width()))
    visible_titlebar = min(
        max(1, int(visible_titlebar)), height, max(1, work_area.height())
    )

    min_x = work_area.left() - width + visible_width
    max_x = work_area.right() - visible_width + 1
    min_y = work_area.top()
    max_y = work_area.bottom() - visible_titlebar + 1

    left = min(max(window_rect.left(), min_x), max_x)
    top = min(max(window_rect.top(), min_y), max_y)
    return QRect(left, top, width, height)


def _native_main_window_style(style):
    """Keep a Qt custom frame while exposing normal Windows main-window semantics."""
    current_style = int(style) & 0xFFFFFFFF
    return (current_style & ~_WS_POPUP) | _WS_OVERLAPPEDWINDOW


def _theme_stylesheet(mode):
    """Build each QDarkStyle stylesheet once, outside the first theme interaction."""
    cached = _THEME_STYLESHEET_CACHE.get(mode)
    if cached is None:
        palette = DarkPalette() if mode == "dark" else LightPalette()
        cached = qdarkstyle.load_stylesheet(palette=palette)
        _THEME_STYLESHEET_CACHE[mode] = cached
    return cached


class UpdatesMenuButton(QToolButton):
    """QToolButton with a theme-aware dropdown chevron."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._menu_indicator_color = QColor("#202832")
        self._menu_indicator_open = False

    def setMenuIndicatorOpen(self, opened):
        """Point the chevron upward only while its popup is open."""
        opened = bool(opened)
        if opened != self._menu_indicator_open:
            self._menu_indicator_open = opened
            self.update()

    def setMenuIndicatorColor(self, color):
        """Set the dropdown chevron to the exact foreground used by the label."""
        resolved = QColor(color)
        if not resolved.isValid():
            return
        if resolved != self._menu_indicator_color:
            self._menu_indicator_color = resolved
            self.update()

    def paintEvent(self, event):
        # QSS disables only Qt's platform-painted indicator. Draw the same
        # compact chevron ourselves so it follows the Updates label color.
        super().paintEvent(event)
        if self.menu() is None:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        pen = QPen(self._menu_indicator_color)
        pen.setWidthF(1.8)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        # Reserve a dedicated lower-right slot. Keep the glyph inset from the
        # rounded border and away from the label/icon content area.
        center_x = self.rect().right() - 10
        center_y = self.rect().bottom() - 8
        path = QPainterPath()
        if self._menu_indicator_open:
            path.moveTo(center_x - 3, center_y + 1)
            path.lineTo(center_x, center_y - 2)
            path.lineTo(center_x + 3, center_y + 1)
        else:
            path.moveTo(center_x - 3, center_y - 1)
            path.lineTo(center_x, center_y + 2)
            path.lineTo(center_x + 3, center_y - 1)
        painter.drawPath(path)


class HoverIconButton(QPushButton):
    """Push button whose icon follows its normal and hover foreground colors."""

    def __init__(self, text, icon_name, icon_color, parent=None):
        super().__init__(text, parent)
        self._icon_name = icon_name
        self._normal_icon_color = str(icon_color)
        self._hover_icon_color = "#ffffff"
        self._hovered = False
        self._sync_icon()

    def _sync_icon(self):
        color = self._hover_icon_color if self._hovered else self._normal_icon_color
        self.setIcon(qta.icon(self._icon_name, color=color))

    def setNormalIconColor(self, color):
        self._normal_icon_color = str(color)
        self._sync_icon()

    def _set_hovered(self, hovered):
        hovered = bool(hovered)
        if hovered != self._hovered:
            self._hovered = hovered
            self._sync_icon()

    def enterEvent(self, event):
        self._set_hovered(True)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._set_hovered(False)
        super().leaveEvent(event)


class Window(QMainWindow):
    PAGE_HOME = 0
    PAGE_SETTINGS = 1
    PAGE_BUNDLES = 2
    PAGE_SYSTEM_TUNNEL = 3
    PAGE_HELP = 4
    PAGE_STATISTICS = 5
    PAGE_CUSTOM_TOR = 6
    PAGE_DEVELOPER_TOR = 7

    toggle_visibility_signal = Signal()
    hotkey_error_signal = Signal(str)
    def __init__(self):
        super().__init__()
        if IS_WINDOWS:
            self.setWindowFlag(Qt.WindowType.FramelessWindowHint)
        self.main_widget = QWidget(self)
        self.setCentralWidget(self.main_widget)
        self.main_layout = QVBoxLayout(self.main_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        self.setWindowTitle("TorProxy")
        self.resize(1080, 720)
        self.setMinimumSize(780, 560)

        # Home is the only feature page required for the first frame. Lightweight
        # placeholders reserve stable indices while page imports and heavyweight
        # widget/service work are deferred until the user first opens each page.
        self.stack = QStackedWidget()
        self.stack.setObjectName("pageStack")
        self.stack.setFrameShape(QFrame.Shape.NoFrame)
        self.stack.setLineWidth(0)
        self._constraining_move = False
        self._native_snap_hwnd = 0
        self._native_user32 = None
        self._native_map_window_points = None
        self._native_dpi_scale = 1.0
        self._native_move_loop_active = False
        self._native_max_button_pressed = False
        self._native_max_button_hovered = False
        self.proxyWidget = ProxyWindow(self)
        self.stack.addWidget(self.proxyWidget)
        self._page_placeholders = {}
        for page_index in range(self.PAGE_SETTINGS, self.PAGE_DEVELOPER_TOR + 1):
            placeholder = QWidget(self.stack)
            placeholder.setObjectName("deferredPagePlaceholder")
            self.stack.addWidget(placeholder)
            self._page_placeholders[page_index] = placeholder

        self.settingWidget = None
        self.block_host_window = None
        self.exclude_host_window = None
        self.updater_window = None
        self.tunnel_window = None
        self.shortcutsWidget = None
        self.statisticsWidget = None
        self.customTorWidget = None
        self.developerTorWidget = None
        self._traffic_session_state = self._create_traffic_session_state()

        if IS_WINDOWS:
            self.title_bar = CustomTitleBar(self)
            self.main_layout.addWidget(self.title_bar)
        self._createMenuBar()
        self._create_window_system_menu()

        # Pages fill the central surface directly; no extra card/frame around Home,
        # Settings, or the other stacked pages.
        self.main_layout.addWidget(self.stack, 1)
        # Select the first page after the stack has real geometry in the root layout.
        self._show_page(self.PAGE_HOME)

        self._state_timer = QTimer(self)
        self._state_timer.setInterval(1000)
        self._state_timer.timeout.connect(self._update_global_state)
        self._state_timer.start()
        self._update_global_state()
        self._set_theme(CONFIG["mode"])
        # Qt 6.5+ forwards native desktop appearance changes through QStyleHints.
        # Only follow these changes while the user preference remains System.
        try:
            self._system_theme_hints = QGuiApplication.styleHints()
            self._system_theme_hints.colorSchemeChanged.connect(
                self._on_system_color_scheme_changed
            )
        except (AttributeError, RuntimeError):
            self._system_theme_hints = None
            logger.debug("Live system theme notifications are unavailable.", exc_info=True)
        # Cache stylesheet strings only. Reapplying alternate QSS to the hidden
        # widget tree would repolish every descendant before the first frame.

        self._exit_authorized = False
        self._exit_request_pending = False
        self._exit_request_in_progress = False
        self._shutdown_in_progress = False
        self._shutdown_complete = False
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(resource_path("assets/icon.png")))
        self.tray_icon.setToolTip("TorProxy")
        self.tray_menu = QMenu(self)
        self.tray_menu.setObjectName("trayContextMenu")
        self.tray_menu.setMinimumWidth(286)
        self.tray_menu.setSeparatorsCollapsible(False)

        # A small branded header makes this feel like an intentional app menu,
        # rather than a default system popup with a few buttons inside it.
        self.tray_menu_header = QWidget(self.tray_menu)
        self.tray_menu_header.setObjectName("trayMenuHeader")
        header_layout = QVBoxLayout(self.tray_menu_header)
        header_layout.setContentsMargins(14, 8, 14, 6)
        header_layout.setSpacing(1)
        self.tray_menu_title = QLabel("TorProxy", self.tray_menu_header)
        self.tray_menu_title.setObjectName("trayMenuTitle")
        self.tray_menu_subtitle = QLabel("Quick controls", self.tray_menu_header)
        self.tray_menu_subtitle.setObjectName("trayMenuSubtitle")
        header_layout.addWidget(self.tray_menu_title)
        header_layout.addWidget(self.tray_menu_subtitle)
        self.tray_menu_header_action = QWidgetAction(self.tray_menu)
        self.tray_menu_header_action.setDefaultWidget(self.tray_menu_header)
        self.tray_menu.addAction(self.tray_menu_header_action)
        self.tray_menu.addSeparator()

        self.tray_toggle_action = QAction("Show / Hide TorProxy", self)
        self.tray_toggle_action.triggered.connect(self._toggle_visibility)
        self.tray_menu.addAction(self.tray_toggle_action)
        self.tray_menu.addSeparator()

        # Keep the three tray choices wired to the same policy combo and
        # handler used by Home; never change OS proxy settings through a second path.
        self.tray_proxy_section = QWidget(self.tray_menu)
        self.tray_proxy_section.setObjectName("trayMenuSection")
        proxy_section_layout = QHBoxLayout(self.tray_proxy_section)
        proxy_section_layout.setContentsMargins(14, 3, 12, 0)
        self.tray_proxy_section_label = QLabel("SYSTEM PROXY", self.tray_proxy_section)
        self.tray_proxy_section_label.setObjectName("trayMenuSectionLabel")
        proxy_section_layout.addWidget(self.tray_proxy_section_label)
        self.tray_proxy_section_action = QWidgetAction(self.tray_menu)
        self.tray_proxy_section_action.setDefaultWidget(self.tray_proxy_section)
        self.tray_menu.addAction(self.tray_proxy_section_action)

        self.tray_system_proxy_action_group = QActionGroup(self)
        self.tray_system_proxy_action_group.setExclusive(True)
        self.tray_system_proxy_mode_actions = {}
        tray_proxy_modes = (
            ("set", "Set system proxy"),
            ("unchanged", "Do not change system proxy"),
            ("clear", "Clear system proxy"),
        )
        for mode, label in tray_proxy_modes:
            action = QAction(label, self)
            action.setCheckable(True)
            action.setData(mode)
            action.triggered.connect(
                lambda _checked=False, selected_mode=mode:
                    self._set_tray_system_proxy_mode(selected_mode)
            )
            self.tray_system_proxy_action_group.addAction(action)
            # Keep all choices visible in one compact group; the exclusive
            # indicator communicates the selected policy without a submenu.
            self.tray_menu.addAction(action)
            self.tray_system_proxy_mode_actions[mode] = action

        self.tray_menu.addSeparator()
        self.tray_exit_action = QAction("Exit TorProxy", self)
        self.tray_exit_action.triggered.connect(self.ask_close)
        self.tray_menu.addAction(self.tray_exit_action)

        proxy_mode_combo = getattr(self.proxyWidget, "system_proxy_mode", None)
        if proxy_mode_combo is not None:
            proxy_mode_combo.currentIndexChanged.connect(self._sync_tray_system_proxy_actions)
        self._sync_tray_system_proxy_actions()
        self._sync_tray_menu_theme()

        # Do not give the menu to the shell: Windows chooses its own anchor and
        # may open it downward over the tray icon. Position our menu explicitly.
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()

        self.toggle_visibility_signal.connect(self._toggle_visibility)
        self.hotkey_error_signal.connect(self._on_hotkey_error)
        self.hotkey_manager = HotkeyManager(on_error=self.hotkey_error_signal.emit)
        self.hotkey_manager.register(
            "window_visibility",
            str(CONFIG["global_shortcut"]),
            lambda: self.toggle_visibility_signal.emit(),
        )
        self.hotkey_manager.start()
        # Create the HWND while hidden and advertise the native sizing/maximize
        # capabilities before the first frame is shown to Windows.
        self._enable_native_snap_support()

    def _create_traffic_session_state(self):
        """Capture the initial traffic-counter baseline for this application run."""
        started_at = time.monotonic()
        try:
            directions = self.proxyWidget.traffic_direction_snapshot()
        except Exception:
            directions = {"upload": 0, "download": 0}
            logger.debug("Could not read initial traffic counters.", exc_info=True)
        return {
            "started_at": started_at,
            "last_sample_at": started_at,
            "last_directions": dict(directions),
            "session_upload": 0,
            "session_download": 0,
            "current_rate": 0.0,
            "peak_rate": 0.0,
            "samples": deque([(started_at, 0, 0, 0, 0.0)], maxlen=3600),
        }

    def _sample_traffic_session(self):
        """Sample cumulative counters even while Statistics is not open."""
        state = getattr(self, "_traffic_session_state", None)
        proxy_widget = getattr(self, "proxyWidget", None)
        if state is None or proxy_widget is None:
            return
        timestamp = time.monotonic()
        elapsed = timestamp - float(state["last_sample_at"])
        if elapsed < 0.75:
            return
        try:
            directions = proxy_widget.traffic_direction_snapshot()
        except Exception:
            logger.debug("Could not sample traffic counters.", exc_info=True)
            return
        previous = state["last_directions"]
        upload_delta = max(0, int(directions.get("upload", 0)) - int(previous.get("upload", 0)))
        download_delta = max(0, int(directions.get("download", 0)) - int(previous.get("download", 0)))
        transfer_delta = upload_delta + download_delta
        rate = transfer_delta / max(0.001, elapsed)
        state["session_upload"] += upload_delta
        state["session_download"] += download_delta
        state["current_rate"] = rate
        state["peak_rate"] = max(float(state["peak_rate"]), rate)
        state["samples"].append((timestamp, transfer_delta, upload_delta, download_delta, rate))
        state["last_sample_at"] = timestamp
        state["last_directions"] = dict(directions)

    def _ensure_page_created(self, index):
        """Create a feature page only when navigation first requests it."""
        if index not in self._page_placeholders:
            return self.stack.widget(index) if 0 <= index < self.stack.count() else None

        if index == self.PAGE_SETTINGS:
            from ui_.window.setting_window import SettingWindow
            page = SettingWindow(self)
            self.settingWidget = page
            self.block_host_window = page.block_hosts_page
            self.exclude_host_window = page.exclude_hosts_page
        elif index == self.PAGE_BUNDLES:
            from ui_.window.updater_window import UpdaterWindow
            page = UpdaterWindow(self)
            self.updater_window = page
        elif index == self.PAGE_SYSTEM_TUNNEL:
            from ui_.window.tunnel_window import TunnelManagerWindow
            page = TunnelManagerWindow(self)
            self.tunnel_window = page
        elif index == self.PAGE_HELP:
            from ui_.window.shortcuts_window import ShortcutsWindow
            page = ShortcutsWindow(self)
            self.shortcutsWidget = page
        elif index == self.PAGE_STATISTICS:
            from ui_.window.statistics_window import StatisticsWindow
            page = StatisticsWindow(self.proxyWidget, self)
            self.statisticsWidget = page
        elif index == self.PAGE_CUSTOM_TOR:
            from ui_.window.tor_services_page import TorServicesPage
            page = TorServicesPage(self, app_window=self, management_only=True)
            self.customTorWidget = page
        elif index == self.PAGE_DEVELOPER_TOR:
            from ui_.window.onion_hosting_page import OnionHostingPage
            page = OnionHostingPage(self.proxyWidget, self)
            self.developerTorWidget = page
        else:
            return self.stack.widget(index)

        placeholder = self.stack.replaceWidget(index, page)
        self._page_placeholders.pop(index, None)
        if placeholder is not None:
            placeholder.deleteLater()
        return page

    def _create_window_system_menu(self):
        """Create the app-themed equivalent of the Windows caption system menu."""
        self.window_system_menu = QMenu(self)
        self.window_system_menu.setObjectName("windowSystemMenu")
        self.window_system_menu.setMinimumWidth(208)
        self.window_system_menu.setSeparatorsCollapsible(False)
        self.window_system_actions = {}

        action_specs = (
            ("restore", "Restore"),
            ("move", "Move"),
            ("size", "Size"),
        )
        for key, label in action_specs:
            self.window_system_actions[key] = self.window_system_menu.addAction(label)

        self.window_system_menu.addSeparator()
        self.window_system_actions["minimize"] = self.window_system_menu.addAction("Minimize")
        self.window_system_actions["maximize"] = self.window_system_menu.addAction("Maximize")
        self.window_system_menu.addSeparator()
        close_action = QAction("Close", self)
        close_action.setShortcut(QKeySequence("Alt+F4"))
        close_action.setShortcutContext(Qt.ShortcutContext.WindowShortcut)
        self.addAction(close_action)
        self.window_system_menu.addAction(close_action)
        self.window_system_actions["close"] = close_action

        self.window_system_actions["restore"].triggered.connect(self.showNormal)
        self.window_system_actions["move"].triggered.connect(
            lambda _checked=False: self._post_native_system_command(_SC_MOVE)
        )
        self.window_system_actions["size"].triggered.connect(
            lambda _checked=False: self._post_native_system_command(_SC_SIZE)
        )
        self.window_system_actions["minimize"].triggered.connect(self.showMinimized)
        self.window_system_actions["maximize"].triggered.connect(self.showMaximized)
        # Match Windows Alt+F4: Close must use the explicit, confirmed app-exit path.
        close_action.triggered.connect(self._request_exit)
        self.window_system_menu.aboutToShow.connect(self._sync_window_system_menu_actions)
        self._window_system_menu_pending = False

    def _sync_window_system_menu_actions(self):
        """Enable only the window commands that make sense in its current state."""
        actions = getattr(self, "window_system_actions", {})
        maximized = self.isMaximized()
        minimized = self.isMinimized()
        enabled = {
            "restore": maximized or minimized,
            "move": not maximized and not minimized,
            "size": not maximized and not minimized,
            "minimize": not minimized,
            "maximize": not maximized and not minimized,
            "close": True,
        }
        for key, state in enabled.items():
            action = actions.get(key)
            if action is not None:
                action.setEnabled(state)

    def _sync_window_system_menu_theme(self, mode=None):
        """Match the caption menu's surface, separators, hover and icons to the app theme."""
        menu = getattr(self, "window_system_menu", None)
        if menu is None:
            return

        dark = (mode or CONFIG.get("mode", "dark")) == "dark"
        if dark:
            surface = "#171e29"
            border = "#303b4c"
            text = "#e8edf6"
            muted = "#94a2b5"
            hover = "#29384d"
            divider = "#303b4c"
            danger = "#ef7777"
            icon_color = "#edf2f9"
        else:
            surface = "#ffffff"
            border = "#dfe6ef"
            text = "#253246"
            muted = "#7b8798"
            hover = "#edf3fb"
            divider = "#e7ecf2"
            danger = "#c94343"
            icon_color = "#344258"

        menu.setStyleSheet(f"""
            QMenu#windowSystemMenu {{
                background-color: {surface};
                color: {text};
                border: 1px solid {border};
                border-radius: 12px;
                padding: 6px;
            }}
            QMenu#windowSystemMenu::item {{
                color: {text};
                background: transparent;
                padding: 7px 18px 7px 10px;
                margin: 1px 3px;
                min-height: 19px;
                border-radius: 7px;
            }}
            QMenu#windowSystemMenu::item:selected {{
                color: {text};
                background-color: {hover};
            }}
            QMenu#windowSystemMenu::item:disabled {{
                color: {muted};
            }}
            QMenu#windowSystemMenu::separator {{
                height: 1px;
                background-color: {divider};
                margin: 4px 10px;
            }}
        """)

        icon_names = {
            "restore": "fa6s.window-restore",
            "move": "fa6s.arrows-up-down-left-right",
            "size": "fa6s.expand",
            "minimize": "fa6s.window-minimize",
            "maximize": "fa6s.window-maximize",
            "close": "fa6s.xmark",
        }
        for key, icon_name in icon_names.items():
            action = self.window_system_actions.get(key)
            if action is not None:
                color = danger if key == "close" else icon_color
                action.setIcon(qta.icon(icon_name, color=color))

    def _post_native_system_command(self, command):
        """Let Windows perform its native Move/Size interaction."""
        if not IS_WINDOWS:
            return
        hwnd = int(getattr(self, "_native_snap_hwnd", 0) or self.winId())
        user32 = getattr(self, "_native_user32", None)
        if not hwnd or user32 is None:
            return
        try:
            if command == _SC_MOVE:
                # SC_MOVE starts its drag from the current pointer position.
                # Place that pointer at the title bar's center first, instead
                # of leaving it at the edge where the system menu was opened.
                titlebar = getattr(self, "title_bar", None)
                if titlebar is not None:
                    center = titlebar.rect().center()
                    QCursor.setPos(titlebar.mapToGlobal(center))

            post_message = user32.PostMessageW
            post_message.argtypes = (
                wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
            )
            post_message.restype = wintypes.BOOL
            if not post_message(
                wintypes.HWND(hwnd),
                _WM_SYSCOMMAND,
                wintypes.WPARAM(command),
                wintypes.LPARAM(0),
            ):
                logger.debug("Could not post native window command 0x%X.", command)
        except (AttributeError, OSError, TypeError, ValueError):
            logger.debug("Native window command failed.", exc_info=True)

    def _queue_window_system_menu(self, position=None, *, keyboard=False):
        """Defer popup creation until the current native message has returned."""
        if getattr(self, "_window_system_menu_pending", False):
            return
        self._window_system_menu_pending = True
        anchor = QPoint(position) if position is not None else None
        QTimer.singleShot(
            0,
            lambda current_anchor=anchor, from_keyboard=keyboard:
                self._show_window_system_menu(current_anchor, keyboard=from_keyboard),
        )

    def _show_window_system_menu(self, position=None, *, keyboard=False):
        self._window_system_menu_pending = False
        menu = getattr(self, "window_system_menu", None)
        if menu is None or not self.isVisible() or self.isMinimized():
            return

        if position is None:
            titlebar = getattr(self, "title_bar", None)
            if titlebar is None:
                return
            position = titlebar.app_icon.mapToGlobal(
                QPoint(0, titlebar.app_icon.height())
            )

        self._sync_window_system_menu_actions()
        menu.popup(position)
        if keyboard:
            first_enabled = next(
                (
                    action for action in menu.actions()
                    if action.isEnabled() and not action.isSeparator()
                ),
                None,
            )
            if first_enabled is not None:
                menu.setActiveAction(first_enabled)

    def _enable_native_snap_support(self):
        """Expose a custom frame as a native, resizable Windows main window."""
        if not IS_WINDOWS:
            return

        try:
            hwnd = int(self.winId())
            if not hwnd or hwnd == self._native_snap_hwnd:
                return

            user32 = ctypes.WinDLL("user32", use_last_error=True)
            # Cache APIs used by WM_NCHITTEST. That message is frequent while
            # resizing/hovering near the frame; DLL lookup and ctypes signature
            # setup must not happen in the interactive hit-test path.
            self._native_user32 = user32
            map_window_points = user32.MapWindowPoints
            map_window_points.argtypes = (
                wintypes.HWND, wintypes.HWND,
                ctypes.POINTER(wintypes.POINT), wintypes.UINT
            )
            map_window_points.restype = ctypes.c_int
            self._native_map_window_points = map_window_points

            self._native_dpi_scale = max(1.0, float(self.devicePixelRatioF()))
            get_dpi_for_window = getattr(user32, "GetDpiForWindow", None)
            if get_dpi_for_window is not None:
                get_dpi_for_window.argtypes = (wintypes.HWND,)
                get_dpi_for_window.restype = wintypes.UINT
                native_dpi = int(get_dpi_for_window(wintypes.HWND(hwnd)))
                if native_dpi > 0:
                    self._native_dpi_scale = max(1.0, native_dpi / 96.0)

            get_window_long = getattr(
                user32, "GetWindowLongPtrW", user32.GetWindowLongW
            )
            set_window_long = getattr(
                user32, "SetWindowLongPtrW", user32.SetWindowLongW
            )
            get_window_long.argtypes = (wintypes.HWND, ctypes.c_int)
            get_window_long.restype = ctypes.c_ssize_t
            set_window_long.argtypes = (
                wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t
            )
            set_window_long.restype = ctypes.c_ssize_t

            # Qt's FramelessWindowHint initially creates a WS_POPUP window.
            # Normalize it to WS_OVERLAPPEDWINDOW so Windows owns the normal
            # taskbar minimize/restore transition and its configured animation.
            # WM_NCCALCSIZE below keeps the entire client area available to our
            # custom title bar, so no native caption is painted over the UI.
            style_index = -16  # GWL_STYLE
            style = int(get_window_long(wintypes.HWND(hwnd), style_index)) & 0xFFFFFFFF
            native_style = _native_main_window_style(style)
            if native_style != style:
                ctypes.set_last_error(0)
                previous = set_window_long(
                    wintypes.HWND(hwnd),
                    style_index,
                    ctypes.c_ssize_t(native_style),
                )
                error = ctypes.get_last_error()
                if previous == 0 and error:
                    raise OSError(error, "SetWindowLongPtrW failed")

                # Recalculate the non-client frame after changing native styles.
                # The WM_NCCALCSIZE handler preserves our custom client geometry.
                set_window_pos = user32.SetWindowPos
                set_window_pos.argtypes = (
                    wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                    ctypes.c_int, ctypes.c_int, wintypes.UINT
                )
                set_window_pos.restype = wintypes.BOOL
                flags = 0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0020
                if not set_window_pos(
                    wintypes.HWND(hwnd), None, 0, 0, 0, 0, flags
                ):
                    raise ctypes.WinError(ctypes.get_last_error())

            self._native_snap_hwnd = hwnd
        except (AttributeError, OSError, TypeError, ValueError):
            logger.debug(
                "Could not enable native Windows snap/maximize styles.",
                exc_info=True,
            )

    def _set_native_max_button_hovered(self, hovered):
        """Mirror the non-client hover state to the Qt maximize button."""
        hovered = bool(hovered)
        if hovered == self._native_max_button_hovered:
            return
        self._native_max_button_hovered = hovered
        titlebar = getattr(self, "title_bar", None)
        button = getattr(titlebar, "btn_max", None) if titlebar is not None else None
        if button is not None:
            QApplication.sendEvent(
                button,
                QEvent(QEvent.Type.Enter if hovered else QEvent.Type.Leave),
            )
            button.update()

    def _forward_native_max_button_mouse_event(self, event_type, button, buttons):
        """Translate native non-client mouse messages to the existing Qt maximize button."""
        titlebar = getattr(self, "title_bar", None)
        target = getattr(titlebar, "btn_max", None) if titlebar is not None else None
        if target is None:
            return

        global_position = QCursor.pos()
        local_position = target.mapFromGlobal(global_position)
        event = QMouseEvent(
            event_type,
            QPointF(local_position),
            QPointF(global_position),
            button,
            buttons,
            Qt.KeyboardModifier.NoModifier,
        )
        QApplication.sendEvent(target, event)

    def nativeEvent(self, event_type, message):
        """Give Windows native drag and maximize hit-testing for the custom title bar."""
        if not IS_WINDOWS or event_type != b"windows_generic_MSG":
            return super().nativeEvent(event_type, message)

        try:
            native_message = wintypes.MSG.from_address(int(message))

            if (
                native_message.message == _WM_NCRBUTTONUP
                and (int(native_message.wParam) & 0xFFFF) == _HTCAPTION
            ):
                self._queue_window_system_menu(QCursor.pos())
                return True, 0

            if (
                native_message.message == _WM_SYSKEYDOWN
                and int(native_message.wParam) == _VK_SPACE
                and int(native_message.lParam) & 0x20000000
            ):
                self._queue_window_system_menu(keyboard=True)
                return True, 0

            if native_message.message == _WM_SYSCOMMAND:
                system_command = int(native_message.wParam) & 0xFFF0
                if system_command == _SC_CLOSE:
                    # Alt+F4 arrives as SC_CLOSE on Windows. Keep it on the
                    # same confirmed shutdown path as the themed menu action.
                    self._request_exit()
                    return True, 0
                if system_command == _SC_KEYMENU and int(native_message.lParam) == _VK_SPACE:
                    self._queue_window_system_menu(keyboard=True)
                    return True, 0

            if native_message.message == _WM_DPICHANGED:
                dpi_x = int(native_message.wParam) & 0xFFFF
                if dpi_x > 0:
                    self._native_dpi_scale = max(1.0, dpi_x / 96.0)
                return super().nativeEvent(event_type, message)

            # The OS uses HTMAXBUTTON for the native Snap Layouts dwell. These
            # non-client messages do not reach QPushButton normally, so bridge them
            # to the existing Qt widget rather than drawing a second native control.
            titlebar = getattr(self, "title_bar", None)
            max_button = getattr(titlebar, "btn_max", None) if titlebar is not None else None

            if native_message.message == _WM_NCMOUSEMOVE:
                if self._native_max_button_hovered:
                    self._forward_native_max_button_mouse_event(
                        QEvent.Type.MouseMove,
                        Qt.MouseButton.NoButton,
                        Qt.MouseButton.NoButton,
                    )
                    # Deliver the movement to Qt, not DefWindowProc's classic
                    # caption-button loop. The OS still sees HTMAXBUTTON in hit-test.
                    return True, 0

            if native_message.message == _WM_NCMOUSELEAVE:
                self._set_native_max_button_hovered(False)
                return True, 0

            if (
                native_message.message in (_WM_NCLBUTTONDOWN, _WM_NCLBUTTONDBLCLK)
                and max_button is not None
                and max_button.rect().contains(max_button.mapFromGlobal(QCursor.pos()))
            ):
                self._native_max_button_pressed = True
                user32 = self._native_user32 or ctypes.WinDLL("user32", use_last_error=True)
                set_capture = user32.SetCapture
                set_capture.argtypes = (wintypes.HWND,)
                set_capture.restype = wintypes.HWND
                set_capture(wintypes.HWND(native_message.hWnd))
                self._forward_native_max_button_mouse_event(
                    QEvent.Type.MouseButtonPress,
                    Qt.MouseButton.LeftButton,
                    Qt.MouseButton.LeftButton,
                )
                # Use HWND capture so the same Qt button receives move/up even
                # if the pointer leaves the non-client maximize rectangle.
                # Never run DefWindowProc's own caption-button click loop.
                return True, 0

            if native_message.message == _WM_MOUSEMOVE and self._native_max_button_pressed:
                self._forward_native_max_button_mouse_event(
                    QEvent.Type.MouseMove,
                    Qt.MouseButton.NoButton,
                    Qt.MouseButton.LeftButton,
                )
                return True, 0

            if native_message.message in (_WM_LBUTTONUP, _WM_NCLBUTTONUP) and self._native_max_button_pressed:
                self._native_max_button_pressed = False
                self._forward_native_max_button_mouse_event(
                    QEvent.Type.MouseButtonRelease,
                    Qt.MouseButton.LeftButton,
                    Qt.MouseButton.NoButton,
                )
                user32 = self._native_user32 or ctypes.WinDLL("user32", use_last_error=True)
                user32.ReleaseCapture.argtypes = ()
                user32.ReleaseCapture.restype = wintypes.BOOL
                user32.ReleaseCapture()
                return True, 0

            if native_message.message == _WM_CAPTURECHANGED and self._native_max_button_pressed:
                self._native_max_button_pressed = False
                if max_button is not None:
                    max_button.setDown(False)
                self._set_native_max_button_hovered(False)
                return super().nativeEvent(event_type, message)

            if native_message.message == _WM_ENTERSIZEMOVE:
                self._native_move_loop_active = True
                proxy_page = getattr(self, "proxyWidget", None)
                if proxy_page is not None:
                    proxy_page.set_live_resize_active(True)
                return super().nativeEvent(event_type, message)
            if native_message.message == _WM_EXITSIZEMOVE:
                self._native_move_loop_active = False
                proxy_page = getattr(self, "proxyWidget", None)
                if proxy_page is not None:
                    proxy_page.set_live_resize_active(False)
                return super().nativeEvent(event_type, message)
            if native_message.message == _WM_MOVING:
                # Keep the off-screen guard for window dragging only. Windows
                # owns WM_SIZING and its live size loop; querying monitor/DPI
                # information on every sizing tick was adding avoidable latency.
                user32 = self._native_user32
                if user32 is None:
                    return super().nativeEvent(event_type, message)
                moving_rect = ctypes.cast(
                    int(native_message.lParam),
                    ctypes.POINTER(wintypes.RECT),
                ).contents
                monitor_from_rect = user32.MonitorFromRect
                monitor_from_rect.argtypes = (
                    ctypes.POINTER(wintypes.RECT), wintypes.DWORD
                )
                monitor_from_rect.restype = wintypes.HANDLE
                monitor = monitor_from_rect(
                    ctypes.byref(moving_rect), 2  # MONITOR_DEFAULTTONEAREST
                )
                if monitor:
                    info = _MONITORINFO()
                    info.cbSize = ctypes.sizeof(info)
                    get_monitor_info = user32.GetMonitorInfoW
                    get_monitor_info.argtypes = (
                        wintypes.HANDLE, ctypes.POINTER(_MONITORINFO)
                    )
                    get_monitor_info.restype = wintypes.BOOL
                    if get_monitor_info(monitor, ctypes.byref(info)):
                        work = info.rcWork
                        work_area = QRect(
                            work.left,
                            work.top,
                            work.right - work.left,
                            work.bottom - work.top,
                        )
                        width = moving_rect.right - moving_rect.left
                        height = moving_rect.bottom - moving_rect.top

                        dpi = 96
                        try:
                            get_dpi_for_monitor = ctypes.WinDLL("shcore").GetDpiForMonitor
                            get_dpi_for_monitor.argtypes = (
                                wintypes.HANDLE,
                                ctypes.c_int,
                                ctypes.POINTER(wintypes.UINT),
                                ctypes.POINTER(wintypes.UINT),
                            )
                            get_dpi_for_monitor.restype = ctypes.c_long
                            dpi_x = wintypes.UINT()
                            dpi_y = wintypes.UINT()
                            if get_dpi_for_monitor(
                                monitor, 0, ctypes.byref(dpi_x), ctypes.byref(dpi_y)
                            ) == 0 and dpi_x.value:
                                dpi = dpi_x.value
                        except (AttributeError, OSError, TypeError):
                            pass

                        scale = max(1.0, float(dpi) / 96.0)
                        logical_work_width = work_area.width() / scale
                        logical_work_height = work_area.height() / scale
                        visible_width = round(
                            min(120, max(88, int(logical_work_width // 12))) * scale
                        )
                        visible_titlebar = round(
                            min(40, max(28, int(logical_work_height // 12))) * scale
                        )
                        proposed = QRect(
                            moving_rect.left, moving_rect.top, width, height
                        )
                        constrained = _clamp_window_rect_to_work_area(
                            proposed,
                            work_area,
                            visible_width=visible_width,
                            visible_titlebar=visible_titlebar,
                        )
                        moving_rect.left = constrained.left()
                        moving_rect.top = constrained.top()
                        moving_rect.right = constrained.left() + width
                        moving_rect.bottom = constrained.top() + height
                        return True, 1
            if native_message.message == _WM_NCCALCSIZE:
                # Keep the custom Qt frame edge-to-edge while the native
                # thick-frame style supplies resize and Snap behavior.
                return True, 0
            if native_message.message == _WM_NCHITTEST:
                screen_point = wintypes.POINT(
                    ctypes.c_short(native_message.lParam & 0xFFFF).value,
                    ctypes.c_short((native_message.lParam >> 16) & 0xFFFF).value,
                )
                map_window_points = self._native_map_window_points
                if map_window_points is None:
                    return super().nativeEvent(event_type, message)
                # WM_NCHITTEST provides physical screen coordinates. Reuse the
                # cached desktop -> HWND mapping and the last known monitor DPI.
                map_window_points(
                    wintypes.HWND(0),
                    wintypes.HWND(native_message.hWnd),
                    ctypes.byref(screen_point),
                    1,
                )

                ratio = self._native_dpi_scale

                point = QPoint(
                    round(screen_point.x / ratio),
                    round(screen_point.y / ratio),
                )

                # Keep native resize handles available around the window perimeter.
                # Full-height caption buttons visually reach these edges, but the
                # thin frame strip still belongs to Windows' resize interaction.
                if not self.isMaximized() and not self.isFullScreen():
                    resize_hit = _native_resize_hit_test(
                        point, QRect(0, 0, self.width(), self.height())
                    )
                    if resize_hit is not None:
                        self._set_native_max_button_hovered(False)
                        return True, resize_hit

                hit_test = None
                if hasattr(self, "title_bar"):
                    titlebar = self.title_bar
                    titlebar_rect = QRect(
                        titlebar.mapTo(self, QPoint(0, 0)), titlebar.size()
                    )
                    maximize = titlebar.btn_max
                    maximize_rect = QRect(
                        maximize.mapTo(self, QPoint(0, 0)), maximize.size()
                    )
                    other_button_rects = []
                    for button in (titlebar.btn_min, titlebar.btn_close):
                        other_button_rects.append(
                            QRect(button.mapTo(self, QPoint(0, 0)), button.size())
                        )

                    hit_test = _native_titlebar_hit_test(
                        point, titlebar_rect, maximize_rect, other_button_rects
                    )
                    self._set_native_max_button_hovered(hit_test == _HTMAXBUTTON)
                    # Native frame resize handles take priority around the outer
                    # edges; the remaining controls are handled by Qt. HTMAXBUTTON
                    # is still returned to Windows for its native Snap Layouts flyout.
                    if hit_test in (_HTMAXBUTTON, _HTCLIENT):
                        return True, hit_test

                # Blank title-bar space remains native caption space. Besides
                # dragging and double-click maximize, this allows Windows to
                # show its real system menu for Alt+Space and caption right-click.
                if hit_test is not None:
                    return True, hit_test
        except (AttributeError, OSError, TypeError, ValueError):
            logger.debug("Native title-bar hit testing failed.", exc_info=True)

        return super().nativeEvent(event_type, message)

    def _refresh_layout_after_restore(self):
        if self.isMinimized() or not hasattr(self, "stack"):
            return
        # Windows can restore a frameless QWidget tree before the central
        # layout has recomputed all child sizes. Activate layouts on the next
        # event-loop turn and request a fresh paint without changing the window size.
        for widget in (self.main_widget, self.stack, self.stack.currentWidget()):
            if widget is None:
                continue
            layout = widget.layout()
            if layout is not None:
                layout.activate()
            widget.updateGeometry()
            widget.update()
        self.main_layout.activate()
        self.update()
        self.repaint()

    def showEvent(self, event):
        super().showEvent(event)
        # The OS theme may have changed while TorProxy was hidden in the tray.
        self._ensure_visible_theme_pages()
        # Recheck in case Qt recreated the native HWND after a window-flag change.
        self._enable_native_snap_support()
        # DWM draws the subtle rounded frame itself, without changing our client area.
        QTimer.singleShot(0, self._apply_native_window_corners)
        QTimer.singleShot(0, self._refresh_layout_after_restore)

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.Type.WindowStateChange:
            # Keep the custom maximize/restore glyph in sync when Windows
            # maximizes the window through Snap, Win+Arrow or the taskbar.
            titlebar = getattr(self, "title_bar", None)
            if titlebar is not None:
                titlebar._sync_maximize_button()
            # DWM suppresses rounding while maximized; re-apply the small
            # restored-window preference after every maximize/restore transition.
            QTimer.singleShot(0, self._apply_native_window_corners)
            if not self.isMinimized():
                QTimer.singleShot(0, self._refresh_layout_after_restore)

    def _apply_native_window_corners(self):
        """Request subtle native rounded corners for the restored Windows window."""
        if not IS_WINDOWS:
            return

        # Windows 11 exposes this preference through DwmSetWindowAttribute.
        # Older Windows builds reject the attribute; that is intentionally a no-op.
        try:
            hwnd = int(self.winId())
            if not hwnd:
                return
            dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
            set_window_attribute = dwmapi.DwmSetWindowAttribute
            set_window_attribute.argtypes = (
                ctypes.c_void_p,
                ctypes.c_uint,
                ctypes.c_void_p,
                ctypes.c_uint,
            )
            set_window_attribute.restype = ctypes.c_long

            # DWMWA_WINDOW_CORNER_PREFERENCE = 33
            # DWMWCP_DONOTROUND = 1; DWMWCP_ROUNDSMALL = 3.
            preference = ctypes.c_int(
                1 if self.isMaximized() or self.isFullScreen() else 3
            )
            result = set_window_attribute(
                ctypes.c_void_p(hwnd),
                33,
                ctypes.byref(preference),
                ctypes.sizeof(preference),
            )
            if result != 0:
                logger.debug(
                    "Windows DWM rounded-corner preference is unavailable (HRESULT 0x%08X).",
                    result & 0xFFFFFFFF,
                )
        except (AttributeError, OSError, TypeError, ValueError):
            logger.debug("Could not apply native rounded window corners.", exc_info=True)

    def _screen_for_geometry(self, geometry):
        center = geometry.center()
        screen = QGuiApplication.screenAt(center)
        if screen is not None:
            return screen
        screens = QGuiApplication.screens()
        if not screens:
            return None

        def distance_to_screen(candidate):
            area = candidate.availableGeometry()
            nearest_x = min(max(center.x(), area.left()), area.right())
            nearest_y = min(max(center.y(), area.top()), area.bottom())
            return (center.x() - nearest_x) ** 2 + (center.y() - nearest_y) ** 2

        return min(screens, key=distance_to_screen)

    def moveEvent(self, event):
        super().moveEvent(event)
        if (
            self._constraining_move
            or self._native_move_loop_active
            or self.isMinimized()
            or self.isMaximized()
            or self.isFullScreen()
        ):
            return
        screen = self._screen_for_geometry(self.frameGeometry())
        if screen is None:
            return
        area = screen.availableGeometry()
        visible_width = min(120, max(88, area.width() // 12))
        visible_titlebar = min(40, max(28, area.height() // 12))
        frame = self.frameGeometry()
        min_x = area.left() - frame.width() + visible_width
        max_x = area.right() - visible_width + 1
        min_y = area.top()
        max_y = area.bottom() - visible_titlebar + 1
        target_x = min(max(self.x(), min_x), max_x)
        target_y = min(max(self.y(), min_y), max_y)
        if target_x != self.x() or target_y != self.y():
            self._constraining_move = True
            try:
                self.move(target_x, target_y)
            finally:
                self._constraining_move = False

    def _toggle_visibility(self):
        if self.isVisible() and not self.isMinimized():
            self.hide_to_tray()
            return
        self.showNormal()
        self.show()
        self.raise_()
        self.activateWindow()

    def hide_to_tray(self):
        """Hide the main window without stopping Tor or removing the tray icon."""
        self.hide()
        if hasattr(self, "tray_icon") and not self.tray_icon.isVisible():
            self.tray_icon.show()
        logger.debug("TorProxy window hidden to the system tray.")

    @contextmanager
    def shortcut_capture_scope(self):
        """Suspend every registered shortcut while a key-binding dialog listens.

        Global bindings are unregistered by HotkeyManager and the QActions
        attached to this main window are disabled temporarily. New navigation
        or application shortcuts can use these same registries without being
        triggered by keys being recorded in the capture dialog.
        """
        actions = [
            action for action in self.actions()
            if not action.shortcut().isEmpty()
        ]
        action_states = [(action, action.isEnabled()) for action in actions]
        manager = getattr(self, "hotkey_manager", None)
        suspended = False
        try:
            if manager is not None:
                manager.suspend()
                suspended = True
            for action, _was_enabled in action_states:
                action.setEnabled(False)
            yield
        finally:
            for action, was_enabled in action_states:
                action.setEnabled(was_enabled)
            if suspended:
                manager.resume()

    def _set_global_shortcut(self, shortcut):
        """Apply and persist a global shortcut as one transaction."""
        normalized = parse_hotkey(shortcut).text
        previous = str(CONFIG["global_shortcut"])
        if normalized == previous:
            return normalized

        # Register first. Native Windows registration is synchronous for edits,
        # so a conflicting key combination can be rejected before config changes.
        self.hotkey_manager.update_shortcut("window_visibility", normalized)
        try:
            CONFIG["global_shortcut"] = normalized
        except Exception:
            try:
                self.hotkey_manager.update_shortcut("window_visibility", previous)
            except Exception:
                logger.exception("Failed to roll back the previous global shortcut.")
            raise

        shortcuts_page = getattr(self, "shortcutsWidget", None)
        if shortcuts_page is not None:
            shortcuts_page.update_global_shortcut(normalized)
        logger.info("Global show/hide shortcut changed to %s.", normalized)
        self.proxyWidget.logs_widget.update_log(
            "Global show/hide shortcut changed to {}.".format(normalized), level="success"
        )
        return normalized

    def _on_hotkey_error(self, message):
        """Surface native registration conflicts in Event Log and the tray."""
        logger.warning("Global shortcut issue: %s", message)
        try:
            self.proxyWidget.logs_widget.update_log(
                "Global shortcut: {}".format(message), level="warning"
            )
        except Exception:
            logger.debug("Could not append hotkey warning to Event Log.", exc_info=True)
        try:
            self.tray_icon.showMessage(
                "Global shortcut", message, QSystemTrayIcon.MessageIcon.Warning, 4500
            )
        except Exception:
            logger.debug("Could not show global-hotkey tray notification.", exc_info=True)

    def show_tray(self):
        self.hide()
        # # shold use show becuase tray will delete after system locked in this case windows
        # self.tray_icon.show()
        
    
    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Context:
            self._show_tray_context_menu()
        elif reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self._toggle_visibility()

    def show_window(self, reason):
        # Retain the old signal-handler name for integrations and tests.
        self._on_tray_activated(reason)

    def _set_tray_system_proxy_mode(self, mode):
        """Route tray choices through Home's existing system-proxy policy control."""
        combo = getattr(getattr(self, "proxyWidget", None), "system_proxy_mode", None)
        if combo is None:
            logger.warning("System proxy tray action is unavailable because the Home policy control is missing.")
            return

        index = combo.findData(mode)
        if index < 0:
            logger.warning("Unknown system proxy mode selected from the tray: %r", mode)
            self._sync_tray_system_proxy_actions()
            return

        if combo.currentIndex() == index:
            # Re-selecting the current tray option is also a useful explicit retry,
            # for example after Tor finishes connecting or an OS action previously failed.
            self.proxyWidget._on_system_proxy_mode_changed(index)
        else:
            # The currentIndexChanged signal invokes the authoritative existing handler.
            combo.setCurrentIndex(index)
        self._sync_tray_system_proxy_actions()

    def _sync_tray_system_proxy_actions(self, *_args):
        """Keep tray radio actions consistent with the saved Home policy."""
        actions = getattr(self, "tray_system_proxy_mode_actions", {})
        current_mode = CONFIG.get("system_proxy_mode", "unchanged")
        for mode, action in actions.items():
            action.setChecked(mode == current_mode)

    def _show_tray_context_menu(self):
        """Open the app menu just above its tray icon, inside the work area."""
        if not hasattr(self, "tray_menu"):
            return
        hidden = self.isHidden() or self.isMinimized()
        self.tray_toggle_action.setText("Show TorProxy" if hidden else "Hide TorProxy")
        self._sync_tray_menu_theme()
        self.tray_menu.ensurePolished()
        size = self.tray_menu.sizeHint()
        anchor = QCursor.pos()
        screen = QGuiApplication.screenAt(anchor) or QGuiApplication.primaryScreen()
        if screen is None:
            self.tray_menu.exec(anchor)
            return

        area = screen.availableGeometry()
        x = anchor.x() - size.width() // 2
        y = anchor.y() - size.height() - 12
        # Prefer opening above the icon. Use below only if the work area really
        # has insufficient vertical room, and clamp both positions to the screen.
        if y < area.top():
            y = anchor.y() + 12
        x = min(max(x, area.left()), area.right() - size.width() + 1)
        y = min(max(y, area.top()), area.bottom() - size.height() + 1)
        self.tray_menu.exec(QPoint(x, y))
   
    def _createMenuBar(self):
        # Use regular buttons: their icons and labels render consistently on every
        # platform, unlike native menu items whose icon/text style is OS-dependent.
        menu_bar = QWidget(self.main_widget)
        menu_bar.setObjectName("topMenuBar")
        menu_layout = QHBoxLayout(menu_bar)
        menu_layout.setContentsMargins(6, 3, 6, 3)
        menu_layout.setSpacing(2)
        self.menu_bar = menu_bar
        self.main_layout.addWidget(menu_bar)

        actions = [
            ("Home", "Home", "Ctrl+H", "fa6s.house", self._show_home, self.stack.indexOf(self.proxyWidget)),
            ("Settings", "Settings", "Ctrl+S", "fa6s.gear", self._show_setting, self.PAGE_SETTINGS),
            (
                "Developer Tor",
                "Host Onion Services with an isolated Tor runtime",
                "Ctrl+Alt+D",
                "fa6s.code",
                self._show_developer_tor,
                self.PAGE_DEVELOPER_TOR,
            ),
            (
                "Custom Tor",
                "Manage independent Tor services and profiles",
                "Ctrl+Alt+T",
                "fa6s.server",
                self._show_custom_tor,
                self.PAGE_CUSTOM_TOR,
            ),
            (
                "Help",
                "Keyboard shortcuts",
                "F1",
                "fa6s.circle-question",
                self._show_help,
                self.PAGE_HELP,
            ),
        ]
        self.page_action_group = QActionGroup(self)
        self.page_action_group.setExclusive(True)
        self.page_actions = []
        self.page_icon_names = []
        self.page_nav_buttons = []
        self.page_nav_page_indices = []
        self.page_action_pages = []
        self.page_nav_group = QButtonGroup(self)
        self.page_nav_group.setExclusive(True)
        icon_color = "#eff1f4" if CONFIG["mode"] == "dark" else "#202832"

        for index, (label, tooltip, shortcut, icon_name, callback, page_index) in enumerate(actions):
            action = QAction(label, self)
            action.setIcon(qta.icon(icon_name, color=icon_color))
            action.setCheckable(True)
            action.setShortcut(shortcut)
            action.setShortcutContext(Qt.ShortcutContext.WindowShortcut)
            action.setToolTip("{} ({})".format(tooltip, shortcut))
            action.triggered.connect(callback)
            self.page_action_group.addAction(action)
            self.addAction(action)
            self.page_actions.append(action)
            self.page_icon_names.append(icon_name)
            self.page_action_pages.append(page_index)

            button = QPushButton(label, menu_bar)
            button.setObjectName("topNavButton")
            button.setIcon(qta.icon(icon_name, color=icon_color))
            button.setIconSize(QSize(17, 17))
            button.setCheckable(True)
            button.setToolTip("{} ({})".format(tooltip, shortcut))
            button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            button.clicked.connect(callback)
            menu_layout.addWidget(button)
            self.page_nav_group.addButton(button, page_index)
            self.page_nav_buttons.append(button)
            self.page_nav_page_indices.append(page_index)
            if label == "Help":
                self.help_action = action
                self.help_nav_button = button

        # Preserve the host-rule keyboard shortcuts without taking up top-level
        # navigation space. Both shortcuts now open the corresponding Settings tab.
        self.block_hosts_shortcut_action = QAction("Blocked Hosts", self)
        self.block_hosts_shortcut_action.setShortcut("Ctrl+B")
        self.block_hosts_shortcut_action.setShortcutContext(Qt.ShortcutContext.WindowShortcut)
        self.block_hosts_shortcut_action.triggered.connect(self._show_block_host)
        self.addAction(self.block_hosts_shortcut_action)
        self.exclude_hosts_shortcut_action = QAction("Excluded Hosts", self)
        self.exclude_hosts_shortcut_action.setShortcut("Ctrl+E")
        self.exclude_hosts_shortcut_action.setShortcutContext(Qt.ShortcutContext.WindowShortcut)
        self.exclude_hosts_shortcut_action.triggered.connect(self._show_exclude_host)
        self.addAction(self.exclude_hosts_shortcut_action)

        self.updates_nav_button = UpdatesMenuButton(menu_bar)
        self.updates_nav_button.setObjectName("updatesNavButton")
        self.updates_nav_button.setText("Updates")
        self._sync_updates_nav_icon()
        self.updates_nav_button.setIconSize(QSize(17, 17))
        self.updates_nav_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.updates_nav_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.updates_nav_button.setCheckable(True)
        self.updates_nav_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.updates_nav_button.setToolTip("Manage Tor bundles and the system tunnel")
        self.updates_menu = QMenu(self.updates_nav_button)
        self.updates_menu.setObjectName("updatesMenu")
        self.updates_menu.setMinimumWidth(268)
        self.updates_menu.setSeparatorsCollapsible(False)

        self.updates_menu_header = QWidget(self.updates_menu)
        self.updates_menu_header.setObjectName("updatesMenuHeader")
        updates_header_layout = QVBoxLayout(self.updates_menu_header)
        updates_header_layout.setContentsMargins(14, 10, 14, 8)
        updates_header_layout.setSpacing(2)
        updates_header_title = QLabel("UPDATES", self.updates_menu_header)
        updates_header_title.setObjectName("updatesMenuEyebrow")
        updates_header_subtitle = QLabel(
            "Manage software components", self.updates_menu_header
        )
        updates_header_subtitle.setObjectName("updatesMenuSubtitle")
        updates_header_layout.addWidget(updates_header_title)
        updates_header_layout.addWidget(updates_header_subtitle)
        self.updates_menu_header_action = QWidgetAction(self.updates_menu)
        self.updates_menu_header_action.setDefaultWidget(self.updates_menu_header)
        self.updates_menu.addAction(self.updates_menu_header_action)
        self.updates_menu.addSeparator()

        self.bundles_update_action = self.updates_menu.addAction(
            qta.icon("fa6s.boxes-stacked", color=icon_color), "Bundles"
        )
        self.bundles_update_action.setToolTip("Download and manage Tor Expert Bundles")
        self.bundles_update_action.triggered.connect(self._show_updater)
        self.bundles_update_action.setShortcut("Ctrl+U")
        self.bundles_update_action.setShortcutContext(Qt.ShortcutContext.WindowShortcut)
        self.addAction(self.bundles_update_action)
        self.tunnel_update_action = self.updates_menu.addAction(
            qta.icon("fa6s.network-wired", color=icon_color), "Tunnel"
        )
        self.tunnel_update_action.setToolTip("Install and manage the system tunnel engine")
        self.tunnel_update_action.triggered.connect(self._show_tunnel_page)
        self.updates_nav_button.setMenu(self.updates_menu)
        self.updates_menu.aboutToShow.connect(self._on_updates_menu_about_to_show)
        self.updates_menu.aboutToHide.connect(self._on_updates_menu_about_to_hide)
        menu_layout.addWidget(self.updates_nav_button)

        self.exit_action = QAction("Exit", self)
        self.exit_action.setIcon(qta.icon("fa6s.right-from-bracket", color=icon_color))
        self.exit_action.setShortcut("Ctrl+Q")
        self.exit_action.setShortcutContext(Qt.ShortcutContext.WindowShortcut)
        self.exit_action.setToolTip("Exit TorProxy")
        self.exit_action.triggered.connect(self.ask_close)
        self.addAction(self.exit_action)

        self.exit_nav_button = HoverIconButton(
            "Exit", "fa6s.right-from-bracket", icon_color, menu_bar
        )
        self.exit_nav_button.setObjectName("topNavExitButton")
        self.exit_nav_button.setIconSize(QSize(17, 17))
        self.exit_nav_button.setToolTip("Exit TorProxy (Ctrl+Q)")
        self.exit_nav_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.exit_nav_button.clicked.connect(self.ask_close)
        menu_layout.addWidget(self.exit_nav_button)

        self.global_state = QPushButton("● Checking Tor state…", self)
        self.global_state.setObjectName("globalState")
        self.global_state.setFlat(True)
        self.global_state.setMinimumWidth(74)
        self.global_state.setToolTip("Open the Home Event Log when Tor reports a failure.")
        self.global_state.clicked.connect(self._open_event_log)
        self.global_state.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._notification_entries = []
        self.notifications_menu = QMenu(self)
        self.notifications_menu.setObjectName("notificationsMenu")
        self.notifications_menu.setMinimumWidth(344)
        self.notifications_menu.setSeparatorsCollapsible(False)

        self.notifications_menu_header = QWidget(self.notifications_menu)
        self.notifications_menu_header.setObjectName("notificationsMenuHeader")
        notifications_header_layout = QHBoxLayout(self.notifications_menu_header)
        notifications_header_layout.setContentsMargins(14, 10, 12, 9)
        notifications_header_layout.setSpacing(8)
        notifications_heading_layout = QVBoxLayout()
        notifications_heading_layout.setContentsMargins(0, 0, 0, 0)
        notifications_heading_layout.setSpacing(1)
        notifications_title = QLabel("Notifications", self.notifications_menu_header)
        notifications_title.setObjectName("notificationsMenuTitle")
        notifications_subtitle = QLabel(
            "Recent activity", self.notifications_menu_header
        )
        notifications_subtitle.setObjectName("notificationsMenuSubtitle")
        notifications_heading_layout.addWidget(notifications_title)
        notifications_heading_layout.addWidget(notifications_subtitle)
        notifications_header_layout.addLayout(notifications_heading_layout)
        notifications_header_layout.addStretch(1)
        self.notification_count_label = QLabel("0", self.notifications_menu_header)
        self.notification_count_label.setObjectName("notificationCountBadge")
        self.notification_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        notifications_header_layout.addWidget(self.notification_count_label)
        self.notification_clear_button = QToolButton(self.notifications_menu_header)
        self.notification_clear_button.setObjectName("notificationClearButton")
        self.notification_clear_button.setText("Clear all")
        self.notification_clear_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        self.notification_clear_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.notification_clear_button.clicked.connect(self._clear_notifications)
        notifications_header_layout.addWidget(self.notification_clear_button)
        self.notifications_menu_header_action = QWidgetAction(self)
        self.notifications_menu_header_action.setDefaultWidget(
            self.notifications_menu_header
        )
        self.notifications_menu.addAction(self.notifications_menu_header_action)
        self.notifications_menu.addSeparator()
        self._notification_menu_actions = []
        self.notification_btn = QPushButton(self)
        self.notification_btn.setObjectName("notificationButton")
        self.notification_btn.setToolTip("Notifications")
        self.notification_btn.setFixedSize(38, 30)
        self.notification_btn.clicked.connect(self._show_notifications)

        self.toggle_btn = QPushButton(self)
        self.toggle_btn.setObjectName("themeToggle")
        self.toggle_btn.setToolTip("Toggle light/dark appearance")
        self.toggle_btn.setFixedSize(34, 30)
        self.toggle_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.toggle_btn.clicked.connect(self._toggle_theme)

        corner = QWidget(menu_bar)
        corner.setObjectName("menuBarCorner")
        corner_layout = QHBoxLayout(corner)
        corner_layout.setContentsMargins(0, 0, 0, 0)
        corner_layout.setSpacing(3)
        corner_layout.addWidget(self.global_state)
        corner_layout.addWidget(self.notification_btn)
        corner_layout.addWidget(self.toggle_btn)
        menu_layout.addStretch(1)
        menu_layout.addWidget(corner)

    def _show_notifications(self):
        self.notifications_menu.exec(
            self.notification_btn.mapToGlobal(self.notification_btn.rect().bottomLeft())
        )

    def notify_user(self, title, message, level="info"):
        """Add a persistent, user-openable notification to the top-bar bell."""
        self._notification_entries.append({
            "title": str(title),
            "message": str(message),
            "level": "warning" if level == "warning" else "info",
        })
        self._notification_entries = self._notification_entries[-30:]
        count = len(self._notification_entries)
        self.notification_btn.setText(str(count if count < 100 else "99+"))
        self.notification_btn.setToolTip("{}: {}".format(title, message))
        self._rebuild_notifications_menu()

    def _rebuild_notifications_menu(self, mode=None):
        """Refresh the notification popup while keeping its branded header intact."""
        menu = getattr(self, "notifications_menu", None)
        if menu is None:
            return

        for action in getattr(self, "_notification_menu_actions", []):
            menu.removeAction(action)
            action.deleteLater()
        self._notification_menu_actions = []

        dark = (mode or CONFIG.get("mode", "dark")) == "dark"
        text = "#e8edf6" if dark else "#253246"
        muted = "#94a2b5" if dark else "#7b8798"
        accent = "#5797ed" if dark else "#2878d0"
        warning = "#e5b45b" if dark else "#b87818"

        count = len(self._notification_entries)
        self.notification_count_label.setText(str(count if count < 100 else "99+"))
        self.notification_count_label.setToolTip(
            "{} stored notification{}".format(count, "" if count == 1 else "s")
        )
        self.notification_clear_button.setEnabled(count > 0)
        self.notification_clear_button.setVisible(count > 0)

        if not count:
            empty_action = menu.addAction(
                qta.icon("fa6s.inbox", color=muted), "You're all caught up"
            )
            empty_action.setEnabled(False)
            empty_action.setToolTip("New TorProxy activity will appear here.")
            self._notification_menu_actions.append(empty_action)
            return

        for index, notice in enumerate(reversed(self._notification_entries)):
            is_warning = notice["level"] == "warning"
            icon = qta.icon(
                "fa6s.triangle-exclamation" if is_warning else "fa6s.circle-info",
                color=warning if is_warning else accent,
            )
            action = menu.addAction(icon, notice["title"])
            action.setToolTip(notice["message"])
            action.setStatusTip(notice["message"])
            action.triggered.connect(
                lambda _checked=False, t=notice["title"], m=notice["message"], lv=notice["level"]:
                    self._show_notice(t, m, lv)
            )
            self._notification_menu_actions.append(action)

            description_widget = QWidget(menu)
            description_widget.setObjectName("notificationDescriptionContainer")
            description_layout = QHBoxLayout(description_widget)
            description_layout.setContentsMargins(38, 0, 14, 8)
            description_layout.setSpacing(0)
            description_label = QLabel(notice["message"], description_widget)
            description_label.setObjectName("notificationDescription")
            description_label.setWordWrap(True)
            description_label.setMinimumWidth(260)
            description_label.setMaximumWidth(304)
            description_layout.addWidget(description_label)
            description_action = QWidgetAction(self)
            description_action.setDefaultWidget(description_widget)
            menu.addAction(description_action)
            self._notification_menu_actions.append(description_action)

            if index < count - 1:
                separator = menu.addSeparator()
                self._notification_menu_actions.append(separator)

    def _show_notice(self, title, message, level):
        if level == "warning":
            QMessageBox.warning(self, title, message)
        else:
            QMessageBox.information(self, title, message)

    def _clear_notifications(self):
        self._notification_entries.clear()
        self.notification_btn.setText("0")
        self.notification_btn.setToolTip("No new notifications")
        self._rebuild_notifications_menu()

    def _on_updates_menu_about_to_show(self):
        """Point the dropdown chevron upward while the menu is visible."""
        self.updates_nav_button.setMenuIndicatorOpen(True)
        self._sync_updates_nav_icon()

    def _on_updates_menu_about_to_hide(self):
        """Restore the dropdown chevron after the menu closes."""
        self.updates_nav_button.setMenuIndicatorOpen(False)
        self._sync_updates_nav_icon()

    def _sync_updates_nav_icon(self, mode=None):
        """Make the Updates text, cloud icon, and dropdown chevron share one state."""
        dark = (mode or CONFIG.get("mode", "dark")) == "dark"
        selected = self.stack.currentWidget() in (
            getattr(self, "updater_window", None),
            getattr(self, "tunnel_window", None),
        )
        self.updates_nav_button.setChecked(selected)
        color = "#ffffff" if selected else ("#eff1f4" if dark else "#202832")
        self.updates_nav_button.setIcon(qta.icon("fa6s.cloud-arrow-down", color=color))
        self.updates_nav_button.setMenuIndicatorColor(color)
    def _apply_shell_styles(self, mode=None):
        dark = (mode or CONFIG["mode"]) == "dark"
        border = "#3b4552" if dark else "#d7dee7"
        surface = "#272c33" if dark else "#ffffff"
        menu_surface = "#202630" if dark else "#edf1f6"
        text = "#eff1f4" if dark else "#202832"
        accent = "#287db5"
        hover = "rgba(71, 163, 242, 0.15)" if dark else "rgba(24, 118, 191, 0.11)"
        self.setStyleSheet(f"""
            QWidget#topMenuBar, QWidget#menuBarCorner {{ background-color: {menu_surface}; }}
            QWidget#topMenuBar {{ border: none; border-bottom: 1px solid {border}; }}
            QPushButton#topNavButton, QToolButton#updatesNavButton {{
                min-height: 32px; padding: 0 8px; margin: 0 1px; border: 1px solid transparent;
                border-bottom: 2px solid transparent; border-radius: 7px;
                color: {text}; background: transparent; font-size: 9pt; font-weight: 650;
            }}
            QPushButton#topNavButton:hover, QToolButton#updatesNavButton:hover {{
                color: {text}; background: {hover}; border-color: {border};
            }}
            QPushButton#topNavButton:checked, QToolButton#updatesNavButton:checked {{
                background: {accent}; color: #ffffff; border: 1px solid {accent};
                border-bottom: 2px solid #9bd8ff; font-weight: 750;
            }}
            QPushButton#topNavButton:checked:hover, QToolButton#updatesNavButton:checked:hover {{
                background: {accent}; color: #ffffff; border-color: {accent};
            }}
            /* Reserve a clear lane for the bottom-right dropdown chevron. */
            QToolButton#updatesNavButton {{ padding-right: 22px; }}
            QToolButton#updatesNavButton::menu-indicator {{
                image: none;
                width: 12px;
                height: 12px;
                subcontrol-origin: padding;
                subcontrol-position: bottom right;
            }}
            QPushButton#topNavExitButton {{
                min-height: 32px; padding: 0 9px; margin: 0 1px; border: 1px solid {border};
                border-radius: 7px; color: {text}; background: transparent; font-size: 9pt; font-weight: 700;
            }}
            QPushButton#topNavExitButton:hover {{ color: #ffffff; background: #b83336; border-color: #b83336; }}
            QWidget#menuBarCorner {{ border-bottom: 1px solid {border}; }}
            QWidget#menuBarCorner QLabel {{ background: transparent; color: {text}; border: none; padding: 0 4px; }}
            QPushButton#globalState {{ background: transparent; color: {text}; border: none; border-radius: 7px; padding: 0 4px; font-size: 10px; }}
            QPushButton#globalState:hover {{ background: {hover}; }}
            QWidget#menuBarCorner QPushButton {{ background: transparent; color: {text}; border: none; border-radius: 7px; }}
            QWidget#menuBarCorner QPushButton:hover {{ background: {hover}; }}
            QWidget#customTitleBar {{ background: {menu_surface}; border-bottom: 1px solid {border}; }}
            QLabel#windowTitle {{ color: {text}; font-size: 13px; font-weight: 700; }}
            QWidget#titleBarWindowControls {{ background: transparent; border: none; }}
            QPushButton#titleBarButton, QPushButton#titleBarCloseButton {{
                min-width: 46px; max-width: 46px; min-height: 40px; max-height: 40px;
                background: transparent; border: none; border-radius: 0px;
                padding: 0px; margin: 0px;
            }}
            QPushButton#titleBarButton:hover {{ background: {hover}; }}
            QPushButton#titleBarButton:pressed {{ background: rgba(90, 105, 125, 0.24); }}
            QPushButton#titleBarCloseButton:hover {{ background: #c42b1c; }}
            QPushButton#titleBarCloseButton:pressed {{ background: #a61f16; }}
            QPushButton#themeToggle, QPushButton#notificationButton {{ background: transparent; min-height: 28px; border: none; border-radius: 7px; padding: 0 7px; }}
            QPushButton#themeToggle:hover, QPushButton#notificationButton:hover {{ background: {hover}; }}
            QPushButton#notificationButton {{ font-weight: 700; }}
            QStackedWidget#pageStack {{ border: none; outline: none; background: {surface}; padding: 0; margin: 0; }}
            QMenu {{ background: {menu_surface}; color: {text}; border: 1px solid {border}; padding: 5px; }}
            QMenu::item {{ padding: 7px 20px 7px 10px; border-radius: 5px; }}
            QMenu::item:selected {{ background: {hover}; }}
            QMenu#updatesMenu, QMenu#notificationsMenu {{
                background: {"#171e29" if dark else "#ffffff"};
                color: {text};
                border: 1px solid {"#303b4c" if dark else "#dfe6ef"};
                border-radius: 13px;
                padding: 7px;
            }}
            QMenu#updatesMenu::item, QMenu#notificationsMenu::item {{
                color: {text};
                background: transparent;
                padding: 9px 16px 9px 36px;
                margin: 2px 4px;
                min-height: 22px;
                border-radius: 8px;
            }}
            QMenu#updatesMenu::item:selected, QMenu#notificationsMenu::item:selected {{
                color: {text};
                background: {"#29384d" if dark else "#edf3fb"};
            }}
            QMenu#updatesMenu::item:disabled, QMenu#notificationsMenu::item:disabled {{
                color: {"#94a2b5" if dark else "#7b8798"};
            }}
            QMenu#updatesMenu::separator, QMenu#notificationsMenu::separator {{
                height: 1px;
                background: {"#303b4c" if dark else "#e7ecf2"};
                margin: 5px 12px;
            }}
            QWidget#updatesMenuHeader, QWidget#notificationsMenuHeader,
            QWidget#notificationDescriptionContainer {{
                background: transparent;
                border: none;
            }}
            /* Header copy should sit directly on the menu surface, never on its own tile. */
            QLabel#updatesMenuEyebrow, QLabel#updatesMenuSubtitle,
            QLabel#notificationsMenuTitle, QLabel#notificationsMenuSubtitle,
            QLabel#notificationDescription {{
                background: transparent;
                border: none;
            }}
            QLabel#updatesMenuEyebrow {{
                color: {"#94a2b5" if dark else "#7b8798"};
                font-size: 8pt;
                font-weight: 750;
                letter-spacing: 1px;
            }}
            QLabel#updatesMenuSubtitle, QLabel#notificationsMenuSubtitle {{
                color: {"#94a2b5" if dark else "#7b8798"};
                font-size: 8pt;
            }}
            QLabel#notificationsMenuTitle {{
                color: {text};
                font-size: 10pt;
                font-weight: 750;
            }}
            QLabel#notificationCountBadge {{
                color: {accent};
                background: {"#263c55" if dark else "#eaf2fc"};
                border: 1px solid {"#385574" if dark else "#d8e7f8"};
                border-radius: 9px;
                min-width: 22px;
                min-height: 19px;
                padding: 1px 6px;
                font-size: 8pt;
                font-weight: 750;
            }}
            QToolButton#notificationClearButton {{
                color: {accent};
                background: transparent;
                border: none;
                border-radius: 6px;
                padding: 5px 7px;
                font-size: 8pt;
                font-weight: 650;
            }}
            QToolButton#notificationClearButton:hover {{
                background: {"#29384d" if dark else "#edf3fb"};
            }}
            QLabel#notificationDescription {{
                color: {"#94a2b5" if dark else "#7b8798"};
                background: transparent;
                font-size: 8pt;
                padding: 0;
            }}
        """)
        icon_color = text
        for index, (action, icon_name) in enumerate(zip(self.page_actions, self.page_icon_names)):
            color = "#ffffff" if action.isChecked() else icon_color
            action.setIcon(qta.icon(icon_name, color=color))
            if index < len(self.page_nav_buttons):
                self.page_nav_buttons[index].setIcon(qta.icon(icon_name, color=color))
        self._sync_updates_nav_icon(mode)
        self.bundles_update_action.setIcon(qta.icon("fa6s.boxes-stacked", color=icon_color))
        self.tunnel_update_action.setIcon(qta.icon("fa6s.network-wired", color=icon_color))
        self.exit_action.setIcon(qta.icon("fa6s.right-from-bracket", color=icon_color))
        self.exit_nav_button.setNormalIconColor(icon_color)
        self.toggle_btn.setIcon(qta.icon("fa6s.sun" if dark else "fa6s.moon", color=icon_color))
        self.notification_btn.setIcon(qta.icon("fa6s.bell", color=icon_color))
        self.notification_btn.setText(
            str(len(self._notification_entries) if len(self._notification_entries) < 100 else "99+")
        )
        self.notification_btn.setFixedSize(44, 30)
        self._rebuild_notifications_menu(mode)
        if IS_WINDOWS and hasattr(self, "title_bar"):
            self.title_bar.update_theme(icon_color)
        if hasattr(self, "proxyWidget") and hasattr(self.proxyWidget, "_apply_home_theme"):
            self.proxyWidget._apply_home_theme()

    def _open_event_log(self):
        self._show_home()
        proxy = getattr(self, "proxyWidget", None)
        if proxy is not None and (
            getattr(proxy, "failed", False)
            or getattr(getattr(proxy, "tor", None), "state", "") == "FAILED"
        ):
            if not getattr(proxy, "logs_open", False):
                proxy.show_logs()

    def _on_navigation_changed(self, row):
        # Compatibility hook for integrations which select a page by index.
        self._show_page(row)

    def _show_page(self, index):
        if 0 <= index < self.stack.count():
            page = self._ensure_page_created(index)
            # Apply local page styling only after the lazy page exists and just
            # before it becomes visible. Subsequent visits reuse that instance.
            self._ensure_page_theme(page)
            self.stack.setCurrentIndex(index)
            if hasattr(self, "page_actions"):
                self.page_action_group.setExclusive(False)
                for action, page_index in zip(self.page_actions, self.page_action_pages):
                    action.setChecked(page_index == index)
                self.page_action_group.setExclusive(True)
                if hasattr(self, "updates_nav_button"):
                    updates_pages = {
                        self.PAGE_BUNDLES,
                        self.PAGE_SYSTEM_TUNNEL,
                    }
                    self.updates_nav_button.setChecked(index in updates_pages)
                    self._sync_updates_nav_icon()
            if hasattr(self, "page_nav_buttons"):
                neutral_icon = "#eff1f4" if CONFIG["mode"] == "dark" else "#202832"
                # Updates is a separate menu destination, not one of the regular
                # top-level pages. Temporarily disable exclusivity so the old
                # Home/Settings button can actually become unchecked.
                self.page_nav_group.setExclusive(False)
                try:
                    for page_index, button, icon_name in zip(
                        self.page_nav_page_indices, self.page_nav_buttons, self.page_icon_names
                    ):
                        selected = page_index == index
                        button.setChecked(selected)
                        button.setIcon(qta.icon(icon_name, color="#ffffff" if selected else neutral_icon))
                finally:
                    self.page_nav_group.setExclusive(True)
            self._update_global_state()
    def _update_global_state(self):
        proxy_widget = getattr(self, "proxyWidget", None)
        if proxy_widget is None:
            self.global_state.setText("● Initializing")
            return
        self._sample_traffic_session()
        refresh_tunnel = getattr(proxy_widget, "_update_tunnel_hint", None)
        if callable(refresh_tunnel):
            refresh_tunnel()
        tor = getattr(proxy_widget, "tor", None)
        if tor is not None and not getattr(tor, "path_set", False):
            # The notification bell carries actionable setup warnings; keep the
            # persistent top-bar status short and visually unobtrusive.
            status = "Stopped"
        elif getattr(proxy_widget, "failed", False) or getattr(tor, "state", "") == "FAILED":
            status = "Failed · open Event Log"
        elif getattr(tor, "state", "") == "STOPPING" or getattr(proxy_widget, "_stopping", False):
            status = "Stopping"
        elif getattr(tor, "state", "") == "STARTING":
            status = "Starting"
        elif getattr(tor, "state", "") in {"BOOTSTRAPPING", "CONNECTING"}:
            status = "Bootstrapping"
        elif getattr(proxy_widget, "connected", False):
            status = "Ready"
        elif getattr(proxy_widget, "running", False):
            status = "Bootstrapping"
        else:
            status = "Stopped"
        if status == "Failed · open Event Log":
            status = "Failed"
        self.global_state.setText("●  {}".format(status))
        self.global_state.setToolTip(
            getattr(tor, "last_error", None)
            or ("No Tor bundle is configured. Open Bundles or review the notification bell. "
                if tor is not None and not getattr(tor, "path_set", False) else "")
            + "State is derived from TorRunner lifecycle and bootstrap/control-port checks. "
            "A running local HTTP proxy alone is not shown as Tor-ready."
        )

    def _prewarm_theme_stylesheets(self):
        """Compatibility hook: warm QSS strings without touching the widget tree."""
        _theme_stylesheet(CONFIG.get("mode", "dark"))
        _theme_stylesheet("light" if CONFIG.get("mode", "dark") == "dark" else "dark")

    def _ensure_page_theme(self, page, mode=None):
        """Apply a page's local theme once, immediately before it becomes visible."""
        if page is None:
            return False
        mode = mode or CONFIG.get("mode", "dark")
        if getattr(page, "_torproxy_theme_mode", None) == mode:
            return False

        apply_theme = getattr(page, "_apply_local_styles", None)
        if not callable(apply_theme):
            apply_theme = getattr(page, "apply_theme", None)
        if not callable(apply_theme):
            return False

        apply_theme(mode)
        page._torproxy_theme_mode = mode
        return True

    def _ensure_visible_theme_pages(self):
        """Catch up pages after the app is restored from the system tray."""
        for page in (
            getattr(self, "updater_window", None),
            getattr(self, "tunnel_window", None),
            getattr(self, "settingWidget", None),
            getattr(self, "block_host_window", None),
            getattr(self, "exclude_host_window", None),
            getattr(self, "shortcutsWidget", None),
            getattr(self, "statisticsWidget", None),
            getattr(self, "customTorWidget", None),
            getattr(self, "developerTorWidget", None),
        ):
            if page is not None and page.isVisible():
                self._ensure_page_theme(page)

    def _apply_local_theme_styles(self, mode, *, visible_only=False):
        """Update visible pages now; hidden pages are themed as they are opened."""
        pages = (
            getattr(self, "updater_window", None),
            getattr(self, "tunnel_window", None),
            getattr(self, "settingWidget", None),
            getattr(self, "block_host_window", None),
            getattr(self, "exclude_host_window", None),
            getattr(self, "shortcutsWidget", None),
            getattr(self, "statisticsWidget", None),
            getattr(self, "customTorWidget", None),
            getattr(self, "developerTorWidget", None),
        )
        for page in pages:
            if page is None or (visible_only and not page.isVisible()):
                continue
            started = time.perf_counter()
            self._ensure_page_theme(page, mode)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            if visible_only and elapsed_ms >= 8.0:
                name = page.objectName() or type(page).__name__
                logger.info("Theme page styling: %s took %.1f ms.", name, elapsed_ms)

        self._apply_shell_styles(mode)
        if hasattr(self, "window_system_menu"):
            self._sync_window_system_menu_theme(mode)
        if hasattr(self, "tray_menu"):
            self._sync_tray_menu_theme(mode)

    def _sync_tray_menu_theme(self, mode=None):
        """Apply the current app theme to the floating system-tray menu."""
        menu = getattr(self, "tray_menu", None)
        if menu is None:
            return

        dark = (mode or CONFIG.get("mode", "dark")) == "dark"
        if dark:
            surface = "#171e29"
            border = "#303b4c"
            text = "#e8edf6"
            muted = "#94a2b5"
            hover = "#29384d"
            accent = "#5797ed"
            divider = "#303b4c"
            danger = "#ef7777"
        else:
            surface = "#ffffff"
            border = "#dfe6ef"
            text = "#253246"
            muted = "#7b8798"
            hover = "#edf3fb"
            accent = "#2878d0"
            divider = "#e7ecf2"
            danger = "#c94343"

        menu.setStyleSheet(f"""
            QMenu#trayContextMenu {{
                background-color: {surface};
                color: {text};
                border: 1px solid {border};
                border-radius: 14px;
                padding: 6px;
            }}
            QMenu#trayContextMenu::item {{
                color: {text};
                background: transparent;
                padding: 7px 14px 7px 12px;
                margin: 1px 4px;
                min-height: 20px;
                border-radius: 8px;
            }}
            QMenu#trayContextMenu::item:selected {{
                color: {text};
                background-color: {hover};
            }}
            QMenu#trayContextMenu::item:disabled {{
                color: {muted};
            }}
            QMenu#trayContextMenu::separator {{
                height: 1px;
                background-color: {divider};
                margin: 4px 12px;
            }}
            QMenu#trayContextMenu::indicator {{
                width: 14px;
                height: 14px;
                border: 1px solid {border};
                border-radius: 7px;
                background: transparent;
                margin-left: 4px;
            }}
            QMenu#trayContextMenu::indicator:checked {{
                background-color: {accent};
                border: 4px solid {surface};
            }}
            QWidget#trayMenuHeader, QWidget#trayMenuSection {{
                background: transparent;
                border: none;
            }}
            QLabel#trayMenuTitle {{
                color: {text};
                font-size: 10pt;
                font-weight: 700;
            }}
            QLabel#trayMenuSubtitle {{
                color: {muted};
                font-size: 8pt;
            }}
            QLabel#trayMenuSectionLabel {{
                color: {muted};
                font-size: 8pt;
                font-weight: 700;
            }}
        """)

        icon_color = "#edf2f9" if dark else "#344258"
        hidden = self.isHidden() or self.isMinimized()
        self.tray_toggle_action.setIcon(
            qta.icon("fa6s.eye" if hidden else "fa6s.eye-slash", color=icon_color)
        )
        proxy_icons = {
            "set": "fa6s.link",
            "unchanged": "fa6s.circle-minus",
            "clear": "fa6s.link-slash",
        }
        for proxy_mode, action in self.tray_system_proxy_mode_actions.items():
            action.setIcon(qta.icon(proxy_icons[proxy_mode], color=icon_color))
        self.tray_exit_action.setIcon(
            qta.icon("fa6s.right-from-bracket", color=danger)
        )

    def _theme_reveal_origin(self):
        """Choose the pointer position as the reveal origin, with a safe fallback."""
        pointer = self.mapFromGlobal(QCursor.pos())
        if self.rect().contains(pointer):
            return pointer
        toggle = getattr(self, "toggle_btn", None)
        if toggle is not None:
            return toggle.mapTo(self, toggle.rect().center())
        return self.rect().center()

    def _cancel_theme_reveal(self):
        overlay = getattr(self, "_theme_reveal", None)
        self._theme_reveal = None
        if overlay is not None:
            overlay.cancel()

    def _finish_theme_reveal(self, overlay):
        if getattr(self, "_theme_reveal", None) is overlay:
            self._theme_reveal = None

    def _set_theme(self, mode, *, preference=None):
        if mode not in {"dark", "light"}:
            return
        if preference is not None and preference not in {"system", "dark", "light"}:
            return

        theme_started = time.perf_counter()
        app = QApplication.instance()
        should_animate = (
            app is not None
            and self.isVisible()
            and self.width() > 0
            and self.height() > 0
            and CONFIG.get("mode") != mode
        )
        old_snapshot = None
        reveal_origin = None
        snapshot_ms = 0.0
        if should_animate:
            # Keep one old frame only. The new theme is rendered live underneath
            # the overlay; taking a second full-window snapshot adds a costly
            # synchronous grab without adding useful information.
            self._cancel_theme_reveal()
            capture_started = time.perf_counter()
            old_snapshot = self.grab()
            snapshot_ms = (time.perf_counter() - capture_started) * 1000.0
            reveal_origin = self._theme_reveal_origin()

        persist_started = time.perf_counter()
        try:
            if preference is None:
                if CONFIG.get("mode") != mode:
                    CONFIG["mode"] = mode
            else:
                CONFIG.update_many({"mode": mode, "theme_preference": preference})
        except (ValueError, OSError, KeyError):
            logger.exception("Could not persist the selected theme preference.")
            return
        persist_ms = (time.perf_counter() - persist_started) * 1000.0

        app_stylesheet_ms = 0.0
        if app is not None:
            stylesheet = _theme_stylesheet(mode)
            # main.py has already installed the startup theme. Skip the second
            # QApplication-wide repolish when the requested mode is unchanged.
            if app.styleSheet() != stylesheet:
                stylesheet_started = time.perf_counter()
                app.setStyleSheet(stylesheet)
                app_stylesheet_ms = (time.perf_counter() - stylesheet_started) * 1000.0

        if hasattr(self, "settingWidget"):
            sync_theme = getattr(self.settingWidget, "set_theme_mode", None)
            if callable(sync_theme):
                sync_theme(mode)

        local_started = time.perf_counter()
        self._apply_local_theme_styles(mode, visible_only=True)
        local_styles_ms = (time.perf_counter() - local_started) * 1000.0

        overlay_ms = 0.0
        if should_animate and old_snapshot is not None and not old_snapshot.isNull():
            overlay_started = time.perf_counter()
            overlay = CircularThemeReveal(
                self,
                old_snapshot,
                reveal_origin,
                duration_ms=300,
            )
            overlay.setGeometry(self.rect())
            overlay.finished.connect(
                lambda current=overlay: self._finish_theme_reveal(current)
            )
            self._theme_reveal = overlay
            overlay.show()
            overlay.raise_()
            overlay.start()
            overlay_ms = (time.perf_counter() - overlay_started) * 1000.0

        total_ms = (time.perf_counter() - theme_started) * 1000.0
        logger.info(
            "Theme switch to %s: %.1f ms total "
            "(snapshot %.1f, config %.1f, application QSS %.1f, "
            "visible-page styles %.1f, reveal setup %.1f).",
            mode,
            total_ms,
            snapshot_ms,
            persist_ms,
            app_stylesheet_ms,
            local_styles_ms,
            overlay_ms,
        )

    def _set_theme_preference(self, preference):
        """Apply and persist one of the three supported theme preferences."""
        if preference not in {"system", "light", "dark"}:
            return
        mode = (
            resolve_system_theme(QApplication.instance())
            if preference == "system"
            else preference
        )
        self._set_theme(mode, preference=preference)

    def _on_system_color_scheme_changed(self, _scheme=None):
        """Refresh the UI when the OS changes appearance while System is selected."""
        if CONFIG.get("theme_preference", "system") != "system":
            return
        mode = resolve_system_theme(QApplication.instance())
        if mode != CONFIG.get("mode"):
            self._set_theme(mode)

    def _toggle_theme(self):
        # The title-bar shortcut is an explicit override, not a temporary
        # departure from System mode that would be undone by the next OS event.
        mode = "light" if CONFIG["mode"] == "dark" else "dark"
        self._set_theme(mode, preference=mode)

    def _request_exit(self):
        """Coalesce menu and native Alt+F4 requests into one confirmed exit."""
        if (
            getattr(self, "_exit_request_pending", False)
            or getattr(self, "_exit_request_in_progress", False)
            or getattr(self, "_exit_authorized", False)
            or getattr(self, "_shutdown_in_progress", False)
            or getattr(self, "_shutdown_complete", False)
        ):
            return

        self._exit_request_pending = True
        QTimer.singleShot(0, self._dispatch_exit_request)

    def _dispatch_exit_request(self):
        """Run the potentially modal exit confirmation outside native message handling."""
        self._exit_request_pending = False
        if (
            getattr(self, "_exit_request_in_progress", False)
            or getattr(self, "_exit_authorized", False)
            or getattr(self, "_shutdown_in_progress", False)
            or getattr(self, "_shutdown_complete", False)
        ):
            return

        self._exit_request_in_progress = True
        try:
            self.ask_close()
        finally:
            self._exit_request_in_progress = False

    def ask_close(self):
        """Perform a deliberate application exit from either Exit command."""
        if bool(CONFIG["confirm_exit"]):
            dialog = ExitConfirmDialog(self if self.isVisible() else None)
            dialog.exec()
            if dialog.dont_ask_checkbox.isChecked():
                try:
                    CONFIG["confirm_exit"] = False
                except (ValueError, OSError, KeyError):
                    logger.exception("Could not persist the do-not-ask-again preference.")
                if hasattr(self, "settingWidget"):
                    checkbox = getattr(self.settingWidget, "chk_confirm_exit", None)
                    if checkbox is not None:
                        checkbox.blockSignals(True)
                        checkbox.setChecked(bool(CONFIG["confirm_exit"]))
                        checkbox.blockSignals(False)
            if dialog.choice != QMessageBox.Yes:
                return
        self._exit_authorized = True
        self.close()
            
    
    def _show_help(self):
        self._show_page(self.PAGE_HELP)

    def _show_statistics(self):
        self._show_page(self.PAGE_STATISTICS)

    def _show_custom_tor(self):
        self._show_page(self.PAGE_CUSTOM_TOR)

    def _show_developer_tor(self):
        self._show_page(self.PAGE_DEVELOPER_TOR)

    def _show_home(self):
        self._show_page(self.PAGE_HOME)

    def _show_setting(self):
        self._show_page(self.PAGE_SETTINGS)

    def _show_block_host(self):
        self._show_setting()
        self.settingWidget.show_blocked_hosts()

    def _show_exclude_host(self):
        self._show_setting()
        self.settingWidget.show_excluded_hosts()

    def _show_updater(self):
        self._show_page(self.PAGE_BUNDLES)

    def _show_tunnel_page(self):
        self._show_page(self.PAGE_SYSTEM_TUNNEL)

    def _notify(self, title, message):
        self.tray_icon.showMessage(title, message, QSystemTrayIcon.Information, 2000)

    def closeEvent(self, event):
        # Ordinary window closes only hide to the tray. Explicit Exit performs
        # cleanup asynchronously, then closes again when the worker completes.
        if not getattr(self, "_exit_authorized", False):
            event.ignore()
            self.hide_to_tray()
            return

        if getattr(self, "_shutdown_complete", False):
            event.accept()
            return

        event.ignore()
        if self._shutdown_in_progress:
            return

        self._shutdown_in_progress = True
        self._closing = True
        if hasattr(self, "_state_timer"):
            self._state_timer.stop()
        if hasattr(self, "hotkey_manager"):
            self.hotkey_manager.stop()
        try:
            self.tray_icon.hide()
        except Exception:
            pass

        if not self.proxyWidget._request_stop_services(final_status="APPLICATION EXIT"):
            self._on_proxy_shutdown_complete(
                False,
                "Application exit could not start asynchronous cleanup. "
                "Resolve the active tunnel operation and try again.",
            )

    def _on_proxy_shutdown_complete(self, success: bool, error: str = "") -> None:
        """Finish or roll back an explicit asynchronous application shutdown."""
        self._shutdown_in_progress = False
        if success:
            self._shutdown_complete = True
            self._exit_authorized = True
            self.close()
            app = QApplication.instance()
            if app is not None:
                app.quit()
            return

        self._closing = False
        self._exit_authorized = False
        self._shutdown_complete = False
        # The exit worker may have stopped Developer Tor successfully before
        # another child (for example the system tunnel) failed. Re-open the
        # Developer Tor lifecycle when the application exit is rolled back.
        onion_manager = getattr(self.proxyWidget, "onion_hosting_manager", None)
        resume_runtime = getattr(onion_manager, "resume_after_cancelled_shutdown", None)
        if callable(resume_runtime):
            try:
                resume_runtime()
            except Exception:
                logger.exception("Could not resume Developer Tor after the application exit was cancelled.")
        try:
            self.tray_icon.show()
        except Exception:
            pass
        if hasattr(self, "_state_timer"):
            self._state_timer.start()
        hotkey_start = getattr(getattr(self, "hotkey_manager", None), "start", None)
        if callable(hotkey_start):
            hotkey_start()
        QMessageBox.warning(
            self,
            "Could not exit TorProxy",
            str(error or "Cleanup failed; the app remains open for network-state inspection."),
        )
