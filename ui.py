from collections import deque
from contextlib import contextmanager
import ctypes
import math
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
from PySide6.QtCore import QEvent, QThreadPool, QTimer, Qt, Signal, QSize, QPoint, QPointF, QRect
import qtawesome as qta
from ui_.window.theme_transition import CircularThemeReveal
from ui_.window.theme import resolve_system_theme
from utils import resource_path
import logging
from config import CONFIG, IS_WINDOWS
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


class PageSpinner(QWidget):
    """Small, theme-aware circular activity indicator for deferred page loading."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._phase = 0
        self._accent = QColor("#47a3f2")
        self.setFixedSize(30, 30)
        self._timer = QTimer(self)
        self._timer.setInterval(85)
        self._timer.timeout.connect(self._advance)
        self.hide()

    def set_accent(self, color: str) -> None:
        selected = QColor(str(color))
        if selected.isValid() and selected != self._accent:
            self._accent = selected
            self.update()

    def start(self) -> None:
        if not self._timer.isActive():
            self._timer.start()
        self.show()

    def stop(self) -> None:
        self._timer.stop()

    def _advance(self) -> None:
        self._phase = (self._phase + 1) % 12
        self.update()

    def paintEvent(self, event) -> None:
        if not self.isVisible():
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        center_x = self.width() / 2.0
        center_y = self.height() / 2.0
        inner_radius = 5.0
        outer_radius = 11.5
        for index in range(12):
            distance = (self._phase - index) % 12
            alpha = max(28, int(255 * (1.0 - distance / 12.0) ** 1.7))
            color = QColor(self._accent)
            color.setAlpha(alpha)
            angle = (index * math.tau / 12.0) - math.pi / 2.0
            start = QPointF(
                center_x + math.cos(angle) * inner_radius,
                center_y + math.sin(angle) * inner_radius,
            )
            finish = QPointF(
                center_x + math.cos(angle) * outer_radius,
                center_y + math.sin(angle) * outer_radius,
            )
            painter.setPen(
                QPen(
                    color,
                    2.2,
                    Qt.PenStyle.SolidLine,
                    Qt.PenCapStyle.RoundCap,
                )
            )
            painter.drawLine(start, finish)
        painter.end()


class DeferredPagePlaceholder(QWidget):
    """Visible, retryable loading surface for a page that is not ready yet."""

    retry_requested = Signal()

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self._page_title = str(title)
        self.setObjectName("deferredPagePlaceholder")
        self.setMinimumSize(0, 0)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(0)
        outer.addStretch(1)

        self.content = QWidget(self)
        self.content.setObjectName("deferredPageLoadingContent")
        content_layout = QVBoxLayout(self.content)
        content_layout.setContentsMargins(18, 18, 18, 18)
        content_layout.setSpacing(12)

        self.title_label = QLabel(self.content)
        self.title_label.setObjectName("deferredPageLoadingTitle")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.detail_label = QLabel(self.content)
        self.detail_label.setObjectName("deferredPageLoadingDetail")
        self.detail_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.detail_label.setWordWrap(True)
        self.detail_label.setMaximumWidth(440)

        self.spinner = PageSpinner(self.content)

        self.retry_button = QPushButton("Try again", self.content)
        self.retry_button.setObjectName("deferredPageRetry")
        self.retry_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.retry_button.setFixedHeight(36)
        self.retry_button.clicked.connect(self.retry_requested.emit)

        content_layout.addWidget(self.title_label)
        content_layout.addWidget(self.detail_label)
        content_layout.addWidget(self.spinner, 0, Qt.AlignmentFlag.AlignHCenter)
        content_layout.addWidget(self.retry_button, 0, Qt.AlignmentFlag.AlignHCenter)
        outer.addWidget(self.content, 0, Qt.AlignmentFlag.AlignHCenter)
        outer.addStretch(1)

        self.apply_theme(CONFIG.get("mode", "dark"))
        self.set_queued()

    def apply_theme(self, mode: str) -> None:
        dark = str(mode).strip().lower() == "dark"
        title = "#edf3fa" if dark else "#202b38"
        detail = "#9eacbc" if dark else "#627184"
        track = "#303b49" if dark else "#e2e8f0"
        accent = "#47a3f2" if dark else "#1876bf"
        self.content.setStyleSheet("background: transparent;")
        self.title_label.setStyleSheet(
            f"background: transparent; color: {title}; font-size: 16px; font-weight: 700;"
        )
        self.detail_label.setStyleSheet(
            f"background: transparent; color: {detail}; font-size: 12px;"
        )
        self.spinner.set_accent(accent)
        self.retry_button.setStyleSheet(
            f"QPushButton#deferredPageRetry {{ color: {title}; background: {track}; "
            f"border: 1px solid {accent}; border-radius: 8px; padding: 0 16px; }}"
            f"QPushButton#deferredPageRetry:hover {{ background: {accent}; color: #ffffff; }}"
        )
        self._torproxy_theme_mode = "dark" if dark else "light"

    def set_queued(self) -> None:
        self.title_label.setText(f"{self._page_title} is queued")
        self.detail_label.setText("This section will prepare automatically after Home is ready.")
        self.spinner.stop()
        self.spinner.hide()
        self.retry_button.hide()

    def set_loading(self) -> None:
        self.title_label.setText(f"Loading {self._page_title}")
        self.detail_label.setText(
            "Preparing this section. It will appear here automatically when it is ready."
        )
        self.spinner.start()
        self.retry_button.hide()

    def set_error(self, error: Exception | str) -> None:
        detail = " ".join(str(error or "Unknown error").split())
        if len(detail) > 260:
            detail = detail[:257] + "..."
        self.title_label.setText(f"{self._page_title} could not be loaded")
        self.detail_label.setText(
            f"{detail}\nYou can retry without restarting TorProxy."
        )
        self.spinner.stop()
        self.spinner.hide()
        self.retry_button.show()


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
        self._page_titles = {
            self.PAGE_SETTINGS: "Settings",
            self.PAGE_BUNDLES: "Updates",
            self.PAGE_SYSTEM_TUNNEL: "System Tunnel",
            self.PAGE_HELP: "Keyboard Shortcuts",
            self.PAGE_STATISTICS: "Statistics",
            self.PAGE_CUSTOM_TOR: "Custom Tor",
            self.PAGE_DEVELOPER_TOR: "Developer Tor",
        }
        self._page_placeholders = {}
        self._page_states = {}
        self._page_load_queue = deque(
            range(self.PAGE_SETTINGS, self.PAGE_DEVELOPER_TOR + 1)
        )
        self._page_loading_index = None
        self._page_preload_started = False
        self._page_load_timer = QTimer(self)
        self._page_load_timer.setSingleShot(True)
        self._page_load_timer.timeout.connect(self._load_next_deferred_page)
        self._page_build_timer = QTimer(self)
        self._page_build_timer.setSingleShot(True)
        self._page_build_timer.timeout.connect(self._construct_active_deferred_page)
        for page_index in range(self.PAGE_SETTINGS, self.PAGE_DEVELOPER_TOR + 1):
            placeholder = DeferredPagePlaceholder(
                self._page_titles[page_index], self.stack
            )
            placeholder.retry_requested.connect(
                lambda selected=page_index: self._retry_deferred_page(selected)
            )
            self.stack.addWidget(placeholder)
            self._page_placeholders[page_index] = placeholder
            self._page_states[page_index] = "queued"

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
        self._deferred_startup_started = False
        self._hotkey_start_worker = None
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
        # The hotkey backend is imported and constructed after the first Home frame.
        self.hotkey_manager = None
        # Global hotkeys are started asynchronously after the first Home frame.
        # Create the HWND while hidden and advertise the native sizing/maximize
        # capabilities before the first frame is shown to Windows.
        self._enable_native_snap_support()

    def start_deferred_startup(self) -> None:
        """Start optional desktop services after the first Home frame is painted."""
        if self._deferred_startup_started:
            return
        self._deferred_startup_started = True
        start_proxy_deferred = getattr(self.proxyWidget, "start_deferred_startup", None)
        if callable(start_proxy_deferred):
            try:
                start_proxy_deferred()
            except Exception:
                logger.exception("Could not schedule the deferred system-tunnel status check.")
        self._start_hotkey_manager_async()
        # Home has already been shown and painted by main.py before this hook.
        # Warm feature pages afterwards, never as part of the first window frame.
        QTimer.singleShot(650, self._start_deferred_page_preloading)

    def _ensure_hotkey_manager(self):
        """Import and configure the optional global-hotkey backend on demand."""
        if self.hotkey_manager is None:
            from torproxy.hotkeys import HotkeyManager

            self.hotkey_manager = HotkeyManager(on_error=self.hotkey_error_signal.emit)
            self.hotkey_manager.register(
                "window_visibility",
                str(CONFIG["global_shortcut"]),
                lambda: self.toggle_visibility_signal.emit(),
            )
        return self.hotkey_manager

    def _start_hotkey_manager_async(self) -> None:
        """Initialize the global-hotkey backend away from the GUI thread."""
        if self._hotkey_start_worker is not None or getattr(self, "_closing", False):
            return
        manager = self._ensure_hotkey_manager()
        worker = Worker(manager.start)
        worker.signals.finished.connect(self._on_hotkey_manager_started)
        worker.signals.error.connect(self._on_hotkey_manager_start_failed)
        self._hotkey_start_worker = worker
        QThreadPool.globalInstance().start(worker)

    def _on_hotkey_manager_started(self, _result: str) -> None:
        self._hotkey_start_worker = None
        # A close can race with the queued startup task. Stop again after the
        # backend confirms startup so no global shortcut survives application exit.
        manager = getattr(self, "hotkey_manager", None)
        if getattr(self, "_closing", False) and self.hotkey_manager is not None:
            self.hotkey_manager.stop()

    def _on_hotkey_manager_start_failed(self, error: str) -> None:
        self._hotkey_start_worker = None
        logger.warning("Global hotkey initialization failed: %s", error)
        if not getattr(self, "_closing", False):
            self.hotkey_error_signal.emit(str(error))

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

    def _build_deferred_page(self, index):
        """Construct one QWidget on the GUI thread after its loading surface paints."""
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
            raise ValueError(f"Unsupported deferred page index: {index}")
        return page

    def _ensure_page_created(self, index):
        """Return a ready page or its loading surface and queue one safe creation."""
        if not 0 <= index < self.stack.count():
            return None
        placeholder = self._page_placeholders.get(index)
        if placeholder is None:
            return self.stack.widget(index)

        self._request_deferred_page(index, prioritize=True)
        return placeholder

    def _request_deferred_page(self, index, *, prioritize=False):
        if index not in self._page_placeholders:
            return
        state = self._page_states.get(index)
        if state in {"ready", "loading", "failed"}:
            return
        placeholder = self._page_placeholders.get(index)
        if placeholder is not None:
            placeholder.set_loading()
        if prioritize:
            try:
                self._page_load_queue.remove(index)
            except ValueError:
                pass
            self._page_load_queue.appendleft(index)
        elif index not in self._page_load_queue:
            self._page_load_queue.append(index)
        self._schedule_deferred_page_load(90)

    def _schedule_deferred_page_load(self, delay_ms=180):
        if (
            getattr(self, "_closing", False)
            or self._page_loading_index is not None
            or self._page_load_timer.isActive()
            or self._page_build_timer.isActive()
        ):
            return
        if self._page_load_queue:
            self._page_load_timer.start(max(0, int(delay_ms)))

    def _start_deferred_page_preloading(self):
        """Queue every secondary page only after Home has had time to become interactive."""
        if self._page_preload_started or getattr(self, "_closing", False):
            return
        self._page_preload_started = True
        self._schedule_deferred_page_load(0)

    def _retry_deferred_page(self, index):
        if index not in self._page_placeholders:
            return
        if self._page_states.get(index) != "failed":
            return
        placeholder = self._page_placeholders[index]
        placeholder.set_loading()
        self._page_states[index] = "queued"
        try:
            self._page_load_queue.remove(index)
        except ValueError:
            pass
        self._page_load_queue.appendleft(index)
        self._schedule_deferred_page_load(90)

    def _load_next_deferred_page(self):
        if getattr(self, "_closing", False) or self._page_loading_index is not None:
            return
        while self._page_load_queue:
            index = self._page_load_queue.popleft()
            if (
                index not in self._page_placeholders
                or self._page_states.get(index) != "queued"
            ):
                continue
            self._page_loading_index = index
            self._page_states[index] = "loading"
            self._page_placeholders[index].set_loading()
            # Give Qt one event-loop turn to paint the progress indicator before
            # entering a page constructor. Constructors stay on the GUI thread,
            # as required by QWidget; they are never run in a worker thread.
            self._page_build_timer.start(90)
            return

    def _construct_active_deferred_page(self):
        index = self._page_loading_index
        if index is None:
            self._schedule_deferred_page_load(0)
            return
        if getattr(self, "_closing", False):
            self._page_states[index] = "queued"
            self._page_loading_index = None
            return

        placeholder = self._page_placeholders.get(index)
        if placeholder is None:
            self._page_loading_index = None
            self._schedule_deferred_page_load(0)
            return

        page = None
        try:
            page = self._build_deferred_page(index)
            if not isinstance(page, QWidget):
                raise TypeError(
                    f"{self._page_titles.get(index, 'Page')} did not create a QWidget."
                )
            # Style before inserting so a theme error cannot leave a partially
            # replaced stack entry or a stale page reference behind.
            self._ensure_page_theme(page)
            self.stack.removeWidget(placeholder)
            self.stack.insertWidget(index, page)
            self._page_placeholders.pop(index, None)
            self._page_states[index] = "ready"
            placeholder.deleteLater()
            if self.stack.currentIndex() == index:
                self.stack.setCurrentWidget(page)
            logger.debug(
                "Deferred page %s finished loading.",
                self._page_titles.get(index, index),
            )
        except Exception as exc:
            # Constructors and theme hooks may fail after allocating a QWidget.
            # Dispose of any unattached instance and clear its public references
            # so Retry always creates a fresh, internally consistent page.
            if isinstance(page, QWidget) and self.stack.indexOf(page) >= 0:
                self._page_placeholders.pop(index, None)
                self._page_states[index] = "ready"
                placeholder.deleteLater()
            else:
                if isinstance(page, QWidget):
                    page.deleteLater()
                if self.stack.indexOf(placeholder) < 0:
                    self.stack.insertWidget(index, placeholder)
                if index == self.PAGE_SETTINGS:
                    self.settingWidget = None
                    self.block_host_window = None
                    self.exclude_host_window = None
                elif index == self.PAGE_BUNDLES:
                    self.updater_window = None
                elif index == self.PAGE_SYSTEM_TUNNEL:
                    self.tunnel_window = None
                elif index == self.PAGE_HELP:
                    self.shortcutsWidget = None
                elif index == self.PAGE_STATISTICS:
                    self.statisticsWidget = None
                elif index == self.PAGE_CUSTOM_TOR:
                    self.customTorWidget = None
                elif index == self.PAGE_DEVELOPER_TOR:
                    self.developerTorWidget = None
                self._page_states[index] = "failed"
                placeholder.set_error(f"{type(exc).__name__}: {exc}")
                logger.exception(
                    "Could not load deferred page %s.",
                    self._page_titles.get(index, index),
                )
        finally:
            self._page_loading_index = None
            self._update_global_state()
            self._schedule_deferred_page_load(220)

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
        hotkey_manager = getattr(self, "hotkey_manager", None)
        if hotkey_manager is not None:
            hotkey_manager.stop()
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
        self._start_hotkey_manager_async()
        QMessageBox.warning(
            self,
            "Could not exit TorProxy",
            str(error or "Cleanup failed; the app remains open for network-state inspection."),
        )
