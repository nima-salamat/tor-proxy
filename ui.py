from contextlib import contextmanager

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
    QButtonGroup,
    QFrame,
    QSystemTrayIcon
)
from PySide6.QtGui import QIcon, QAction, QActionGroup, QGuiApplication, QCursor
import qdarkstyle
from qdarkstyle.dark.palette import DarkPalette
from qdarkstyle.light.palette import LightPalette
from PySide6.QtCore import QEvent, QTimer, Qt, Signal, QSize, QPoint
import qtawesome as qta
from ui_.window.theme_transition import CircularThemeReveal
from utils import resource_path
import logging
from config import CONFIG, IS_WINDOWS
from torproxy.hotkeys import HotkeyManager, parse_hotkey
from ui_.worker.worker import Worker
from ui_.window.proxy_window import ProxyWindow
from ui_.window.custom_titlebar import CustomTitleBar
from ui_.window.setting_window import SettingWindow
from ui_.window.block_host_window import BlcokHostsWindow
from ui_.window.exclude_host_window import ExcludeHostsWindow
from ui_.window.updater_window import UpdaterWindow
from ui_.window.dialogs import QMessageBox, ExitConfirmDialog
from ui_.window.shortcuts_window import ShortcutsWindow
logger = logging.getLogger(__name__)

class Window(QMainWindow):
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

        # Existing feature pages remain the authoritative widgets and controllers.
        self.stack = QStackedWidget()
        self.stack.setObjectName("pageStack")
        self.stack.setFrameShape(QFrame.Shape.NoFrame)
        self.stack.setLineWidth(0)
        self._constraining_move = False
        self.proxyWidget = ProxyWindow(self)
        self.stack.addWidget(self.proxyWidget)
        self.settingWidget = SettingWindow(self)
        self.stack.addWidget(self.settingWidget)
        self.block_host_window = BlcokHostsWindow(self)
        self.stack.addWidget(self.block_host_window)
        self.exclude_host_window = ExcludeHostsWindow(self)
        self.stack.addWidget(self.exclude_host_window)
        self.updater_window = UpdaterWindow(self)
        self.stack.addWidget(self.updater_window)
        self.shortcutsWidget = ShortcutsWindow(self)
        self.stack.addWidget(self.shortcutsWidget)

        if IS_WINDOWS:
            self.title_bar = CustomTitleBar(self)
            self.main_layout.addWidget(self.title_bar)
        self._createMenuBar()

        # Pages fill the central surface directly; no extra card/frame around Home,
        # Settings, or the other stacked pages.
        self.main_layout.addWidget(self.stack, 1)
        # Select the first page after the stack has real geometry in the root layout.
        self._show_page(0)
        self._apply_shell_styles()

        self._state_timer = QTimer(self)
        self._state_timer.setInterval(1000)
        self._state_timer.timeout.connect(self._update_global_state)
        self._state_timer.start()
        self._update_global_state()
        self._set_theme(CONFIG["mode"])

        self._exit_authorized = False
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(resource_path("assets/icon.png")))
        self.tray_icon.setToolTip("TorProxy")
        self.tray_menu = QMenu(self)
        self.tray_toggle_action = QAction("Show / Hide TorProxy", self)
        self.tray_toggle_action.triggered.connect(self._toggle_visibility)
        self.tray_menu.addAction(self.tray_toggle_action)
        self.tray_menu.addSeparator()

        # Keep the three tray choices wired to the same policy combo and
        # handler used by Home; never change OS proxy settings through a second path.
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
            # Put each checkable policy directly in the tray menu. QActionGroup
            # keeps exactly one active choice checked without another submenu.
            self.tray_menu.addAction(action)
            self.tray_system_proxy_mode_actions[mode] = action

        self.tray_menu.addSeparator()
        self.tray_exit_action = QAction("Exit TorProxy", self)
        self.tray_exit_action.setIcon(qta.icon("fa6s.right-from-bracket", color="#d9534f"))
        self.tray_exit_action.triggered.connect(self.ask_close)
        self.tray_menu.addAction(self.tray_exit_action)

        proxy_mode_combo = getattr(self.proxyWidget, "system_proxy_mode", None)
        if proxy_mode_combo is not None:
            proxy_mode_combo.currentIndexChanged.connect(self._sync_tray_system_proxy_actions)
        self._sync_tray_system_proxy_actions()

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
        QTimer.singleShot(0, self._refresh_layout_after_restore)

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.Type.WindowStateChange and not self.isMinimized():
            QTimer.singleShot(0, self._refresh_layout_after_restore)

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
        if self._constraining_move or self.isMinimized() or self.isMaximized() or self.isFullScreen():
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
        self.tray_toggle_action.setText(
            "Show TorProxy" if self.isHidden() or self.isMinimized() else "Hide TorProxy"
        )
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
            ("Home", "Home", "Ctrl+H", "fa6s.house", self._show_home),
            ("Settings", "Settings", "Ctrl+S", "fa6s.gear", self._show_setting),
            ("Block Host", "Blocked host rules", "Ctrl+B", "fa6s.shield-halved", self._show_block_host),
            ("Exclude Host", "Bypass rules", "Ctrl+E", "fa6s.route", self._show_exclude_host),
            ("Bundles", "Tor bundles and updates", "Ctrl+U", "fa6s.boxes-stacked", self._show_updater),
            ("Help", "Keyboard shortcuts", "F1", "fa6s.circle-question", self._show_help),
        ]
        self.page_action_group = QActionGroup(self)
        self.page_action_group.setExclusive(True)
        self.page_actions = []
        self.page_icon_names = []
        self.page_nav_buttons = []
        self.page_nav_group = QButtonGroup(self)
        self.page_nav_group.setExclusive(True)
        icon_color = "#eff1f4" if CONFIG["mode"] == "dark" else "#202832"

        for index, (label, tooltip, shortcut, icon_name, callback) in enumerate(actions):
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

            button = QPushButton(label, menu_bar)
            button.setObjectName("topNavButton")
            button.setIcon(qta.icon(icon_name, color=icon_color))
            button.setIconSize(QSize(17, 17))
            button.setCheckable(True)
            button.setToolTip("{} ({})".format(tooltip, shortcut))
            button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            button.clicked.connect(callback)
            menu_layout.addWidget(button)
            self.page_nav_group.addButton(button, index)
            self.page_nav_buttons.append(button)
            if label == "Help":
                self.help_action = action
                self.help_nav_button = button

        self.exit_action = QAction("Exit", self)
        self.exit_action.setIcon(qta.icon("fa6s.right-from-bracket", color=icon_color))
        self.exit_action.setShortcut("Ctrl+Q")
        self.exit_action.setShortcutContext(Qt.ShortcutContext.WindowShortcut)
        self.exit_action.setToolTip("Exit TorProxy")
        self.exit_action.triggered.connect(self.ask_close)
        self.addAction(self.exit_action)

        self.exit_nav_button = QPushButton("Exit", menu_bar)
        self.exit_nav_button.setObjectName("topNavExitButton")
        self.exit_nav_button.setIcon(qta.icon("fa6s.right-from-bracket", color=icon_color))
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
        empty_notification = self.notifications_menu.addAction("No notifications")
        empty_notification.setEnabled(False)
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
        self.notifications_menu.clear()
        clear_action = self.notifications_menu.addAction("Clear notifications")
        clear_action.triggered.connect(self._clear_notifications)
        self.notifications_menu.addSeparator()
        for notice in reversed(self._notification_entries):
            action = self.notifications_menu.addAction(
                "{} · {}".format("⚠" if notice["level"] == "warning" else "●", notice["title"])
            )
            action.setToolTip(notice["message"])
            action.triggered.connect(
                lambda _checked=False, t=notice["title"], m=notice["message"], lv=notice["level"]: self._show_notice(t, m, lv)
            )

    def _show_notice(self, title, message, level):
        if level == "warning":
            QMessageBox.warning(self, title, message)
        else:
            QMessageBox.information(self, title, message)

    def _clear_notifications(self):
        self._notification_entries.clear()
        self.notification_btn.setText("0")
        self.notification_btn.setToolTip("No new notifications")
        self.notifications_menu.clear()
        empty = self.notifications_menu.addAction("No notifications")
        empty.setEnabled(False)

    def _apply_shell_styles(self):
        dark = CONFIG["mode"] == "dark"
        border = "#3b4552" if dark else "#d7dee7"
        surface = "#272c33" if dark else "#ffffff"
        menu_surface = "#202630" if dark else "#edf1f6"
        text = "#eff1f4" if dark else "#202832"
        accent = "#287db5"
        hover = "rgba(71, 163, 242, 0.15)" if dark else "rgba(24, 118, 191, 0.11)"
        self.setStyleSheet(f"""
            QWidget#topMenuBar, QWidget#menuBarCorner {{ background-color: {menu_surface}; }}
            QWidget#topMenuBar {{ border: none; border-bottom: 1px solid {border}; }}
            QPushButton#topNavButton {{
                min-height: 32px; padding: 0 8px; margin: 0 1px; border: 1px solid transparent;
                border-bottom: 2px solid transparent; border-radius: 7px;
                color: {text}; background: transparent; font-size: 9pt; font-weight: 650;
            }}
            QPushButton#topNavButton:hover {{ background: {hover}; border-color: {border}; }}
            QPushButton#topNavButton:checked {{
                background: {accent}; color: #ffffff; border: 1px solid {accent};
                border-bottom: 2px solid #9bd8ff; font-weight: 750;
            }}
            QPushButton#topNavButton:checked:hover {{ background: {accent}; color: #ffffff; }}
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
            QPushButton#titleBarButton, QPushButton#titleBarCloseButton {{ background: transparent; border: none; border-radius: 5px; }}
            QPushButton#titleBarButton:hover {{ background: {hover}; }}
            QPushButton#titleBarCloseButton:hover {{ background: #c42b1c; }}
            QPushButton#themeToggle, QPushButton#notificationButton {{ background: transparent; min-height: 28px; border: none; border-radius: 7px; padding: 0 7px; }}
            QPushButton#themeToggle:hover, QPushButton#notificationButton:hover {{ background: {hover}; }}
            QPushButton#notificationButton {{ font-weight: 700; }}
            QStackedWidget#pageStack {{ border: none; outline: none; background: {surface}; padding: 0; margin: 0; }}
            QMenu {{ background: {menu_surface}; color: {text}; border: 1px solid {border}; padding: 5px; }}
            QMenu::item {{ padding: 7px 20px 7px 10px; border-radius: 5px; }}
            QMenu::item:selected {{ background: {hover}; }}
        """)
        icon_color = text
        for index, (action, icon_name) in enumerate(zip(self.page_actions, self.page_icon_names)):
            color = "#ffffff" if action.isChecked() else icon_color
            action.setIcon(qta.icon(icon_name, color=color))
            if index < len(self.page_nav_buttons):
                self.page_nav_buttons[index].setIcon(qta.icon(icon_name, color=color))
        self.exit_action.setIcon(qta.icon("fa6s.right-from-bracket", color=icon_color))
        self.exit_nav_button.setIcon(qta.icon("fa6s.right-from-bracket", color=icon_color))
        self.toggle_btn.setIcon(qta.icon("fa6s.sun" if dark else "fa6s.moon", color=icon_color))
        self.notification_btn.setIcon(qta.icon("fa6s.bell", color=icon_color))
        self.notification_btn.setText(
            str(len(self._notification_entries) if len(self._notification_entries) < 100 else "99+")
        )
        self.notification_btn.setFixedSize(44, 30)
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
            self.stack.setCurrentIndex(index)
            if hasattr(self, "page_actions") and index < len(self.page_actions):
                self.page_actions[index].setChecked(True)
            if hasattr(self, "page_nav_buttons"):
                neutral_icon = "#eff1f4" if CONFIG["mode"] == "dark" else "#202832"
                for page_index, button in enumerate(self.page_nav_buttons):
                    selected = page_index == index
                    button.setChecked(selected)
                    icon_name = self.page_icon_names[page_index]
                    button.setIcon(qta.icon(icon_name, color="#ffffff" if selected else neutral_icon))
            self._update_global_state()
    def _update_global_state(self):
        proxy_widget = getattr(self, "proxyWidget", None)
        if proxy_widget is None:
            self.global_state.setText("● Initializing")
            return
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

    def _set_theme(self, mode):
        if mode not in {"dark", "light"}:
            return

        overlay = None
        app = QApplication.instance()
        should_animate = (
            app is not None
            and self.isVisible()
            and self.width() > 0
            and self.height() > 0
            and CONFIG.get("mode") != mode
        )
        if should_animate:
            # Remove an in-flight reveal before taking the next snapshot. This
            # makes rapid theme toggles restart from the currently applied theme.
            self._cancel_theme_reveal()
            snapshot = self.grab()
            if not snapshot.isNull():
                overlay = CircularThemeReveal(
                    self, snapshot, self._theme_reveal_origin(), duration_ms=460
                )
                overlay.setGeometry(self.rect())
                overlay.finished.connect(
                    lambda current=overlay: self._finish_theme_reveal(current)
                )
                self._theme_reveal = overlay
                overlay.show()
                overlay.raise_()

        CONFIG["mode"] = mode
        palette = DarkPalette() if mode == "dark" else LightPalette()
        if app is not None:
            app.setStyleSheet(qdarkstyle.load_stylesheet(palette=palette))
        if hasattr(self, "settingWidget"):
            sync_theme = getattr(self.settingWidget, "set_theme_mode", None)
            if callable(sync_theme):
                sync_theme(mode)
        if hasattr(self, "updater_window"):
            self.updater_window._apply_local_styles()
        for page in (
            getattr(self, "settingWidget", None),
            getattr(self, "block_host_window", None),
            getattr(self, "exclude_host_window", None),
            getattr(self, "shortcutsWidget", None),
        ):
            apply_theme = getattr(page, "apply_theme", None)
            if callable(apply_theme):
                apply_theme(mode)
        self._apply_shell_styles()
        if overlay is not None:
            overlay.start()

    def _toggle_theme(self):
        self._set_theme("light" if CONFIG["mode"] == "dark" else "dark")

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
        # A window hidden to the tray is no longer a visible "last window".
        # Quit explicitly so Exit works identically from the tray menu.
        app = QApplication.instance()
        if app is not None:
            app.quit()
            
    
    def _show_help(self):
        self._show_page(5)
    
    def _show_home(self):
        self._show_page(0)

    def _show_setting(self):
        self._show_page(1)

    def _show_block_host(self):
        self._show_page(2)

    def _show_exclude_host(self):
        self._show_page(3)

    def _show_updater(self):
        self._show_page(4)

    def _notify(self, title, message):
        self.tray_icon.showMessage(title, message, QSystemTrayIcon.Information, 2000)

    def closeEvent(self, event):
        # OS taskbar close and the titlebar × are hide actions, not application
        # exits. Only one of the explicit Exit commands sets this flag.
        if not getattr(self, "_exit_authorized", False):
            event.ignore()
            self.hide_to_tray()
            return

        self._closing = True
        if hasattr(self, "_state_timer"):
            self._state_timer.stop()
        if hasattr(self, "hotkey_manager"):
            self.hotkey_manager.stop()
        try:
            self.tray_icon.hide()
        except Exception:
            pass
        try:
            self.proxyWidget._stop_services()
        except Exception:
            logger.exception("Failed while stopping services during application shutdown.")
        logger.info("TorProxy application exit accepted.")
        event.accept()
