from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QMenuBar,
    QMenu,
    QStackedWidget,
    QWidget,
    QLabel,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QMessageBox,
    QSystemTrayIcon
)
from PySide6.QtGui import QIcon, QAction, QActionGroup
import qdarkstyle
from qdarkstyle.dark.palette import DarkPalette
from qdarkstyle.light.palette import LightPalette
from PySide6.QtCore import Qt, Signal, QTimer
from utils import resource_path
import keyboard
import threading
import time
import logging
from config import CONFIG, IS_WINDOWS
from ui_.worker.worker import Worker
from ui_.window.proxy_window import ProxyWindow
from ui_.window.custom_titlebar import CustomTitleBar
from ui_.window.setting_window import SettingWindow
from ui_.window.block_host_window import BlcokHostsWindow
from ui_.window.exclude_host_window import ExcludeHostsWindow
from ui_.window.updater_window import UpdaterWindow
from ui_.emojis import DARK, LIGHT, QUIT, HOME, EXCLUDE_HOST, BLOCK_HOST, SETTING, HELP
logger = logging.getLogger(__name__)

class Window(QMainWindow):
    toggle_visibility_signal = Signal()
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

        if IS_WINDOWS:
            self.title_bar = CustomTitleBar(self)
            self.main_layout.addWidget(self.title_bar)
        self._createMenuBar()
        self._show_page(0)

        # Each page owns its own content; avoid wasting vertical space on a duplicate global header.
        page_area = QWidget(self.main_widget)
        page_area.setObjectName("pageSurface")
        page_layout = QVBoxLayout(page_area)
        page_layout.setContentsMargins(16, 12, 16, 14)
        page_layout.setSpacing(0)
        page_layout.addWidget(self.stack, 1)
        self.main_layout.addWidget(page_area, 1)
        self._apply_shell_styles()

        self._state_timer = QTimer(self)
        self._state_timer.setInterval(1000)
        self._state_timer.timeout.connect(self._update_global_state)
        self._state_timer.start()
        self._update_global_state()

        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(resource_path("assets/icon.png")))
        tray_menu = QMenu()
        show_action = QAction("Show TorProxy", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(lambda: (self.show(), self.close()))
        tray_menu.addAction(quit_action)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.show_window)
        self.tray_icon.show()

        self.listener_running = True
        self.listener_thread = threading.Thread(target=self._start_key_listener, daemon=True)
        if IS_WINDOWS:
            self.listener_thread.start()
        self.toggle_visibility_signal.connect(self._toggle_visibility)

    def _toggle_visibility(self):
        self.setHidden(not self.isHidden())

    def _start_key_listener(self):
        keyboard.add_hotkey('ctrl+alt+p', lambda: self.toggle_visibility_signal.emit())
        while self.listener_running:
            time.sleep(0.5)
        keyboard.unhook_all_hotkeys()

    def show_tray(self):
        self.hide()
        # # shold use show becuase tray will delete after system locked in this case windows
        # self.tray_icon.show()
        
    
    def show_window(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            if self.isHidden():
                self.show()
            else:
                self.hide()
   
    def _createMenuBar(self):
        menu_bar = QMenuBar(self)
        menu_bar.setObjectName("topMenuBar")
        self.menu_bar = menu_bar
        self.main_layout.addWidget(menu_bar)

        actions = [
            (HOME, "Overview", "Ctrl+H", self._show_home),
            (SETTING, "Settings", "Ctrl+S", self._show_setting),
            (BLOCK_HOST, "Blocked hosts", "Ctrl+B", self._show_block_host),
            (EXCLUDE_HOST, "Bypass rules", "Ctrl+E", self._show_exclude_host),
            ("Bundles", "Tor Bundles & Updates", "Ctrl+U", self._show_updater),
        ]
        self.page_action_group = QActionGroup(self)
        self.page_action_group.setExclusive(True)
        self.page_actions = []
        for label, tooltip, shortcut, callback in actions:
            action = QAction(label, self)
            action.setCheckable(True)
            self.page_action_group.addAction(action)
            self.page_actions.append(action)
            action.setShortcut(shortcut)
            action.setToolTip("{} ({})".format(tooltip, shortcut))
            action.triggered.connect(callback)
            menu_bar.addAction(action)

        help_action = QAction(HELP, self)
        help_action.setShortcut("F1")
        help_action.setToolTip("Keyboard shortcuts")
        help_action.triggered.connect(self._show_help)
        menu_bar.addAction(help_action)

        exit_action = QAction(QUIT, self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.setToolTip("Quit TorProxy")
        exit_action.triggered.connect(self.ask_close)
        menu_bar.addAction(exit_action)

        self.global_state = QLabel("● Checking Tor state…", self)
        self.global_state.setObjectName("globalState")
        self.global_state.setMinimumWidth(112)
        self.global_state.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.global_state.setWordWrap(False)
        self._notification_entries = []
        self.notifications_menu = QMenu(self)
        empty_notification = self.notifications_menu.addAction("No notifications")
        empty_notification.setEnabled(False)
        self.notification_btn = QPushButton("🔔 0", self)
        self.notification_btn.setObjectName("notificationButton")
        self.notification_btn.setToolTip("Notifications")
        self.notification_btn.clicked.connect(self._show_notifications)

        self.toggle_btn = QPushButton(LIGHT if CONFIG["mode"] == "light" else DARK, self)
        self.toggle_btn.setObjectName("themeToggle")
        self.toggle_btn.setToolTip("Toggle light/dark appearance")
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.clicked.connect(self._toggle_theme)

        corner = QWidget(menu_bar)
        corner_layout = QHBoxLayout(corner)
        corner_layout.setContentsMargins(0, 0, 0, 0)
        corner_layout.setSpacing(6)
        corner_layout.addWidget(self.global_state)
        corner_layout.addWidget(self.notification_btn)
        corner_layout.addWidget(self.toggle_btn)
        menu_bar.setCornerWidget(corner, Qt.TopRightCorner)

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
        self.notification_btn.setText("🔔 {}".format(count if count < 100 else "99+"))
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
        self.notification_btn.setText("🔔 0")
        self.notification_btn.setToolTip("No new notifications")
        self.notifications_menu.clear()
        empty = self.notifications_menu.addAction("No notifications")
        empty.setEnabled(False)

    def _apply_shell_styles(self):
        if CONFIG["mode"] == "dark":
            border, surface, text = "#414a56", "#272c33", "#eff1f4"
        else:
            border, surface, text = "#d5dbe2", "#ffffff", "#202832"
        self.setStyleSheet("""
            QLabel#globalState { color: %s; font-size: 10px; font-weight: 650; padding: 0 5px; background: transparent; border: none; }
            QWidget#pageSurface { background: %s; }
            QMenuBar#topMenuBar { border: none; border-bottom: 1px solid %s; padding: 3px 8px; }
            QMenuBar#topMenuBar::item { padding: 7px 10px; margin: 0 2px; border-radius: 6px; }
            QMenuBar#topMenuBar::item:selected { background: rgba(65, 137, 196, 0.22); }
            QMenuBar#topMenuBar::item:checked { background: #287db5; color: #ffffff; }
            QWidget#customTitleBar { background: %s; border-bottom: 1px solid %s; }
            QLabel#windowTitle { color: %s; font-size: 13px; font-weight: 700; }
            QPushButton#titleBarButton, QPushButton#titleBarCloseButton { background: transparent; border: none; border-radius: 5px; color: %s; font-size: 16px; }
            QPushButton#titleBarButton:hover { background: rgba(120, 140, 160, 0.22); }
            QPushButton#titleBarCloseButton:hover { background: #c42b1c; color: white; }
            QPushButton#themeToggle, QPushButton#notificationButton { min-height: 28px; padding: 0 9px; border-radius: 6px; }
            QPushButton#notificationButton { font-weight: 650; }
            QStackedWidget#pageStack { background: transparent; }
        """ % (text, surface, border, surface, border, text, text))

    def _on_navigation_changed(self, row):
        # Compatibility hook for integrations which select a page by index.
        self._show_page(row)

    def _show_page(self, index):
        if 0 <= index < self.stack.count():
            self.stack.setCurrentIndex(index)
            if hasattr(self, "page_actions") and index < len(self.page_actions):
                self.page_actions[index].setChecked(True)
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
        self.global_state.setText("●  {}".format(status))
        self.global_state.setToolTip(
            getattr(tor, "last_error", None)
            or ("No Tor bundle is configured. Open Bundles or review the notification bell. "
                if tor is not None and not getattr(tor, "path_set", False) else "")
            + "State is derived from TorRunner lifecycle and bootstrap/control-port checks. "
            "A running local HTTP proxy alone is not shown as Tor-ready."
        )

    def _toggle_theme(self):
        app = QApplication.instance()
        if self.toggle_btn.text() == (LIGHT):
            self.toggle_btn.setText(DARK)
            self.settingWidget.btn_dark.setChecked(True)
            app.setStyleSheet(qdarkstyle.load_stylesheet(palette=DarkPalette()))  
            
            CONFIG.mode= "dark"
                
        else:
            self.toggle_btn.setText(LIGHT)
            self.settingWidget.btn_light.setChecked(True)
            app.setStyleSheet(qdarkstyle.load_stylesheet(palette=LightPalette())) 
            CONFIG.mode = "light"
     
        self._apply_shell_styles()
        if hasattr(self, "updater_window"):
            self.updater_window._apply_local_styles()

    def ask_close(self):
        reply = QMessageBox.question(
            self,
            "Confirm Exit",
            "Are you sure you want to quit?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            
            self.close()
            
    
    def _show_help(self):
        QMessageBox.information(
            self,
            "Keyboard Shortcuts",
            (
                "<b>Keyboard Shortcuts:</b><br><br>"+
                ("Alt + Ctrl + P → Hide/Show Hotkey<br>" if IS_WINDOWS else "")+
                "Ctrl + H → Home<br>"
                "Ctrl + S → Setting<br>"
                "Ctrl + B → Block Host<br>"
                "Ctrl + E → Bypass rules<br>"
                "Ctrl + U → Tor bundles and updates<br>"
                "Ctrl + Q → Quit"
            )
        )
    
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
        # The custom title bar's Exit action confirms, then closes and stops services.
        self.listener_running = False
        if IS_WINDOWS and hasattr(self, "listener_thread") and self.listener_thread.is_alive():
            self.listener_thread.join(timeout=1.0)
        try:
            self.tray_icon.hide()
        except Exception:
            pass
        try:
            self.proxyWidget._stop_services()
        except Exception:
            logger.exception("Failed while stopping services during application shutdown.")
        logger.info("TorProxy window closed.")
        event.accept()
