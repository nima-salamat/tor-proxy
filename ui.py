from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QMenuBar,
    QMenu,
    QStackedWidget,
    QWidget,
    QVBoxLayout,
    QPushButton,
    QMessageBox,
    QSystemTrayIcon
)
from PySide6.QtGui import QIcon, QAction
import qdarkstyle
from qdarkstyle.dark.palette import DarkPalette
from qdarkstyle.light.palette import LightPalette
from PySide6.QtCore import Qt, Signal
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
            self.setWindowFlag(Qt.FramelessWindowHint)
        self.main_widget = QWidget(self)
        self.setCentralWidget(self.main_widget)
        self.stack = QStackedWidget(self.main_widget)
        self.main_layout = QVBoxLayout(self.main_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)

        self.setWindowTitle("app")
        self.resize(800, 600)
        
        
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
        self.main_layout.addWidget(self.stack)
        
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(resource_path("assets/icon.png")))
        
        tray_menu = QMenu()
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
        menuBar = QMenuBar(self)
        self.main_layout.addWidget(menuBar)

        # --- Home ---
        home_action = QAction(HOME, self)
        home_action.setShortcut("Ctrl+H")
        home_action.setToolTip("Ctrl+H")
        home_action.triggered.connect(self._show_home)
        menuBar.addAction(home_action)

        # --- Setting ---
        setting_action = QAction(SETTING, self)
        setting_action.setShortcut("Ctrl+S")
        setting_action.setToolTip("Ctrl+S")
        setting_action.triggered.connect(self._show_setting)
        menuBar.addAction(setting_action)

        # --- Block Host ---
        block_action = QAction(BLOCK_HOST, self)
        block_action.setShortcut("Ctrl+B")
        block_action.setToolTip("Ctrl+B")
        block_action.triggered.connect(self._show_block_host)
        menuBar.addAction(block_action)
        
        # --- Exclude Host ---
        exclude_action = QAction(EXCLUDE_HOST, self)
        exclude_action.setShortcut("Ctrl+E")
        exclude_action.setToolTip("Ctrl+E")
        exclude_action.triggered.connect(self._show_exclude_host)
        menuBar.addAction(exclude_action)
        
        # --- Updater ---
        updater_action = QAction("Updater", self)
        updater_action.setShortcut("Ctrl+U")
        updater_action.setToolTip("Ctrl+U")
        updater_action.triggered.connect(self._show_updater)
        menuBar.addAction(updater_action)

        # --- Help ---
        help_action = QAction(HELP, self)
        help_action.setShortcut("F1")
        help_action.setToolTip("Show shortcuts")
        help_action.triggered.connect(self._show_help)
        menuBar.addAction(help_action)
        
        # --- Quit ---
        exit_action = QAction(QUIT, self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.setToolTip("Ctrl+Q")
        exit_action.triggered.connect(self.ask_close)
        menuBar.addAction(exit_action)
        
        self.toggle_btn = QPushButton(LIGHT if CONFIG["mode"] == "light" else DARK, self)
        self.toggle_btn.setToolTip("Toggle Light/Dark Mode")
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.clicked.connect(self._toggle_theme)
        menuBar.setCornerWidget(self.toggle_btn, Qt.TopRightCorner)
    
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
                "Ctrl + E → Exlude Host<br>"
                "Ctrl + Q → Quit"
            )
        )
    
    def _show_home(self):
        self.stack.setCurrentIndex(0)

    def _show_setting(self):
        self.stack.setCurrentIndex(1)
    
    def _show_block_host(self):
        self.stack.setCurrentIndex(2)
    
    def _show_exclude_host(self):
        self.stack.setCurrentIndex(3)
        
    def _show_updater(self):
        self.stack.setCurrentIndex(4)
        
    def _notify(self, title, message):
        self.tray_icon.showMessage(title, message, QSystemTrayIcon.Information, 2000)

    def closeEvent(self, event):
        if IS_WINDOWS and event.spontaneous():
            logger.info("The window is closing by the close button.")
            event.ignore()
            self.hide()
            return
        elif IS_WINDOWS:
            self.listener_running = False
            self.listener_thread.join()
        
        self.listener_running = False 
        self.tray_icon.hide()  
        self.proxyWidget._stop_services()
        logger.info("The window is closing by some other method.")
        event.accept()

    def moveEvent(self, event):
        if IS_WINDOWS:
            btn_x, btn_y, btn_w, btn_h = self.title_bar.btn_close.geometry().getRect()

            x, y, w, h = self.geometry().getRect()

            screen_rect = QApplication.primaryScreen().availableGeometry()
            screen_w, screen_h = screen_rect.width(), screen_rect.height()

            if x + btn_x < 0:
                x = -btn_x
            if y + btn_y < 0:
                y = -btn_y
            if x + btn_x + btn_w > screen_w:
                x = screen_w - (btn_x + btn_w)
            if y + btn_y + btn_h > screen_h:
                y = screen_h - (btn_y + btn_h)

            self.move(x, y)
