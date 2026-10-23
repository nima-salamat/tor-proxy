from __future__ import annotations

import ast
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def qt_app():
    pytest.importorskip("PySide6")
    try:
        from PySide6.QtWidgets import QApplication
    except (ImportError, OSError) as exc:
        pytest.skip(f"Qt native libraries are unavailable in this environment: {exc}")

    return QApplication.instance() or QApplication([])


def _message_handler_capture():
    from PySide6.QtCore import qInstallMessageHandler

    warnings: list[str] = []
    previous = qInstallMessageHandler(
        lambda _mode, _context, message: warnings.append(message)
        if "QLayout: Attempting to add QLayout" in message
        else None
    )
    return warnings, previous, qInstallMessageHandler


def test_settings_and_main_window_construct_without_duplicate_layout_warning(qt_app, monkeypatch):
    try:
        import ui
        from PySide6.QtWidgets import QWidget
    except (ImportError, OSError) as exc:
        pytest.skip(f"Desktop UI native dependencies are unavailable in this environment: {exc}")

    class _FakeProxyWidget(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.tor = SimpleNamespace(path_set=False, MaxCircuitDirtiness=600)
            self.connected = False
            self.running = False

        def _stop_services(self):
            return None

    monkeypatch.setattr(ui, "ProxyWindow", _FakeProxyWidget)
    monkeypatch.setattr(ui, "IS_WINDOWS", False)
    warnings, previous, install_handler = _message_handler_capture()
    window = None
    try:
        window = ui.Window()
        qt_app.processEvents()
    finally:
        install_handler(previous)
        if window is not None:
            window.close()
            window.deleteLater()
            qt_app.processEvents()
    assert warnings == []


def test_layout_source_has_one_owner_per_root_and_no_widget_parented_nested_layout():
    repository = Path(__file__).resolve().parents[1]
    paths = [
        repository / "ui.py",
        repository / "ui_/window/setting_window.py",
        repository / "ui_/window/proxy_window.py",
        repository / "ui_/window/block_host_window.py",
        repository / "ui_/window/exclude_host_window.py",
    ]
    for path in paths:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        # Root layouts created with QWidget as parent already install themselves.
        # The previously problematic duplicate setLayout calls are therefore forbidden
        # for a variable initialized by Q*Layout(self).
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            parented_layouts = set()
            for child in ast.walk(node):
                if not isinstance(child, ast.Assign) or len(child.targets) != 1:
                    continue
                target = child.targets[0]
                value = child.value
                if (
                    isinstance(target, ast.Name)
                    and isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Name)
                    and value.func.id in {"QVBoxLayout", "QHBoxLayout", "QGridLayout", "QFormLayout"}
                    and value.args
                    and isinstance(value.args[0], ast.Name)
                    and value.args[0].id == "self"
                ):
                    parented_layouts.add(target.id)
            for child in ast.walk(node):
                if not isinstance(child, ast.Call) or not isinstance(child.func, ast.Attribute):
                    continue
                if child.func.attr != "setLayout" or not child.args:
                    continue
                if isinstance(child.args[0], ast.Name) and child.args[0].id in parented_layouts:
                    pytest.fail(f"{path.name} redundantly attaches parent-owned layout '{child.args[0].id}'")

def test_top_menu_is_the_only_page_navigation_and_release_filter_uses_bool():
    repository = Path(__file__).resolve().parents[1]
    ui_source = (repository / "ui.py").read_text(encoding="utf-8")
    assert "self.navigation" not in ui_source
    assert "sidebar = QFrame" not in ui_source
    assert "self._createMenuBar()" in ui_source

    updater_tree = ast.parse(
        (repository / "ui_/window/updater_window.py").read_text(encoding="utf-8")
    )
    filter_method = next(
        node for node in ast.walk(updater_tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_filter_versions"
    )
    set_hidden_calls = [
        node for node in ast.walk(filter_method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "setHidden"
    ]
    assert set_hidden_calls
    assert all(
        isinstance(call.args[0], ast.Call)
        and isinstance(call.args[0].func, ast.Name)
        and call.args[0].func.id == "bool"
        for call in set_hidden_calls if call.args
    )



def test_window_uses_native_multimonitor_frame_and_persistent_notifications():
    repository = Path(__file__).resolve().parents[1]
    ui_source = (repository / "ui.py").read_text(encoding="utf-8")
    main_source = (repository / "main.py").read_text(encoding="utf-8")
    titlebar_source = (repository / "ui_/window/custom_titlebar.py").read_text(encoding="utf-8")
    assert "FramelessWindowHint" in ui_source
    assert "def moveEvent" in ui_source
    assert "_screen_for_geometry" in ui_source
    assert "visible_width = min(120" in ui_source
    assert "CustomTitleBar(self)" in ui_source
    assert "startSystemMove" in titlebar_source
    assert "HighDpiScaleFactorRoundingPolicy.PassThrough" in main_source
    assert "QActionGroup" in ui_source and "QPushButton#topNavButton:checked" in ui_source
    assert 'self.notification_btn = QPushButton(self)' in ui_source
    assert 'qta.icon("fa6s.bell"' in ui_source
    assert "def notify_user(self, title, message, level=\"info\")" in ui_source
    assert "page_description" not in ui_source
    assert 'status = "Bundle setup required"' not in ui_source


def test_settings_and_bundle_pages_use_available_height_without_duplicate_subtitles():
    repository = Path(__file__).resolve().parents[1]
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    updater_source = (repository / "ui_/window/updater_window.py").read_text(encoding="utf-8")
    proxy_source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    assert '("General", "Bridges", "Ports", "Advanced"), self.settings_nav_icon_names' in settings_source
    assert "verify_tor_signatures" in settings_source
    assert "QScrollArea" in settings_source and "setWidgetResizable(True)" in settings_source
    assert "lbl_page_number" not in settings_source
    assert "Browse official release channels" not in updater_source
    assert "self.updates_list.setMinimumHeight(250)" in updater_source
    assert "self.list_tor_versions.setMinimumHeight(250)" in updater_source
    pulse_source = (repository / "ui_/btn/pulse_button.py").read_text(encoding="utf-8")
    assert "connectPulseButton" in proxy_source
    assert "setFixedSize(264, 264)" in pulse_source
    assert "homeActionCard" not in proxy_source


def test_home_uses_circular_animation_proxy_policies_and_left_log_drawer():
    repository = Path(__file__).resolve().parents[1]
    home_source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    pulse_source = (repository / "ui_/btn/pulse_button.py").read_text(encoding="utf-8")
    log_source = (repository / "ui_/window/log_window.py").read_text(encoding="utf-8")
    config_source = (repository / "config.py").read_text(encoding="utf-8")
    proxy_manager_source = (repository / "set_proxy.py").read_text(encoding="utf-8")

    assert 'addItem("Set system proxy", "set")' in home_source
    assert 'addItem("Do not change system proxy", "unchanged")' in home_source
    assert 'addItem("Clear system proxy", "clear")' in home_source
    assert 'CONFIG["system_proxy_mode"] = mode' in home_source
    assert "self._apply_system_proxy_mode()" in home_source
    assert 'CONFIG["system_proxy_mode"] == "set"' in home_source
    assert "setFixedSize(264, 264)" in pulse_source
    assert 'QPropertyAnimation(self, b"pulseRadius"' in pulse_source
    assert "drawEllipse(center" in pulse_source
    assert "toggle_state" not in pulse_source
    assert "QWidget#logsDrawer" in log_source
    assert 'QPropertyAnimation(self.logs_widget, b"maximumWidth"' in home_source
    assert '"system_proxy_mode": "unchanged"' in config_source
    assert 'if action not in {"set", "clear", "disable"}' in proxy_manager_source
    assert "def disable_windows_proxy(self)" in proxy_manager_source
    assert "def disable_linux_proxy(self)" in proxy_manager_source
    assert "self._system_proxy_is_cleared = True" in home_source
    assert "Could not clear the system proxy; it may still be enabled." in home_source
    assert "QTimer.singleShot(0, self._clear_system_proxy_mode)" in home_source


def test_theme_sync_and_titlebar_use_fontawesome_icons_and_consistent_corner_background():
    repository = Path(__file__).resolve().parents[1]
    ui_source = (repository / "ui.py").read_text(encoding="utf-8")
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    titlebar_source = (repository / "ui_/window/custom_titlebar.py").read_text(encoding="utf-8")
    assert "QWidget#topMenuBar, QWidget#menuBarCorner" in ui_source
    assert "QPushButton#topNavButton:checked" in ui_source
    assert "def _set_theme(self, mode)" in ui_source
    assert "self._parent._set_theme(mode)" in settings_source
    assert "self.theme_switch.modeChanged.connect" in settings_source
    assert 'qta.icon("fa6s.window-minimize"' in titlebar_source
    assert 'qta.icon("fa6s.window-maximize"' in titlebar_source
    assert 'qta.icon("fa6s.xmark"' in titlebar_source



def test_manage_proxy_disable_dispatches_explicit_clear_to_the_current_platform(monkeypatch):
    import set_proxy

    windows_calls = []
    monkeypatch.setattr(set_proxy, "get_os_name", lambda: set_proxy.Os.Windows)
    monkeypatch.setattr(
        set_proxy.Handler,
        "disable_windows_proxy",
        lambda self: windows_calls.append((self.host, self.port)) or True,
    )
    assert set_proxy.manage_proxy("127.0.0.1", 9150, "disable")
    assert windows_calls == [("127.0.0.1", 9150)]

    linux_calls = []
    monkeypatch.setattr(set_proxy, "get_os_name", lambda: set_proxy.Os.Linux)
    monkeypatch.setattr(
        set_proxy.Handler,
        "disable_linux_proxy",
        lambda self: linux_calls.append((self.host, self.port)) or True,
    )
    assert set_proxy.manage_proxy("127.0.0.1", 9151, "disable")
    assert linux_calls == [("127.0.0.1", 9151)]



def test_connect_button_exposes_actual_lifecycle_states_and_white_theme_explicit_colors():
    repository = Path(__file__).resolve().parents[1]
    pulse_source = (repository / "ui_/btn/pulse_button.py").read_text(encoding="utf-8")
    home_source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    manager_source = (repository / "src/torproxy/tor_manager.py").read_text(encoding="utf-8")

    assert 'self._set_state("connecting", "CONNECTING…")' in pulse_source
    assert 'self._set_state("connected", "CONNECTED")' in pulse_source
    assert 'self._connected_feedback_timer.start(1000)' in pulse_source
    assert 'self._state = "disconnect"' in pulse_source
    assert 'self.setText("DISCONNECT")' in pulse_source
    assert "self.connect_btn.set_connecting()" in home_source
    assert "self.connect_btn.set_disconnecting()" in home_source
    assert "Tor startup failed" in home_source
    assert "Tor rejected its configuration" in manager_source
    assert "Recent Tor log" in manager_source
    assert "QComboBox#systemProxyMode QAbstractItemView" in home_source
    assert "color: {text}" in home_source



def test_menu_actions_use_fontawesome_and_window_restore_reactivates_layouts():
    repository = Path(__file__).resolve().parents[1]
    ui_source = (repository / "ui.py").read_text(encoding="utf-8")
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    block_source = (repository / "ui_/window/block_host_window.py").read_text(encoding="utf-8")
    exclude_source = (repository / "ui_/window/exclude_host_window.py").read_text(encoding="utf-8")
    manager_source = (repository / "src/torproxy/tor_manager.py").read_text(encoding="utf-8")
    main_source = (repository / "main.py").read_text(encoding="utf-8")

    for icon_name in (
        "fa6s.house",
        "fa6s.gear",
        "fa6s.shield-halved",
        "fa6s.route",
        "fa6s.boxes-stacked",
        "fa6s.circle-question",
        "fa6s.right-from-bracket",
    ):
        assert icon_name in ui_source
    assert "def _refresh_layout_after_restore" in ui_source
    assert "QEvent.Type.WindowStateChange" in ui_source
    assert "SetWindowDisplayAffinity" not in main_source
    assert 'self.settings_nav_icon_names' in settings_source
    assert "def NewCircuitPeriod_changed" in settings_source
    assert "settingsSectionTitle" in settings_source
    assert "hostSearchBox" in block_source and "fa6s.shield-halved" in block_source
    assert "hostSearchBox" in exclude_source and "fa6s.route" in exclude_source
    assert "def _acquire_data_directory_lock" in manager_source
    assert "def _release_data_directory_lock" in manager_source



def test_host_rule_pages_have_searchable_lists_and_theme_refresh_hooks():
    repository = Path(__file__).resolve().parents[1]
    block_source = (repository / "ui_/window/block_host_window.py").read_text(encoding="utf-8")
    exclude_source = (repository / "ui_/window/exclude_host_window.py").read_text(encoding="utf-8")
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    assert "def apply_theme(self, mode)" in block_source
    assert "def apply_theme(self, mode)" in exclude_source
    assert "def _filter_rules(self, query)" in block_source
    assert "def _filter_rules(self, query)" in exclude_source
    assert "QMenu" in block_source and "fa6s.trash" in block_source
    assert "QMenu" in exclude_source and "fa6s.trash" in exclude_source
    assert '"fa6s.link"' in settings_source
    assert "NewCircuitPeriod" in settings_source



def test_navigation_labels_frameless_pages_and_custom_shortcuts_dialog():
    repository = Path(__file__).resolve().parents[1]
    ui_source = (repository / "ui.py").read_text(encoding="utf-8")
    dialogs_source = (repository / "ui_/window/dialogs.py").read_text(encoding="utf-8")
    shortcuts_source = (repository / "ui_/window/shortcuts_window.py").read_text(encoding="utf-8")

    assert "QPushButton(label, menu_bar)" in ui_source
    assert "button.setIcon(qta.icon(icon_name" in ui_source
    assert 'button.setObjectName("topNavButton")' in ui_source
    assert "page_area" not in ui_source
    assert "self.main_layout.addWidget(self.stack, 1)" in ui_source
    assert "QStackedWidget#pageStack {{ border: none; outline: none;" in ui_source
    assert "self.shortcutsWidget = ShortcutsWindow(self)" in ui_source
    assert "self._show_page(5)" in ui_source
    assert "class ShortcutsWindow" in shortcuts_source
    assert 'QLabel#shortcutsKeycap' in shortcuts_source
    assert 'tuple(str(CONFIG["global_shortcut"]).split("+"))' in shortcuts_source
    assert "def update_global_shortcut(self, shortcut)" in shortcuts_source
    assert "class QMessageBox:" in dialogs_source


def test_application_message_prompts_use_the_shared_custom_dialog():
    repository = Path(__file__).resolve().parents[1]
    paths = (
        "main.py",
        "ui.py",
        "ui_/window/setting_window.py",
        "ui_/window/proxy_window.py",
        "ui_/window/block_host_window.py",
        "ui_/window/exclude_host_window.py",
        "ui_/window/updater_window.py",
        "ui_/window/qrcode_widget.py",
    )
    for relative_path in paths:
        source = (repository / relative_path).read_text(encoding="utf-8")
        assert "from ui_.window.dialogs import QMessageBox" in source, relative_path
        assert "from PySide6.QtWidgets import QApplication, QMessageBox" not in source



def test_theme_switch_is_animated_and_exit_confirmation_is_persistent():
    repository = Path(__file__).resolve().parents[1]
    config_source = (repository / "config.py").read_text(encoding="utf-8")
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    switch_source = (repository / "ui_/btn/theme_switch.py").read_text(encoding="utf-8")
    ui_source = (repository / "ui.py").read_text(encoding="utf-8")
    dialog_source = (repository / "ui_/window/dialogs.py").read_text(encoding="utf-8")
    titlebar_source = (repository / "ui_/window/custom_titlebar.py").read_text(encoding="utf-8")

    assert '"confirm_exit": True' in config_source
    assert '"confirm_exit")' in config_source
    assert 'self.chk_confirm_exit.setChecked(bool(CONFIG["confirm_exit"]))' in settings_source
    assert 'CONFIG["confirm_exit"] = enabled' in settings_source
    assert 'self.theme_switch.modeChanged.connect(self.change_mode)' in settings_source
    assert 'self._animation.setDuration(180)' in switch_source
    assert 'qta.icon(icon_name, color=icon_color)' in switch_source
    assert 'class ExitConfirmDialog(MessageDialog)' in dialog_source
    assert '"Don\'t ask me again"' in dialog_source
    assert 'self._exit_authorized = True' in ui_source
    assert 'if not getattr(self, "_exit_authorized", False)' in ui_source
    assert "parent.hide_to_tray" in titlebar_source
    assert 'self.tray_toggle_action.triggered.connect(self._toggle_visibility)' in ui_source
    assert 'self.tray_exit_action.triggered.connect(self.ask_close)' in ui_source


def test_close_event_hides_to_tray_unless_exit_was_explicitly_authorized():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")
    close_event = source[source.index("    def closeEvent(self, event):"):]
    assert close_event.index("event.ignore()") < close_event.index("event.accept()")
    assert 'self.hide_to_tray()' in close_event
    assert 'self.proxyWidget._stop_services()' in close_event


def test_dialog_recalculates_size_and_styles_after_screen_change():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/dialogs.py").read_text(encoding="utf-8")
    assert "handle.screenChanged.connect(self._on_screen_changed)" in source
    assert "def _refresh_for_screen_change(self)" in source
    assert 'font-size: 9pt;' in source
    assert "self._place_on_screen(center_on_parent=False)" in source
    assert "self._base_max_size = QSize(680, 16777215)" in source
    assert "self._restore_size_limits()" in source


def test_primary_navigation_uses_slightly_larger_text_and_icons():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")
    assert "font-size: 9pt; font-weight: 650;" in source
    assert "button.setIconSize(QSize(17, 17))" in source
    assert "self.exit_nav_button.setIconSize(QSize(17, 17))" in source




def test_theme_switch_changes_its_mode_and_emits_the_new_mode(qt_app):
    pytest.importorskip("qtawesome")
    from ui_.btn.theme_switch import ThemeSwitch

    switch = ThemeSwitch("dark")
    emitted = []
    switch.modeChanged.connect(emitted.append)

    switch.toggle()
    assert switch.mode == "light"
    assert emitted == ["light"]

    switch.set_mode("dark")
    assert switch.mode == "dark"
    switch._animation.stop()
    switch.deleteLater()



def test_custom_dialog_keeps_rounded_corners_transparent_and_clamps_to_screen(qt_app):
    from PySide6.QtCore import Qt, QPoint
    from PySide6.QtGui import QGuiApplication
    from ui_.window.dialogs import MessageDialog

    dialog = MessageDialog(None, "Bounds", "A short message", level="info")
    assert dialog.testAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

    screen = QGuiApplication.primaryScreen()
    assert screen is not None
    position = dialog.clamp_to_screen(QPoint(-100000, -100000))
    area = screen.availableGeometry()
    assert position.x() >= area.left()
    assert position.y() >= area.top()
    assert position.x() + dialog.width() <= area.right() + 1
    assert position.y() + dialog.height() <= area.bottom() + 1
    dialog.deleteLater()
    qt_app.processEvents()


def test_tray_menu_is_custom_anchored_above_tray_icon():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")
    assert "self.tray_icon.activated.connect(self._on_tray_activated)" in source
    assert "QSystemTrayIcon.ActivationReason.Context" in source
    assert "y = anchor.y() - size.height() - 12" in source
    assert "self.tray_menu.exec(QPoint(x, y))" in source
    assert "setContextMenu(self.tray_menu)" not in source


def test_theme_switch_uses_centered_dpi_aware_icon_painting():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/btn/theme_switch.py").read_text(encoding="utf-8")
    assert "QVariantAnimation(self)" in source
    assert "round(x + (diameter - icon_size) / 2)" in source
    assert "round(y + (diameter - icon_size) / 2)" in source
    assert "icon.paint(painter, icon_rect, Qt.AlignmentFlag.AlignCenter)" in source



def test_event_log_classifies_levels_and_inserts_plain_text_in_color(qt_app):
    from PySide6.QtGui import QColor
    from ui_.window.log_window import LogWindow

    log = LogWindow()
    log.apply_theme("dark")
    assert log._message_level("Tor supervisor failed: control socket closed") == "error"
    assert log._message_level("Retrying after rate limit") == "warning"
    assert log._message_level("Started proxy and tor successfully.") == "success"
    assert log._message_level("arbitrary event", "critical") == "critical"

    log.update_log("<b>literal text</b>", level="error")
    assert log.text_edit.toPlainText() == "<b>literal text</b>"
    block = log.text_edit.document().begin()
    fragment = block.begin().fragment()
    assert fragment.text() == "<b>literal text</b>"
    assert fragment.charFormat().foreground().color() == QColor("#ff7b82")

    log.apply_theme("light")
    fragment_after_theme = log.text_edit.document().begin().begin().fragment()
    assert fragment_after_theme.charFormat().foreground().color() == QColor("#c62833")
    log.deleteLater()
    qt_app.processEvents()


def test_global_hotkey_is_configurable_and_uses_native_session_recovery():
    repository = Path(__file__).resolve().parents[1]
    config_source = (repository / "config.py").read_text(encoding="utf-8")
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    ui_source = (repository / "ui.py").read_text(encoding="utf-8")
    hotkeys_source = (repository / "src/torproxy/hotkeys.py").read_text(encoding="utf-8")

    dialogs_source = (repository / "ui_/window/dialogs.py").read_text(encoding="utf-8")
    shortcuts_source = (repository / "ui_/window/shortcuts_window.py").read_text(encoding="utf-8")

    assert '"global_shortcut": "Ctrl+Alt+P"' in config_source
    assert "QKeySequenceEdit" not in settings_source
    assert "global_shortcut" not in settings_source
    assert "def _global_shortcut_changed" not in settings_source
    assert "class ShortcutCaptureDialog" in dialogs_source
    assert "Press Enter to save" in dialogs_source
    assert "def change_global_shortcut(self)" in shortcuts_source
    assert 'self.change_shortcut_button.clicked.connect(self.change_global_shortcut)' in shortcuts_source
    assert "QKeySequenceEdit" not in shortcuts_source
    assert 'HotkeyManager(on_error=self.hotkey_error_signal.emit)' in ui_source
    assert 'self.hotkey_manager.register(' in ui_source
    assert 'self.hotkey_manager.update_shortcut("window_visibility", normalized)' in ui_source
    assert 'CONFIG["global_shortcut"] = normalized' in ui_source
    assert 'self.hotkey_manager.stop()' in ui_source
    assert 'RegisterHotKey' in hotkeys_source
    assert 'WTSRegisterSessionNotification' in hotkeys_source
    assert 'WTS_SESSION_UNLOCK' in hotkeys_source
    assert 'PBT_APMRESUMEAUTOMATIC' in hotkeys_source
    assert '_schedule_recovery_retries()' in hotkeys_source
    assert '_reconfigure_done.wait(4)' in hotkeys_source
    assert 'keyboard.add_hotkey' in hotkeys_source  # fallback only, not the Windows path
    assert 'keyboard.add_hotkey(\'ctrl+alt+p\'' not in ui_source



def test_shortcut_capture_dialog_captures_confirms_and_allows_retry(qt_app):
    from PySide6.QtCore import Qt, QEvent
    from PySide6.QtGui import QKeyEvent
    from PySide6.QtWidgets import QDialog
    from ui_.window.dialogs import ShortcutCaptureDialog

    dialog = ShortcutCaptureDialog(None, "Ctrl+Alt+P")
    dialog._begin_listening()
    chord = QKeyEvent(
        QEvent.Type.KeyPress,
        Qt.Key.Key_K,
        Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier,
    )
    dialog.keyPressEvent(chord)
    assert dialog._captured_shortcut == "Ctrl+Shift+K"
    assert dialog.apply_button.isEnabled()
    assert dialog.capture_value.text() == "Ctrl+Shift+K"

    dialog._begin_listening()
    assert dialog._captured_shortcut is None
    assert not dialog.apply_button.isEnabled()

    dialog.keyPressEvent(chord)
    enter = QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Return, Qt.KeyboardModifier.NoModifier)
    dialog.keyPressEvent(enter)
    assert dialog.shortcut == "Ctrl+Shift+K"
    assert dialog.result() == QDialog.DialogCode.Accepted
    dialog.deleteLater()
    qt_app.processEvents()
