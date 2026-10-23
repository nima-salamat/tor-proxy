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
    assert 'enumerate(("General", "Bridges", "Ports", "Advanced"))' in settings_source
    assert "verify_tor_signatures" in settings_source
    assert "QScrollArea" in settings_source and "setWidgetResizable(True)" in settings_source
    assert "lbl_page_number" not in settings_source
    assert "Browse official release channels" not in updater_source
    assert "setMinimumHeight(180)" in updater_source
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
    assert "QToolButton#topNavButton:checked" in ui_source
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
    assert '"Ctrl", "Alt", "P"' in shortcuts_source
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
    assert 'self.hide_to_tray()' in titlebar_source
    assert 'self.tray_toggle_action.triggered.connect(self._toggle_visibility)' in ui_source
    assert 'self.tray_exit_action.triggered.connect(self.ask_close)' in ui_source


def test_close_event_hides_to_tray_unless_exit_was_explicitly_authorized():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")
    close_event = source[source.index("    def closeEvent(self, event):"):]
    assert close_event.index("event.ignore()") < close_event.index("event.accept()")
    assert 'self.hide_to_tray()' in close_event
    assert 'self.proxyWidget._stop_services()' in close_event
