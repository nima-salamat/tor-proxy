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
    assert '"confirm_exit"' in config_source
    assert 'self.chk_confirm_exit.setChecked(bool(CONFIG["confirm_exit"]))' in settings_source
    assert 'CONFIG["confirm_exit"] = enabled' in settings_source
    assert 'self.theme_switch.modeChanged.connect(self.change_mode)' in settings_source
    assert 'self._animation.setDuration(220)' in switch_source
    assert 'self._icons = {' in switch_source
    assert 'icon = self._icons[self._mode]' in switch_source
    assert 'qta.icon(icon_name, color=icon_color)' not in switch_source
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




def test_theme_switch_commits_mode_after_thumb_animation_finishes(qt_app):
    pytest.importorskip("qtawesome")
    from PySide6.QtCore import QAbstractAnimation
    from ui_.btn.theme_switch import ThemeSwitch

    switch = ThemeSwitch("dark")
    emitted = []
    switch.modeChanged.connect(emitted.append)

    switch.toggle()
    assert switch.mode == "dark"
    assert emitted == []
    assert switch.is_animating
    assert switch._thumb_progress < 0.5

    switch._animation.setCurrentTime(switch._animation.duration() // 2)
    assert switch.mode == "dark"
    assert emitted == []
    assert 0.0 < switch._thumb_progress < 1.0
    assert switch._animation.state() == QAbstractAnimation.State.Running

    switch._animation.setCurrentTime(switch._animation.duration())
    assert switch._thumb_progress == 1.0
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

    # All three system-proxy policies are directly visible in the tray menu.
    assert "self.tray_system_proxy_menu" not in source
    assert "self.tray_menu.addMenu(" not in source
    assert "self.tray_menu.addAction(action)" in source
    assert "action.setCheckable(True)" in source
    assert "self.tray_system_proxy_action_group.setExclusive(True)" in source
    assert '("set", "Set system proxy"' in source
    assert '("unchanged", "Do not change system proxy"' in source
    assert '("clear", "Clear system proxy"' in source
    assert "self._set_tray_system_proxy_mode(selected_mode)" in source
    assert "def _sync_tray_system_proxy_actions(self, *_args)" in source
    assert "proxy_mode_combo.currentIndexChanged.connect(self._sync_tray_system_proxy_actions)" in source


def test_theme_switch_thumb_can_be_dragged_in_both_directions(qt_app):
    pytest.importorskip("qtawesome")
    from PySide6.QtCore import QEvent, QPointF, Qt
    from PySide6.QtGui import QMouseEvent
    from ui_.btn.theme_switch import ThemeSwitch

    switch = ThemeSwitch("dark")
    emitted = []
    switch.modeChanged.connect(emitted.append)

    press = QMouseEvent(
        QEvent.Type.MouseButtonPress,
        QPointF(20, 20),
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    switch.mousePressEvent(press)
    assert switch._pressed_thumb

    move_right = QMouseEvent(
        QEvent.Type.MouseMove,
        QPointF(55, 20),
        Qt.MouseButton.NoButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    switch.mouseMoveEvent(move_right)
    assert switch._dragging
    assert switch._thumb_progress > 0.5
    assert switch.mode == "light"
    assert emitted == []

    move_left = QMouseEvent(
        QEvent.Type.MouseMove,
        QPointF(25, 20),
        Qt.MouseButton.NoButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    switch.mouseMoveEvent(move_left)
    assert switch._thumb_progress < 0.5
    assert switch.mode == "dark"
    assert emitted == []

    move_right_again = QMouseEvent(
        QEvent.Type.MouseMove,
        QPointF(70, 20),
        Qt.MouseButton.NoButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    switch.mouseMoveEvent(move_right_again)
    release = QMouseEvent(
        QEvent.Type.MouseButtonRelease,
        QPointF(70, 20),
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.NoButton,
        Qt.KeyboardModifier.NoModifier,
    )
    switch.mouseReleaseEvent(release)
    assert switch.mode == "light"
    assert emitted == []
    assert switch.is_animating
    switch._animation.setCurrentTime(switch._animation.duration())
    assert switch._thumb_progress == 1.0
    assert emitted == ["light"]

    switch.deleteLater()
    qt_app.processEvents()


def test_theme_switch_track_is_a_full_capsule_and_prewarms_the_alternate_theme():
    repository = Path(__file__).resolve().parents[1]
    switch_source = (repository / "ui_/btn/theme_switch.py").read_text(encoding="utf-8")
    ui_source = (repository / "ui.py").read_text(encoding="utf-8")

    assert "track_radius = (self.height() - 2) / 2" in switch_source
    assert "self._progress_from_pointer(position.x() - self._drag_offset_x)" in switch_source
    assert "def mouseMoveEvent(self, event)" in switch_source
    assert "def mouseReleaseEvent(self, event)" in switch_source
    assert "self._warm_icon_pixmaps" in switch_source
    assert "self._prewarm_theme_stylesheets()" in ui_source
    assert "self._apply_local_theme_styles(alternate_mode)" in ui_source
    assert "QTimer.singleShot(0, self._prewarm_theme_stylesheets)" not in ui_source


def test_theme_reveal_keeps_the_settings_switch_live_during_the_transition():
    repository = Path(__file__).resolve().parents[1]
    switch_source = (repository / "ui_/btn/theme_switch.py").read_text(encoding="utf-8")
    theme_source = (repository / "ui.py").read_text(encoding="utf-8")
    transition_source = (
        repository / "ui_/window/theme_transition.py"
    ).read_text(encoding="utf-8")

    assert "self._animation.currentTime() >= self._animation.duration() / 2" not in switch_source
    assert "self._emit_mode_after_settle" in switch_source
    assert "self.modeChanged.emit(mode)" in switch_source
    assert "live_widgets=live_widgets" in theme_source
    assert "widget.render(" in transition_source
    assert "self._live_widgets" in transition_source
    assert "setting_switch.is_interacting" in theme_source


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


def test_bridge_text_editor_canonicalizes_multi_record_clipboard_paste(qt_app):
    from PySide6.QtCore import QMimeData
    from ui_.window.setting_window import _BridgeTextEdit

    editor = _BridgeTextEdit()
    clipboard = QMimeData()
    clipboard.setText(
        "Bridge OBFS4 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=abc "
        "snowflake 198.51.100.12:443 fingerprint=A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
    )
    editor.insertFromMimeData(clipboard)
    assert editor.toPlainText() == (
        "obfs4 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=abc\n"
        "snowflake 198.51.100.12:443 fingerprint=A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
    )
    editor.deleteLater()
    qt_app.processEvents()


def test_bridge_settings_normalize_paste_and_render_individual_cards():
    repository = Path(__file__).resolve().parents[1]
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    parser_source = (repository / "src/torproxy/bridges.py").read_text(encoding="utf-8")
    qr_source = (repository / "src/torproxy/bridge_qr.py").read_text(encoding="utf-8")
    manager_source = (repository / "src/torproxy/tor_manager.py").read_text(encoding="utf-8")

    assert "class _BridgeTextEdit(QTextEdit)" in settings_source
    assert "parsed = parse_bridge_text(pasted)" in settings_source
    assert "self.insertPlainText" in settings_source
    assert "def _refresh_bridge_cards(self, records, *, removable=True)" in settings_source
    assert 'card.setObjectName("bridgeCard")' in settings_source
    assert 'remove_button.clicked.connect(partial(self.remove_bridge_record, record))' in settings_source
    assert 'copy_button.clicked.connect(partial(self.copy_bridge_record, record))' in settings_source
    assert "def _canonicalize_bridge_editor(self)" in settings_source
    assert "SUPPORTED_BRIDGE_TRANSPORTS = (\"obfs4\", \"snowflake\", \"webtunnel\", \"meek_lite\")" in parser_source
    assert "return list(parse_bridge_text(text).records)" in qr_source
    assert "from .bridges import SUPPORTED_BRIDGE_TRANSPORTS, normalize_sni_hostname, parse_bridge_text" in manager_source


def test_bridge_cards_show_only_control_port_verified_active_bridge():
    repository = Path(__file__).resolve().parents[1]
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    runner_source = (repository / "tor.py").read_text(encoding="utf-8")
    manager_source = (repository / "src/torproxy/tor_manager.py").read_text(encoding="utf-8")
    bridge_source = (repository / "src/torproxy/bridges.py").read_text(encoding="utf-8")

    assert "bridge_usage_changed = Signal(object)" in runner_source
    assert "get_active_bridge_fingerprints()" in runner_source
    assert "def get_active_bridge_fingerprints(self)" in manager_source
    assert 'self._controller.get_circuits()' in manager_source
    assert 'bridge_identity_fingerprint(record)' in settings_source
    assert "✓ Connected · observed as the first hop of a built circuit" in settings_source
    assert 'QLabel#bridgeUsageStatus[usageState="active"]' in settings_source
    assert "def bridge_identity_fingerprint(record: str) -> str | None:" in bridge_source
    assert "fingerprint=" in bridge_source


def test_exit_ip_check_is_guarded_logged_and_never_uses_direct_fallback():
    repository = Path(__file__).resolve().parents[1]
    home_source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    worker_source = (repository / "ui_/worker/worker.py").read_text(encoding="utf-8")
    ip_source = (repository / "src/torproxy/ip_check.py").read_text(encoding="utf-8")
    main_source = (repository / "main.py").read_text(encoding="utf-8")

    assert "if self._exit_ip_check_busy:" in home_source
    assert "self.thread_pool.start(worker)" in home_source
    assert "worker.signals.error.connect(self._on_exit_ip_failed)" in home_source
    assert "def _finish_exit_ip_check(self):" in home_source
    assert "finally:\n            self._finish_exit_ip_check()" in home_source
    assert "logger.exception(\"Background task failed (%s).\", task_name)" in worker_source
    assert "direct requests are disabled" in ip_source
    assert "session.trust_env = False" in ip_source
    assert "faulthandler.enable(file=handle, all_threads=True)" in main_source
    assert '"torproxy-crash.log"' in main_source


def test_webtunnel_sni_setting_defaults_to_url_host_and_supports_custom_presets():
    repository = Path(__file__).resolve().parents[1]
    config_source = (repository / "config.py").read_text(encoding="utf-8")
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    runner_source = (repository / "tor.py").read_text(encoding="utf-8")
    manager_source = (repository / "src/torproxy/tor_manager.py").read_text(encoding="utf-8")
    bridge_source = (repository / "src/torproxy/bridges.py").read_text(encoding="utf-8")

    assert '"webtunnel_sni_imitation": ""' in config_source
    assert '"Use the hostname in url= (default; no override)", ""' in settings_source
    assert '"www.google.com"' in settings_source
    assert "def save_webtunnel_sni_imitation(self):" in settings_source
    assert 'webtunnel_sni_imitation=str(CONFIG["webtunnel_sni_imitation"] or "")' in runner_source
    assert "normalize_sni_hostname(settings.webtunnel_sni_imitation or \"\")" in manager_source
    assert 'record += " sni-imitation=" + sni_imitation' in manager_source
    assert "def normalize_sni_hostname(value: str) -> str:" in bridge_source
    assert "sni-imitation=" in bridge_source


def test_automatic_bridge_cleanup_is_opt_in_and_conservative():
    repository = Path(__file__).resolve().parents[1]
    config_source = (repository / "config.py").read_text(encoding="utf-8")
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    runner_source = (repository / "tor.py").read_text(encoding="utf-8")
    home_source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    checker_source = (repository / "src/torproxy/bridge_health.py").read_text(encoding="utf-8")

    assert '"auto_prune_bridges": False' in config_source
    assert '"auto_prune_bridges"' in config_source
    assert 'self.chk_auto_prune_bridges.toggled.connect(self.auto_prune_bridges_changed)' in settings_source
    assert 'CONFIG["auto_prune_bridges"]' in runner_source
    assert 'if not result.working:' in runner_source
    assert 'return self.original' in checker_source
    assert 'bool(self.working and self.failed)' in checker_source
    assert 'self.tor.bridges_updated.connect(self._sync_bridge_editor)' in home_source
    assert 'refresh = getattr(settings_page, "set_bridges", None)' in home_source
    assert "if callable(refresh):" in home_source



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
    assert "press Enter to save" in dialogs_source
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
    assert dialog._captured_shortcut is None
    assert dialog._pending_shortcut == "Ctrl+Shift+K"
    assert not dialog.apply_button.isEnabled()
    assert dialog.capture_value.text() == "Ctrl+Shift+K"

    release = QKeyEvent(
        QEvent.Type.KeyRelease,
        Qt.Key.Key_K,
        Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier,
    )
    dialog.keyReleaseEvent(release)
    assert dialog._captured_shortcut == "Ctrl+Shift+K"
    assert dialog.apply_button.isEnabled()

    dialog._begin_listening()
    assert dialog._captured_shortcut is None
    assert not dialog.apply_button.isEnabled()

    dialog.keyPressEvent(chord)
    release_again = QKeyEvent(
        QEvent.Type.KeyRelease,
        Qt.Key.Key_K,
        Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier,
    )
    dialog.keyReleaseEvent(release_again)
    enter = QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Return, Qt.KeyboardModifier.NoModifier)
    dialog.keyPressEvent(enter)
    assert dialog.shortcut == "Ctrl+Shift+K"
    assert dialog.result() == QDialog.DialogCode.Accepted
    dialog.deleteLater()
    qt_app.processEvents()



def test_custom_message_dialog_can_copy_the_exact_displayed_text(qt_app):
    from PySide6.QtWidgets import QApplication
    from ui_.window.dialogs import MessageDialog

    message = "A custom notification message that should be copied exactly."
    dialog = MessageDialog(None, "Notification details", message, level="warning")
    assert dialog.copy_button.text() == "Copy text"
    dialog.copy_button.click()
    assert QApplication.clipboard().text() == message
    assert dialog.copy_button.text() == "Copied"
    dialog.deleteLater()
    qt_app.processEvents()


def test_shortcut_capture_displays_chord_and_suppresses_qt_shortcut_override(qt_app):
    from PySide6.QtCore import QEvent, Qt
    from PySide6.QtGui import QKeyEvent
    from ui_.window.dialogs import ShortcutCaptureDialog

    dialog = ShortcutCaptureDialog(None, "Ctrl+Alt+P")
    dialog._begin_listening()
    override = QEvent(QEvent.Type.ShortcutOverride)
    assert dialog.event(override) is True
    assert override.isAccepted()

    chord = QKeyEvent(
        QEvent.Type.KeyPress,
        Qt.Key.Key_K,
        Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier,
    )
    dialog.keyPressEvent(chord)
    assert dialog.capture_value.text() == "Ctrl+Shift+K"
    assert dialog._captured_shortcut is None
    assert dialog._pending_shortcut == "Ctrl+Shift+K"
    assert not dialog.apply_button.isEnabled()
    dialog.keyReleaseEvent(
        QKeyEvent(
            QEvent.Type.KeyRelease,
            Qt.Key.Key_K,
            Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier,
        )
    )
    assert dialog._captured_shortcut == "Ctrl+Shift+K"
    assert dialog.apply_button.isEnabled()
    assert dialog.height() >= dialog.minimumHeight()
    dialog.reject()
    dialog.deleteLater()
    qt_app.processEvents()




def test_shortcut_capture_shows_modifiers_and_key_during_keydown(qt_app):
    from PySide6.QtCore import QEvent, Qt
    from PySide6.QtGui import QKeyEvent
    from ui_.window.dialogs import ShortcutCaptureDialog

    dialog = ShortcutCaptureDialog(None, "Ctrl+Alt+P")
    dialog._begin_listening()
    dialog.keyPressEvent(
        QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Control, Qt.KeyboardModifier.NoModifier)
    )
    assert dialog.capture_value.text() == "Ctrl"
    assert dialog._captured_shortcut is None

    dialog.keyPressEvent(
        QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_K, Qt.KeyboardModifier.ControlModifier)
    )
    assert dialog.capture_value.text() == "Ctrl+K"
    assert dialog._pending_shortcut == "Ctrl+K"
    assert dialog._captured_shortcut is None
    assert not dialog.apply_button.isEnabled()

    dialog.keyReleaseEvent(
        QKeyEvent(QEvent.Type.KeyRelease, Qt.Key.Key_K, Qt.KeyboardModifier.ControlModifier)
    )
    assert dialog._captured_shortcut == "Ctrl+K"
    assert dialog.apply_button.isEnabled()
    dialog.reject()
    dialog.deleteLater()
    qt_app.processEvents()

def test_shortcut_capture_uses_shared_scope_to_pause_global_and_local_shortcuts():
    repository = Path(__file__).resolve().parents[1]
    ui_source = (repository / "ui.py").read_text(encoding="utf-8")
    page_source = (repository / "ui_/window/shortcuts_window.py").read_text(encoding="utf-8")
    hotkeys_source = (repository / "src/torproxy/hotkeys.py").read_text(encoding="utf-8")
    dialogs_source = (repository / "ui_/window/dialogs.py").read_text(encoding="utf-8")

    assert "def shortcut_capture_scope(self)" in ui_source
    assert "action.setEnabled(False)" in ui_source
    assert "manager.suspend()" in ui_source and "manager.resume()" in ui_source
    assert "with capture_scope:" in page_source
    assert "def suspend(self)" in hotkeys_source and "def resume(self)" in hotkeys_source
    assert "QKeySequence(combined)" in dialogs_source
    assert "from PySide6.QtGui import QGuiApplication, QKeySequence" in dialogs_source


def test_custom_message_font_and_screen_change_refresh_are_dpi_aware():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/dialogs.py").read_text(encoding="utf-8")
    assert "handle.screenChanged.connect(self._on_screen_changed)" in source
    assert "screen.logicalDotsPerInchChanged.connect(self._on_screen_dpi_changed)" in source
    assert "QTimer.singleShot(120, self._refresh_for_screen_change)" in source
    assert "font-size: 9pt;" in source
    assert "self.adjustSize()" in source


def test_shortcut_capture_event_is_safe_during_qdialog_initialization(qt_app):
    from PySide6.QtCore import QEvent, Qt
    from PySide6.QtGui import QKeyEvent
    from ui_.window.dialogs import ShortcutCaptureDialog

    dialog = ShortcutCaptureDialog(None, "Ctrl+Alt+P")
    # Qt virtual event callbacks can run before subclass state is fully set.
    del dialog._listening
    override = QEvent(QEvent.Type.ShortcutOverride)
    result = dialog.event(override)
    assert isinstance(result, bool)

    # The real capture path still works after restoring the listening state.
    dialog._begin_listening()
    dialog.keyPressEvent(
        QKeyEvent(
            QEvent.Type.KeyPress,
            Qt.Key.Key_K,
            Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier,
        )
    )
    assert dialog.capture_value.text() == "Ctrl+Shift+K"
    dialog.reject()
    dialog.deleteLater()
    qt_app.processEvents()


def test_custom_notification_dialog_keeps_copy_action_available(qt_app):
    from PySide6.QtWidgets import QApplication
    from ui_.window.dialogs import MessageDialog

    message = "Global shortcut could not be registered (Win32 error 1409)."
    dialog = MessageDialog(None, "Global shortcut", message, level="warning")
    assert dialog.copy_button.text() == "Copy text"
    dialog.copy_button.click()
    assert QApplication.clipboard().text() == message
    assert dialog.copy_button.text() == "Copied"
    dialog.deleteLater()
    qt_app.processEvents()



def test_qr_scan_canvas_paints_frame_and_marker_in_shared_geometry():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/qrcode_widget.py").read_text(encoding="utf-8")

    assert "class _ScanOverlay(QWidget)" in source
    assert "painter.drawImage(image_rect, self._frame)" in source
    assert "image_rect.left() + (source_width - 1 - x) * scale_x" in source
    assert "self.scan_overlay = _ScanOverlay(self.preview_panel)" in source
    assert "self.camera_label" not in source
    assert "QPixmap" not in source
    assert "def set_detected(self, corners, source_size)" in source
    assert "self._timer.stop()" in source


def test_circular_theme_reveal_transitions_between_opaque_widget_frames(qt_app):
    from PySide6.QtCore import QPoint, Qt
    from PySide6.QtGui import QColor, QPixmap
    from PySide6.QtWidgets import QWidget

    from ui_.window.theme_transition import CircularThemeReveal

    parent = QWidget()
    parent.resize(120, 80)
    parent.show()
    live_widget = QWidget(parent)
    live_widget.setGeometry(70, 30, 30, 24)
    live_widget.setStyleSheet("background-color: rgb(0, 255, 0);")
    live_widget.show()

    old_snapshot = QPixmap(parent.size())
    old_snapshot.fill(QColor("red"))
    new_snapshot = QPixmap(parent.size())
    new_snapshot.fill(QColor("blue"))
    transition = CircularThemeReveal(
        parent,
        old_snapshot,
        new_snapshot,
        QPoint(10, 12),
        duration_ms=400,
        live_widgets=(live_widget,),
    )
    transition.setGeometry(parent.rect())
    transition.show()
    transition._set_radius(0)
    qt_app.processEvents()

    assert transition.testAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
    assert not transition.testAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
    assert transition._animation.duration() == 400
    old_frame = transition.grab().toImage()
    outside = old_frame.pixelColor(100, 60)
    assert outside.alpha() > 240
    assert outside.red() > 240
    assert outside.blue() < 20
    live_pixel = old_frame.pixelColor(80, 40)
    assert live_pixel.green() > 240
    assert live_pixel.red() < 20

    transition._set_radius(8)
    qt_app.processEvents()
    mixed_frame = transition.grab().toImage()
    revealed = mixed_frame.pixelColor(10, 12)
    outside_during_animation = mixed_frame.pixelColor(100, 60)
    assert revealed.alpha() > 240
    assert revealed.blue() > 240
    assert revealed.red() < 20
    assert outside_during_animation.red() > 240
    assert outside_during_animation.blue() < 20
    live_widget.setStyleSheet("background-color: rgb(255, 255, 0);")
    qt_app.processEvents()
    live_frame = transition.grab().toImage()
    updated_live_pixel = live_frame.pixelColor(80, 40)
    assert updated_live_pixel.red() > 240
    assert updated_live_pixel.green() > 240
    assert updated_live_pixel.blue() < 20

    transition._set_radius(1000)
    qt_app.processEvents()
    new_frame = transition.grab().toImage()
    fully_revealed = new_frame.pixelColor(100, 60)
    assert fully_revealed.alpha() > 240
    assert fully_revealed.blue() > 240
    assert fully_revealed.red() < 20

    transition.cancel()
    parent.close()
    parent.deleteLater()
    qt_app.processEvents()


def test_main_window_theme_changes_use_circular_reveal_for_visible_mode_switches():
    repository = Path(__file__).resolve().parents[1]
    ui_source = (repository / "ui.py").read_text(encoding="utf-8")
    transition_source = (
        repository / "ui_/window/theme_transition.py"
    ).read_text(encoding="utf-8")

    assert "CircularThemeReveal(" in ui_source
    assert "self._theme_reveal_origin()" in ui_source
    assert "overlay.start()" in ui_source
    assert "QVariantAnimation" in transition_source
    assert "painter.setClipPath(reveal_region)" in transition_source
    assert "painter.drawPixmap(self.rect(), self._new_snapshot)" in transition_source
    assert "painter.drawPixmap(self.rect(), self._old_snapshot)" in transition_source
    assert "old_frame_region.subtracted(reveal_region)" not in transition_source
    assert "def _prewarm_theme_stylesheets(self)" in ui_source
    assert "_THEME_STYLESHEET_CACHE" in ui_source
    assert "does not rely on translucent child-window composition" in transition_source
    assert "WA_TransparentForMouseEvents" in transition_source

