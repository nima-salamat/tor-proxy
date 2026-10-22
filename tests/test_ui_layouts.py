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
    assert "def moveEvent" not in ui_source
    assert "CustomTitleBar(self)" in ui_source
    assert "startSystemMove" in titlebar_source
    assert "HighDpiScaleFactorRoundingPolicy.PassThrough" in main_source
    assert "QActionGroup" in ui_source and "QMenuBar#topMenuBar::item:checked" in ui_source
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


def test_theme_sync_and_titlebar_use_fontawesome_icons_and_consistent_corner_background():
    repository = Path(__file__).resolve().parents[1]
    ui_source = (repository / "ui.py").read_text(encoding="utf-8")
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    titlebar_source = (repository / "ui_/window/custom_titlebar.py").read_text(encoding="utf-8")
    assert "QMenuBar#topMenuBar, QWidget#menuBarCorner" in ui_source
    assert "QMenuBar#topMenuBar::item:checked" in ui_source
    assert "def _set_theme(self, mode)" in ui_source
    assert "self._parent._set_theme(mode)" in settings_source
    assert "self.btn_light.toggled.connect" in settings_source
    assert 'qta.icon("fa6s.window-minimize"' in titlebar_source
    assert 'qta.icon("fa6s.window-maximize"' in titlebar_source
    assert 'qta.icon("fa6s.xmark"' in titlebar_source
