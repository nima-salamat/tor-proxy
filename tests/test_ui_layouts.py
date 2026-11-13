from __future__ import annotations

import ast
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")



def test_http_proxy_settings_expose_safe_opt_in_lan_binding():
    repository = Path(__file__).resolve().parents[1]
    settings = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    config = (repository / "config.py").read_text(encoding="utf-8")
    runner = (repository / "tor.py").read_text(encoding="utf-8")

    assert '"http_proxy_bind_all_interfaces": False' in config
    assert 'httpProxyLanAccessPreference' in settings
    assert 'http_proxy_lan_access_changed' in settings
    assert '0.0.0.0' in settings
    assert 'no username/password authentication' in settings
    assert 'allow_remote=self.http_bind_all_interfaces' in runner
    assert 'set_http_bind_all_interfaces' in runner


def test_exit_button_icon_tracks_hover_foreground_and_theme(monkeypatch):
    import ui

    calls = []
    monkeypatch.setattr(
        ui.qta, "icon",
        lambda name, color: calls.append((name, color)) or (name, color),
    )

    class _ButtonState:
        _icon_name = "fa6s.right-from-bracket"
        _normal_icon_color = "#202832"
        _hover_icon_color = "#ffffff"
        _hovered = False

        def _sync_icon(self):
            ui.HoverIconButton._sync_icon(self)

        def setIcon(self, icon):
            self.icon = icon

    button = _ButtonState()
    ui.HoverIconButton._sync_icon(button)
    assert button.icon == ("fa6s.right-from-bracket", "#202832")

    # Hover uses the same white foreground configured by the Exit QSS rule.
    ui.HoverIconButton._set_hovered(button, True)
    assert button.icon == ("fa6s.right-from-bracket", "#ffffff")

    # A theme change while hovered must not make the icon disagree with text.
    ui.HoverIconButton.setNormalIconColor(button, "#eff1f4")
    assert button.icon == ("fa6s.right-from-bracket", "#ffffff")

    ui.HoverIconButton._set_hovered(button, False)
    assert button.icon == ("fa6s.right-from-bracket", "#eff1f4")
    assert calls == [
        ("fa6s.right-from-bracket", "#202832"),
        ("fa6s.right-from-bracket", "#ffffff"),
        ("fa6s.right-from-bracket", "#ffffff"),
        ("fa6s.right-from-bracket", "#eff1f4"),
    ]


def test_exit_button_hover_event_handlers_sync_the_icon():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")
    assert "class HoverIconButton(QPushButton):" in source
    assert "def enterEvent(self, event):" in source
    assert "self._set_hovered(True)" in source
    assert "def leaveEvent(self, event):" in source
    assert "self._set_hovered(False)" in source
    assert 'color: #ffffff; background: #b83336; border-color: #b83336;' in source
    assert 'self.exit_nav_button.setNormalIconColor(icon_color)' in source


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


def test_settings_navigation_icons_follow_the_selected_page_and_theme(monkeypatch):
    from types import MethodType, SimpleNamespace
    import ui_.window.setting_window as settings

    class _PageStack:
        def __init__(self):
            self.current = 0

        def count(self):
            return 4

        def setCurrentIndex(self, index):
            self.current = index

    class _Button:
        def __init__(self, checked=False):
            self.checked = checked
            self.icon = None

        def setChecked(self, checked):
            self.checked = checked

        def isChecked(self):
            return self.checked

        def setIcon(self, icon):
            self.icon = icon

    buttons = [_Button(index == 0) for index in range(4)]
    fake = SimpleNamespace(
        page_setting=_PageStack(),
        settings_nav_buttons=buttons,
        settings_nav_icon_names=(
            "fa6s.sliders", "fa6s.link", "fa6s.network-wired", "fa6s.server"
        ),
        BLOCKED_HOSTS_PAGE_INDEX=4,
        EXCLUDED_HOSTS_PAGE_INDEX=5,
    )
    fake._sync_settings_nav_icons = MethodType(
        settings.SettingWindow._sync_settings_nav_icons, fake
    )
    monkeypatch.setattr(settings, "CONFIG", {"mode": "light"})
    monkeypatch.setattr(settings.qta, "icon", lambda name, color: (name, color))

    # Changing tabs must recolor both the new active icon and the old inactive one.
    settings.SettingWindow._set_settings_page(fake, 1)
    assert fake.page_setting.current == 1
    assert [button.checked for button in buttons] == [False, True, False, False]
    assert buttons[0].icon == ("fa6s.sliders", "#243143")
    assert buttons[1].icon == ("fa6s.link", "#ffffff")

    # Returning to General restores its active white icon.
    settings.SettingWindow._set_settings_page(fake, 0)
    assert [button.checked for button in buttons] == [True, False, False, False]
    assert buttons[0].icon == ("fa6s.sliders", "#ffffff")
    assert buttons[1].icon == ("fa6s.link", "#243143")

    # Theme changes retain the active/inactive distinction.
    settings.SettingWindow._sync_settings_nav_icons(fake, "dark")
    assert buttons[0].icon == ("fa6s.sliders", "#ffffff")
    assert buttons[1].icon == ("fa6s.link", "#f3f6fa")


def test_bundle_primary_action_icons_follow_button_text_in_both_themes():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/updater_window.py").read_text(encoding="utf-8")
    start = source.index("def _apply_local_styles")
    end = source.index("def _copy_bundle_source_url", start)
    styles = source[start:end]

    assert 'QPushButton#primaryButton {{ font-weight: 650; color: {text}; }}' in styles
    assert 'self.btn_get_versions.setIcon(qta.icon("fa6s.arrows-rotate", color=text))' in styles
    assert 'self.btn_set_default_version.setIcon(qta.icon("fa6s.check", color=text))' in styles
    assert 'self.btn_retry.setIcon(qta.icon("fa6s.rotate-right", color=text))' in styles


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

        # Host-rule editors are nested Settings pages, not top-level stack entries.
        assert window.stack.indexOf(window.block_host_window) == -1
        assert window.stack.indexOf(window.exclude_host_window) == -1
        assert window.settingWidget.page_setting.indexOf(window.block_host_window) == 4
        assert window.settingWidget.page_setting.indexOf(window.exclude_host_window) == 5

        settings_labels = [
            button.text() for button in window.settingWidget.settings_nav_buttons
        ]
        assert settings_labels == [
            "General", "Bridges", "Ports", "Custom Tor",
            "Blocked Hosts", "Excluded Hosts", "Advanced",
        ]
        top_labels = [button.text() for button in window.page_nav_buttons]
        assert top_labels == ["Home", "Settings", "Developer Tor", "Custom Tor", "Help"]
        assert "Block Host" not in top_labels
        assert "Exclude Host" not in top_labels

        window._show_block_host()
        assert window.stack.currentWidget() is window.settingWidget
        assert window.settingWidget.page_setting.currentIndex() == 4
        window._show_exclude_host()
        assert window.stack.currentWidget() is window.settingWidget
        assert window.settingWidget.page_setting.currentIndex() == 5
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
        repository / "ui_/window/statistics_window.py",
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
    expected_settings_nav = (
        'self.settings_nav_titles = ('
        '\n            "General",'
        '\n            "Bridges",'
        '\n            "Ports",'
        '\n            "Custom Tor",'
        '\n            "Blocked Hosts",'
        '\n            "Excluded Hosts",'
        '\n            "Advanced",'
    )
    assert expected_settings_nav in settings_source
    assert "verify_tor_signatures" in settings_source
    assert "QScrollArea" in settings_source and "setWidgetResizable(True)" in settings_source
    assert "lbl_page_number" not in settings_source
    assert "Browse official release channels" not in updater_source
    assert "self.updates_list.setMinimumHeight(250)" in updater_source
    assert "self.list_tor_versions.setMinimumHeight(250)" in updater_source
    pulse_source = (repository / "ui_/btn/pulse_button.py").read_text(encoding="utf-8")
    assert "connectPulseButton" in proxy_source
    assert "self.setFixedSize(self._diameter, self._diameter)" in pulse_source
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
    assert "self.setFixedSize(self._diameter, self._diameter)" in pulse_source
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
    assert "def _set_theme(self, mode, *, preference=None)" in ui_source
    assert "self._parent._set_theme_preference(preference)" in settings_source
    assert 'self.theme_mode_buttons = {}' in settings_source
    assert '("system", "System"), ("light", "Light"), ("dark", "Dark")' in settings_source
    assert "def _on_system_color_scheme_changed(self, _scheme=None)" in ui_source
    assert 'qta.icon("fa6s.window-minimize"' in titlebar_source
    assert 'qta.icon("fa6s.window-maximize"' in titlebar_source
    assert 'qta.icon("fa6s.xmark"' in titlebar_source




def test_updates_navigation_keeps_theme_text_color_on_hover():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")

    assert "QToolButton#updatesNavButton:hover {{" in source
    assert "color: {text}; background: {hover}; border-color: {border};" in source
    assert "QToolButton#updatesNavButton:checked:hover {{" in source
    assert "background: {accent}; color: #ffffff; border-color: {accent};" in source
    # Suppress the platform-colored native indicator and draw a chevron with
    # the exact foreground used by the Updates label.
    assert "QToolButton#updatesNavButton::menu-button" not in source
    assert source.count("QToolButton#updatesNavButton::menu-indicator {{") == 1
    assert "image: none;" in source
    assert "subcontrol-origin: padding;" in source
    assert "subcontrol-position: bottom right;" in source
    assert "QToolButton#updatesNavButton {{ padding-right: 22px; }}" in source
    assert "center_y = self.rect().bottom() - 8" in source
    assert "class UpdatesMenuButton(QToolButton):" in source
    assert "self.updates_nav_button.setMenuIndicatorColor(color)" in source
    assert "QPushButton#topNavButton, QToolButton#updatesNavButton {{" in source



def test_updates_nav_icon_and_text_follow_only_the_active_updates_page(monkeypatch):
    pytest.importorskip("qtawesome")
    from types import SimpleNamespace
    import ui

    class _Stack:
        def __init__(self, page):
            self.page = page

        def currentWidget(self):
            return self.page

    class _Button:
        icon = None
        checked = None
        indicator_color = None
        indicator_open = False

        def setIcon(self, icon):
            self.icon = icon

        def setChecked(self, checked):
            self.checked = checked

        def setMenuIndicatorColor(self, color):
            self.indicator_color = color

        def setMenuIndicatorOpen(self, opened):
            self.indicator_open = bool(opened)

    updater_page = object()
    tunnel_page = object()
    other_page = object()
    fake = SimpleNamespace(
        stack=_Stack(updater_page),
        updater_window=updater_page,
        tunnel_window=tunnel_page,
        updates_nav_button=_Button(),
    )
    fake._sync_updates_nav_icon = lambda mode=None: ui.Window._sync_updates_nav_icon(fake, mode)
    monkeypatch.setattr(ui, "CONFIG", {"mode": "light"})
    monkeypatch.setattr(ui.qta, "icon", lambda name, color: (name, color))

    # Bundles/Tunnel active: text, cloud and custom dropdown chevron are white.
    ui.Window._sync_updates_nav_icon(fake, "light")
    assert fake.updates_nav_button.checked is True
    assert fake.updates_nav_button.icon == ("fa6s.cloud-arrow-down", "#ffffff")
    assert fake.updates_nav_button.indicator_color == "#ffffff"

    fake.stack.page = tunnel_page
    ui.Window._sync_updates_nav_icon(fake, "dark")
    assert fake.updates_nav_button.checked is True
    assert fake.updates_nav_button.icon == ("fa6s.cloud-arrow-down", "#ffffff")

    # Other page, light theme: opening Updates must not make the button active.
    fake.stack.page = other_page
    ui.Window._sync_updates_nav_icon(fake, "light")
    assert fake.updates_nav_button.checked is False
    assert fake.updates_nav_button.icon == ("fa6s.cloud-arrow-down", "#202832")
    assert fake.updates_nav_button.indicator_color == "#202832"

    ui.Window._on_updates_menu_about_to_show(fake)
    assert fake.updates_nav_button.indicator_open is True
    assert fake.updates_nav_button.checked is False
    assert fake.updates_nav_button.icon == ("fa6s.cloud-arrow-down", "#202832")
    assert fake.updates_nav_button.indicator_color == "#202832"

    # Switching into an Updates page while the popup is shown follows page state.
    fake.stack.page = updater_page
    ui.Window._on_updates_menu_about_to_show(fake)
    assert fake.updates_nav_button.checked is True
    assert fake.updates_nav_button.icon == ("fa6s.cloud-arrow-down", "#ffffff")
    assert fake.updates_nav_button.indicator_color == "#ffffff"

    ui.Window._on_updates_menu_about_to_hide(fake)
    assert fake.updates_nav_button.indicator_open is False
    assert fake.updates_nav_button.checked is True
    assert fake.updates_nav_button.icon == ("fa6s.cloud-arrow-down", "#ffffff")
    assert fake.updates_nav_button.indicator_color == "#ffffff"

    # Leaving Updates restores the normal theme text/icon/caret color.
    fake.stack.page = other_page
    ui.Window._on_updates_menu_about_to_hide(fake)
    assert fake.updates_nav_button.checked is False
    ui.Window._sync_updates_nav_icon(fake, "dark")
    assert fake.updates_nav_button.icon == ("fa6s.cloud-arrow-down", "#eff1f4")
    assert fake.updates_nav_button.indicator_color == "#eff1f4"


def test_updates_dropdown_chevron_is_inside_the_reserved_bottom_right_slot(qt_app):
    from PySide6.QtGui import QImage
    from PySide6.QtWidgets import QMenu
    from PySide6.QtCore import Qt
    import ui

    button = ui.UpdatesMenuButton()
    button.setObjectName("updatesNavButton")
    button.setText("Updates")
    button.setToolButtonStyle(ui.Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
    menu = QMenu(button)
    button.setMenu(menu)
    button.setPopupMode(ui.QToolButton.ToolButtonPopupMode.InstantPopup)
    button.setStyleSheet(
        "QToolButton#updatesNavButton { min-height: 32px; padding: 0 22px 0 8px; }"
        "QToolButton#updatesNavButton::menu-indicator { image: none; width: 12px; "
        "height: 12px; subcontrol-origin: padding; subcontrol-position: bottom right; }"
    )
    button.resize(150, 36)
    button.setMenuIndicatorColor("#202832")
    button.show()
    qt_app.processEvents()

    def chevron_pixels(color):
        image = QImage(button.size(), QImage.Format.Format_ARGB32)
        image.fill(Qt.GlobalColor.transparent)
        button.render(image)
        points = []
        for y in range(image.height()):
            for x in range(image.width()):
                pixel = image.pixelColor(x, y)
                if color == "dark" and pixel.red() < 80 and pixel.green() < 90 and pixel.blue() < 100:
                    points.append((x, y))
                elif color == "light" and pixel.red() > 225 and pixel.green() > 225 and pixel.blue() > 225:
                    points.append((x, y))
        return points

    button.setMenuIndicatorOpen(False)
    dark_points = chevron_pixels("dark")
    dark_chevron = [
        (x, y) for x, y in dark_points
        if button.width() - 16 <= x <= button.width() - 5
        and button.height() - 16 <= y <= button.height() - 5
    ]
    assert dark_chevron, "Dark dropdown chevron should be visible in the bottom-right slot."
    assert min(x for x, _ in dark_chevron) >= button.width() - 15
    assert max(x for x, _ in dark_chevron) <= button.width() - 6
    assert min(y for _, y in dark_chevron) > button.height() // 2
    assert max(y for _, y in dark_chevron) <= button.height() - 5

    button.setMenuIndicatorColor("#ffffff")
    button.setMenuIndicatorOpen(True)
    qt_app.processEvents()
    white_points = chevron_pixels("light")
    white_chevron = [
        (x, y) for x, y in white_points
        if button.width() - 16 <= x <= button.width() - 5
        and button.height() - 16 <= y <= button.height() - 5
    ]
    assert white_chevron, "White dropdown chevron should stay inside the bottom-right slot."
    assert min(y for _, y in white_chevron) > button.height() // 2
    assert max(x for x, _ in white_chevron) <= button.width() - 6
    assert max(y for _, y in white_chevron) <= button.height() - 5

    button.close()
    menu.deleteLater()
    button.deleteLater()
    qt_app.processEvents()


def test_updates_menu_initialization_avoids_undefined_mode_and_tracks_popup_state():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")
    menu_builder = source[source.index("def _createMenuBar"):source.index("def _show_notifications")]

    assert 'self._sync_updates_nav_icon()' in menu_builder
    assert 'self._sync_updates_nav_icon(mode)' not in menu_builder
    assert 'self.updates_menu.aboutToShow.connect(self._on_updates_menu_about_to_show)' in menu_builder
    assert 'self.updates_menu.aboutToHide.connect(self._on_updates_menu_about_to_hide)' in menu_builder
    assert 'def _on_updates_menu_about_to_show(self):' in source
    assert 'def _on_updates_menu_about_to_hide(self):' in source
    assert 'self.updates_nav_button.setIcon(qta.icon("fa6s.cloud-arrow-down", color=color))' in source
    assert 'self.updates_nav_button.setChecked(selected)' in source
    assert 'color = "#ffffff" if selected else ("#eff1f4" if dark else "#202832")' in source
    assert 'self.updates_nav_button.setMenuIndicatorColor(color)' in source
    assert "class UpdatesMenuButton(QToolButton):" in source
    assert "QToolButton#updatesNavButton::menu-indicator {{" in source
    assert "subcontrol-position: bottom right;" in source
    assert "QToolButton#updatesNavButton {{ padding-right: 22px; }}" in source
    assert "center_y = self.rect().bottom() - 8" in source
    assert "_updates_menu_open" not in source
    assert "QPushButton#topNavButton, QToolButton#updatesNavButton {{" in source
    assert "QToolButton#updatesNavButton::menu-button" not in source
    # Qt's native arrow is explicitly disabled because UpdatesMenuButton paints
    # its own state-aware chevron in paintEvent().
    assert "QToolButton#updatesNavButton::menu-indicator {{" in source
    assert "image: none;" in source


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
    assert "def _request_stop_services(" in home_source
    assert "worker = Worker(self._stop_services_worker)" in home_source
    assert "def _stop_services_worker(self)" in home_source
    assert "self._parent._on_proxy_shutdown_complete(True, \"\")" in home_source
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
        "fa6s.code",
        "fa6s.server",
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
    assert "self.stack.indexOf(self.shortcutsWidget)" in ui_source
    assert "def _show_tunnel_page(self)" in ui_source
    assert "self.stack.indexOf(self.tunnel_window)" in ui_source
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
        "ui_/window/tunnel_window.py",
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
    assert 'self.theme_mode_buttons = {}' in settings_source
    assert '("system", "System"), ("light", "Light"), ("dark", "Dark")' in settings_source
    assert 'button.clicked.connect(' in settings_source
    assert 'self._parent._set_theme_preference(preference)' in settings_source
    assert '"theme_preference": "system"' in config_source
    assert 'CONFIG.update_many({"mode": mode, "theme_preference": preference})' in ui_source
    assert 'self._system_theme_hints.colorSchemeChanged.connect(' in ui_source
    assert 'def _on_system_color_scheme_changed(self, _scheme=None)' in ui_source
    assert 'self._set_theme(mode, preference=mode)' in ui_source
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
    assert 'self.proxyWidget._request_stop_services(final_status="APPLICATION EXIT")' in close_event
    assert "def _on_proxy_shutdown_complete(" in source
    assert "_shutdown_in_progress" in close_event
    home_source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    assert "onion_manager.shutdown_runtime()" in home_source
    assert '"resume_after_cancelled_shutdown"' in source
    page_source = (repository / "ui_/window/onion_hosting_page.py").read_text(encoding="utf-8")
    rebuild = page_source[page_source.index("    def _rebuild_service_cards("):page_source.index("    def _service_card(")]
    assert "self.empty_label.setVisible(not services)" in rebuild
    assert "self.empty_label.deleteLater()" not in rebuild
    assert "worker.signals.finished.connect(relay.on_finished)" in page_source
    assert "worker.signals.error.connect(relay.on_error)" in page_source


def test_onion_service_dashboard_keeps_empty_label_alive_across_card_refreshes(qt_app):
    from ui_.window.onion_hosting_page import OnionHostingPage

    class FakeOnionManager:
        def runtime_snapshot(self):
            return {
                "state": "stopped",
                "progress": None,
                "message": "Developer Tor is stopped.",
                "network_summary": "Direct connection",
                "version": "",
                "memory_bytes": 0,
                "uptime_seconds": 0,
                "pid": None,
            }

        def services_snapshot(self):
            return []

        def traffic_snapshot(self, service_id=None):
            return {
                "incoming_bytes": 0,
                "outgoing_bytes": 0,
                "connections": 0,
                "http_requests": 0,
                "errors": 0,
                "active_connections": 0,
                "last_activity": "",
            }

        def traffic_events(self, service_id, limit=250):
            return []

    manager = FakeOnionManager()

    class FakeProxy:
        def _ensure_onion_hosting_manager(self):
            return manager

    page = OnionHostingPage(FakeProxy())
    page._timer.stop()
    qt_app.processEvents()

    service = {
        "id": "test-service",
        "display_name": "Test service",
        "local_host": "127.0.0.1",
        "local_port": 8000,
        "onion_port": 80,
        "persistent": True,
        "access_mode": "public",
        "running": False,
        "error": None,
        "address": "",
    }

    # Initial empty refresh -> populated -> empty -> populated must never
    # delete the persistent QLabel or leave a stale Python wrapper.
    assert not page.empty_label.isHidden()
    page._rebuild_service_cards([service])
    qt_app.processEvents()
    assert page.empty_label.isHidden()
    assert len(page._service_card_widgets) == 1

    page._rebuild_service_cards([])
    qt_app.processEvents()
    assert not page.empty_label.isHidden()
    assert len(page._service_card_widgets) == 0

    page._rebuild_service_cards([service, {**service, "id": "test-service-2"}])
    qt_app.processEvents()
    assert page.empty_label.isHidden()
    assert len(page._service_card_widgets) == 2
    assert page.empty_label.text().startswith("No Onion Services yet")

    page._timer.stop()
    page.deleteLater()
    qt_app.processEvents()


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


def test_theme_reveal_uses_widget_snapshots_and_supports_live_widgets():
    repository = Path(__file__).resolve().parents[1]
    theme_source = (repository / "ui.py").read_text(encoding="utf-8")
    transition_source = (
        repository / "ui_/window/theme_transition.py"
    ).read_text(encoding="utf-8")

    # The current three-choice Settings selector commits directly; the main
    # window animates a circular reveal between snapshots of the real widget tree.
    assert "old_snapshot = self.grab()" in theme_source
    assert theme_source.count("self.grab()") == 1
    assert "new_snapshot = self.grab()" not in theme_source
    assert "CircularThemeReveal(" in theme_source
    assert "duration_ms=300" in theme_source
    assert "self._old_snapshot = old_snapshot" in transition_source
    assert "self._new_snapshot" not in transition_source
    assert "old_frame_region.setFillRule(Qt.FillRule.OddEvenFill)" in transition_source
    assert "widget.render(" in transition_source
    assert "self._live_widgets = tuple(widget for widget in live_widgets if widget is not None)" in transition_source


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
    assert "logger.warning(\"Background task failed (%s): %s\", task_name, exc)" in worker_source
    assert "logger.exception(\"Unexpected background task failure (%s).\", task_name)" in worker_source
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
    assert '"webtunnel_use_default_tls": True' in config_source
    assert "webtunnelDefaultTlsPreference" in settings_source
    assert "def save_webtunnel_default_tls(self, enabled: bool):" in settings_source
    assert '"Use the hostname in url= (default; no override)", ""' in settings_source
    assert '"www.google.com"' in settings_source
    assert "def save_webtunnel_sni_imitation(self):" in settings_source
    assert 'webtunnel_sni_imitation=str(CONFIG["webtunnel_sni_imitation"] or "")' in runner_source
    assert "normalize_sni_hostname(settings.webtunnel_sni_imitation or \"\")" in manager_source
    assert 'tokens.append("utls=none")' in manager_source
    assert 'webtunnel_use_default_tls=bool(CONFIG["webtunnel_use_default_tls"])' in runner_source
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
    parent.setStyleSheet("background-color: rgb(0, 0, 255);")
    transition = CircularThemeReveal(
        parent,
        old_snapshot,
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
    assert "painter.setClipPath(old_frame_region)" in transition_source
    assert "painter.drawPixmap(self.rect(), self._old_snapshot)" in transition_source
    assert "painter.drawPixmap(self.rect(), self._new_snapshot)" not in transition_source
    assert "self._paint_max_ms" in transition_source
    assert "old_frame_region.subtracted(reveal_region)" not in transition_source
    assert "def _prewarm_theme_stylesheets(self)" in ui_source
    assert "_THEME_STYLESHEET_CACHE" in ui_source
    assert "only one captured pixmap" in transition_source
    assert "WA_TransparentForMouseEvents" in transition_source




def test_statistics_page_is_reachable_from_proxy_traffic_and_uses_live_directional_counters():
    repository = Path(__file__).resolve().parents[1]
    ui_source = (repository / "ui.py").read_text(encoding="utf-8")
    home_source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    stats_source = (repository / "ui_/window/statistics_window.py").read_text(encoding="utf-8")
    proxy_source = (repository / "proxy.py").read_text(encoding="utf-8")

    assert "self.btn_statistics = QPushButton(" in home_source
    assert 'self.btn_statistics.setObjectName("statisticsLink")' in home_source
    assert "self.btn_statistics.clicked.connect(self.open_statistics_page)" in home_source
    assert "self.stack.addWidget(self.statisticsWidget)" in ui_source
    assert "self._show_page(self.stack.indexOf(self.statisticsWidget))" in ui_source
    assert "def get_traffic_direction_snapshot()" in proxy_source
    assert 'if direction in {"upload", "download"}' in proxy_source
    assert '("lifetime", "TOTAL TRAFFIC"' in stats_source
    assert '("upload", "UPLOADED"' in stats_source
    assert '("download", "DOWNLOADED"' in stats_source
    assert 'TrafficChart("rate"' in stats_source
    assert 'TrafficChart("volume"' in stats_source



def test_legacy_kill_switch_ui_and_tunnel_dependency_are_removed():
    repository = Path(__file__).resolve().parents[1]
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    home_source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    tor_source = (repository / "tor.py").read_text(encoding="utf-8")
    tunnel_source = (repository / "src/torproxy/system_tunnel.py").read_text(encoding="utf-8")
    shell_source = (repository / "ui.py").read_text(encoding="utf-8")

    assert "Kill Switch" not in settings_source
    assert "killSwitch" not in settings_source
    assert "KillSwitchManager" not in home_source
    assert "kill_switch_enabled" not in home_source
    assert "Kill Switch" not in home_source
    assert "isolate_in_cgroup=" not in tor_source
    assert "cgroup_callback=" not in tor_source
    assert "_enable_windows_wfp_tun_exception" not in tunnel_source
    assert "_apply_wfp_tun_exception" not in tunnel_source
    assert "Kill Switch" not in tunnel_source
    assert "systemTunnelCard" not in home_source
    assert "systemTunnelHint" in home_source
    assert "TunnelManagerWindow" in shell_source
    assert '("Tunnel"' not in shell_source
    assert "updates_nav_button" in shell_source
    assert "self.page_nav_group.setExclusive(False)" in shell_source
    assert "self.page_nav_group.setExclusive(True)" in shell_source
    assert "def _show_tunnel_page(self)" in shell_source


def test_home_places_system_proxy_and_tunnel_controls_in_one_row():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")

    assert "service_controls_row = QHBoxLayout()" in source
    assert "service_controls_row.addWidget(proxy_controls, 1)" in source
    assert "service_controls_row.addWidget(self.system_tunnel_hint, 1)" in source
    assert "self.home_layout.addLayout(service_controls_row)" in source
    assert "self.home_layout.addWidget(self.system_tunnel_hint)" not in source
    assert "self.home_layout.addLayout(proxy_row)" not in source


def test_home_proxy_controls_hide_explanatory_copy_and_use_consistent_surfaces():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")

    assert "self.proxy_status_label.setVisible(False)" in source
    assert "proxy_controls_layout.addWidget(self.proxy_status_label)" not in source
    assert "QComboBox#systemProxyMode" in source
    assert "QFrame#systemProxyControls" in source
    assert "QFrame#systemTunnelHint" in source
    assert "border-radius: 12px" in source


def test_home_tunnel_controls_start_and_stop_installed_engine_without_showing_manage():
    repository = Path(__file__).resolve().parents[1]
    home_source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    tunnel_source = (repository / "ui_/window/tunnel_window.py").read_text(encoding="utf-8")

    assert 'self.btn_system_tunnel_action = SystemTunnelActionButton("Start"' in home_source
    assert 'self.btn_system_tunnel_action.clicked.connect(self.toggle_system_tunnel)' in home_source
    assert 'self.btn_system_tunnel_manage.clicked.connect(self.open_tunnel_manager)' in home_source
    assert 'manage_button.setVisible(show_manage)' in home_source
    assert 'action_button.setVisible(show_action)' in home_source
    assert 'action_text = "Stop"' in home_source
    assert 'action_text = "Reconcile"' in home_source
    assert 'action_text = "Start"' in home_source
    assert 'def toggle_system_tunnel(self):' in home_source
    assert 'toggle_tunnel_from_home' in home_source
    assert 'def toggle_tunnel_from_home(self)' in tunnel_source
    assert 'self.manager.installed_version' in tunnel_source
    assert 'self.versions_list.setCurrentItem(item)' in tunnel_source
    assert 'self.toggle_tunnel()' in tunnel_source


def test_tunnel_manager_is_a_versioned_updates_page_with_explicit_network_routes():
    repository = Path(__file__).resolve().parents[1]
    ui_source = (repository / "ui.py").read_text(encoding="utf-8")
    tunnel_source = (repository / "ui_/window/tunnel_window.py").read_text(encoding="utf-8")
    engine_source = (repository / "src/torproxy/system_tunnel.py").read_text(encoding="utf-8")

    assert "TunnelManagerWindow(self)" in ui_source
    assert "updates_nav_button" in ui_source
    assert "bundles_update_action" in ui_source
    assert "tunnel_update_action" in ui_source
    assert "def _show_tunnel_page(self)" in ui_source
    assert 'QLabel("Available releases")' in tunnel_source
    assert "check_latest_release" in tunnel_source
    assert "upstream-unpinned" in tunnel_source
    assert 'self.versions_list.insertItem(0, item)' in tunnel_source
    assert 'item.setData(Qt.ItemDataRole.UserRole + 2, platform_asset)' in tunnel_source
    assert 'allow_unpinned=upstream_unpinned' in tunnel_source
    assert "Install newer upstream sing-box release?" in tunnel_source
    assert "Install selected version" in tunnel_source
    assert "_resolve_network_route" in tunnel_source
    assert "allow_direct=allow_direct" in tunnel_source
    assert "create_session(proxy_url, allow_direct=allow_direct)" in engine_source
    assert 'self.btn_test_connection = QPushButton("Test traffic")' in tunnel_source
    assert 'self.btn_test_connection.clicked.connect(self.test_tunnel_traffic)' in tunnel_source
    assert "def test_tunnel_traffic(self)" in tunnel_source
    assert "self.manager.test_connection" in tunnel_source
    assert "def test_connection(self, socks_port:" in engine_source
    assert 'result = self._invoke_helper("start")' in engine_source
    assert "_apply_wfp_tun_exception" not in engine_source


def test_bundle_manager_exposes_manual_import_and_tor_only_network_routing():
    repository = Path(__file__).resolve().parents[1]
    updater_source = (repository / "ui_/window/updater_window.py").read_text(encoding="utf-8")
    assert "QFileDialog.getOpenFileName" in updater_source
    assert "self.btn_import_bundle.clicked.connect(self.choose_local_bundle)" in updater_source
    assert 'tor_socks_proxy_url("127.0.0.1", port)' in updater_source
    assert "Allow direct bootstrap connection?" in updater_source
    assert 'if CONFIG["kill_switch_enabled"]:' not in updater_source
    assert "LOCAL · UNSIGNED" in updater_source



def test_bundle_source_url_is_copyable_in_the_existing_title_row_without_extra_height():
    repository = Path(__file__).resolve().parents[1]
    updater_source = (repository / "ui_/window/updater_window.py").read_text(encoding="utf-8")
    title_row_start = updater_source.index("title_row = QHBoxLayout()")
    title_row_end = updater_source.index("root.addLayout(title_row)", title_row_start)
    title_row = updater_source[title_row_start:title_row_end]
    assert "self.bundle_source_url = QLineEdit(TOR_BUNDLE_BASE_URL)" in title_row
    assert "self.bundle_source_url.setReadOnly(True)" in title_row
    assert "self.bundle_source_url.setFixedSize(272, 27)" in title_row
    assert "self.btn_copy_bundle_source.clicked.connect(self._copy_bundle_source_url)" in title_row
    assert "QApplication.clipboard().setText(TOR_BUNDLE_BASE_URL)" in updater_source
    assert "QLineEdit#bundleSourceUrl" in updater_source
    assert "QPushButton#copySourceButton" in updater_source


def test_failed_release_discovery_keeps_installed_bundles_available():
    repository = Path(__file__).resolve().parents[1]
    updater_source = (repository / "ui_/window/updater_window.py").read_text(encoding="utf-8")
    start = updater_source.index("def _on_discovery_error")
    end = updater_source.index("def selected_version", start)
    error_handler = updater_source[start:end]
    assert "Installed bundles remain available" in error_handler
    assert "self.list_tor_versions.clear()" not in error_handler
    assert "logger.error(" not in error_handler



def test_bundle_source_tooltip_documents_official_archive_fallback():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/updater_window.py").read_text(encoding="utf-8")
    assert "archive.torproject.org/tor-package-archive/torbrowser/" in source
    assert "same explicitly selected network route" in source


def test_custom_tor_profile_editor_scrolls_advanced_options_without_growing_dialog(qt_app):
    pytest.importorskip("qtawesome")

    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QScrollArea
    from ui_.window.tor_services_page import TorServiceEditorDialog

    dialog = TorServiceEditorDialog()
    try:
        assert isinstance(dialog.scroll_area, QScrollArea)
        assert dialog.scroll_area.widget() is dialog.scroll_content
        assert dialog.body_layout.count() == 1
        assert dialog.scroll_area.horizontalScrollBarPolicy() == Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        assert dialog.scroll_area.verticalScrollBarPolicy() == Qt.ScrollBarPolicy.ScrollBarAsNeeded

        # Mimic a shorter laptop display and expand the advanced controls.
        dialog.resize(620, 420)
        dialog._remember_preferred_size()
        dialog.show()
        qt_app.processEvents()
        dialog._toggle_network_options(True)
        qt_app.processEvents()

        assert dialog.height() == 420
        assert dialog.network_options_container.isVisible()
        assert dialog.scroll_area.verticalScrollBar().maximum() > 0
        assert dialog.footer.isVisible()
        assert dialog.footer.geometry().bottom() <= dialog.rect().bottom()
    finally:
        dialog.close()
        dialog.deleteLater()
        qt_app.processEvents()


def test_open_browser_dialog_lists_installed_browsers_and_filters_search(qt_app, tmp_path):
    pytest.importorskip("qtawesome")
    from PySide6.QtWidgets import QLabel
    from torproxy.browsers import Browser, BrowserInventoryStore
    from ui_.window.dialogs import _FramelessDialog
    from ui_.window.open_browser_dialog import OpenBrowserDialog

    chrome_path = tmp_path / "chrome"
    firefox_path = tmp_path / "firefox"
    chrome_path.write_text("browser", encoding="utf-8")
    firefox_path.write_text("browser", encoding="utf-8")
    if os.name != "nt":
        chrome_path.chmod(0o755)
        firefox_path.chmod(0o755)
    icon_path = tmp_path / "browser.svg"
    icon_path.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">'
        '<circle cx="32" cy="32" r="28" fill="#287db5"/></svg>',
        encoding="utf-8",
    )

    class _FakeDetector:
        def detect(self):
            return [
                Browser("chrome", "Chrome", "chromium", str(chrome_path), icon=str(icon_path)),
                Browser("firefox", "Firefox", "firefox", str(firefox_path), icon=str(icon_path)),
            ]

        def register_custom(self, browser):
            return None

    class _FakeLauncher:
        def launch(self, browser, proxy_port, url=None):
            return 1234

    inventory = BrowserInventoryStore(tmp_path / "browser_inventory.sqlite3")
    inventory.replace_snapshot([
        Browser("chrome", "Chrome", "chromium", str(chrome_path), icon=str(icon_path)),
        Browser("firefox", "Firefox", "firefox", str(firefox_path), icon=str(icon_path)),
    ])
    dialog = OpenBrowserDialog(
        proxy_port=45555,
        detector=_FakeDetector(),
        launcher=_FakeLauncher(),
        inventory=inventory,
    )
    try:
        assert isinstance(dialog, _FramelessDialog)
        assert dialog.title_bar is not None
        assert len(dialog._cards) == 2
        assert dialog.start_page_input.text() == "https://check.torproject.org/"
        assert dialog.body_layout.spacing() <= 7
        assert dialog.body_layout.contentsMargins().top() <= 10
        assert dialog.notice.wordWrap() is False
        assert dialog.refresh_button.toolTip() == "Refresh installed browsers"
        assert dialog.findChild(QLabel, "dialogMessage") is None
        browser_icon = dialog.findChild(QLabel, "browserIconLabel")
        assert browser_icon is not None
        assert browser_icon.property("browserId") == "chrome"
        assert browser_icon.pixmap() is not None and not browser_icon.pixmap().isNull()
        endpoint = dialog.findChild(QLabel, "browserProxyEndpoint")
        assert endpoint is not None
        assert "127.0.0.1:45555" in endpoint.text()

        dialog._filter_cards("firefox")
        visibility = {
            name: card.isHidden()
            for card, name, _family, _browser in dialog._cards
        }
        assert visibility["chrome"] is True
        assert visibility["firefox"] is False
    finally:
        dialog.close()
        dialog.deleteLater()
        qt_app.processEvents()


def test_open_browser_dialog_shows_cache_then_scans_off_the_ui_thread(qt_app, tmp_path):
    import threading

    from PySide6.QtCore import QThreadPool
    from torproxy.browsers import Browser, BrowserInventoryStore
    from ui_.window.open_browser_dialog import OpenBrowserDialog

    cached_executable = tmp_path / "cached-browser"
    fresh_executable = tmp_path / "fresh-browser"
    for executable in (cached_executable, fresh_executable):
        executable.write_text("browser", encoding="utf-8")
        if os.name != "nt":
            executable.chmod(0o755)

    cached = Browser("cached", "Cached Browser", "chromium", str(cached_executable))
    fresh = Browser("fresh", "Fresh Browser", "firefox", str(fresh_executable))
    inventory = BrowserInventoryStore(tmp_path / "browser_inventory.sqlite3")
    inventory.upsert(cached)

    entered = threading.Event()
    release = threading.Event()
    scan_threads = []

    class _SlowDetector:
        def detect(self):
            scan_threads.append(threading.get_ident())
            entered.set()
            release.wait(4)
            return [fresh]

        def register_custom(self, browser):
            return None

    class _Launcher:
        def launch(self, browser, proxy_port, url=None):
            return 1234

    dialog = OpenBrowserDialog(
        proxy_port=45556,
        detector=_SlowDetector(),
        launcher=_Launcher(),
        inventory=inventory,
    )
    try:
        # The cache is rendered synchronously; the expensive detector has not run.
        assert [browser.id for browser in dialog.browsers] == ["cached"]
        assert len(dialog._cards) == 1
        assert scan_threads == []

        dialog.show()
        qt_app.processEvents()
        assert entered.wait(2)
        assert scan_threads[0] != threading.get_ident()
        assert dialog._scan_running is True
        assert not dialog.scan_spinner.isHidden()

        release.set()
        assert QThreadPool.globalInstance().waitForDone(4000)
        qt_app.processEvents()
        assert [browser.id for browser in dialog.browsers] == ["fresh"]
        assert [browser.id for browser in inventory.load()] == ["fresh"]
        assert dialog.scan_spinner.isHidden()
    finally:
        release.set()
        dialog.close()
        dialog.deleteLater()
        QThreadPool.globalInstance().waitForDone(4000)
        qt_app.processEvents()


def test_open_browser_removes_a_deleted_cached_executable_immediately(qt_app, tmp_path):
    import threading

    from PySide6.QtCore import QThreadPool
    from torproxy.browsers import Browser, BrowserInventoryStore
    from ui_.window.open_browser_dialog import OpenBrowserDialog

    executable = tmp_path / "removed-browser"
    executable.write_text("browser", encoding="utf-8")
    if os.name != "nt":
        executable.chmod(0o755)
    browser = Browser("removed", "Removed Browser", "chromium", str(executable))
    inventory = BrowserInventoryStore(tmp_path / "browser_inventory.sqlite3")
    inventory.upsert(browser)

    entered = threading.Event()
    release = threading.Event()

    class _SlowDetector:
        def detect(self):
            entered.set()
            release.wait(4)
            return []

        def register_custom(self, browser):
            return None

    class _Launcher:
        called = False

        def launch(self, browser, proxy_port, url=None):
            self.called = True
            raise AssertionError("A removed browser must not be launched")

    launcher = _Launcher()
    dialog = OpenBrowserDialog(
        proxy_port=45557,
        detector=_SlowDetector(),
        launcher=launcher,
        inventory=inventory,
    )
    try:
        dialog._start_scan()
        assert entered.wait(2)
        executable.unlink()

        dialog._launch(browser)

        assert launcher.called is False
        assert inventory.load() == []
        assert dialog.browsers == []
        assert "no longer installed" in dialog.notice.text()
    finally:
        release.set()
        dialog.close()
        dialog.deleteLater()
        QThreadPool.globalInstance().waitForDone(4000)
        qt_app.processEvents()


def test_sing_box_manager_uses_bundle_manager_visual_language_and_live_state_refresh():
    repository = Path(__file__).resolve().parents[1]
    tunnel_source = (repository / "ui_/window/tunnel_window.py").read_text(encoding="utf-8")
    bundle_source = (repository / "ui_/window/updater_window.py").read_text(encoding="utf-8")

    assert 'root.setContentsMargins(12, 7, 12, 8)' in tunnel_source
    assert 'title.setObjectName("pageTitle")' in tunnel_source
    assert 'self.release_panel.setObjectName("contentCard")' in tunnel_source
    assert 'self.versions_list.setObjectName("releaseList")' in tunnel_source
    assert 'self.btn_install.setObjectName("primaryButton")' in tunnel_source
    assert 'self.progress.setObjectName("bundleProgress")' in tunnel_source
    assert 'QLabel#pageTitle' in tunnel_source and 'QLabel#pageTitle' in bundle_source
    assert 'QFrame#infoCard, QFrame#contentCard' in tunnel_source
    assert 'QListWidget#releaseList' in tunnel_source and 'QListWidget#releaseList' in bundle_source
    assert 'QPushButton#primaryButton' in bundle_source
    assert 'self._state_refresh_timer.setInterval(1000)' in tunnel_source
    assert 'self._state_refresh_timer.timeout.connect(self._refresh_state)' in tunnel_source
    assert 'self.btn_start_stop.setIcon(qta.icon(action_icon' in tunnel_source
    assert 'self._refresh_state()' in tunnel_source


def test_advanced_settings_exposes_conservative_sing_box_recovery():
    repository = Path(__file__).resolve().parents[1]
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    tunnel_source = (repository / "src/torproxy/system_tunnel.py").read_text(encoding="utf-8")

    assert 'self._section_title("System tunnel recovery")' in settings_source
    assert 'QPushButton("Check / clean up", self)' in settings_source
    assert 'self.btn_tunnel_recovery.clicked.connect(self.cleanup_system_tunnel)' in settings_source
    assert 'QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No' in settings_source
    assert 'Worker(manager.cleanup_previous_session)' in settings_source
    assert 'def cleanup_previous_session(self)' in tunnel_source
    assert 'An untracked TUN adapter is never deleted or adopted' in tunnel_source
    assert 'self._tunnel_recovery_pool.start(worker)' in settings_source


def test_connect_preflight_reconciles_previous_sing_box_state_before_starting_tor():
    repository = Path(__file__).resolve().parents[1]
    home_source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    tunnel_source = (repository / "src/torproxy/system_tunnel.py").read_text(encoding="utf-8")

    preflight = home_source[home_source.index("def _check_ports_worker"):home_source.index("def _request_stop_services")]
    assert 'self.system_tunnel_manager.cleanup_previous_session()' in preflight
    assert "Tor was not started to avoid connecting while stale system routes may remain." in preflight
    assert 'tunnel_record_exists = self.system_tunnel_manager.process_state_path.exists()' in home_source
    assert 'if tunnel_record_exists or tunnel_status.get("active")' in home_source
    assert 'def cleanup_previous_session(self)' in tunnel_source


def test_proxy_state_refreshes_the_tunnel_page_and_home_status():
    repository = Path(__file__).resolve().parents[1]
    home_source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    update = home_source[home_source.index("def _update_proxy_buttons"):home_source.index("def _update_tunnel_hint")]
    assert 'self._update_tunnel_hint()' in update
    assert 'refresh_tunnel_page = getattr(tunnel_page, "_refresh_state", None)' in update
    assert 'refresh_tunnel_page()' in update



def test_main_window_requests_small_dwm_corners_only_when_restored():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")

    assert "def _apply_native_window_corners(self):" in source
    assert "if not IS_WINDOWS:" in source
    assert "ctypes.WinDLL(\"dwmapi\"" in source
    assert "# DWMWA_WINDOW_CORNER_PREFERENCE = 33" in source
    assert "# DWMWCP_DONOTROUND = 1; DWMWCP_ROUNDSMALL = 3." in source
    assert "1 if self.isMaximized() or self.isFullScreen() else 3" in source
    assert "QTimer.singleShot(0, self._apply_native_window_corners)" in source
    assert "setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground" not in source



def test_tray_menu_uses_a_modern_theme_aware_floating_surface():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")

    # The tray popup is a designed application surface, not an unstyled
    # platform-default menu with a few isolated actions.
    assert "QWidgetAction" in source
    assert 'self.tray_menu.setObjectName("trayContextMenu")' in source
    assert "self.tray_menu.setMinimumWidth(286)" in source
    assert 'self.tray_menu_header_action.setDefaultWidget(self.tray_menu_header)' in source
    assert 'QLabel("Quick controls", self.tray_menu_header)' in source
    assert 'QLabel("SYSTEM PROXY", self.tray_proxy_section)' in source

    theme_start = source.index("def _sync_tray_menu_theme(self, mode=None):")
    theme_end = source.index("def _theme_reveal_origin", theme_start)
    theme_sync = source[theme_start:theme_end]
    assert "QMenu#trayContextMenu" in theme_sync
    assert "QMenu#trayContextMenu::item:selected" in theme_sync
    assert "QMenu#trayContextMenu::separator" in theme_sync
    assert "QMenu#trayContextMenu::indicator:checked" in theme_sync
    assert 'surface = "#171e29"' in theme_sync
    assert 'surface = "#ffffff"' in theme_sync
    assert 'hover = "#29384d"' in theme_sync
    assert 'hover = "#edf3fb"' in theme_sync
    assert '"fa6s.eye" if hidden else "fa6s.eye-slash"' in theme_sync
    assert '"set": "fa6s.link"' in theme_sync
    assert '"clear": "fa6s.link-slash"' in theme_sync
    assert 'qta.icon("fa6s.right-from-bracket", color=danger)' in theme_sync

    local_theme_start = source.index("def _apply_local_theme_styles(self, mode, *, visible_only=False):")
    local_theme_end = source.index("def _sync_tray_menu_theme", local_theme_start)
    local_theme = source[local_theme_start:local_theme_end]
    assert "visible_only and not page.isVisible()" in local_theme
    assert "self._ensure_page_theme(page, mode)" in local_theme
    assert "self._sync_tray_menu_theme(mode)" in local_theme
    assert "self._ensure_page_theme(self.stack.widget(index))" in source
    assert "self._ensure_visible_theme_pages()" in source
    assert "self._apply_local_theme_styles(mode, visible_only=True)" in source
    assert "self._sync_tray_menu_theme()" in source[
        source.index("self._sync_tray_system_proxy_actions()"):
        source.index("# Do not give the menu to the shell:")
    ]


def test_shortcut_row_icons_remain_transparent_over_the_hover_surface():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/shortcuts_window.py").read_text(encoding="utf-8")

    assert 'icon_label.setObjectName("shortcutsRowIcon")' in source
    assert (
        "QLabel#shortcutsRowIcon, QFrame#shortcutsRow:hover QLabel#shortcutsRowIcon "
        "{{ background: transparent; border: none; }}"
    ) in source
    assert "QFrame#shortcutsRow:hover {{ background: {hover}; }}" in source
    # A single grouped transparent rule covers both normal and hovered states.
    assert source.count("QLabel#shortcutsRowIcon") == 2


def test_tray_menu_uses_compact_vertical_spacing():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")

    assert "header_layout.setContentsMargins(14, 8, 14, 6)" in source
    assert "header_layout.setSpacing(1)" in source
    assert "proxy_section_layout.setContentsMargins(14, 3, 12, 0)" in source

    theme_start = source.index("def _sync_tray_menu_theme(self, mode=None):")
    theme_end = source.index("def _theme_reveal_origin", theme_start)
    theme = source[theme_start:theme_end]
    assert "padding: 6px;" in theme
    assert "padding: 7px 14px 7px 12px;" in theme
    assert "margin: 1px 4px;" in theme
    assert "margin: 4px 12px;" in theme


def test_open_browser_action_button_colors_follow_the_active_theme():
    from types import SimpleNamespace

    pytest.importorskip("qtawesome")
    from ui_.window.open_browser_dialog import OpenBrowserDialog

    colors = {
        "text": "#253041",
        "panel": "#f6f8fb",
        "border": "#d7dee7",
        "hover": "rgba(24, 118, 191, 0.09)",
        "muted": "#657386",
        "surface": "#f6f8fb",
    }
    light_css = OpenBrowserDialog._extra_styles(
        SimpleNamespace(_dark=False, _accent="#287db5", _colors=colors)
    )
    dark_css = OpenBrowserDialog._extra_styles(
        SimpleNamespace(_dark=True, _accent="#287db5", _colors=colors)
    )

    assert "color: #287db5;" in light_css
    assert "background: #eaf3fc;" in light_css
    assert "background: #dcecfb;" in light_css
    assert "color: #ffffff;" not in light_css
    assert "color: #ffffff;" in dark_css
    assert "background: #287db5;" in dark_css
    assert "background: #236b9b;" in dark_css


def test_disabled_home_action_text_uses_the_theme_muted_foreground():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")

    assert 'self.btn_open_browser.setObjectName("secondaryAction")' in source
    assert 'self.btn_open_browser.setEnabled(False)' in source
    assert "QPushButton#secondaryAction:disabled {{" in source
    assert "background: {field}; color: {muted}; border-color: {border};" in source
    assert 'muted = "#aab4c1" if dark else "#667386"' in source


def test_system_theme_detection_prefers_qt_platform_color_scheme(qt_app):
    from PySide6.QtCore import Qt
    from ui_.window.theme import resolve_system_theme

    class _StyleHints:
        def __init__(self, scheme):
            self._scheme = scheme

        def colorScheme(self):
            return self._scheme

    class _FakeApplication:
        def __init__(self, scheme):
            self._hints = _StyleHints(scheme)

        def styleHints(self):
            return self._hints

    assert resolve_system_theme(_FakeApplication(Qt.ColorScheme.Dark)) == "dark"
    assert resolve_system_theme(_FakeApplication(Qt.ColorScheme.Light)) == "light"


def test_system_theme_detection_falls_back_to_platform_window_palette(qt_app):
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor, QPalette
    from ui_.window.theme import resolve_system_theme

    class _StyleHints:
        def colorScheme(self):
            return Qt.ColorScheme.Unknown

    class _FakeApplication:
        def __init__(self, window_color):
            self._palette = QPalette()
            self._palette.setColor(QPalette.ColorRole.Window, QColor(window_color))

        def styleHints(self):
            return _StyleHints()

        def palette(self):
            return self._palette

    assert resolve_system_theme(_FakeApplication("#202630")) == "dark"
    assert resolve_system_theme(_FakeApplication("#ffffff")) == "light"


def test_system_theme_selector_and_live_os_updates_are_wired_into_the_app():
    repository = Path(__file__).resolve().parents[1]
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    ui_source = (repository / "ui.py").read_text(encoding="utf-8")
    main_source = (repository / "main.py").read_text(encoding="utf-8")

    assert 'self.theme_mode_selector.setObjectName("themeModeSelector")' in settings_source
    assert 'button.setObjectName("themeModeOption")' in settings_source
    assert "System follows your desktop setting" in settings_source
    assert "QPushButton#themeModeOption:checked" in settings_source
    assert 'CONFIG.get("theme_preference", "system") != "system"' in ui_source
    assert "resolve_system_theme(QApplication.instance())" in ui_source
    assert "self._system_theme_hints.colorSchemeChanged.connect(" in ui_source
    assert 'theme_preference = CONFIG.get("theme_preference", "system")' in main_source
    assert "resolve_system_theme(app)" in main_source
    assert main_source.index("resolve_system_theme(app)") < main_source.index("app.setStyleSheet")


def test_tunnel_download_icon_uses_the_same_foreground_as_its_button():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/tunnel_window.py").read_text(encoding="utf-8")
    init_source = source[source.index("def __init__"):source.index("def _populate_versions")]
    styles_start = source.index("def _apply_local_styles")
    styles_end = source.index("__all__")
    styles_source = source[styles_start:styles_end]

    assert 'self.btn_install.setObjectName("primaryButton")' in source
    assert 'QPushButton#primaryButton {{ font-weight: 650; color: {text}; }}' in source
    # The icon is assigned with a theme-derived color after the button exists.
    # Do not reference the local stylesheet variable from __init__.
    assert 'self.btn_install.setIcon' not in init_source
    assert 'self.btn_install.setIcon(qta.icon("fa6s.download", color=text))' in styles_source
    assert 'self.btn_install.setIcon(qta.icon("fa6s.download", color="#ffffff"))' not in source


def test_live_tor_log_viewport_uses_a_theme_appropriate_background():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/tor_log_dialog.py").read_text(encoding="utf-8")

    assert 'log_background = "#111820" if self._dark else "#f6f8fb"' in source
    assert 'QTextEdit#torLogText {{' in source
    assert 'color: {self._colors["text"]}; background: {log_background};' in source
    assert 'background: #111820;' not in source



def test_transfer_volume_chart_maps_hovered_bars_to_directional_tooltip(qt_app):
    from ui_.window.statistics_window import TrafficChart

    chart = TrafficChart("volume")
    chart.resize(640, 260)
    chart.set_history(
        [
            {
                "timestamp": 1794272400,
                "total_bytes": 3072,
                "upload_bytes": 1024,
                "download_bytes": 2048,
            },
            {
                "timestamp": 1794276000,
                "total_bytes": 6144,
                "upload_bytes": 4096,
                "download_bytes": 2048,
            },
        ],
        7200,
    )
    try:
        first_bar = chart._volume_bar_rect(0)
        assert not first_bar.isEmpty()
        point = first_bar.center()
        assert chart._volume_bucket_index_at(point.x(), point.y()) == 0

        tooltip = chart._volume_tooltip(0)
        assert "Total: 3.00 KiB" in tooltip
        assert "Uploaded: 1.00 KiB" in tooltip
        assert "Downloaded: 2.00 KiB" in tooltip
        assert "–" in tooltip
    finally:
        chart.close()
        chart.deleteLater()
        qt_app.processEvents()


def test_statistics_transfer_volume_chart_displays_theme_aware_hover_tooltips():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/statistics_window.py").read_text(encoding="utf-8")

    assert "self.setMouseTracking(True)" in source
    assert "def _volume_bucket_index_at(self, x: float, y: float) -> int | None:" in source
    assert "def _volume_tooltip(self, index: int) -> str:" in source
    assert "QToolTip.showText(" in source
    assert "QToolTip.hideText()" in source
    assert "QToolTip {{ color: {text}; background: {surface};" in source
    assert "QToolTip.setPalette(tooltip_palette)" in source
    assert "QPalette.ColorRole.ToolTipBase" in source
    assert "QPalette.ColorRole.ToolTipText" in source
    assert '"timestamp": _safe_non_negative_int(bucket.get("timestamp", 0))' in source


def test_statistics_back_button_icon_tracks_the_active_theme_foreground():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/statistics_window.py").read_text(encoding="utf-8")
    styles_start = source.index("def _apply_theme_styles")
    styles_end = source.index("__all__")
    styles = source[styles_start:styles_end]

    assert 'self.back_button.setIcon(qta.icon("fa6s.arrow-left", color=text))' in styles
    assert "QPushButton#statisticsBackButton {{ color: {text};" in styles

def test_system_tunnel_recovery_warning_uses_the_module_logger():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "src/torproxy/system_tunnel.py").read_text(encoding="utf-8")

    assert "logger = logging.getLogger(__name__)" in source
    assert "logger.warning(" in source
    assert "LOGGER.warning(" not in source


def test_worker_routes_expected_system_tunnel_cancellation_without_error_logging(qt_app, caplog):
    from torproxy.system_tunnel import SystemTunnelCancelled
    from ui_.worker.worker import Worker

    def _cancel():
        raise SystemTunnelCancelled("Administrator approval was cancelled.")

    import logging

    caplog.set_level(logging.INFO, logger="ui_.worker.worker")
    worker = Worker(_cancel)
    cancelled = []
    failures = []
    worker.signals.cancelled.connect(cancelled.append)
    worker.signals.error.connect(failures.append)

    worker.run()

    assert cancelled == ["SystemTunnelCancelled: Administrator approval was cancelled."]
    assert failures == []
    assert "Background task cancelled" in caplog.text
    assert "Unexpected background task failure" not in caplog.text
    assert not [record for record in caplog.records if record.levelno >= 30]


def test_tunnel_page_handles_cancelled_uac_without_warning_or_error_log():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/tunnel_window.py").read_text(encoding="utf-8")

    assert "worker.signals.cancelled.connect(self._on_operation_cancelled)" in source
    assert "def _on_operation_cancelled(self, reason: str) -> None:" in source
    callback = source[source.index("def _on_operation_cancelled"):source.index("def _on_operation_failed")]
    assert 'level="info"' in callback
    assert "QMessageBox.warning" not in callback
    assert '"stop": "Stop cancelled' in callback
    assert "self._finish_operation()" in callback


def test_home_disconnect_preserves_uac_cancellation_and_restores_connected_state():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")

    assert "worker.signals.cancelled.connect(self._on_services_stop_cancelled)" in source
    assert "def _on_services_stop_cancelled(self, reason: str) -> None:" in source
    assert "except SystemTunnelCancelled:" in source
    callback = source[source.index("def _on_services_stop_cancelled"):source.index("def _on_services_stop_failed")]
    assert "self._stopping = False" in callback
    assert "self.connect_btn.setEnabled(True)" in callback
    assert 'level="info"' in callback
    assert 'level="error"' not in callback
    assert "QMessageBox.warning" not in callback


def test_home_system_tunnel_action_icon_tracks_enabled_hover_and_theme_colors(qt_app):
    import ui_.window.proxy_window as home

    button = home.SystemTunnelActionButton()
    try:
        button.set_icon_name("fa6s.play")
        button.set_theme_colors(text="#253041", muted="#667386")
        assert button._icon_color == "#ffffff"

        button._set_hovered(True)
        assert button._icon_color == "#253041"

        button.setEnabled(False)
        assert button._icon_color == "#667386"

        button.setEnabled(True)
        assert button._icon_color == "#253041"

        button._set_hovered(False)
        assert button._icon_color == "#ffffff"
    finally:
        button.deleteLater()
        qt_app.processEvents()


def test_home_tunnel_action_uses_state_aware_icon_colors():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")

    assert "class SystemTunnelActionButton(QPushButton):" in source
    assert "def set_theme_colors(self, *, text: str, muted: str) -> None:" in source
    assert "def enterEvent(self, event):" in source
    assert "def leaveEvent(self, event):" in source
    assert "self.btn_system_tunnel_action.set_theme_colors(text=text, muted=muted)" in source
    assert "action_button.set_icon_name(action_icon)" in source
    assert 'action_button.setIcon(qta.icon(action_icon, color="#ffffff"))' not in source

def test_connection_preflight_treats_declined_tunnel_recovery_as_cancellation():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")

    assert "worker.signals.cancelled.connect(self._on_port_check_cancelled)" in source
    assert "except SystemTunnelCancelled:" in source
    callback = source[source.index("def _on_port_check_cancelled"):source.index("def _on_port_check_error")]
    assert "self._connect_operation_busy = False" in callback
    assert "self.connect_btn.setEnabled(True)" in callback
    assert 'level="info"' in callback
    assert 'level="error"' not in callback
    assert "CONNECTION CANCELLED" in callback

def test_settings_emergency_tunnel_cleanup_handles_declined_uac_as_cancellation():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")

    assert "worker.signals.cancelled.connect(self._on_tunnel_recovery_cancelled)" in source
    assert "def _on_tunnel_recovery_cancelled(self, reason: str):" in source
    callback = source[source.index("def _on_tunnel_recovery_cancelled"):source.index("def _on_tunnel_recovery_failed")]
    assert "self._finish_tunnel_recovery()" in callback
    assert "self._refresh_tunnel_views_after_recovery()" in callback
    assert 'level="info"' in callback
    assert 'level="error"' not in callback




def test_custom_titlebar_shows_high_resolution_app_icon_beside_title(qt_app):
    assert qt_app is not None
    from PySide6.QtWidgets import QMainWindow
    from ui_.window.custom_titlebar import CustomTitleBar

    class _TitleBarHost(QMainWindow):
        def hide_to_tray(self):
            self.hide()

    parent = _TitleBarHost()
    titlebar = CustomTitleBar(parent)
    logo = titlebar.app_icon
    pixmap = logo.pixmap()

    assert logo.objectName() == "customTitleBarAppIcon"
    assert pixmap is not None and not pixmap.isNull()
    assert titlebar.layout().indexOf(logo) < titlebar.layout().indexOf(titlebar.title)
    assert titlebar.layout().indexOf(titlebar.title) < titlebar.layout().indexOf(titlebar.window_controls)
    assert logo.width() == 24 and logo.height() == 24



def test_updates_and_notifications_dropdowns_use_dedicated_modern_theme_styles():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")

    assert 'self.updates_menu.setObjectName("updatesMenu")' in source
    assert 'self.notifications_menu.setObjectName("notificationsMenu")' in source
    assert 'QWidget#updatesMenuHeader' in source
    assert 'QWidget#notificationsMenuHeader' in source
    assert 'QLabel#notificationCountBadge' in source
    assert 'QToolButton#notificationClearButton' in source
    assert 'QLabel#notificationDescription' in source
    assert 'QMenu#updatesMenu, QMenu#notificationsMenu' in source
    assert 'QMenu#updatesMenu::item:selected, QMenu#notificationsMenu::item:selected' in source
    assert 'def _rebuild_notifications_menu(self, mode=None):' in source
    assert 'self._rebuild_notifications_menu(mode)' in source
    assert 'self._rebuild_notifications_menu()' in source
    # Notification dismissal and the existing update shortcut remain connected.
    assert 'self.notification_clear_button.clicked.connect(self._clear_notifications)' in source
    assert 'self.bundles_update_action.setShortcut("Ctrl+U")' in source



def test_dropdown_header_copy_has_no_individual_background_or_border():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")
    start = source.index("/* Header copy should sit directly on the menu surface")
    end = source.index('QLabel#notificationCountBadge', start)
    header_styles = source[start:end]

    for selector in (
        "QLabel#updatesMenuEyebrow",
        "QLabel#updatesMenuSubtitle",
        "QLabel#notificationsMenuTitle",
        "QLabel#notificationsMenuSubtitle",
        "QLabel#notificationDescription",
    ):
        assert selector in header_styles
    assert "background: transparent;" in header_styles
    assert "border: none;" in header_styles
    assert "background: transparent;" in source[
        source.index("QWidget#updatesMenuHeader"):
        source.index("QLabel#updatesMenuEyebrow")
    ]


def test_native_maximize_event_forwarding_preserves_button_and_pressed_state():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")
    helper = source[
        source.index("def _forward_native_max_button_mouse_event"):
        source.index("def nativeEvent", source.index("def _forward_native_max_button_mouse_event"))
    ]

    assert "event_type, button, buttons" in helper
    assert "            button," in helper
    assert "            buttons," in helper
    assert "Qt.MouseButton.LeftButton" not in helper


def test_native_titlebar_hit_testing_uses_windows_snap_hit_code():
    from PySide6.QtCore import QPoint, QRect

    from ui import _HTCAPTION, _HTCLIENT, _HTMAXBUTTON, _native_titlebar_hit_test

    titlebar = QRect(0, 0, 500, 40)
    minimize = QRect(362, 0, 46, 40)
    maximize = QRect(408, 0, 46, 40)
    close = QRect(454, 0, 46, 40)

    assert _native_titlebar_hit_test(
        maximize.center(), titlebar, maximize, (minimize, close)
    ) == _HTMAXBUTTON
    assert _native_titlebar_hit_test(
        minimize.center(), titlebar, maximize, (minimize, close)
    ) == _HTCLIENT
    assert _native_titlebar_hit_test(
        close.center(), titlebar, maximize, (minimize, close)
    ) == _HTCLIENT
    assert _native_titlebar_hit_test(
        QPoint(120, 20), titlebar, maximize, (minimize, close)
    ) == _HTCAPTION


def test_custom_titlebar_leaves_snap_layouts_to_windows():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/custom_titlebar.py").read_text(encoding="utf-8")

    assert "QMenu" not in source
    assert "snap_menu" not in source
    assert "SNAP_LAYOUT_HOVER_DELAY_MS" not in source
    assert "self.btn_max.clicked.connect(self._toggle_maximized)" in source


def test_native_resize_hit_testing_covers_all_window_edges_and_corners(qt_app):
    from PySide6.QtCore import QPoint, QRect

    from ui import (
        _HTBOTTOM,
        _HTBOTTOMLEFT,
        _HTBOTTOMRIGHT,
        _HTLEFT,
        _HTRIGHT,
        _HTTOP,
        _HTTOPLEFT,
        _HTTOPRIGHT,
        _native_resize_hit_test,
    )

    bounds = QRect(0, 0, 500, 300)
    cases = (
        (QPoint(2, 150), _HTLEFT),
        (QPoint(497, 150), _HTRIGHT),
        (QPoint(250, 2), _HTTOP),
        (QPoint(250, 297), _HTBOTTOM),
        (QPoint(2, 2), _HTTOPLEFT),
        (QPoint(497, 2), _HTTOPRIGHT),
        (QPoint(2, 297), _HTBOTTOMLEFT),
        (QPoint(497, 297), _HTBOTTOMRIGHT),
    )

    for point, expected in cases:
        assert _native_resize_hit_test(point, bounds) == expected

    assert _native_resize_hit_test(QPoint(250, 150), bounds) is None
    assert _native_resize_hit_test(QPoint(510, 150), bounds) is None


def test_native_titlebar_hit_testing_enables_system_menu_without_stealing_maximize_clicks():
    from PySide6.QtCore import QPoint, QRect

    from ui import (
        _HTCAPTION,
        _HTCLIENT,
        _HTMAXBUTTON,
        _WS_OVERLAPPEDWINDOW,
        _WS_SYSMENU,
        _native_titlebar_hit_test,
    )

    titlebar = QRect(0, 0, 500, 40)
    minimize = QRect(362, 0, 46, 40)
    maximize = QRect(408, 0, 46, 40)
    close = QRect(454, 0, 46, 40)
    other_buttons = (minimize, close)

    # Windows receives HTMAXBUTTON, so it owns the Snap Layout hover delay and flyout.
    assert _native_titlebar_hit_test(
        maximize.center(), titlebar, maximize, other_buttons
    ) == _HTMAXBUTTON

    # Minimize and Close remain Qt client controls too.
    assert _native_titlebar_hit_test(
        minimize.center(), titlebar, maximize, other_buttons
    ) == _HTCLIENT
    assert _native_titlebar_hit_test(
        close.center(), titlebar, maximize, other_buttons
    ) == _HTCLIENT

    # Empty title-bar space remains caption area for drag and native system menu.
    assert _native_titlebar_hit_test(
        QPoint(200, 20), titlebar, maximize, other_buttons
    ) == _HTCAPTION
    assert _native_titlebar_hit_test(
        QPoint(200, 50), titlebar, maximize, other_buttons
    ) is None
    assert _WS_OVERLAPPEDWINDOW & _WS_SYSMENU


def test_clamp_window_rect_to_work_area_keeps_a_grabbable_strip_visible():
    from PySide6.QtCore import QRect

    from ui import _clamp_window_rect_to_work_area

    # A secondary monitor can have a negative X origin. Keep 88 px visible
    # without assuming the primary monitor starts at (0, 0).
    work_area = QRect(-1920, 0, 1920, 1040)
    window_rect = QRect(-3100, -180, 1080, 720)
    constrained = _clamp_window_rect_to_work_area(
        window_rect, work_area, visible_width=88, visible_titlebar=40
    )

    assert constrained.left() == work_area.left() - window_rect.width() + 88
    assert constrained.top() == work_area.top()
    assert constrained.width() == window_rect.width()
    assert constrained.height() == window_rect.height()

    # Moving below the work area keeps the title-bar strip reachable.
    below = QRect(-1600, 1300, 1080, 720)
    constrained_below = _clamp_window_rect_to_work_area(
        below, work_area, visible_width=88, visible_titlebar=40
    )
    assert constrained_below.top() == work_area.bottom() - 40 + 1


def test_native_main_window_style_restores_overlapped_windows_semantics():
    from ui import (
        _WS_CAPTION,
        _WS_OVERLAPPEDWINDOW,
        _WS_POPUP,
        _native_main_window_style,
    )

    unrelated_styles = 0x10000000 | 0x02000000  # WS_VISIBLE | WS_CLIPCHILDREN
    frameless_popup_style = _WS_POPUP | unrelated_styles

    normalized = _native_main_window_style(frameless_popup_style)

    assert normalized & _WS_POPUP == 0
    assert normalized & _WS_CAPTION == _WS_CAPTION
    assert normalized & _WS_OVERLAPPEDWINDOW == _WS_OVERLAPPEDWINDOW
    assert normalized & unrelated_styles == unrelated_styles
    assert _native_main_window_style(normalized) == normalized


def test_main_window_advertises_native_windows_snap_and_maximize_support():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")
    titlebar_source = (repository / "ui_/window/custom_titlebar.py").read_text(
        encoding="utf-8"
    )

    assert "def _enable_native_snap_support(self):" in source
    assert "_WS_POPUP = 0x80000000" in source
    assert "_WS_CAPTION = 0x00C00000" in source
    assert "_WS_OVERLAPPEDWINDOW = (" in source
    assert "def _native_main_window_style(style):" in source
    assert "native_style = _native_main_window_style(style)" in source
    assert "if native_style != style:" in source
    assert "self.btn_min.clicked.connect(parent.showMinimized)" in titlebar_source
    assert "def _native_resize_hit_test(point, window_rect, border=8):" in source
    assert "resize_hit = _native_resize_hit_test(" in source
    assert "if not self.isMaximized() and not self.isFullScreen():" in source
    assert "_HTBOTTOMRIGHT = 17" in source
    assert "def nativeEvent(self, event_type, message):" in source
    assert "native_message.message == _WM_NCCALCSIZE" in source
    assert "native_message.message == _WM_NCHITTEST" in source
    assert "_HTMAXBUTTON = 9" in source
    assert "return _HTMAXBUTTON" in source
    assert "MapWindowPoints" in source
    assert "GetDpiForWindow" in source
    assert "_WM_NCLBUTTONDOWN = 0x00A1" in source
    assert "_WM_NCLBUTTONUP = 0x00A2" in source
    assert "self._forward_native_max_button_mouse_event(" in source
    assert "self._set_native_max_button_hovered(hit_test == _HTMAXBUTTON)" in source
    assert "return super().nativeEvent(event_type, message)" in source
    assert "QEvent.Type.MouseButtonPress" in source
    assert "QEvent.Type.MouseButtonRelease" in source
    assert "QEvent.Type.MouseMove" in source
    assert "QEvent.Type.Enter if hovered else QEvent.Type.Leave" in source
    assert "_WM_MOUSEMOVE = 0x0200" in source
    assert "_WM_LBUTTONUP = 0x0202" in source
    assert "_WM_CAPTURECHANGED = 0x0215" in source
    assert "SetCapture" in source and "ReleaseCapture" in source
    assert "DefWindowProc's own caption-button click loop." in source
    assert "Never run DefWindowProc's own caption-button click loop." in source
    assert "_WM_MOVING = 0x0216" in source
    assert "_WM_SIZING = 0x0214" not in source
    assert "if native_message.message == _WM_MOVING:" in source
    assert "if native_message.message == _WM_DPICHANGED:" in source
    assert "self._native_map_window_points = map_window_points" in source
    assert "ratio = self._native_dpi_scale" in source
    assert "proxy_page.set_live_resize_active(True)" in source
    assert "proxy_page.set_live_resize_active(False)" in source
    assert "_WM_ENTERSIZEMOVE = 0x0231" in source
    assert "_WM_EXITSIZEMOVE = 0x0232" in source
    assert "self._native_move_loop_active = True" in source
    assert "_clamp_window_rect_to_work_area(" in source
    assert "MonitorFromRect" in source and "GetMonitorInfoW" in source
    assert "Native frame resize handles take priority around the outer" in source
    native_event_start = source.index("def nativeEvent(self, event_type, message):")
    native_event_end = source.index("def ", native_event_start + 5)
    native_event = source[native_event_start:native_event_end]
    assert native_event.index("_native_resize_hit_test(") < native_event.index(
        "_native_titlebar_hit_test("
    )
    assert "Blank title-bar space remains native caption space." in source
    assert "return True, hit_test" in source
    assert "titlebar._sync_maximize_button()" in source
    assert "handle.startSystemMove()" in titlebar_source
    assert "self.parent_.showMaximized()" in titlebar_source


def test_listener_port_inputs_are_editable_only_when_fixed_is_checked():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/setting_window.py").read_text(
        encoding="utf-8"
    )

    initialize = source[
        source.index("def initialize_second_page"):
        source.index("def sync_listener_ports")
    ]
    handler = source[
        source.index("def check_port_changed"):
        source.index("# ---------- other helpers ----------")
    ]

    # On startup, automatic ports are display-only; Fixed ports can be edited.
    assert "inp_port.setEnabled(enabled_initial)" in initialize
    assert "inp_port.setEnabled(True)" not in initialize

    # Toggling Fixed must persist the preference before changing editability.
    save_preference = handler.index('CONFIG[port + "_checked"] = enabled')
    set_editability = handler.index("inp_port.setEnabled(enabled)")
    assert save_preference < set_editability
    assert 'previous_fixed = bool(CONFIG[port + "_checked"])' in handler
    assert "checkbox.setChecked(previous_fixed)" in handler



def test_settings_exposes_isolated_tor_profiles_and_parallel_bridge_workers():
    repository = Path(__file__).resolve().parents[1]
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    services_source = (repository / "ui_/window/tor_services_page.py").read_text(encoding="utf-8")
    proxy_source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    tor_source = (repository / "tor.py").read_text(encoding="utf-8")

    assert '"Custom Tor"' in settings_source
    assert "TorServicesSettingsPage(self, app_window=self._parent)" in settings_source
    assert '"Concurrent bridge probes"' in services_source
    assert '"Concurrent service operations"' in services_source
    assert 'def add_service(self)' in services_source
    assert 'def start_all(self)' in services_source
    assert 'def stop_all(self)' in services_source
    assert 'def _build_tor_service_settings(self, profile: dict) -> TorSettings:' in proxy_source
    assert 'self.tor_service_pool.stop_all()' in proxy_source
    assert '"bridge_probe_workers"' in tor_source and "DEFAULT_MAX_WORKERS" in tor_source



def test_settings_expose_default_enabled_http_proxy_and_connectivity_diagnostic():
    repository = Path(__file__).resolve().parents[1]
    settings = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    config = (repository / "config.py").read_text(encoding="utf-8")
    assert '"http_proxy_enabled": True' in config
    assert 'self.chk_http_proxy_enabled = QCheckBox("Enable local HTTP proxy", self)' in settings
    assert 'self.btn_test_http_connect = QPushButton("Test HTTP CONNECT", self)' in settings
    assert "def test_http_connect(self)" in settings



def test_tor_service_settings_display_real_network_health_and_gateway_load():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/tor_services_page.py").read_text(encoding="utf-8")
    assert "def _service_health_text(status: dict)" in source
    assert '"Tor egress verified"' in source
    assert '"NO TOR EGRESS"' in source
    assert "def _refresh_live_service_health(self)" in source
    assert "active_connections" in source
    assert "max_sessions" in source



def test_tor_service_status_refresh_keeps_start_stop_actions_in_sync():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/tor_services_page.py").read_text(encoding="utf-8")
    assert "self._service_start_buttons: dict[str, QPushButton]" in source
    assert "self._service_stop_buttons: dict[str, QPushButton]" in source
    assert 'manager_state == "stopped" and not is_busy' in source
    assert 'manager_state == "failed"' in source
    assert "PROCESS EXITED · STOP TO RECONCILE" in source


def test_disconnect_shutdown_keeps_tor_alive_when_http_listener_is_still_owned():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    assert "http_proxy_blocks_tor_shutdown = False" in source
    assert "if self.tor and not http_proxy_blocks_tor_shutdown:" in source
    assert "Tor was deliberately kept running" in source



def test_tor_tools_use_top_navigation_without_home_or_back_buttons():
    repository = Path(__file__).resolve().parents[1]
    ui_source = (repository / "ui.py").read_text(encoding="utf-8")
    home_source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    custom_page_source = (repository / "ui_/window/tor_services_page.py").read_text(encoding="utf-8")
    developer_page_source = (repository / "ui_/window/onion_hosting_page.py").read_text(encoding="utf-8")
    settings_source = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")

    assert "Developer Tor" in ui_source and "Custom Tor" in ui_source
    assert "def _show_custom_tor(self)" in ui_source
    assert "def _show_developer_tor(self)" in ui_source
    assert 'QPushButton("Custom Tor"' not in home_source
    assert 'QPushButton("Developer Tor"' not in home_source
    assert "self.btn_custom_tor" not in home_source
    assert "self.btn_developer_tor" not in home_source
    assert "Back to Home" not in custom_page_source
    assert "Back to Home" not in developer_page_source
    assert "def _go_home(" not in custom_page_source
    assert "def _back_home(" not in developer_page_source
    assert "TorServicesPage(self, app_window=self, management_only=True)" in ui_source
    assert "TorServicesSettingsPage(self, app_window=self._parent)" in settings_source
    assert "def refresh_health(self)" in custom_page_source
    assert "QFrame#customTorHero" in custom_page_source
    assert "QFrame#onionPageHero" in developer_page_source
    assert "def refresh_dashboard(self)" in developer_page_source


def test_developer_and_custom_tor_pages_use_compact_consistent_surfaces():
    repository = Path(__file__).resolve().parents[1]
    developer = (repository / "ui_/window/onion_hosting_page.py").read_text(encoding="utf-8")
    custom = (repository / "ui_/window/tor_services_page.py").read_text(encoding="utf-8")

    # Both pages share the same compact page insets and 12px outer-card radius.
    assert "root.setContentsMargins(20, 12, 20, 12)" in developer
    assert "root_layout.setContentsMargins(20, 12, 20, 12)" in custom
    assert "border-radius: 12px" in developer
    assert "border-radius: 12px" in custom
    assert "border-radius: 16px" not in developer
    assert "border-radius: 16px" not in custom

    # Compact title rows and controls replace the oversized 54px icon headers.
    assert "setFixedSize(34, 34)" in developer
    assert "setFixedSize(34, 34)" in custom
    assert "setMinimumHeight(32)" in developer
    assert "self._management_hero_layout.addLayout(actions)" in custom
    assert "QPushButton#settingsActionButton, QPushButton#customTorPrimaryButton" in custom


def test_custom_tor_supports_startup_cancellation_force_stop_and_live_logs():
    repository = Path(__file__).resolve().parents[1]
    page = (repository / "ui_/window/tor_services_page.py").read_text(encoding="utf-8")
    pool = (repository / "src/torproxy/service_pool.py").read_text(encoding="utf-8")
    manager = (repository / "src/torproxy/tor_manager.py").read_text(encoding="utf-8")

    assert "stop_button.setEnabled(bool(pool) and can_stop" in page
    assert 'QPushButton("Force stop"' in page
    assert "_service_force_stop_buttons" in page
    assert "self._stop_thread_pool = QThreadPool(self)" in page
    assert "self._stop_thread_pool.start(worker)" in page
    assert "TorLogDialog(self, path, manager=manager).exec()" in page
    assert "manager._start_cancel_event = entry.start_cancel_event" in pool
    assert "entry.start_cancel_event.set()" in pool
    assert "def force_stop_service(self, service_id: str)" in pool
    assert "def force_stop(self) -> None:" in manager
    assert "process.kill()" in manager


def test_custom_tor_profile_updates_are_persisted_atomically_and_exit_stops_services():
    repository = Path(__file__).resolve().parents[1]
    page = (repository / "ui_/window/tor_services_page.py").read_text(encoding="utf-8")
    proxy = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    pool = (repository / "src/torproxy/service_pool.py").read_text(encoding="utf-8")

    assert 'CONFIG.update_many({"tor_services": updated})' in page
    assert 'getattr(self._parent, "_closing", False)' in proxy
    assert "self.tor_service_pool.stop_all()" in proxy
    assert "def stop_all(self, service_ids" in pool
    assert "already_stopping" in pool



def test_numeric_spinboxes_ignore_mouse_wheel_events(qt_app):
    from PySide6.QtCore import QPoint, QPointF, Qt
    from PySide6.QtGui import QWheelEvent
    from ui_.window.numeric_controls import NoWheelDoubleSpinBox, NoWheelSpinBox

    for spin, initial in ((NoWheelSpinBox(), 42), (NoWheelDoubleSpinBox(), 4.2)):
        spin.setRange(0, 100)
        spin.setValue(initial)
        spin.show()
        spin.setFocus()
        qt_app.processEvents()
        event = QWheelEvent(
            QPointF(4, 4),
            QPointF(4, 4),
            QPoint(0, 0),
            QPoint(0, 120),
            Qt.MouseButton.NoButton,
            Qt.KeyboardModifier.NoModifier,
            Qt.ScrollPhase.ScrollUpdate,
            False,
        )
        qt_app.sendEvent(spin, event)
        qt_app.processEvents()
        assert spin.value() == initial
        assert not event.isAccepted()
        spin.close()


def test_custom_tor_editor_offers_and_persists_installed_bundle_version(qt_app, monkeypatch):
    pytest.importorskip("qtawesome")
    import ui_.window.tor_services_page as services_page

    monkeypatch.setattr(
        services_page,
        "get_verified_bundle_inventory",
        lambda: [
            {"version": "16.0", "path": "/verified/tor-expert-bundle-windows-x86_64-16.0", "source": "user"},
            {"version": "15.0.26", "path": "/verified/tor-expert-bundle-windows-x86_64-15.0.26", "source": "packaged"},
        ],
    )
    dialog = services_page.TorServiceEditorDialog({"id": "work", "display_name": "Work"})
    try:
        assert dialog.inp_tor_bundle.findData("16.0") >= 0
        assert dialog.inp_tor_bundle.findData("15.0.26") >= 0
        dialog.inp_tor_bundle.setCurrentIndex(dialog.inp_tor_bundle.findData("16.0"))
        profile = dialog._validated_profile()
        assert profile["tor_bundle_version"] == "16.0"
    finally:
        dialog.close()
        dialog.deleteLater()
        qt_app.processEvents()


def test_all_numeric_qt_inputs_use_no_wheel_spinbox_controls():
    import re

    repository = Path(__file__).resolve().parents[1]
    for relative in ("ui_/window/tor_services_page.py", "ui_/window/onion_hosting_page.py"):
        source = (repository / relative).read_text(encoding="utf-8")
        assert not re.search(r"(?<!NoWheel)QSpinBox\s*\(", source)
        assert "NoWheelSpinBox(" in source



def test_home_connected_feedback_only_changes_on_aggregate_ready_edges():
    from ui_.window.proxy_window import ProxyWindow

    class FakeButton:
        def __init__(self):
            self.transitions = []

        def set_connected(self, connected):
            self.transitions.append(bool(connected))

    class FakeHome:
        connected = False
        connect_btn = FakeButton()

    home = FakeHome()

    assert ProxyWindow._set_home_connected_feedback(home, True) is True
    # Repeated pool reports, and a worker going down while another stays up,
    # must not restart the one-second CONNECTED acknowledgement timer.
    assert ProxyWindow._set_home_connected_feedback(home, True) is False
    assert ProxyWindow._set_home_connected_feedback(home, True) is False
    assert home.connect_btn.transitions == [True]

    # Only a complete outage changes the aggregate state; first recovery
    # produces one new acknowledgement, not one per worker.
    assert ProxyWindow._set_home_connected_feedback(home, False) is True
    assert ProxyWindow._set_home_connected_feedback(home, False) is False
    assert ProxyWindow._set_home_connected_feedback(home, True) is True
    assert home.connect_btn.transitions == [True, False, True]


def test_custom_tor_copy_socks_icon_tracks_light_and_dark_theme(qt_app, monkeypatch):
    pytest.importorskip("qtawesome")
    import ui_.window.tor_services_page as services_page
    from PySide6.QtWidgets import QPushButton

    page = services_page.TorServicesPage(management_only=True)
    try:
        button = QPushButton(page)
        button.setObjectName("settingsActionButton")
        button.setProperty("themeIconRole", "copy")
        calls = []
        original_icon = services_page.qta.icon

        def capture_icon(name, *args, **kwargs):
            calls.append((name, kwargs.get("color")))
            return original_icon(name, *args, **kwargs)

        monkeypatch.setattr(services_page.qta, "icon", capture_icon)
        page.apply_theme("dark")
        page.apply_theme("light")

        assert ("fa6s.copy", "#edf3fa") in calls
        assert ("fa6s.copy", "#243247") in calls
        assert button.icon().isNull() is False
    finally:
        page.close()
        page.deleteLater()
        qt_app.processEvents()



def test_main_socks_gateway_settings_and_authentication_are_wired_safely():
    repository = Path(__file__).resolve().parents[1]
    settings = (repository / "ui_/window/setting_window.py").read_text(encoding="utf-8")
    config = (repository / "config.py").read_text(encoding="utf-8")
    gateway = (repository / "src/torproxy/socks_gateway.py").read_text(encoding="utf-8")
    tor_source = (repository / "tor.py").read_text(encoding="utf-8")
    proxy_source = (repository / "proxy.py").read_text(encoding="utf-8")

    assert '"tor_socks_bind_all_interfaces": False' in config
    assert 'mainSocksLanAccessPreference' in settings
    assert 'generate_socks_gateway_credentials' in settings
    assert 'write_socks_gateway_credentials' in settings
    assert 'not encrypted' in settings
    assert 'traffic_recorder=record_proxy_traffic' in tor_source
    assert 'hmac.compare_digest' in gateway
    assert 'record_traffic=(route == "direct")' in proxy_source



def test_home_endpoint_cards_have_clear_copy_targets_and_consistent_exit_ip_summary():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")

    assert 'self._build_home_endpoint_card("SOCKS5", "socks")' in source
    assert 'self._build_home_endpoint_card("HTTP", "http")' in source
    assert 'endpoint_row.addWidget(endpoint_panel, 2)' in source
    assert 'endpoint_row.addWidget(self.exit_ip_card, 1)' in source
    assert 'QLabel("ADDRESS", card)' in source
    assert 'QLabel("PORT", card)' in source
    assert 'copy_button.setText("Copy")' in source
    assert 'copy_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)' in source
    assert 'copy_button.setFixedSize(84, 32)' in source
    assert 'self._show_home_endpoint_copy_feedback(key)' in source
    assert '"copy_timer": copy_feedback_timer' in source
    assert 'controls["host"].clicked' not in source  # QToolButton.clicked is connected when the card is built.
    assert '_copy_home_endpoint_part(endpoint, "host")' in source
    assert '_copy_home_endpoint_part(endpoint, "port")' in source
    assert '_copy_home_endpoint_full(endpoint)' in source
    assert 'QApplication.clipboard().setText(f"{host}:{port}")' in source
    assert 'QFrame#homeEndpointCard, QFrame#homeExitIpCard' in source
    assert 'QFrame#systemProxyControls' in source
    assert 'QFrame#homeMetricsPanel' in source
    assert 'self._home_connect_host = PulseButtonHost(self.connect_btn, self.home_content)' in source
    assert 'self.home_layout.addWidget(self._home_connect_host, 1)' in source
    assert 'connection_hint' not in source
    assert 'connectionHint' not in source
    assert 'connectionHero' not in source
    assert 'QLabel("BOOTSTRAP", metrics_panel)' in source
    assert 'QLabel#homeMetricCaption' in source
    assert 'left_metrics_layout.setAlignment(' in source
    assert 'Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter' in source
    assert 'right_metrics_layout.setAlignment(' in source
    assert 'Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter' in source
    assert 'metrics.addWidget(left_metrics, 1)' in source
    assert 'metrics.addWidget(separator, 0, Qt.AlignmentFlag.AlignCenter)' in source
    assert 'metrics.addWidget(right_metrics, 1)' in source
    assert 'separator.setFixedWidth(1)' in source
    assert 'separator.setFixedHeight(36)' in source
    normalized_source = " ".join(source.split())
    assert "QWidget#homeEndpointPanel, QWidget#homeMetricsLeft, QWidget#homeMetricsRight" in normalized_source
    assert 'http_proxy_bind_all_interfaces' in source
    assert 'tor_socks_bind_all_interfaces' in source
    assert 'LAN IP unavailable' in source



def test_developer_tor_separates_runtime_logs_from_service_activity_and_exposes_traffic_tools():
    repository = Path(__file__).resolve().parents[1]
    page = (repository / "ui_/window/onion_hosting_page.py").read_text(encoding="utf-8")
    manager = (repository / "src/torproxy/onion_hosting.py").read_text(encoding="utf-8")
    traffic = (repository / "src/torproxy/onion_traffic.py").read_text(encoding="utf-8")

    assert page.count("clicked.connect(self.open_runtime_logs)") == 1
    assert "logs.clicked.connect(self.open_runtime_logs)" not in page
    assert "self.open_service_activity(data)" in page
    assert "def open_service_activity(self, service: dict)" in page
    assert "def traffic_snapshot(self, service_id: str | None = None)" in manager
    assert "def traffic_events(self, service_id: str, limit: int = 250)" in manager
    assert '("incoming_bytes", "TOTAL IN")' in page
    assert '("outgoing_bytes", "TOTAL OUT")' in page
    assert "self._service_traffic_widgets" in page
    assert "QFrame#onionTrafficSummary" in page
    assert "def rotate_service_identity(self, profile_id: str)" in manager
    assert "self._traffic_relays[profile_id] = relay" in manager
    assert "OnionServiceRelay(profile_id, mappings, self._traffic_store)" in manager
    assert "self.store.finish_connection(" in traffic
    assert "self._request_buffer.find(b\"\\r\\n\")" in traffic
    assert "def _safe_request_path(raw_target: bytes) -> str" in traffic
    assert "self.path = _safe_request_path(" in traffic
    assert "query strings are not stored" in page


def test_developer_tor_service_cards_use_activity_and_rotatable_addresses():
    repository = Path(__file__).resolve().parents[1]
    page = (repository / "ui_/window/onion_hosting_page.py").read_text(encoding="utf-8")
    card = page[page.index("    def _service_card("):]

    assert 'QPushButton("Tor runtime logs", runtime)' in page
    assert 'activity = QPushButton("Request logs", card)' in card
    assert 'activity.clicked.connect(' in card
    assert 'new_address = QPushButton("New address", card)' in card
    assert 'bool(service.get("address")) and f"service:{service[\'id\']}" not in self._workers' in card
    assert 'new_address.clicked.connect(' in card
    assert 'def rotate_service_address(self, service: dict)' in page
    assert 'The current .onion address will stop working' in page
    assert 'manager.rotate_service_identity(service_id)' in page



def test_developer_tor_activity_exposes_per_port_events_and_error_counters():
    repository = Path(__file__).resolve().parents[1]
    page = (repository / "ui_/window/onion_hosting_page.py").read_text(encoding="utf-8")
    store = (repository / "src/torproxy/onion_traffic.py").read_text(encoding="utf-8")

    assert '["Time (UTC)", "Onion port", "Protocol", "First request line / connection"' in page
    assert '("errors", "ERRORS")' in page
    assert '("errors", "ERR")' in page
    assert 'labels["errors"].setText' in page
    assert 'self._traffic_store.delete_service(profile_id)' in (
        repository / "src/torproxy/onion_hosting.py"
    ).read_text(encoding="utf-8")
    assert 'HTTP sessions  {stats[' in page
    assert "one first request line per TCP connection" in page
    assert "_MAX_CONNECTIONS_PER_PORT = 128" in store



def test_pulse_button_host_sizes_from_independent_available_geometry(qt_app):
    from PySide6.QtCore import QPoint
    from ui_.btn.pulse_button import PulseButton, PulseButtonHost

    button = PulseButton()
    host = PulseButtonHost(button)
    try:
        host.resize(400, 300)
        host.show()
        qt_app.processEvents()
        host._sync_button_geometry()

        assert button.diameter == 280
        assert button.pos() == QPoint(60, 10)
        assert host.size().width() == 400
        assert host.size().height() == 300

        host.resize(800, 400)
        qt_app.processEvents()
        host._sync_button_geometry()
        assert button.diameter == 380
        assert button.pos() == QPoint(210, 10)
        assert host.size().width() == 800
        assert host.size().height() == 400

        host.resize(1200, 900)
        qt_app.processEvents()
        host._sync_button_geometry()
        assert button.diameter == 420
        assert button.pos() == QPoint(390, 240)
        assert host.size().width() == 1200
        assert host.size().height() == 900
    finally:
        host.deleteLater()
        qt_app.processEvents()


def test_pulse_button_host_updates_connect_synchronously_on_resize(qt_app):
    from PySide6.QtCore import QPoint
    from ui_.btn.pulse_button import PulseButton, PulseButtonHost

    button = PulseButton()
    host = PulseButtonHost(button)
    try:
        host.resize(400, 300)
        host.show()
        qt_app.processEvents()

        host.resize(620, 360)

        # No processEvents(), QTimer wait, or manual sync between resize and assertion.
        assert button.diameter == 340
        assert button.pos() == QPoint(140, 10)
    finally:
        host.deleteLater()
        qt_app.processEvents()


def test_pulse_button_pauses_and_resumes_pulses_during_live_resize(qt_app):
    from PySide6.QtCore import QAbstractAnimation
    from ui_.btn.pulse_button import PulseButton

    button = PulseButton()
    try:
        assert button.outer_anim.state() == QAbstractAnimation.State.Running
        assert button.halo_anim.state() == QAbstractAnimation.State.Running

        button.set_live_resize_active(True)
        assert button.outer_anim.state() == QAbstractAnimation.State.Paused
        assert button.halo_anim.state() == QAbstractAnimation.State.Paused

        button.set_live_resize_active(False)
        assert button.outer_anim.state() == QAbstractAnimation.State.Running
        assert button.halo_anim.state() == QAbstractAnimation.State.Running
    finally:
        button.close()
        button.deleteLater()
        qt_app.processEvents()


def test_pulse_button_host_ignores_unusable_geometry_without_jumping(qt_app):
    from ui_.btn.pulse_button import PulseButton, PulseButtonHost

    button = PulseButton()
    host = PulseButtonHost(button)
    try:
        host.resize(0, 0)
        host._sync_button_geometry()
        assert button.diameter == 264

        host.resize(80, 70)
        host._sync_button_geometry()
        assert button.diameter == 264
        assert PulseButtonHost.diameter_for_size(400, 300) == 280
        assert PulseButtonHost.diameter_for_size(80, 70) is None
    finally:
        host.deleteLater()
        qt_app.processEvents()


def test_home_resize_work_is_coalesced_and_connect_geometry_is_host_owned():
    repository = Path(__file__).resolve().parents[1]
    home_source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    button_source = (repository / "ui_/btn/pulse_button.py").read_text(encoding="utf-8")

    initialization = home_source[
        home_source.index("self._home_responsive_mode = None"):
        home_source.index("self.connection_status_frame")
    ]
    assert "self._home_resize_timer" not in initialization

    resize_event = home_source[
        home_source.index("def resizeEvent(self, event) -> None:"):
        home_source.index("def _build_home_endpoint_card", home_source.index("def resizeEvent(self, event) -> None:"))
    ]
    assert "self._apply_home_resize_update()" in resize_event
    assert "_home_resize_timer" not in resize_event

    assert "self._home_connect_host = PulseButtonHost(self.connect_btn, self.home_content)" in home_source
    assert "self.home_layout.addWidget(self._home_connect_host, 1)" in home_source
    assert "class PulseButtonHost(QWidget):" in button_source
    assert "self._resize_timer" not in button_source
    assert "self._sync_button_geometry()" in button_source
    assert "def set_live_resize_active(self, active: bool) -> None:" in button_source
    assert "animation.pause()" in button_source
    assert "animation.resume()" in button_source
    assert "self.button.set_diameter(diameter)" in button_source
    assert "self.button.move(target_position)" in button_source
    set_diameter = button_source[
        button_source.index("def set_diameter"):
        button_source.index("def _set_state")
    ]
    assert "updateGeometry()" not in set_diameter


def test_home_page_uses_adaptive_compact_layout_without_scrollbars():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")
    pulse = (repository / "ui_/btn/pulse_button.py").read_text(encoding="utf-8")

    assert "QScrollArea" not in source
    assert "home_scroll" not in source
    assert "self.home_content = QWidget(self)" in source
    assert "self.home_content.setSizePolicy(" in source
    assert "def _update_home_responsive_layout(self) -> None:" in source
    assert "def resizeEvent(self, event) -> None:" in source
    assert "height < 490" in source
    assert "height < 530" in source
    assert "height < 570" in source
    assert "height_band = (" in source
    assert 'self._home_metrics_panel.setFixedHeight(' in source
    assert '50 if stacked_metrics else' in source
    assert 'QFrame#homeMetricsPanel' in source
    assert 'font-size: 15px; font-weight: 620' in source
    assert 'font-size: 9px; font-weight: 600' in source
    assert 'QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed' in source
    assert 'self.btn_status.setWordWrap(False)' in source
    assert "status_frame_layout.setContentsMargins(20, 3, 20, 3)" in source
    assert "class ConnectionStatusPill(QWidget):" in source
    assert "def set_status_text(self, label: QLabel, text: str, max_width: int)" in source
    assert "metrics.elidedText(" in source
    assert "self._set_home_status_text(" in source
    assert "self._refresh_home_status_geometry()" in source
    assert "self.btn_status.setText(" not in source
    assert "self.connection_status_frame.set_connection_state(stmt)" in source
    assert "self.connection_status_frame.set_theme_mode(CONFIG[\"mode\"])" in source
    assert "self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)" in source
    assert "Qt.WidgetAttribute.WA_NoSystemBackground" not in source
    assert "Paint only the rounded capsule." in source
    assert "QPainter.RenderHint.Antialiasing" in source
    assert "painter.drawRoundedRect(rect, radius, radius)" in source
    assert "QFrame#connectionStatusFrame" not in source
    assert 'self.home_layout.addWidget(self._home_connect_host, 1)' in source
    assert 'self.connection_status_frame.setMaximumWidth(900)' in source
    assert 'background: transparent; border: none; border-radius: 0;' in source
    assert "self._home_service_controls_layout.setDirection(" in source
    assert "self._home_endpoint_row.setDirection(" in source
    assert "self._home_endpoint_layout.setDirection(" in source
    assert "self._home_utility_layout.setDirection(" in source
    assert "self._home_metrics_layout.setDirection(" in source
    assert "self._home_metric_separator.setFrameShape(QFrame.Shape.HLine)" in source
    assert 'QPushButton#secondaryAction[compact="true"]' in source
    assert 'QToolButton#homeEndpointCopy[compact="true"]' in source
    assert "self.system_tunnel_hint_label.setWordWrap(compact)" in source
    assert "card.setMinimumWidth(210)" not in source
    assert "self.exit_ip_card.setMinimumWidth(180)" not in source
    assert "self.tor_ip_label.setMinimumWidth(140)" not in source
    assert "self.btn_status.setWordWrap(False)" in source
    assert "def set_diameter(self, diameter: int) -> None:" in pulse
    assert "diameter = max(96, min(420, int(diameter)))" in pulse
    assert "scale = min(self.width(), self.height()) / 264.0" in pulse


def test_connection_status_pill_resizes_for_dynamic_status_text(qt_app):
    from PySide6.QtWidgets import QHBoxLayout, QLabel
    from ui_.window.proxy_window import ConnectionStatusPill

    pill = ConnectionStatusPill()
    layout = QHBoxLayout(pill)
    layout.setContentsMargins(20, 3, 20, 3)
    label = QLabel(pill)
    layout.addWidget(label)

    try:
        pill.set_status_text(label, "CONNECTED", 400)
        short_width = pill.width()

        pill.set_status_text(label, "CHECKING PORTS…", 400)
        checking_width = pill.width()
        assert checking_width > short_width
        assert label.text() == "CHECKING PORTS…"
        assert checking_width == label.width() + 42

        long_status = "CONNECTED · 123/123 TOR INSTANCES READY"
        pill.set_status_text(label, long_status, 140)
        assert pill.width() <= 140
        assert label.text() != long_status
        assert label.toolTip() == long_status
    finally:
        pill.close()
        pill.deleteLater()
        qt_app.processEvents()


def test_connection_status_pill_renders_over_its_parent_background(qt_app):
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor, QPalette
    from PySide6.QtWidgets import QWidget
    from ui_.window.proxy_window import ConnectionStatusPill

    parent = QWidget()
    parent_color = QColor("#314159")
    palette = parent.palette()
    palette.setColor(QPalette.ColorRole.Window, parent_color)
    parent.setPalette(palette)
    parent.setStyleSheet("background-color: #314159;")
    parent.setAutoFillBackground(True)

    pill = ConnectionStatusPill(parent)
    try:
        parent.resize(260, 58)
        pill.setGeometry(10, 10, 240, 38)
        pill.set_theme_mode("dark")
        pill.set_connection_state("connected")
        parent.show()
        qt_app.processEvents()

        image = parent.grab().toImage()
        # The capsule is visible in its centre, but its outer corner pixels
        # show the actual parent surface rather than a black rectangle.
        assert image.pixelColor(130, 29) != parent_color
        # The parent background is inherited by the custom-painted child;
        # the transparent QSS surface must not replace it with a palette fill.
        assert image.pixelColor(10, 10) == parent_color
        assert image.pixelColor(11, 11) == parent_color
        assert not pill.testAttribute(
            Qt.WidgetAttribute.WA_StyledBackground
        )
        assert pill.testAttribute(
            Qt.WidgetAttribute.WA_TranslucentBackground
        )
        assert pill.testAttribute(
            Qt.WidgetAttribute.WA_NoSystemBackground
        )
    finally:
        parent.close()
        parent.deleteLater()
        qt_app.processEvents()


def test_pulse_button_can_shrink_without_losing_its_animation_geometry(qt_app):
    from ui_.btn.pulse_button import PulseButton

    button = PulseButton()
    try:
        assert button.size().width() == 264
        button.set_diameter(144)
        assert button.size().width() == 144
        assert button.size().height() == 144
        assert button.diameter == 144
        button.set_diameter(480)
        assert button.diameter == 420
        button.set_diameter(70)
        assert button.diameter == 96
    finally:
        button.close()
        button.deleteLater()
        qt_app.processEvents()



def test_home_keeps_status_at_top_with_a_minimum_gap_and_polishes_bottom_actions():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/proxy_window.py").read_text(encoding="utf-8")

    status_index = source.index(
        'self.home_layout.addWidget('
        + '\n            self.connection_status_frame, 0, Qt.AlignmentFlag.AlignHCenter'
    )
    connect_host_index = source.index("self.home_layout.addWidget(self._home_connect_host, 1)", status_index)
    metrics_index = source.index("self.home_layout.addWidget(metrics_panel)", connect_host_index)
    assert status_index < connect_host_index < metrics_index
    status_setup = source[source.index('self.btn_status = QLabel'):status_index]
    assert "self.home_layout.addStretch(1)" not in status_setup
    assert "Keep the connection status anchored at the top of Home." in status_setup

    assert "utility_row.setSpacing(10)" in source
    assert "button.setMinimumHeight(42)" in source
    assert "button.setMaximumHeight(48)" in source

    assert 'utility_row.addWidget(self.btn_change_identity, 1)' in source
    assert 'utility_row.addWidget(self.btn_log, 1)' in source
    assert 'utility_row.addWidget(self.btn_whatismyip, 1)' in source
    assert 'utility_row.addWidget(self.btn_open_browser, 1)' in source
    assert 'self.btn_log.setIcon(qta.icon("fa6s.list-ul", color=icon_color))' in source
    assert 'qta.icon("fa6s.arrow-up-right-from-square", color=icon_color)' in source
    assert "button.setIconSize(QSize(14, 14) if compact else QSize(16, 16))" in source
    assert "QPushButton#secondaryAction:hover" in source
    assert "QPushButton#secondaryAction:pressed" in source
    assert "QPushButton#secondaryAction:checked" in source
    assert "QPushButton#secondaryAction:disabled" in source



def test_window_system_menu_native_shortcuts_and_caption_right_click_are_routed_to_qt():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")

    assert "_WM_SYSKEYDOWN = 0x0104" in source
    assert "_WM_NCRBUTTONUP = 0x00A5" in source
    assert "_WM_SYSCOMMAND = 0x0112" in source
    assert "native_message.message == _WM_NCRBUTTONUP" in source
    assert "native_message.message == _WM_SYSKEYDOWN" in source
    assert "native_message.message == _WM_SYSCOMMAND" in source
    assert "self._queue_window_system_menu(keyboard=True)" in source
    assert "self._queue_window_system_menu(QCursor.pos())" in source
    assert "menu.popup(position)" in source


def test_window_system_menu_actions_follow_maximized_and_minimized_state():
    import ui

    class _Action:
        def __init__(self):
            self.enabled = None

        def setEnabled(self, enabled):
            self.enabled = enabled

    fake = SimpleNamespace(
        window_system_actions={key: _Action() for key in (
            "restore", "move", "size", "minimize", "maximize", "close"
        )},
        isMaximized=lambda: False,
        isMinimized=lambda: False,
    )
    ui.Window._sync_window_system_menu_actions(fake)
    assert {key: action.enabled for key, action in fake.window_system_actions.items()} == {
        "restore": False,
        "move": True,
        "size": True,
        "minimize": True,
        "maximize": True,
        "close": True,
    }

    fake.isMaximized = lambda: True
    ui.Window._sync_window_system_menu_actions(fake)
    assert {key: action.enabled for key, action in fake.window_system_actions.items()} == {
        "restore": True,
        "move": False,
        "size": False,
        "minimize": True,
        "maximize": False,
        "close": True,
    }

    fake.isMaximized = lambda: False
    fake.isMinimized = lambda: True
    ui.Window._sync_window_system_menu_actions(fake)
    assert fake.window_system_actions["restore"].enabled is True
    assert fake.window_system_actions["move"].enabled is False
    assert fake.window_system_actions["size"].enabled is False
    assert fake.window_system_actions["minimize"].enabled is False
    assert fake.window_system_actions["maximize"].enabled is False
    assert fake.window_system_actions["close"].enabled is True


def test_window_system_menu_uses_current_dark_and_light_palette(monkeypatch):
    import ui

    styles = []
    icons = []

    class _Menu:
        def setStyleSheet(self, stylesheet):
            styles.append(stylesheet)

    class _Action:
        def setIcon(self, icon):
            icons.append(icon)

    fake = SimpleNamespace(
        window_system_menu=_Menu(),
        window_system_actions={key: _Action() for key in (
            "restore", "move", "size", "minimize", "maximize", "close"
        )},
    )
    monkeypatch.setattr(ui.qta, "icon", lambda name, color: (name, color))

    ui.Window._sync_window_system_menu_theme(fake, "dark")
    assert "background-color: #171e29;" in styles[-1]
    assert "border: 1px solid #303b4c;" in styles[-1]
    assert "background-color: #29384d;" in styles[-1]
    assert ("fa6s.xmark", "#ef7777") in icons

    ui.Window._sync_window_system_menu_theme(fake, "light")
    assert "background-color: #ffffff;" in styles[-1]
    assert "border: 1px solid #dfe6ef;" in styles[-1]
    assert "background-color: #edf3fb;" in styles[-1]
    assert ("fa6s.xmark", "#c94343") in icons



def test_window_system_menu_does_not_call_unsupported_qmenu_icon_size_api():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")
    start = source.index("def _create_window_system_menu(self):")
    end = source.index("def _sync_window_system_menu_actions(self):", start)
    construction = source[start:end]

    # QMenu has no setIconSize() in PySide6. Per-action icons already carry
    # their own artwork and the menu uses the application style for sizing.
    assert "window_system_menu.setIconSize(" not in construction
    assert "self.window_system_menu.setSeparatorsCollapsible(False)" in construction
    assert "action.setIcon(qta.icon(icon_name, color=color))" in source

def test_window_system_menu_close_matches_alt_f4_and_uses_confirmed_exit():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")
    construction = source[
        source.index("def _create_window_system_menu(self):"):
        source.index("def _sync_window_system_menu_actions(self):")
    ]
    assert 'close_action = QAction("Close", self)' in construction
    assert 'close_action.setShortcut(QKeySequence("Alt+F4"))' in construction
    assert "close_action.setShortcutContext(Qt.ShortcutContext.WindowShortcut)" in construction
    assert "self.addAction(close_action)" in construction
    assert "close_action.triggered.connect(self._request_exit)" in construction
    assert 'self.window_system_actions["close"].triggered.connect(self.close)' not in construction

    assert "_SC_CLOSE = 0xF060" in source
    native_event = source[
        source.index("def nativeEvent(self, event_type, message):"):
        source.index("def ", source.index("def nativeEvent(self, event_type, message):") + 5)
    ]
    assert "system_command == _SC_CLOSE" in native_event
    assert "self._request_exit()" in native_event


def test_exit_requests_are_deferred_and_coalesced(monkeypatch):
    import ui

    scheduled = []
    calls = []

    def ask_close():
        calls.append("exit")
        # A duplicate Alt+F4/native SC_CLOSE arriving during the modal
        # confirmation must not open a second confirmation dialog.
        ui.Window._request_exit(fake)

    fake = SimpleNamespace(
        _exit_request_pending=False,
        _exit_request_in_progress=False,
        _exit_authorized=False,
        _shutdown_in_progress=False,
        _shutdown_complete=False,
        ask_close=ask_close,
    )
    fake._dispatch_exit_request = lambda: ui.Window._dispatch_exit_request(fake)
    monkeypatch.setattr(ui.QTimer, "singleShot", lambda delay, callback: scheduled.append(callback))

    ui.Window._request_exit(fake)
    ui.Window._request_exit(fake)
    assert len(scheduled) == 1
    assert fake._exit_request_pending is True

    scheduled.pop(0)()
    assert calls == ["exit"]
    assert scheduled == []
    assert fake._exit_request_pending is False
    assert fake._exit_request_in_progress is False


def test_custom_titlebar_window_controls_fill_right_edge_without_gaps(qt_app):
    from PySide6.QtCore import QPoint, QRect
    from PySide6.QtWidgets import QMainWindow
    from ui import (
        _HTCAPTION,
        _HTCLIENT,
        _HTMAXBUTTON,
        _HTRIGHT,
        _HTTOPRIGHT,
        _native_resize_hit_test,
        _native_titlebar_hit_test,
    )
    from ui_.window.custom_titlebar import CustomTitleBar

    class _TitleBarHost(QMainWindow):
        def hide_to_tray(self):
            self.hide()

    parent = _TitleBarHost()
    titlebar = CustomTitleBar(parent)
    try:
        titlebar.resize(900, 40)
        titlebar.show()
        titlebar.layout().activate()
        qt_app.processEvents()

        controls = titlebar.window_controls
        controls.layout().activate()
        qt_app.processEvents()
        buttons = (titlebar.btn_min, titlebar.btn_max, titlebar.btn_close)
        assert controls.geometry() == QRect(900 - 3 * 46, 0, 3 * 46, 40)
        assert controls.layout().getContentsMargins() == (0, 0, 0, 0)
        assert controls.layout().spacing() == 0
        assert titlebar.layout().getContentsMargins() == (12, 0, 0, 0)

        for button in buttons:
            assert button.height() == titlebar.height() == 40
            assert button.y() == 0
            assert button.width() == 46

        assert buttons[0].x() == 0
        assert buttons[1].x() == buttons[0].geometry().right() + 1
        assert buttons[2].x() == buttons[1].geometry().right() + 1
        assert buttons[-1].geometry().right() == controls.rect().right()
        assert controls.geometry().right() == titlebar.rect().right()

        def in_titlebar(button):
            return QRect(button.mapTo(titlebar, QPoint(0, 0)), button.size())

        minimize_rect, maximize_rect, close_rect = map(in_titlebar, buttons)
        other_buttons = (minimize_rect, close_rect)
        assert _native_titlebar_hit_test(
            maximize_rect.center(), titlebar.rect(), maximize_rect, other_buttons
        ) == _HTMAXBUTTON
        assert _native_titlebar_hit_test(
            close_rect.center(), titlebar.rect(), maximize_rect, other_buttons
        ) == _HTCLIENT
        assert _native_titlebar_hit_test(
            QPoint(150, 20), titlebar.rect(), maximize_rect, other_buttons
        ) == _HTCAPTION

        # Buttons visually occupy the outer corners, but Windows keeps the
        # narrow native frame strip available for resizing before button hit tests.
        assert close_rect.contains(QPoint(898, 2))
        frame_rect = QRect(0, 0, titlebar.width(), titlebar.height())
        assert _native_resize_hit_test(QPoint(898, 2), frame_rect) == _HTTOPRIGHT
        assert _native_resize_hit_test(QPoint(898, 20), frame_rect) == _HTRIGHT
    finally:
        titlebar.close()
        parent.close()
        titlebar.deleteLater()
        parent.deleteLater()
        qt_app.processEvents()


def test_custom_titlebar_controls_use_square_edges_and_full_strip_dimensions():
    repository = Path(__file__).resolve().parents[1]
    titlebar = (repository / "ui_/window/custom_titlebar.py").read_text(encoding="utf-8")
    ui_source = (repository / "ui.py").read_text(encoding="utf-8")
    assert "_TITLE_BAR_HEIGHT = 40" in titlebar
    assert "_WINDOW_CONTROL_BUTTON_WIDTH = 46" in titlebar
    assert "button.setFixedSize(_WINDOW_CONTROL_BUTTON_WIDTH, _TITLE_BAR_HEIGHT)" in titlebar
    assert "self.window_controls_layout.setContentsMargins(0, 0, 0, 0)" in titlebar
    assert "self.window_controls_layout.setSpacing(0)" in titlebar
    assert "layout.setContentsMargins(12, 0, 0, 0)" in titlebar
    assert "QWidget#titleBarWindowControls" in ui_source
    assert "border-radius: 0px;" in ui_source
    assert "QPushButton#titleBarCloseButton:pressed" in ui_source

def test_system_move_positions_pointer_at_titlebar_center_before_posting(monkeypatch):
    from PySide6.QtCore import QPoint, QRect

    import ui

    events = []

    class _NativeFunction:
        def __init__(self, callback):
            self.callback = callback
            self.argtypes = None
            self.restype = None

        def __call__(self, *args):
            return self.callback(*args)

    class _TitleBar:
        def rect(self):
                return QRect(0, 0, 900, 40)

        def mapToGlobal(self, point):
            from PySide6.QtCore import QPoint
            return QPoint(120, 240) + point

    fake_user32 = SimpleNamespace(
        PostMessageW=_NativeFunction(
            lambda *_args: events.append(("post", *_args[1:])) or 1
        )
    )
    fake = SimpleNamespace(
        _native_snap_hwnd=1234,
        _native_user32=fake_user32,
        title_bar=_TitleBar(),
        winId=lambda: 1234,
    )
    monkeypatch.setattr(ui, "IS_WINDOWS", True)
    monkeypatch.setattr(
        ui,
        "QCursor",
        SimpleNamespace(setPos=lambda point: events.append(("cursor", point))),
    )

    ui.Window._post_native_system_command(fake, ui._SC_MOVE)

    assert len(events) == 2
    assert events[0][0] == "cursor"
    expected_center = QPoint(120, 240) + QRect(0, 0, 900, 40).center()
    assert events[0][1] == expected_center
    assert events[1][0] == "post"
    assert events[1][1].value == ui._WM_SYSCOMMAND
    assert events[1][2].value == ui._SC_MOVE


def test_system_size_command_does_not_reposition_pointer(monkeypatch):
    import ui

    posted = []

    class _NativeFunction:
        def __init__(self):
            self.argtypes = None
            self.restype = None

        def __call__(self, *args):
            posted.append(args)
            return 1

    fake = SimpleNamespace(
        _native_snap_hwnd=1234,
        _native_user32=SimpleNamespace(PostMessageW=_NativeFunction()),
        title_bar=object(),
        winId=lambda: 1234,
    )
    monkeypatch.setattr(ui, "IS_WINDOWS", True)
    monkeypatch.setattr(
        ui,
        "QCursor",
        SimpleNamespace(setPos=lambda _point: pytest.fail("Size must not move the cursor")),
    )

    ui.Window._post_native_system_command(fake, ui._SC_SIZE)
    assert len(posted) == 1
    assert posted[0][2].value == ui._SC_SIZE

def test_page_theme_is_applied_only_when_its_cached_mode_is_stale():
    import ui

    applied = []
    page = SimpleNamespace(
        _torproxy_theme_mode="dark",
        apply_theme=lambda mode: applied.append(mode),
    )

    owner = SimpleNamespace()
    assert ui.Window._ensure_page_theme(owner, page, "dark") is False
    assert applied == []

    assert ui.Window._ensure_page_theme(owner, page, "light") is True
    assert applied == ["light"]
    assert page._torproxy_theme_mode == "light"
    assert ui.Window._ensure_page_theme(owner, page, "light") is False
    assert applied == ["light"]


def test_theme_switch_profiles_sync_stages_and_updates_only_visible_local_pages():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui.py").read_text(encoding="utf-8")
    start = source.index("def _set_theme(self, mode, *, preference=None):")
    end = source.index("def _set_theme_preference", start)
    theme_switch = source[start:end]

    assert "snapshot_ms" in theme_switch
    assert "app_stylesheet_ms" in theme_switch
    assert "local_styles_ms" in theme_switch
    assert "logger.info(" in theme_switch
    assert "new_snapshot" not in theme_switch
    assert "visible_only=True" in theme_switch

