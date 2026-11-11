from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QWidget,
    QButtonGroup,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QCheckBox,
    QComboBox,
    QTextEdit,
    QLineEdit,
    QStackedWidget,
    QListWidget,
    QFrame,
    QScrollArea,
    QProgressBar
)
from PySide6.QtCore import Qt, QThreadPool, QTimer
from PySide6.QtGui import QColor, QPalette
import qtawesome as qta

import qdarkstyle
from qdarkstyle.dark.palette import DarkPalette
from qdarkstyle.light.palette import LightPalette

import logging
from functools import partial

logger = logging.getLogger(__name__)

from config import CONFIG
from torproxy.bridges import (
    SUPPORTED_BRIDGE_TRANSPORTS,
    bridge_identity_fingerprint,
    normalize_sni_hostname,
    parse_bridge_text,
)
from ui_.window.dialogs import QMessageBox
from ui_.worker.worker import Worker
from ui_.window.qrcode_widget import QrCodeFloatingWindow
from ui_.window.theme import resolve_system_theme
from ui_.window.tor_services_page import TorServicesSettingsPage
from ui_.emojis import WRONG, CORRECT

class _BridgeTextEdit(QTextEdit):
    """Text editor that formats valid pasted bridge records immediately."""

    def insertFromMimeData(self, source):
        pasted = source.text() if source is not None else ""
        parsed = parse_bridge_text(pasted)
        if parsed.records and not parsed.invalid_records:
            # A bridge is stored as one canonical record per line regardless of
            # whether the clipboard had newlines or joined records with spaces.
            self.insertPlainText("\n".join(parsed.records))
            return
        super().insertFromMimeData(source)


class SettingWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._parent = parent
        self._tunnel_recovery_pool = QThreadPool(self)
        self._tunnel_recovery_worker = None
        self._tunnel_recovery_busy = False
        self._http_proxy_toggle_pending = False
        self._http_proxy_toggle_previous = bool(CONFIG["http_proxy_enabled"])
        self._http_proxy_test_busy = False
        self._http_proxy_test_worker = None
        self._http_proxy_test_pool = QThreadPool(self)
        self._http_proxy_test_pool.setMaxThreadCount(1)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 8, 10, 8)
        main_layout.setSpacing(8)

        navigation = QHBoxLayout()
        navigation.setContentsMargins(0, 0, 0, 2)
        navigation.setSpacing(6)
        self.settings_nav_group = QButtonGroup(self)
        self.settings_nav_group.setExclusive(True)
        self.settings_nav_buttons = []
        self.settings_nav_icon_names = (
            "fa6s.sliders",
            "fa6s.link",
            "fa6s.network-wired",
            "fa6s.server",
            "fa6s.shield-halved",
        )
        for index, (title, icon_name) in enumerate(zip(
            ("General", "Bridges", "Ports", "Custom Tor", "Advanced"), self.settings_nav_icon_names
        )):
            button = QPushButton(title, self)
            button.setObjectName("settingsNavButton")
            button.setIcon(qta.icon(icon_name, color="#eff1f4" if CONFIG["mode"] == "dark" else "#202832"))
            button.setMinimumHeight(38)
            button.setToolTip(title)
            button.setCheckable(True)
            button.clicked.connect(lambda _checked=False, page=index: self._set_settings_page(page))
            self.settings_nav_group.addButton(button, index)
            navigation.addWidget(button)
            self.settings_nav_buttons.append(button)
        navigation.addStretch(1)
        main_layout.addLayout(navigation)

        self.page_setting = QStackedWidget(self)
        self.page_setting.setObjectName("settingsPages")
        main_layout.addWidget(self.page_setting, 1)
        self.first_page, self.first_page_layout = self._create_scroll_page()
        self.bridges_page, self.bridges_page_layout = self._create_scroll_page()
        self.second_page, self.second_page_layout = self._create_scroll_page()
        self.services_page, self.services_page_layout = self._create_scroll_page()
        self.advanced_page, self.advanced_page_layout = self._create_scroll_page()
        self.settings_nav_buttons[0].setChecked(True)
        initial_bridges = parse_bridge_text(str(CONFIG["bridges"] or ""))
        self._saved_bridge_records = initial_bridges.records
        self._bridge_input_invalid = False
        self._bridge_normalizing = False
        self._bridge_usage_enabled = bool(CONFIG["bridge"])
        self._bridge_tor_ready = False
        self._active_bridge_fingerprints: set[str] = set()
        self._bridge_status_labels = {}
        try:
            tor_runner = self._parent.proxyWidget.tor
            tor_runner.bridge_usage_changed.connect(self.update_bridge_usage)
            self.update_bridge_usage({
                "enabled": bool(tor_runner.bridge),
                "ready": str(tor_runner.state).upper() == "READY",
                "active_fingerprints": (),
            })
        except (AttributeError, RuntimeError):
            logger.debug("Live bridge status is not available yet.", exc_info=True)
        self._bridge_normalize_timer = QTimer(self)
        self._bridge_normalize_timer.setSingleShot(True)
        self._bridge_normalize_timer.setInterval(650)
        self._bridge_normalize_timer.timeout.connect(self._canonicalize_bridge_editor)

        self.initialize_first_page()
        self.initialize_bridges_page()
        self.initialize_second_page()
        self.initialize_tor_services_page()
        self.initialize_advanced_page()
        self.apply_theme(CONFIG["mode"])
        self.set_bridges()

    def _create_scroll_page(self):
        content = QWidget()
        content.setObjectName("settingsPageContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(14, 10, 14, 12)
        layout.setSpacing(10)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        scroll = QScrollArea(self.page_setting)
        scroll.setObjectName("settingsScrollArea")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(content)
        self.page_setting.addWidget(scroll)
        return scroll, layout

    def _set_settings_page(self, index):
        if not 0 <= index < self.page_setting.count():
            return
        self.page_setting.setCurrentIndex(index)
        if index == 2 and hasattr(self, "chk_http_proxy_enabled"):
            self._refresh_http_proxy_status()
        for page_index, button in enumerate(self.settings_nav_buttons):
            button.setChecked(page_index == index)
        self._sync_settings_nav_icons()
        if index == 3 and hasattr(self, "tor_services_panel"):
            refresh = getattr(self.tor_services_panel, "refresh_health", None)
            if callable(refresh):
                refresh()

    def _sync_settings_nav_icons(self, mode=None):
        """Keep every Settings navigation icon in sync with its label state."""
        dark = (mode or CONFIG.get("mode", "dark")) == "dark"
        icon_color = "#f3f6fa" if dark else "#243143"
        for button, icon_name in zip(self.settings_nav_buttons, self.settings_nav_icon_names):
            color = "#ffffff" if button.isChecked() else icon_color
            button.setIcon(qta.icon(icon_name, color=color))

    def apply_theme(self, mode):
        dark = mode == "dark"
        border = "#3b4552" if dark else "#d9e0e8"
        accent = "#287db5"
        hover = "rgba(71, 163, 242, 0.14)" if dark else "rgba(24, 118, 191, 0.08)"
        icon_color = "#f3f6fa" if dark else "#243143"
        panel = "#202630" if dark else "#ffffff"
        field = "#171c23" if dark else "#f8fafc"
        text = "#f0f3f7" if dark else "#263344"
        muted = "#aab5c4" if dark else "#667487"
        placeholder = "#8996a8" if dark else "#7b8797"
        disabled = "#768294" if dark else "#9aa5b2"
        self.setStyleSheet(f"""
            QWidget#settingsPageContent {{ background: transparent; }}
            QLabel {{ color: {text}; background: transparent; border: none; }}
            QLabel#settingsSectionTitle {{ font-size: 14px; font-weight: 750; color: {text}; padding: 1px 0; }}
            QLabel#settingsDescription {{ color: {muted}; font-size: 11px; padding: 0; }}
            QLabel#settingsFieldLabel {{ color: {text}; font-weight: 650; }}
            QLabel#signatureVerificationDetails {{ color: {muted}; background: transparent; padding: 3px 0; }}
            QLabel#globalShortcutStatus {{ background: transparent; font-size: 10px; }}
            QLabel#bridgeInputStatus {{ color: {muted}; background: transparent; font-size: 10px; padding: 2px 1px; }}
            QLabel#bridgeCountLabel {{ color: {accent}; background: transparent; font-size: 10px; font-weight: 750; }}
            QLabel#bridgeEmptyState {{ color: {muted}; background: {panel}; border: 1px dashed {border}; border-radius: 8px; padding: 13px; font-size: 10px; }}
            QFrame#bridgeCard {{ background: {panel}; border: 1px solid {border}; border-radius: 9px; }}
            QFrame#bridgeCard:hover {{ border-color: {accent}; }}
            QFrame#torServiceCard {{ background: {panel}; border: 1px solid {border}; border-radius: 9px; }}
            QFrame#torServiceCard:hover {{ border-color: {accent}; }}
            QLabel#torServiceStatus {{ color: {muted}; background: {field}; border: 1px solid {border}; border-radius: 6px; padding: 3px 7px; font-size: 8px; font-weight: 800; }}
            QLabel#torServiceStatus[serviceState="ready"] {{ color: #31b981; border-color: rgba(49, 185, 129, 0.35); }}
            QLabel#torServiceStatus[serviceState="failed"] {{ color: #e36b75; border-color: rgba(227, 107, 117, 0.35); }}
            QLabel#bridgeTransportBadge {{ color: {accent}; background: {hover}; border: 1px solid {border}; border-radius: 5px; padding: 3px 7px; font-size: 8px; font-weight: 800; }}
            QLabel#bridgeEndpoint {{ color: {text}; background: transparent; font-family: Consolas, monospace; font-size: 10pt; font-weight: 700; }}
            QLabel#bridgeRecordOptions {{ color: {muted}; background: transparent; font-family: Consolas, monospace; font-size: 8pt; }}
            QLabel#bridgeUsageStatus {{ color: {muted}; background: transparent; font-size: 9px; font-weight: 600; padding-top: 2px; }}
            QLabel#bridgeUsageStatus[usageState="active"] {{ color: #31b981; font-weight: 800; }}
            QLabel#bridgeUsageStatus[usageState="waiting"] {{ color: {accent}; }}
            QLabel#bridgeUsageStatus[usageState="inactive"] {{ color: {muted}; }}
            QPushButton#bridgeCardAction, QPushButton#bridgeCardRemove {{ min-height: 30px; min-width: 32px; padding: 0; border: 1px solid {border}; border-radius: 7px; background: transparent; }}
            QPushButton#bridgeCardAction:hover {{ background: {hover}; border-color: {accent}; }}
            QPushButton#bridgeCardRemove:hover {{ background: rgba(227, 107, 117, 0.13); border-color: #e36b75; }}
            QPushButton#bridgeCardAction:disabled, QPushButton#bridgeCardRemove:disabled {{ color: {disabled}; background: transparent; }}
            QLabel#themeModeValue {{ color: {accent}; background: transparent; font-size: 10px; font-weight: 800; min-width: 82px; }}
            QWidget#themeModeSelector {{
                background: {field}; border: 1px solid {border};
                border-radius: 9px; padding: 2px;
            }}
            QPushButton#themeModeOption {{
                min-height: 29px; min-width: 58px; padding: 0 9px;
                color: {muted}; background: transparent; border: 1px solid transparent;
                border-radius: 7px; font-size: 9px; font-weight: 700;
            }}
            QPushButton#themeModeOption:hover {{
                color: {text}; background: {hover};
            }}
            QPushButton#themeModeOption:checked {{
                color: #ffffff; background: {accent}; border-color: {accent};
            }}
            QCheckBox#confirmExitPreference {{ color: {text}; background: transparent; spacing: 8px; font-weight: 650; }}
            QPushButton#settingsNavButton {{
                min-height: 34px; padding: 0 11px; spacing: 7px;
                border: 1px solid transparent; border-radius: 7px;
                background: transparent; color: {text}; font-weight: 650;
            }}
            QPushButton#settingsNavButton:hover {{ background: {hover}; border-color: {border}; }}
            QPushButton#settingsNavButton:checked {{
                background: {accent}; color: #ffffff; border-color: {accent}; font-weight: 750;
            }}
            QStackedWidget#settingsPages {{ border: none; background: transparent; }}
            QScrollArea#settingsScrollArea {{ background: transparent; border: none; }}
            QFrame#settingsRowCard {{
                background: transparent; border: none; border-bottom: 1px solid {border}; border-radius: 0;
            }}
            QLineEdit, QTextEdit {{
                background: {field}; color: {text};
                border: 1px solid {border}; border-radius: 7px; padding: 6px 9px;
                selection-background-color: {accent}; selection-color: #ffffff;
            }}
            QLineEdit:focus, QTextEdit:focus {{ border: 1px solid {accent}; }}
            QLineEdit:disabled, QTextEdit:disabled {{ color: {disabled}; background: {panel}; }}
            QPushButton#settingsActionButton {{
                min-height: 32px; padding: 0 11px; border: 1px solid {border};
                border-radius: 7px; background: transparent; color: {text}; font-weight: 650;
            }}
            QPushButton#settingsActionButton:hover {{ background: {hover}; border-color: {accent}; }}
            QCheckBox {{ spacing: 7px; color: {text}; background: transparent; }}
            QCheckBox:disabled {{ color: {disabled}; }}
        """)
        # Qt stylesheets don't expose a portable ::placeholder selector. Set the
        # placeholder palette role explicitly so both light and dark remain legible.
        for widget in self.findChildren(QLineEdit) + self.findChildren(QTextEdit):
            palette = widget.palette()
            palette.setColor(QPalette.ColorRole.Text, QColor(text))
            palette.setColor(QPalette.ColorRole.Base, QColor(field))
            palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(placeholder))
            palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(disabled))
            widget.setPalette(palette)
        self._sync_settings_nav_icons(mode)
        if hasattr(self, "btn_qrcode"):
            self.btn_qrcode.setIcon(qta.icon("fa6s.qrcode", color=icon_color))

    @staticmethod
    def _section_title(text):
        label = QLabel(text)
        label.setObjectName("settingsSectionTitle")
        return label

    @staticmethod
    def _description(text):
        label = QLabel(text)
        label.setObjectName("settingsDescription")
        label.setWordWrap(True)
        return label

    def initialize_first_page(self):
        self.first_page_layout.addWidget(self._section_title("Appearance"))
        self.first_page_layout.addWidget(
            self._description("Follow your operating system appearance, or choose a fixed light or dark theme.")
        )
        theme_row = QFrame(self)
        theme_row.setObjectName("settingsRowCard")
        mode_layout = QHBoxLayout(theme_row)
        mode_layout.setContentsMargins(14, 10, 14, 10)
        mode_layout.setSpacing(12)

        theme_copy = QVBoxLayout()
        theme_copy.setSpacing(3)
        theme_label = QLabel("Color theme")
        theme_label.setObjectName("settingsFieldLabel")
        theme_description = self._description("System follows your desktop setting and updates when it changes.")
        theme_copy.addWidget(theme_label)
        theme_copy.addWidget(theme_description)
        mode_layout.addLayout(theme_copy, 1)

        self.theme_mode_label = QLabel(self._theme_mode_status_text())
        self.theme_mode_label.setObjectName("themeModeValue")
        mode_layout.addWidget(self.theme_mode_label, 0, Qt.AlignmentFlag.AlignVCenter)

        self.theme_mode_selector = QWidget(theme_row)
        self.theme_mode_selector.setObjectName("themeModeSelector")
        selector_layout = QHBoxLayout(self.theme_mode_selector)
        selector_layout.setContentsMargins(2, 2, 2, 2)
        selector_layout.setSpacing(2)
        self.theme_mode_group = QButtonGroup(self)
        self.theme_mode_group.setExclusive(True)
        self.theme_mode_buttons = {}
        for preference, label in (("system", "System"), ("light", "Light"), ("dark", "Dark")):
            button = QPushButton(label, self.theme_mode_selector)
            button.setObjectName("themeModeOption")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setToolTip({
                "system": "Follow the operating system appearance",
                "light": "Always use the light theme",
                "dark": "Always use the dark theme",
            }[preference])
            button.clicked.connect(
                lambda _checked=False, selected=preference: self.change_mode(selected)
            )
            self.theme_mode_group.addButton(button)
            self.theme_mode_buttons[preference] = button
            selector_layout.addWidget(button)
        mode_layout.addWidget(self.theme_mode_selector, 0, Qt.AlignmentFlag.AlignVCenter)
        self._sync_theme_preference_controls()
        self.first_page_layout.addWidget(theme_row)

        exit_row = QFrame(self)
        exit_row.setObjectName("settingsRowCard")
        exit_layout = QHBoxLayout(exit_row)
        exit_layout.setContentsMargins(14, 10, 14, 10)
        exit_layout.setSpacing(12)
        exit_copy = QVBoxLayout()
        exit_copy.setSpacing(3)
        exit_title = QLabel("Exit confirmation")
        exit_title.setObjectName("settingsFieldLabel")
        exit_description = self._description(
            "Ask before shutting down TorProxy. This setting is saved and can be changed later."
        )
        exit_copy.addWidget(exit_title)
        exit_copy.addWidget(exit_description)
        exit_layout.addLayout(exit_copy, 1)
        self.chk_confirm_exit = QCheckBox("Ask before exit", self)
        self.chk_confirm_exit.setObjectName("confirmExitPreference")
        self.chk_confirm_exit.setChecked(bool(CONFIG["confirm_exit"]))
        self.chk_confirm_exit.toggled.connect(self._set_confirm_exit_preference)
        exit_layout.addWidget(self.chk_confirm_exit, 0, Qt.AlignmentFlag.AlignVCenter)
        self.first_page_layout.addWidget(exit_row)

        self.first_page_layout.addWidget(self._section_title("Circuit behavior"))
        self.first_page_layout.addWidget(
            self._description("These values are used when Tor starts. Changing them while connected applies them on the next connection.")
        )

        max_row = QFrame(self)
        max_row.setObjectName("settingsRowCard")
        max_circuit_dirtiness_layout = QHBoxLayout(max_row)
        max_circuit_dirtiness_layout.setContentsMargins(14, 10, 14, 10)
        max_circuit_dirtiness_layout.addWidget(QLabel("Max circuit dirtiness (seconds)"))
        self.first_page_layout.addWidget(max_row)

        # read from parent.tor if available, else from CONFIG or fallback
        try:
            start_val = getattr(self._parent.proxyWidget.tor, "MaxCircuitDirtiness")
            if start_val is None:
                start_val = CONFIG["MaxCircuitDirtiness"] or 10
        except Exception:
            start_val = CONFIG["MaxCircuitDirtiness"] or 10

        self.inp_MaxCircuitDirtiness = QLineEdit(str(start_val))
        self.inp_MaxCircuitDirtiness.setPlaceholderText("10–86400 seconds")
        self.inp_MaxCircuitDirtiness.setMaximumWidth(180)
        self.inp_MaxCircuitDirtiness.setToolTip("How long a circuit may be reused before Tor considers building another one.")
        max_circuit_dirtiness_layout.addWidget(self.inp_MaxCircuitDirtiness)
        self.inp_MaxCircuitDirtiness.textChanged.connect(self.MaxCircuitDirtiness_changed)
        self.lbl_MaxCircuitDirtiness = QLabel(CORRECT)
        max_circuit_dirtiness_layout.addWidget(self.lbl_MaxCircuitDirtiness)

        new_period_row = QFrame(self)
        new_period_row.setObjectName("settingsRowCard")
        new_period_layout = QHBoxLayout(new_period_row)
        new_period_layout.setContentsMargins(14, 10, 14, 10)
        new_period_layout.addWidget(QLabel("New circuit period (seconds)"))
        self.inp_NewCircuitPeriod = QLineEdit(str(CONFIG["NewCircuitPeriod"]))
        self.inp_NewCircuitPeriod.setPlaceholderText("10–86400 seconds")
        self.inp_NewCircuitPeriod.setMaximumWidth(180)
        self.inp_NewCircuitPeriod.setToolTip("Tor's circuit-building interval; this does not automatically request NEWNYM.")
        new_period_layout.addWidget(self.inp_NewCircuitPeriod)
        self.lbl_NewCircuitPeriod = QLabel(CORRECT)
        new_period_layout.addWidget(self.lbl_NewCircuitPeriod)
        self.first_page_layout.addWidget(new_period_row)
        self.inp_NewCircuitPeriod.textChanged.connect(self.NewCircuitPeriod_changed)

        # Automatic identity rotation is intentionally disabled by default.
        identity_note = QLabel(
            "Identity changes remain manual. Tor rate-limits NEWNYM; requesting it does not guarantee a new exit IP."
        )
        identity_note.setObjectName("settingsDescription")
        identity_note.setWordWrap(True)
        self.first_page_layout.addWidget(identity_note)

    def initialize_bridges_page(self):
        self.bridges_page_layout.addWidget(self._section_title("Bridge configuration"))
        description = self._description(
            "Paste complete Tor bridge records below. TorProxy detects adjacent records, fixes spacing, and stores one bridge per line. "
            "Each saved bridge appears as its own card so you can copy or remove it separately."
        )
        self.bridges_page_layout.addWidget(description)

        sni_row = QFrame(self)
        sni_row.setObjectName("settingsRowCard")
        sni_layout = QVBoxLayout(sni_row)
        sni_layout.setContentsMargins(14, 10, 14, 10)
        sni_layout.setSpacing(6)
        sni_title = QLabel("WebTunnel SNI imitation (optional)", sni_row)
        sni_title.setObjectName("settingsFieldLabel")
        sni_layout.addWidget(sni_title)
        self.cmb_webtunnel_sni = QComboBox(sni_row)
        self.cmb_webtunnel_sni.setObjectName("webtunnelSniInput")
        self.cmb_webtunnel_sni.setEditable(True)
        self.cmb_webtunnel_sni.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.cmb_webtunnel_sni.setToolTip(
            "No override is sent by default. Select a suggested hostname or enter your own DNS hostname. "
            "This adds sni-imitation= to WebTunnel bridge lines in torrc; it does not change the original url= host."
        )
        self.cmb_webtunnel_sni.addItem("Use the hostname in url= (default; no override)", "")
        for hostname in (
            "www.google.com",
            "www.microsoft.com",
            "www.cloudflare.com",
            "www.wikipedia.org",
            "www.apple.com",
        ):
            self.cmb_webtunnel_sni.addItem(hostname, hostname)
        saved_sni = normalize_sni_hostname(str(CONFIG["webtunnel_sni_imitation"] or ""))
        if saved_sni:
            selected_sni_index = self.cmb_webtunnel_sni.findData(saved_sni)
            if selected_sni_index >= 0:
                self.cmb_webtunnel_sni.setCurrentIndex(selected_sni_index)
            else:
                self.cmb_webtunnel_sni.setCurrentIndex(-1)
                self.cmb_webtunnel_sni.setEditText(saved_sni)
        else:
            self.cmb_webtunnel_sni.setCurrentIndex(0)
        self.cmb_webtunnel_sni.activated.connect(
            lambda _index: self.save_webtunnel_sni_imitation()
        )
        self.cmb_webtunnel_sni.lineEdit().editingFinished.connect(
            self.save_webtunnel_sni_imitation
        )
        sni_layout.addWidget(self.cmb_webtunnel_sni)
        sni_note = self._description(
            "Default: off — Lyrebird uses the hostname from each bridge's url=. Custom SNI is added as "
            "sni-imitation= only for WebTunnel bridges and applies on the next Tor start. Not every bridge or "
            "Lyrebird bundle supports SNI imitation; if it fails, return to the default option."
        )
        sni_layout.addWidget(sni_note)
        initial_sni_status = (
            f"Saved SNI override: {saved_sni}. Applies on the next Tor start."
            if saved_sni else
            "Default: no SNI override; Lyrebird uses each WebTunnel bridge's url= hostname."
        )
        self.webtunnel_sni_status = QLabel(initial_sni_status, sni_row)
        self.webtunnel_sni_status.setObjectName("bridgeInputStatus")
        self.webtunnel_sni_status.setWordWrap(True)
        sni_layout.addWidget(self.webtunnel_sni_status)
        self.bridges_page_layout.addWidget(sni_row)

        self.btn_bridge = QCheckBox("Use Tor bridges", self)
        self.btn_bridge.setChecked(bool(CONFIG["bridge"]))
        self.btn_bridge.stateChanged.connect(self.bridge_state_changed)
        self.bridges_page_layout.addWidget(self.btn_bridge)

        self.inp_bridges = _BridgeTextEdit(self, placeholderText=(
            "Paste bridge lines here…\nExample: obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=… iat-mode=0"
        ))
        self.inp_bridges.setObjectName("bridgeRecordsInput")
        self.inp_bridges.setMinimumHeight(104)
        self.inp_bridges.setText(CONFIG["bridges"] or "")
        self.inp_bridges.setEnabled(bool(CONFIG["bridge"]))
        self.inp_bridges.setToolTip(
            "Paste one or many bridges. Records can be separated by newlines or spaces; recognized bridge starts are separated automatically."
        )
        self.inp_bridges.textChanged.connect(self.set_bridges)
        self.bridges_page_layout.addWidget(self.inp_bridges)

        self.bridge_status_label = QLabel(self)
        self.bridge_status_label.setObjectName("bridgeInputStatus")
        self.bridge_status_label.setWordWrap(True)
        self.bridges_page_layout.addWidget(self.bridge_status_label)

        bridge_list_header = QHBoxLayout()
        bridge_list_title = QLabel("Saved bridge cards", self)
        bridge_list_title.setObjectName("settingsSectionTitle")
        bridge_list_header.addWidget(bridge_list_title)
        bridge_list_header.addStretch(1)
        self.bridge_count_label = QLabel("0 bridges", self)
        self.bridge_count_label.setObjectName("bridgeCountLabel")
        bridge_list_header.addWidget(self.bridge_count_label)
        self.bridges_page_layout.addLayout(bridge_list_header)

        self.bridge_cards_host = QWidget(self)
        self.bridge_cards_host.setObjectName("bridgeCardsHost")
        self.bridge_cards_layout = QVBoxLayout(self.bridge_cards_host)
        self.bridge_cards_layout.setContentsMargins(0, 0, 0, 0)
        self.bridge_cards_layout.setSpacing(7)
        self.bridges_page_layout.addWidget(self.bridge_cards_host)

        self.btn_qrcode = QPushButton("Import bridges from QR code")
        self.btn_qrcode.setObjectName("settingsActionButton")
        self.btn_qrcode.setIcon(qta.icon(
            "fa6s.qrcode", color="#eff1f4" if CONFIG["mode"] == "dark" else "#202832"
        ))
        self.btn_qrcode.clicked.connect(self.show_qrcode)
        self.bridges_page_layout.addWidget(self.btn_qrcode)

        self.chk_auto_prune_bridges = QCheckBox(
            "Automatically remove confirmed-unreachable bridges", self
        )
        self.chk_auto_prune_bridges.setObjectName("autoPruneBridgesPreference")
        self.chk_auto_prune_bridges.setToolTip(
            "Check bridges independently before connecting and recheck once if real Tor bootstrap times out. "
            "A refused connection or permanent hostname-resolution failure is endpoint-specific; timeouts, resets, "
            "and EOFs need repeated failed dial attempts. Cleanup requires another bridge to complete bootstrap. "
            "Generic SOCKS warnings, DNS-leak notices, missing-hop messages, TLS/SNI errors, and local network "
            "failures do not by themselves prove a bridge is dead."
        )
        self.chk_auto_prune_bridges.setChecked(bool(CONFIG["auto_prune_bridges"]))
        self.chk_auto_prune_bridges.setEnabled(bool(CONFIG["bridge"]))
        self.chk_auto_prune_bridges.toggled.connect(self.auto_prune_bridges_changed)
        self.bridges_page_layout.addWidget(self.chk_auto_prune_bridges)
        self.bridges_page_layout.addWidget(self._description(
            "OFF by default. When enabled, TorProxy checks multiple bridges independently before connecting, and may run one fresh "
            "check if the real Tor bootstrap times out. Startup can take longer. Only explicit per-bridge dial failures are eligible "
            "for removal, and only if at least one other bridge completes Tor bootstrap. Unsupported Lyrebird/TLS options, generic "
            "SOCKS errors, DNS-leak warnings, missing relay descriptors, and inconclusive results preserve the list. If every check "
            "fails or is uncertain, nothing is deleted and the list remains intact."
        ))
        self._refresh_bridge_cards(self._saved_bridge_records, removable=True)
        self.bridges_page_layout.addStretch(1)
        self.qrcode_widget = QrCodeFloatingWindow(self)
        self.threadpool = QThreadPool(self)

    def _refresh_bridge_cards(self, records, *, removable=True):
        """Render the saved bridge list as independent, copyable/removable cards."""
        while self.bridge_cards_layout.count():
            item = self.bridge_cards_layout.takeAt(0)
            widget = item.widget()
            nested = item.layout()
            if widget is not None:
                widget.deleteLater()
            elif nested is not None:
                while nested.count():
                    child = nested.takeAt(0)
                    if child.widget() is not None:
                        child.widget().deleteLater()

        records = tuple(records)
        self._bridge_status_labels = {}
        self.bridge_count_label.setText(f"{len(records)} bridge{'s' if len(records) != 1 else ''}")
        if not records:
            empty = QLabel(
                "No bridge addresses saved yet. Paste one or more complete bridge records above.",
                self.bridge_cards_host,
            )
            empty.setObjectName("bridgeEmptyState")
            empty.setWordWrap(True)
            self.bridge_cards_layout.addWidget(empty)
            return

        icon_color = "#e8edf3" if CONFIG["mode"] == "dark" else "#253041"
        for record in records:
            fields = record.split()
            has_transport = bool(fields and fields[0].casefold() in SUPPORTED_BRIDGE_TRANSPORTS)
            transport = fields[0] if has_transport else "direct"
            address_index = 1 if has_transport else 0
            address = fields[address_index] if len(fields) > address_index else "Address unavailable"
            options = " ".join(fields[address_index + 1:]) if len(fields) > address_index + 1 else ""

            card = QFrame(self.bridge_cards_host)
            card.setObjectName("bridgeCard")
            card_layout = QHBoxLayout(card)
            card_layout.setContentsMargins(11, 9, 9, 9)
            card_layout.setSpacing(10)

            detail = QVBoxLayout()
            detail.setContentsMargins(0, 0, 0, 0)
            detail.setSpacing(4)
            transport_badge = QLabel(transport.upper(), card)
            transport_badge.setObjectName("bridgeTransportBadge")
            transport_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            transport_badge.setMaximumWidth(112)
            detail.addWidget(transport_badge, 0, Qt.AlignmentFlag.AlignLeft)

            address_label = QLabel(address, card)
            address_label.setObjectName("bridgeEndpoint")
            address_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            address_label.setWordWrap(True)
            detail.addWidget(address_label)
            if options:
                options_label = QLabel(options, card)
                options_label.setObjectName("bridgeRecordOptions")
                options_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                options_label.setWordWrap(True)
                detail.addWidget(options_label)

            usage_label = QLabel(card)
            usage_label.setObjectName("bridgeUsageStatus")
            usage_label.setWordWrap(True)
            self._bridge_status_labels[record] = usage_label
            detail.addWidget(usage_label)
            card_layout.addLayout(detail, 1)

            copy_button = QPushButton(card)
            copy_button.setObjectName("bridgeCardAction")
            copy_button.setIcon(qta.icon("fa6s.copy", color=icon_color))
            copy_button.setToolTip("Copy full bridge record")
            copy_button.setAccessibleName("Copy bridge record")
            copy_button.setFixedSize(34, 32)
            copy_button.clicked.connect(partial(self.copy_bridge_record, record))
            card_layout.addWidget(copy_button, 0, Qt.AlignmentFlag.AlignVCenter)

            remove_button = QPushButton(card)
            remove_button.setObjectName("bridgeCardRemove")
            remove_button.setIcon(qta.icon("fa6s.trash-can", color="#e36b75"))
            remove_button.setToolTip("Remove this bridge")
            remove_button.setAccessibleName(f"Remove {transport} bridge {address}")
            remove_button.setFixedSize(34, 32)
            remove_button.setEnabled(bool(removable))
            remove_button.clicked.connect(partial(self.remove_bridge_record, record))
            card_layout.addWidget(remove_button, 0, Qt.AlignmentFlag.AlignVCenter)
            self.bridge_cards_layout.addWidget(card)

        self._update_bridge_card_statuses()

    def update_bridge_usage(self, payload):
        """Apply live, ControlPort-derived bridge usage without rebuilding cards."""
        if not isinstance(payload, dict):
            return
        self._bridge_usage_enabled = bool(payload.get("enabled", False))
        self._bridge_tor_ready = bool(payload.get("ready", False))
        fingerprints = payload.get("active_fingerprints", ()) or ()
        self._active_bridge_fingerprints = {
            str(value).upper()
            for value in fingerprints
            if isinstance(value, str)
        }
        self._update_bridge_card_statuses()

    def _update_bridge_card_statuses(self):
        if not hasattr(self, "_bridge_status_labels"):
            return
        for record, label in tuple(self._bridge_status_labels.items()):
            state = "inactive"
            if not self._bridge_usage_enabled:
                message = "Bridge mode is off"
            elif not self._bridge_tor_ready:
                message = "Waiting for Tor's verified connection"
                state = "waiting"
            else:
                try:
                    fingerprint = bridge_identity_fingerprint(record)
                except (TypeError, ValueError):
                    fingerprint = None
                if fingerprint and fingerprint in self._active_bridge_fingerprints:
                    message = "✓ Connected · observed as the first hop of a built circuit"
                    state = "active"
                elif not fingerprint:
                    message = "Tor is ready · this record has no matchable relay identity"
                    state = "waiting"
                elif self._active_bridge_fingerprints:
                    message = "Configured · not observed in a currently built circuit"
                else:
                    message = "Tor is ready · active bridge not yet identified"
                    state = "waiting"
            label.setText(message)
            label.setProperty("usageState", state)
            label.style().unpolish(label)
            label.style().polish(label)

    def copy_bridge_record(self, record):
        QApplication.clipboard().setText(str(record))
        if hasattr(self, "bridge_status_label"):
            self.bridge_status_label.setText("Copied one complete bridge record to the clipboard.")

    def remove_bridge_record(self, record):
        current_text = self.inp_bridges.toPlainText()
        parsed = parse_bridge_text(current_text)
        if parsed.invalid_records:
            self.bridge_status_label.setText(
                "Fix the incomplete or unsupported text above before removing saved bridge cards. "
                "Your last valid saved list is still preserved."
            )
            return
        remaining = list(parsed.records)
        try:
            remaining.remove(record)
        except ValueError:
            return
        self.inp_bridges.setPlainText("\n".join(remaining))
        self.bridge_status_label.setText(
            f"Removed one bridge. {len(remaining)} bridge{'s' if len(remaining) != 1 else ''} remain."
        )

    def _canonicalize_bridge_editor(self):
        text = self.inp_bridges.toPlainText()
        parsed = parse_bridge_text(text)
        if parsed.invalid_records:
            return
        normalized = "\n".join(parsed.records)
        if normalized != text:
            self._bridge_normalizing = True
            try:
                self.inp_bridges.setPlainText(normalized)
            finally:
                self._bridge_normalizing = False

    def initialize_second_page(self):
        self.second_page_layout.addWidget(self._section_title("Local HTTP proxy"))
        self.second_page_layout.addWidget(
            self._description(
                "When enabled, TorProxy starts a loopback HTTP proxy with the primary Tor session. "
                "HTTPS and raw TCP applications use HTTP CONNECT; the listener is not a direct Internet proxy."
            )
        )
        self.chk_http_proxy_enabled = QCheckBox("Enable local HTTP proxy", self)
        self.chk_http_proxy_enabled.setObjectName("httpProxyEnabledPreference")
        self.chk_http_proxy_enabled.setToolTip(
            "Enabled by default. The listener is available on 127.0.0.1 and routes requests through Tor's verified SOCKS gateway."
        )
        self.chk_http_proxy_enabled.setChecked(bool(CONFIG["http_proxy_enabled"]))
        self.chk_http_proxy_enabled.toggled.connect(self.http_proxy_enabled_changed)
        self.second_page_layout.addWidget(self.chk_http_proxy_enabled)

        proxy_test_row = QFrame(self)
        proxy_test_row.setObjectName("settingsRowCard")
        proxy_test_layout = QHBoxLayout(proxy_test_row)
        proxy_test_layout.setContentsMargins(14, 9, 14, 9)
        proxy_test_layout.setSpacing(12)
        self.lbl_http_proxy_status = self._description("HTTP proxy status will appear here.")
        self.lbl_http_proxy_status.setWordWrap(True)
        proxy_test_layout.addWidget(self.lbl_http_proxy_status, 1)
        self.btn_test_http_connect = QPushButton("Test HTTP CONNECT", self)
        self.btn_test_http_connect.setObjectName("settingsActionButton")
        self.btn_test_http_connect.setToolTip(
            "Checks a real HTTPS request through HTTP CONNECT and Tor; a listening TCP port alone is not considered a pass."
        )
        self.btn_test_http_connect.clicked.connect(self.test_http_connect)
        proxy_test_layout.addWidget(self.btn_test_http_connect, 0, Qt.AlignmentFlag.AlignVCenter)
        self.second_page_layout.addWidget(proxy_test_row)
        self._refresh_http_proxy_status()

        self.second_page_layout.addSpacing(12)
        self.second_page_layout.addWidget(self._section_title("Listener ports"))
        description = self._description(
            "TorProxy automatically selects and remembers distinct loopback ports. The displayed values are reused on later launches. "
            "Use Fixed only when you want to pin a listener to a manual port; a busy fixed port is reported instead of silently changed. "
            "Port changes are applied on the next connection."
        )
        self.second_page_layout.addWidget(description)
        ports = ["tor_port", "proxy_port", "dns_port", "control_port"]
        port_labels = {
            "tor_port": "SOCKS listener",
            "proxy_port": "HTTP proxy",
            "dns_port": "DNS listener",
            "control_port": "Control interface",
        }
        self._listener_port_inputs = {}
        self._listener_port_status_labels = {}
        for port in ports:
            row = QFrame(self)
            row.setObjectName("settingsRowCard")
            lyt = QHBoxLayout(row)
            lyt.setContentsMargins(14, 9, 14, 9)
            lbl = QLabel(port_labels[port])
            lbl.setObjectName("settingsFieldLabel")
            lbl.setMinimumWidth(140)
            inp_port = QLineEdit()
            inp_port.setObjectName("portValueInput")
            inp_port.setPlaceholderText("Port 1–65535")
            inp_port.setMaximumWidth(220)
            inp_port.setToolTip(
                "Current loopback port. Leave automatic mode selected to reuse TorProxy's saved value, "
                "or pin this value as a manual port."
            )

            # populate input with existing value if present (avoid "None" string)
            current_val = CONFIG[port]
            inp_port.setText(str(current_val) if current_val is not None else "")

            enabled_initial = bool(CONFIG[port + "_checked"]) if CONFIG[port + "_checked"] is not None else False
            # Automatic mode owns this value; only Fixed ports are manually editable.
            inp_port.setEnabled(enabled_initial)

            lbl_status = QLabel(
                CORRECT if enabled_initial and self._is_valid_port(current_val)
                else ("AUTO" if self._is_valid_port(current_val) else WRONG)
            )
            check_port = QCheckBox("Fixed")
            check_port.setToolTip(
                "Pin the value above as a manual port. When unchecked, TorProxy chooses and remembers an available port."
            )
            check_port.setChecked(enabled_initial)

            # connect text changed -> validator (partial binds the widgets)
            inp_port.textChanged.connect(partial(self.inp_port_changed, inp_port, lbl_status, port))

            # connect checkbox state change -> enable/disable input and update CONFIG
            # stateChanged provides an int state; partial with keywords keeps signature clean
            check_port.stateChanged.connect(partial(self.check_port_changed, inp_port=inp_port, lbl_status=lbl_status, port=port))

            lyt.addWidget(lbl)
            lyt.addWidget(inp_port)
            lyt.addWidget(lbl_status)
            lyt.addWidget(check_port)

            self._listener_port_inputs[port] = inp_port
            self._listener_port_status_labels[port] = lbl_status
            self.second_page_layout.addWidget(row)

    def sync_listener_ports(self, ports: dict[str, int]) -> None:
        """Refresh automatically reassigned port values without changing pin preferences."""
        for port, value in ports.items():
            if port not in self._listener_port_inputs or CONFIG[port + "_checked"]:
                continue
            editor = self._listener_port_inputs[port]
            previous = editor.blockSignals(True)
            try:
                editor.setText(str(int(value)))
            finally:
                editor.blockSignals(previous)
            status = self._listener_port_status_labels.get(port)
            if status is not None:
                status.setText("AUTO")

    def _refresh_http_proxy_status(self) -> None:
        """Keep Settings truthful about listener availability and Tor readiness."""
        if not hasattr(self, "lbl_http_proxy_status"):
            return
        enabled = bool(CONFIG["http_proxy_enabled"])
        proxy_widget = getattr(self._parent, "proxyWidget", None)
        runner = getattr(proxy_widget, "proxy", None)
        listener_ready = bool(getattr(runner, "is_running", False))
        tor_ready = bool(
            getattr(proxy_widget, "running", False)
            and getattr(proxy_widget, "connected", False)
            and not getattr(proxy_widget, "_stopping", False)
        )
        if not enabled:
            status = "Disabled · Tor SOCKS and System Tunnel are unaffected."
        elif listener_ready and tor_ready:
            status = f"Ready · 127.0.0.1:{getattr(runner, 'port', CONFIG['proxy_port'])} · HTTPS uses CONNECT."
        elif listener_ready:
            status = "Listening · waiting for a verified Tor network connection."
        elif getattr(proxy_widget, "running", False):
            status = "Enabled · HTTP listener is not running; check the Event Log."
        else:
            status = "Enabled · the listener starts automatically when you connect to Tor."
        self.lbl_http_proxy_status.setText(status)
        busy = self._http_proxy_toggle_pending or self._http_proxy_test_busy
        self.btn_test_http_connect.setEnabled(bool(enabled and listener_ready and tor_ready and not busy))

    def http_proxy_enabled_changed(self, checked: bool) -> None:
        """Persist and apply the HTTP listener preference without changing Tor."""
        enabled = bool(checked)
        previous = bool(CONFIG["http_proxy_enabled"])
        if self._http_proxy_toggle_pending:
            self.chk_http_proxy_enabled.blockSignals(True)
            self.chk_http_proxy_enabled.setChecked(previous)
            self.chk_http_proxy_enabled.blockSignals(False)
            return
        if enabled == previous:
            self._refresh_http_proxy_status()
            return

        proxy_widget = getattr(self._parent, "proxyWidget", None)
        if not enabled and (
            CONFIG["system_proxy_mode"] == "set"
            or bool(getattr(proxy_widget, "proxy_set", False))
        ):
            self.chk_http_proxy_enabled.blockSignals(True)
            self.chk_http_proxy_enabled.setChecked(True)
            self.chk_http_proxy_enabled.blockSignals(False)
            QMessageBox.warning(
                self,
                "HTTP proxy is required",
                "The operating-system proxy is configured to use this listener. Change System Proxy to Unchanged or Clear before disabling the HTTP proxy.",
            )
            self._refresh_http_proxy_status()
            return
        if bool(getattr(proxy_widget, "_stopping", False)):
            self.chk_http_proxy_enabled.blockSignals(True)
            self.chk_http_proxy_enabled.setChecked(previous)
            self.chk_http_proxy_enabled.blockSignals(False)
            self._refresh_http_proxy_status()
            return

        try:
            CONFIG["http_proxy_enabled"] = enabled
        except (ValueError, OSError, KeyError) as exc:
            self.chk_http_proxy_enabled.blockSignals(True)
            self.chk_http_proxy_enabled.setChecked(previous)
            self.chk_http_proxy_enabled.blockSignals(False)
            QMessageBox.warning(self, "Settings could not be saved", str(exc))
            self._refresh_http_proxy_status()
            return

        self._http_proxy_toggle_previous = previous
        runner = getattr(proxy_widget, "proxy", None)
        if runner is None:
            self._refresh_http_proxy_status()
            return

        self._http_proxy_toggle_pending = True
        self.chk_http_proxy_enabled.setEnabled(False)
        self.btn_test_http_connect.setEnabled(False)
        self.lbl_http_proxy_status.setText(
            "Starting the local HTTP listener…" if enabled else "Stopping the local HTTP listener…"
        )
        worker = Worker(runner.set_http_enabled, enabled)
        worker.signals.finished.connect(self._on_http_proxy_toggle_finished)
        worker.signals.error.connect(self._on_http_proxy_toggle_failed)
        self._http_proxy_toggle_worker = worker
        self._http_proxy_test_pool.start(worker)

    def _on_http_proxy_toggle_finished(self, result: str) -> None:
        self._http_proxy_toggle_pending = False
        self._http_proxy_toggle_worker = None
        self.chk_http_proxy_enabled.setEnabled(True)
        self._refresh_http_proxy_status()
        if result:
            self.lbl_http_proxy_status.setText(str(result))

    def _on_http_proxy_toggle_failed(self, error: str) -> None:
        self._http_proxy_toggle_pending = False
        self._http_proxy_toggle_worker = None
        previous = self._http_proxy_toggle_previous
        try:
            CONFIG["http_proxy_enabled"] = previous
        except (ValueError, OSError, KeyError):
            logger.exception("Could not restore HTTP proxy preference after listener failure.")
        self.chk_http_proxy_enabled.blockSignals(True)
        self.chk_http_proxy_enabled.setChecked(previous)
        self.chk_http_proxy_enabled.blockSignals(False)
        self.chk_http_proxy_enabled.setEnabled(True)
        detail = str(error or "Unknown HTTP proxy listener error.")
        self.lbl_http_proxy_status.setText("HTTP listener change failed · " + detail)
        logger.warning("Could not apply HTTP proxy preference: %s", detail)
        QMessageBox.warning(self, "HTTP proxy", detail)
        self._refresh_http_proxy_status()

    def test_http_connect(self) -> None:
        """Verify an actual HTTPS request through this HTTP proxy and Tor."""
        if self._http_proxy_test_busy or self._http_proxy_toggle_pending:
            return
        proxy_widget = getattr(self._parent, "proxyWidget", None)
        runner = getattr(proxy_widget, "proxy", None)
        if (
            not bool(CONFIG["http_proxy_enabled"])
            or not bool(getattr(runner, "is_running", False))
            or not bool(getattr(proxy_widget, "connected", False))
        ):
            self.lbl_http_proxy_status.setText("Connect to Tor and start the HTTP proxy before running this test.")
            self._refresh_http_proxy_status()
            return

        self._http_proxy_test_busy = True
        self.btn_test_http_connect.setText("Testing…")
        self._refresh_http_proxy_status()
        self.btn_test_http_connect.setEnabled(False)
        proxy_url = f"http://127.0.0.1:{int(runner.port)}"
        worker = Worker(proxy_widget._perform_exit_ip_check, proxy_url)
        worker.signals.finished.connect(self._on_http_connect_test_finished)
        worker.signals.error.connect(self._on_http_connect_test_failed)
        self._http_proxy_test_worker = worker
        self._http_proxy_test_pool.start(worker)

    def _finish_http_connect_test(self) -> None:
        self._http_proxy_test_busy = False
        self._http_proxy_test_worker = None
        self.btn_test_http_connect.setText("Test HTTP CONNECT")
        proxy_widget = getattr(self._parent, "proxyWidget", None)
        runner = getattr(proxy_widget, "proxy", None)
        ready = bool(
            CONFIG["http_proxy_enabled"]
            and getattr(runner, "is_running", False)
            and getattr(proxy_widget, "connected", False)
            and not getattr(proxy_widget, "_stopping", False)
        )
        self.btn_test_http_connect.setEnabled(ready and not self._http_proxy_toggle_pending)

    def _on_http_connect_test_finished(self, result: str) -> None:
        value = str(result or "").strip()
        if value and value.casefold() != "none":
            self.lbl_http_proxy_status.setText("Verified · HTTP CONNECT reached an external HTTPS endpoint through Tor.")
        else:
            self.lbl_http_proxy_status.setText("Test incomplete · no Tor exit response was verified.")
        self._finish_http_connect_test()

    def _on_http_connect_test_failed(self, error: str) -> None:
        detail = str(error or "Unknown CONNECT test failure.")
        self.lbl_http_proxy_status.setText("HTTP CONNECT test failed · " + detail)
        logger.warning("HTTP CONNECT diagnostic failed: %s", detail)
        self._finish_http_connect_test()

    def initialize_tor_services_page(self):
        """Expose only the persistent resource/concurrency preferences in Settings."""
        self.tor_services_panel = TorServicesSettingsPage(self, app_window=self._parent)
        self.services_page_layout.addWidget(self.tor_services_panel)
        self.services_page_layout.addStretch(1)

    def initialize_advanced_page(self):
        self.advanced_page_layout.addWidget(self._section_title("Optional publisher signature verification"))
        self.advanced_page_layout.addWidget(
            self._description("OpenPGP verification is OFF by default. Enable it only when you explicitly want the additional publisher-signature check.")
        )
        self.chk_verify_tor_signatures = QCheckBox(
            "Verify Tor bundle signatures with OpenPGP (GnuPG)", self
        )
        self.chk_verify_tor_signatures.setChecked(bool(CONFIG["verify_tor_signatures"]))
        self.chk_verify_tor_signatures.stateChanged.connect(self.signature_verification_changed)
        self.advanced_page_layout.addWidget(self.chk_verify_tor_signatures)

        details = QLabel(
            "OFF (default): TorProxy downloads from the official HTTPS host and safely extracts the archive, "
            "but does not authenticate the publisher's cryptographic signature.\n\n"
            "ON: TorProxy requires the matching detached .asc signature and checks it against Tor's pinned signing key. "
            "A working GnuPG installation is required; missing or invalid signatures stop installation.\n\n"
            "The same preference applies to manually imported bundles when a matching .asc file is available."
        )
        details.setWordWrap(True)
        details.setObjectName("signatureVerificationDetails")
        self.advanced_page_layout.addWidget(details)

        self.advanced_page_layout.addSpacing(14)
        self.advanced_page_layout.addWidget(self._section_title("System tunnel recovery"))
        self.advanced_page_layout.addWidget(
            self._description(
                "Check for a sing-box process or TUN session left behind by an interrupted TorProxy run. "
                "Cleanup is limited to a process whose saved PID, executable, start time and config identity match. "
                "An untracked adapter or unknown process is never terminated or removed automatically."
            )
        )
        recovery_row = QFrame(self)
        recovery_row.setObjectName("settingsRowCard")
        recovery_layout = QHBoxLayout(recovery_row)
        recovery_layout.setContentsMargins(14, 10, 14, 10)
        recovery_layout.setSpacing(12)
        recovery_copy = QVBoxLayout()
        recovery_copy.setSpacing(3)
        recovery_title = QLabel("Emergency sing-box cleanup")
        recovery_title.setObjectName("settingsFieldLabel")
        self.lbl_tunnel_recovery_status = self._description(
            "No cleanup has been requested."
        )
        recovery_copy.addWidget(recovery_title)
        recovery_copy.addWidget(self.lbl_tunnel_recovery_status)
        recovery_layout.addLayout(recovery_copy, 1)
        self.btn_tunnel_recovery = QPushButton("Check / clean up", self)
        self.btn_tunnel_recovery.setObjectName("settingsActionButton")
        self.btn_tunnel_recovery.setIcon(qta.icon("fa6s.broom"))
        self.btn_tunnel_recovery.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_tunnel_recovery.clicked.connect(self.cleanup_system_tunnel)
        recovery_layout.addWidget(self.btn_tunnel_recovery, 0, Qt.AlignmentFlag.AlignVCenter)
        self.advanced_page_layout.addWidget(recovery_row)
        self.advanced_page_layout.addStretch(1)


    def cleanup_system_tunnel(self):
        """Offer conservative cleanup of a recorded, app-managed sing-box session."""
        if self._tunnel_recovery_busy:
            return
        proxy_widget = getattr(self._parent, "proxyWidget", None)
        manager = getattr(proxy_widget, "system_tunnel_manager", None)
        if manager is None:
            QMessageBox.warning(self, "System tunnel recovery", "The system tunnel manager is unavailable.")
            return
        tunnel_page = getattr(self._parent, "tunnel_window", None)
        if (
            getattr(proxy_widget, "_system_tunnel_busy", False)
            or getattr(proxy_widget, "_stopping", False)
            or getattr(proxy_widget, "_connect_operation_busy", False)
            or getattr(tunnel_page, "_busy", False)
        ):
            QMessageBox.information(
                self,
                "System tunnel recovery",
                "Wait for the current Tor or system tunnel operation to finish before starting emergency cleanup.",
            )
            return
        reply = QMessageBox.question(
            self,
            "Check / clean up sing-box",
            (
                "TorProxy will inspect the saved sing-box process record. If it can verify that the "
                "process belongs to this installation, it will request the required permission and stop "
                "it gracefully so its TUN routes can be released. An unknown process or untracked TUN "
                "adapter will not be terminated or removed.\n\n"
                "Continue?"
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._tunnel_recovery_busy = True
        if proxy_widget is not None:
            proxy_widget._system_tunnel_busy = True
            refresh_home = getattr(proxy_widget, "_update_tunnel_hint", None)
            if callable(refresh_home):
                refresh_home()
        self.btn_tunnel_recovery.setEnabled(False)
        self.lbl_tunnel_recovery_status.setText("Inspecting saved process identity and TUN state…")
        worker = Worker(manager.cleanup_previous_session)
        worker.signals.finished.connect(self._on_tunnel_recovery_finished)
        worker.signals.cancelled.connect(self._on_tunnel_recovery_cancelled)
        worker.signals.error.connect(self._on_tunnel_recovery_failed)
        self._tunnel_recovery_worker = worker
        self._tunnel_recovery_pool.start(worker)

    def _finish_tunnel_recovery(self):
        self._tunnel_recovery_busy = False
        self._tunnel_recovery_worker = None
        proxy_widget = getattr(self._parent, "proxyWidget", None)
        if proxy_widget is not None:
            proxy_widget._system_tunnel_busy = False
        self.btn_tunnel_recovery.setEnabled(True)

    def _refresh_tunnel_views_after_recovery(self):
        proxy_widget = getattr(self._parent, "proxyWidget", None)
        if proxy_widget is not None:
            refresh_home = getattr(proxy_widget, "_update_tunnel_hint", None)
            if callable(refresh_home):
                refresh_home()
        tunnel_page = getattr(self._parent, "tunnel_window", None)
        refresh_page = getattr(tunnel_page, "_refresh_state", None)
        if callable(refresh_page):
            refresh_page()

    def _on_tunnel_recovery_finished(self, result):
        self._finish_tunnel_recovery()
        message = str(result or "No previous TorProxy tunnel state needed cleanup.")
        self.lbl_tunnel_recovery_status.setText(message)
        proxy_widget = getattr(self._parent, "proxyWidget", None)
        logs_widget = getattr(proxy_widget, "logs_widget", None)
        if logs_widget is not None:
            logs_widget.update_log("Emergency sing-box recovery: " + message)
        self._refresh_tunnel_views_after_recovery()

    def _on_tunnel_recovery_cancelled(self, reason: str):
        """Restore Settings after the administrator prompt is declined."""
        self._finish_tunnel_recovery()
        message = "Recovery cancelled; no system-tunnel changes were made."
        self.lbl_tunnel_recovery_status.setText(message)
        proxy_widget = getattr(self._parent, "proxyWidget", None)
        logs_widget = getattr(proxy_widget, "logs_widget", None)
        if logs_widget is not None:
            logs_widget.update_log(
                message + " " + str(reason or ""),
                level="info",
            )
        self._refresh_tunnel_views_after_recovery()

    def _on_tunnel_recovery_failed(self, error):
        self._finish_tunnel_recovery()
        detail = str(error or "Unknown sing-box recovery error.")
        self.lbl_tunnel_recovery_status.setText("Cleanup could not be verified. See Event Log.")
        proxy_widget = getattr(self._parent, "proxyWidget", None)
        logs_widget = getattr(proxy_widget, "logs_widget", None)
        if logs_widget is not None:
            logs_widget.update_log("Emergency sing-box cleanup failed: " + detail, level="error")
        QMessageBox.warning(self, "System tunnel recovery", detail)
        self._refresh_tunnel_views_after_recovery()

    def signature_verification_changed(self, state):
        enabled = bool(state)
        try:
            CONFIG["verify_tor_signatures"] = enabled
        except (ValueError, OSError, KeyError) as exc:
            logger.error("Could not save OpenPGP signature-verification preference: %s", exc)
            self.chk_verify_tor_signatures.blockSignals(True)
            self.chk_verify_tor_signatures.setChecked(not enabled)
            self.chk_verify_tor_signatures.blockSignals(False)
            QMessageBox.warning(self, "Settings could not be saved", str(exc))

    def _enabled_port_conflict(self, port: str, value: int) -> str | None:
        for other in ("tor_port", "proxy_port", "dns_port", "control_port"):
            if other == port or not CONFIG[other + "_checked"]:
                continue
            current = CONFIG[other]
            try:
                if current is not None and int(current) == value:
                    return other
            except (TypeError, ValueError):
                continue
        return None

    def inp_port_changed(self, inp_port, lbl_status, port, text=None):
        value = inp_port.text().strip() if text is None else str(text).strip()
        if not value or not self._is_valid_port(value):
            lbl_status.setText(WRONG)
            try:
                CONFIG[port] = None
            except (ValueError, OSError) as exc:
                logger.warning("Could not clear invalid %s setting: %s", port, exc)
            return

        port_value = int(value)
        conflict = self._enabled_port_conflict(port, port_value) if CONFIG[port + "_checked"] else None
        if conflict:
            lbl_status.setText(WRONG)
            try:
                CONFIG[port] = None
            except (ValueError, OSError) as exc:
                logger.warning("Could not clear conflicting %s setting: %s", port, exc)
            logger.warning("Port %s conflicts with enabled %s.", port_value, conflict)
            return

        try:
            CONFIG[port] = port_value
        except (ValueError, OSError) as exc:
            lbl_status.setText(WRONG)
            logger.warning("Could not save %s: %s", port, exc)
            return

        lbl_status.setText(CORRECT)
        try:
            proxy = getattr(self._parent, "proxyWidget", None)
            if proxy and hasattr(proxy, "set_port"):
                proxy.set_port(port, port_value)
            elif proxy:
                setattr(proxy, port, port_value)
        except Exception:
            pass

    def check_port_changed(self, state: int, inp_port: QLineEdit = None, lbl_status: QLabel = None, port: str = ""):
        enabled = bool(state)
        val_text = inp_port.text().strip() if inp_port is not None else ""
        if enabled and not self._is_valid_port(val_text):
            if lbl_status is not None:
                lbl_status.setText(WRONG)
            QMessageBox.warning(
                self,
                "Invalid listener port",
                "Enter a port between 1 and 65535 before marking this listener as Fixed.",
            )
            checkbox = self.sender()
            if checkbox is not None and hasattr(checkbox, "setChecked"):
                checkbox.setChecked(False)
            return

        if enabled:
            conflict = self._enabled_port_conflict(port, int(val_text))
            if conflict:
                if lbl_status is not None:
                    lbl_status.setText(WRONG)
                QMessageBox.warning(
                    self, "Port conflict",
                    f"Port {val_text} is already assigned to enabled setting '{conflict}'."
                )
                checkbox = self.sender()
                if checkbox is not None and hasattr(checkbox, "setChecked"):
                    checkbox.setChecked(False)
                return

        previous_fixed = bool(CONFIG[port + "_checked"])
        try:
            CONFIG[port + "_checked"] = enabled
        except (ValueError, OSError) as exc:
            logger.warning("Could not update %s enabled flag: %s", port, exc)
            if lbl_status is not None:
                lbl_status.setText(WRONG)
            checkbox = self.sender()
            if checkbox is not None and hasattr(checkbox, "setChecked"):
                checkbox.blockSignals(True)
                checkbox.setChecked(previous_fixed)
                checkbox.blockSignals(False)
            return

        if inp_port is not None:
            inp_port.setEnabled(enabled)

        if lbl_status is not None:
            lbl_status.setText(
                CORRECT if enabled and self._is_valid_port(val_text)
                else ("AUTO" if self._is_valid_port(val_text) else WRONG)
            )

    # ---------- other helpers ----------
    def go_to_before_page(self):
        self._set_settings_page(max(0, self.page_setting.currentIndex() - 1))

    def go_to_next_page(self):
        self._set_settings_page(min(self.page_setting.count() - 1, self.page_setting.currentIndex() + 1))
    def show_qrcode(self):
        """Open the live QR scanner modally; camera work stays on its own thread."""
        self.btn_qrcode.setDisabled(True)
        try:
            self.qrcode_widget.exec()
        finally:
            self.btn_qrcode.setEnabled(True)
        
    def newnym_inp_changed(self):
        text = self.newnym_inp.text().strip()
        if text and text.isdigit() and 0 < int(text) < 2_147_483_647:
            try:
                interval = int(text)
                # set to parent timer if exists
                try:
                    self._parent.proxyWidget.timer.setInterval(interval)
                except Exception:
                    pass
                self.newnym_lbl_stat.setText(f"({interval//1000} sec)  " + CORRECT )
                CONFIG["newnym_interval"] = interval
            except OverflowError:
                logger.error("newnym interval overflow: %s", text)
                self.newnym_lbl_stat.setText(WRONG)
        else:
            self.newnym_lbl_stat.setText(WRONG)

    def MaxCircuitDirtiness_changed(self):
        text = self.inp_MaxCircuitDirtiness.text().strip()
        if not (text.isdigit() and 10 <= int(text) <= 86400):
            self.lbl_MaxCircuitDirtiness.setText(WRONG)
            return
        value = int(text)
        try:
            CONFIG["MaxCircuitDirtiness"] = value
        except (ValueError, OSError) as exc:
            logger.warning("Could not save MaxCircuitDirtiness: %s", exc)
            self.lbl_MaxCircuitDirtiness.setText(WRONG)
            return
        proxy = getattr(self._parent, "proxyWidget", None)
        if proxy is not None and hasattr(proxy, "tor"):
            proxy.tor.MaxCircuitDirtiness = value
        self.lbl_MaxCircuitDirtiness.setText(CORRECT)

    def NewCircuitPeriod_changed(self):
        text = self.inp_NewCircuitPeriod.text().strip()
        if not (text.isdigit() and 10 <= int(text) <= 86400):
            self.lbl_NewCircuitPeriod.setText(WRONG)
            return
        value = int(text)
        try:
            CONFIG["NewCircuitPeriod"] = value
        except (ValueError, OSError) as exc:
            logger.warning("Could not save NewCircuitPeriod: %s", exc)
            self.lbl_NewCircuitPeriod.setText(WRONG)
            return
        proxy = getattr(self._parent, "proxyWidget", None)
        if proxy is not None and hasattr(proxy, "tor"):
            proxy.tor.NewCircuitPeriod = value
        self.lbl_NewCircuitPeriod.setText(CORRECT)

    def set_bridges(self):
        """Validate, canonicalize, save and render the bridge records as one transaction."""
        text = self.inp_bridges.toPlainText()
        parsed = parse_bridge_text(text)
        if text.strip() and parsed.invalid_records:
            self._bridge_normalize_timer.stop()
            invalid_count = len(parsed.invalid_records)
            details = " ".join(parsed.errors[:3])
            if len(parsed.errors) > 3:
                details += f" Plus {len(parsed.errors) - 3} more item(s)."
            self.bridge_status_label.setText(
                f"Could not use {invalid_count} bridge item(s). {details} "
                "Copy the complete bridge line from Tor's bridge source. Fingerprints, when present, must be 40 hex characters. "
                "A direct bridge without a transport label is accepted, and IPv6 endpoints are normalized automatically. "
                "The last valid saved bridge list remains active until the input is fixed."
            )
            if not self._bridge_input_invalid:
                self._refresh_bridge_cards(self._saved_bridge_records, removable=False)
            self._bridge_input_invalid = True
            return

        normalized = "\n".join(parsed.records)
        records_changed = parsed.records != self._saved_bridge_records
        was_invalid = self._bridge_input_invalid
        try:
            if str(CONFIG["bridges"] or "") != normalized:
                CONFIG["bridges"] = normalized
        except (ValueError, OSError, KeyError) as exc:
            logger.warning("Could not save bridge records: %s", exc)
            self.bridge_status_label.setText("Bridge records could not be saved. Your previous settings were preserved.")
            if not self._bridge_input_invalid:
                self._refresh_bridge_cards(self._saved_bridge_records, removable=False)
            self._bridge_input_invalid = True
            return

        self._saved_bridge_records = parsed.records
        self._bridge_input_invalid = False
        try:
            proxy = getattr(self._parent, "proxyWidget", None)
            if proxy is not None and hasattr(proxy, "tor"):
                proxy.tor.bridges = normalized
        except Exception:
            logger.debug("Could not update the live Tor adapter's bridge list.", exc_info=True)

        if records_changed or was_invalid:
            self._refresh_bridge_cards(self._saved_bridge_records, removable=True)
        if normalized != text and not self._bridge_normalizing:
            self._bridge_normalize_timer.start()
            self.bridge_status_label.setText(
                f"Detected {len(parsed.records)} bridge(s). Standardizing spacing and separating each record…"
            )
        elif not parsed.records:
            self.bridge_status_label.setText("No bridge addresses saved.")
        else:
            self.bridge_status_label.setText(
                f"{len(parsed.records)} bridge(s) saved in TorProxy format — one complete record per line."
            )

    def save_webtunnel_sni_imitation(self):
        """Save the optional custom SNI hostname; blank/default means no override."""
        combo = getattr(self, "cmb_webtunnel_sni", None)
        if combo is None:
            return False

        current_index = combo.currentIndex()
        current_text = combo.currentText().strip()
        if current_index >= 0 and current_text == combo.itemText(current_index):
            value = str(combo.itemData(current_index) or "").strip()
        else:
            value = current_text

        try:
            value = normalize_sni_hostname(value)
        except (TypeError, ValueError) as exc:
            self.webtunnel_sni_status.setText(str(exc))
            logger.warning("Rejected invalid WebTunnel SNI hostname: %s", exc)
            return False

        try:
            CONFIG["webtunnel_sni_imitation"] = value
        except (TypeError, ValueError, OSError, KeyError) as exc:
            self.webtunnel_sni_status.setText("SNI setting could not be saved. The previous setting remains active.")
            logger.exception("Could not save the WebTunnel SNI preference.")
            return False

        proxy = getattr(self._parent, "proxyWidget", None)
        tor_runner = getattr(proxy, "tor", None)
        if tor_runner is not None:
            tor_runner.webtunnel_sni_imitation = value

        if value:
            self.webtunnel_sni_status.setText(
                f"Saved SNI override: {value}. Applies to WebTunnel bridges on the next Tor start."
            )
        else:
            self.webtunnel_sni_status.setText(
                "SNI override disabled. Lyrebird will use each WebTunnel bridge's url= hostname."
            )
        return True

    def bridge_state_changed(self, state):
        checked = bool(state)
        try:
            self._parent.proxyWidget.tor.bridge = checked
        except Exception:
            pass
        self.inp_bridges.setEnabled(checked)
        self._bridge_usage_enabled = checked
        self._update_bridge_card_statuses()
        if hasattr(self, "chk_auto_prune_bridges"):
            self.chk_auto_prune_bridges.setEnabled(checked)
        CONFIG["bridge"] = bool(checked)

    def auto_prune_bridges_changed(self, checked):
        enabled = bool(checked)
        try:
            CONFIG["auto_prune_bridges"] = enabled
        except (ValueError, OSError, KeyError) as exc:
            logger.exception("Could not save automatic bridge cleanup preference.")
            self.chk_auto_prune_bridges.blockSignals(True)
            self.chk_auto_prune_bridges.setChecked(not enabled)
            self.chk_auto_prune_bridges.blockSignals(False)
            QMessageBox.warning(self, "Settings could not be saved", str(exc))

    def _theme_mode_status_text(self):
        preference = CONFIG.get("theme_preference", "system")
        if preference == "system":
            resolved = "Light" if CONFIG.get("mode", "dark") == "light" else "Dark"
            return f"System · {resolved}"
        return "Light" if preference == "light" else "Dark"

    def _sync_theme_preference_controls(self):
        preference = CONFIG.get("theme_preference", "system")
        for value, button in getattr(self, "theme_mode_buttons", {}).items():
            button.setChecked(value == preference)
        if hasattr(self, "theme_mode_label"):
            self.theme_mode_label.setText(self._theme_mode_status_text())

    def set_theme_mode(self, mode):
        """Refresh the active appearance label without losing System selection."""
        if mode not in {"dark", "light"}:
            return
        self._sync_theme_preference_controls()

    def change_mode(self, preference, *_args):
        """Persist System, Light, or Dark as the user's theme preference."""
        if not isinstance(preference, str):
            preference = str(getattr(preference, "text", lambda: "")()).strip().lower()
        preference = preference.lower()
        if preference not in {"system", "dark", "light"}:
            return

        if self._parent is not None and hasattr(self._parent, "_set_theme_preference"):
            self._parent._set_theme_preference(preference)
            return

        mode = resolve_system_theme(QApplication.instance()) if preference == "system" else preference
        app = QApplication.instance()
        try:
            CONFIG.update_many({"theme_preference": preference, "mode": mode})
        except (ValueError, OSError, KeyError) as exc:
            logger.exception("Could not save the theme preference.")
            QMessageBox.warning(self, "Theme preference", str(exc))
            self._sync_theme_preference_controls()
            return
        if app is not None:
            palette = LightPalette() if mode == "light" else DarkPalette()
            app.setStyleSheet(qdarkstyle.load_stylesheet(palette=palette))
        self.apply_theme(mode)
        self.set_theme_mode(mode)

    def _set_confirm_exit_preference(self, enabled):
        enabled = bool(enabled)
        try:
            CONFIG["confirm_exit"] = enabled
        except (ValueError, OSError, KeyError) as exc:
            logger.exception("Could not save exit confirmation preference.")
            self.chk_confirm_exit.blockSignals(True)
            self.chk_confirm_exit.setChecked(bool(CONFIG["confirm_exit"]))
            self.chk_confirm_exit.blockSignals(False)
            QMessageBox.warning(self, "Settings could not be saved", str(exc))

    # small utility
    @staticmethod
    def _is_valid_port(value):
        try:
            p = int(value)
            return 0 < p <= 65535
        except Exception:
            return False
