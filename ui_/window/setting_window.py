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
    QScrollArea
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
from ui_.btn.theme_switch import ThemeSwitch
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
            "fa6s.shield-halved",
        )
        for index, (title, icon_name) in enumerate(zip(
            ("General", "Bridges", "Ports", "Advanced"), self.settings_nav_icon_names
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
        for page_index, button in enumerate(self.settings_nav_buttons):
            button.setChecked(page_index == index)

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
            QLabel#themeModeValue {{ color: {accent}; background: transparent; font-size: 11px; font-weight: 800; min-width: 44px; }}
            QWidget#themeSwitch {{ background: transparent; border: none; }}
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
        for button, icon_name in zip(self.settings_nav_buttons, self.settings_nav_icon_names):
            button.setIcon(qta.icon(icon_name, color="#ffffff" if button.isChecked() else icon_color))
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
            self._description("Choose how TorProxy looks. The theme is synchronized with the top-right appearance button.")
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
        theme_description = self._description("Switch between the light and dark appearance.")
        theme_copy.addWidget(theme_label)
        theme_copy.addWidget(theme_description)
        mode_layout.addLayout(theme_copy, 1)

        self.theme_mode_label = QLabel("Light" if CONFIG["mode"] == "light" else "Dark")
        self.theme_mode_label.setObjectName("themeModeValue")
        mode_layout.addWidget(self.theme_mode_label, 0, Qt.AlignmentFlag.AlignVCenter)
        self.theme_switch = ThemeSwitch(CONFIG["mode"], self)
        self.theme_switch.modeChanged.connect(self.change_mode)
        mode_layout.addWidget(self.theme_switch, 0, Qt.AlignmentFlag.AlignVCenter)
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
        self.webtunnel_sni_status = QLabel("Default: no SNI override.", sni_row)
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
            "Remove only bridge-specific dial failures when another bridge completes bootstrap. Generic SOCKS warnings, "
            "DNS-leak notices, missing-hop messages, and global Lyrebird/TLS errors do not prove a bridge is dead."
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
        self.second_page_layout.addWidget(self._section_title("Listener ports"))
        description = self._description("Enable only the listeners you use. Active ports must be unique and within 1–65535. Changes to active listeners apply on the next Tor start.")
        self.second_page_layout.addWidget(description)
        ports = ["tor_port", "proxy_port", "dns_port", "control_port"]
        port_labels = {
            "tor_port": "SOCKS listener",
            "proxy_port": "HTTP proxy",
            "dns_port": "DNS listener",
            "control_port": "Control interface",
        }
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
            inp_port.setToolTip("Local loopback listener port. Active listener ports must not conflict.")

            # populate input with existing value if present (avoid "None" string)
            current_val = CONFIG[port]
            inp_port.setText(str(current_val) if current_val is not None else "")

            enabled_initial = bool(CONFIG[port + "_checked"]) if CONFIG[port + "_checked"] is not None else False
            inp_port.setEnabled(enabled_initial)

            lbl_status = QLabel(CORRECT if enabled_initial and self._is_valid_port(current_val) else WRONG)
            check_port = QCheckBox("Enabled")
            check_port.setToolTip("Enable or disable this listener on the next Tor start.")
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

            self.second_page_layout.addWidget(row)

    def initialize_advanced_page(self):
        self.advanced_page_layout.addWidget(self._section_title("Optional security verification"))
        self.advanced_page_layout.addWidget(
            self._description("Choose whether to authenticate the Tor publisher using its signed release metadata.")
        )
        self.chk_verify_tor_signatures = QCheckBox(
            "Verify Tor bundle signatures with OpenPGP (GnuPG)", self
        )
        self.chk_verify_tor_signatures.setChecked(bool(CONFIG["verify_tor_signatures"]))
        self.chk_verify_tor_signatures.stateChanged.connect(self.signature_verification_changed)
        self.advanced_page_layout.addWidget(self.chk_verify_tor_signatures)

        details = QLabel(
            "OFF (default): TorProxy downloads the exact Expert Bundle from the official Tor HTTPS host, "
            "checks archive structure and records its SHA-256 digest, but does not authenticate the publisher's "
            "cryptographic signature. This is less secure if the distribution host, connection or archive is compromised.\n\n"
            "ON: TorProxy requires the matching detached .asc signature and checks it against Tor's pinned signing "
            "key. A working GnuPG installation is required; missing or invalid signatures stop the installation."
        )
        details.setWordWrap(True)
        details.setObjectName("signatureVerificationDetails")
        self.advanced_page_layout.addWidget(details)
        self.advanced_page_layout.addStretch(1)

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
        if enabled and self._is_valid_port(val_text):
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

        if inp_port is not None:
            inp_port.setEnabled(enabled)
        try:
            CONFIG[port + "_checked"] = enabled
        except (ValueError, OSError) as exc:
            logger.warning("Could not update %s enabled flag: %s", port, exc)
            if lbl_status is not None:
                lbl_status.setText(WRONG)
            checkbox = self.sender()
            if enabled and checkbox is not None and hasattr(checkbox, "setChecked"):
                checkbox.setChecked(False)
            return

        if lbl_status is not None:
            lbl_status.setText(CORRECT if enabled and self._is_valid_port(val_text) else WRONG)

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

    def set_theme_mode(self, mode):
        """Synchronize the switch after theme changes from the title bar."""
        if mode not in {"dark", "light"}:
            return
        if hasattr(self, "theme_switch"):
            self.theme_switch.set_mode(mode, animate=True)
        if hasattr(self, "theme_mode_label"):
            self.theme_mode_label.setText("Light" if mode == "light" else "Dark")

    def change_mode(self, mode):
        # Accept a mode string from ThemeSwitch. Keep compatibility with callers
        # that may still pass a radio-like object from older integrations.
        if not isinstance(mode, str):
            mode = "light" if str(getattr(mode, "text", lambda: "dark")()).lower() == "light" else "dark"
        if mode not in {"dark", "light"}:
            return
        if self._parent is not None and hasattr(self._parent, "_set_theme"):
            self._parent._set_theme(mode)
            return
        app = QApplication.instance()
        if app is not None:
            palette = LightPalette() if mode == "light" else DarkPalette()
            app.setStyleSheet(qdarkstyle.load_stylesheet(palette=palette))
        CONFIG["mode"] = mode
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
