from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QWidget,
    QButtonGroup,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QCheckBox,
    QTextEdit,
    QLineEdit,
    QStackedWidget,
    QListWidget,
    QFrame,
    QScrollArea
)
from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtGui import QColor, QPalette
import qtawesome as qta

import qdarkstyle
from qdarkstyle.dark.palette import DarkPalette
from qdarkstyle.light.palette import LightPalette

import logging
from functools import partial

logger = logging.getLogger(__name__)

from config import CONFIG
from ui_.window.dialogs import QMessageBox
from ui_.worker.worker import Worker
from ui_.window.qrcode_widget import QrCodeFloatingWindow
from ui_.btn.theme_switch import ThemeSwitch
from ui_.emojis import WRONG, CORRECT

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

        self.initialize_first_page()
        self.initialize_bridges_page()
        self.initialize_second_page()
        self.initialize_advanced_page()
        self.apply_theme(CONFIG["mode"])

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
            QKeySequenceEdit#globalShortcutEdit {{ color: {text}; background: {field}; border: 1px solid {border}; border-radius: 7px; padding: 5px 9px; min-height: 30px; min-width: 190px; }}
            QKeySequenceEdit#globalShortcutEdit:focus {{ border-color: {accent}; }}
            QLabel#globalShortcutStatus {{ background: transparent; font-size: 10px; }}
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
            "Use bridges when direct access to Tor relays is blocked or unreliable. Bridge configuration is kept separate from listener ports."
        )
        self.bridges_page_layout.addWidget(description)
        self.btn_bridge = QCheckBox("Use Tor bridges", self)
        self.btn_bridge.setChecked(bool(CONFIG["bridge"]))
        self.btn_bridge.stateChanged.connect(self.bridge_state_changed)
        self.bridges_page_layout.addWidget(self.btn_bridge)
        self.inp_bridges = QTextEdit(self, placeholderText="Enter your bridges (obfs4 or webtunnel)")
        self.inp_bridges.setMinimumHeight(130)
        self.inp_bridges.setText(CONFIG["bridges"] or "")
        self.inp_bridges.setEnabled(bool(CONFIG["bridge"]))
        self.inp_bridges.textChanged.connect(self.set_bridges)
        self.bridges_page_layout.addWidget(self.inp_bridges)
        self.btn_qrcode = QPushButton("Import bridges from QR code")
        self.btn_qrcode.setObjectName("settingsActionButton")
        self.btn_qrcode.setIcon(qta.icon("fa6s.qrcode", color="#eff1f4" if CONFIG["mode"] == "dark" else "#202832"))
        self.btn_qrcode.clicked.connect(self.show_qrcode)
        self.bridges_page_layout.addWidget(self.btn_qrcode)
        self.bridges_page_layout.addStretch(1)
        self.qrcode_widget = QrCodeFloatingWindow(self)
        self.threadpool = QThreadPool(self)

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
        worker = Worker(self.qrcode_widget.run)
        worker.signals.finished.connect(self.show_qrcode_widget)
        worker.signals.error.connect(self.show_qrcode_widget)
        self.threadpool.start(worker)
        self.btn_qrcode.setDisabled(True)

    def show_qrcode_widget(self, *args):
        self.qrcode_widget.setParent(self)
        self.qrcode_widget.move(80, 0)
        self.qrcode_widget.show()
        self.qrcode_widget.timer.start(30)
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
        txt = self.inp_bridges.toPlainText()
        try:
            self._parent.proxyWidget.tor.bridges = txt
        except Exception:
            pass
        CONFIG["bridges"] = txt

    def bridge_state_changed(self, state):
        checked = bool(state)
        try:
            self._parent.proxyWidget.tor.bridge = checked
        except Exception:
            pass
        self.inp_bridges.setEnabled(checked)
        CONFIG["bridge"] = bool(checked)

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
