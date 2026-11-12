"""Home dashboard for the independent Developer Tor Onion Hosting runtime."""
from __future__ import annotations

import logging

import qtawesome as qta
from PySide6.QtCore import Qt, QThreadPool, QTimer, Signal, QUrl, QObject, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from config import CONFIG
from torproxy.paths import user_directories
from torproxy.bridges import normalize_sni_hostname, parse_bridge_text
from ui_.worker.worker import Worker
from ui_.window.dialogs import QMessageBox, StandardButton, _FramelessDialog
from ui_.window.tor_log_dialog import TorLogDialog

logger = logging.getLogger(__name__)


class _WorkerResultRelay(QObject):
    """Marshal QRunnable results onto the GUI thread with a real QObject receiver."""

    finished = Signal(str, str, object)
    error = Signal(str, str)
    cancelled = Signal(str, str)

    def __init__(self, parent, operation: str, completion_callback=None):
        super().__init__(parent)
        self._operation = operation
        self._completion_callback = completion_callback
        self.finished.connect(parent._on_worker_finished)
        self.error.connect(parent._on_worker_error)
        self.cancelled.connect(parent._on_worker_cancelled)

    @Slot(str)
    def on_finished(self, result: str):
        self.finished.emit(self._operation, result, self._completion_callback)

    @Slot(str)
    def on_error(self, error: str):
        self.error.emit(self._operation, error)

    @Slot(str)
    def on_cancelled(self, detail: str):
        self.cancelled.emit(self._operation, detail)


class OnionServiceDialog(_FramelessDialog):
    """Themed create/edit dialog for one v3 Onion Service."""

    def __init__(self, parent, service: dict | None = None):
        editing = service is not None
        super().__init__(
            parent,
            "Edit Onion Service" if editing else "Create Onion Service",
            "fa6s.network-wired",
            "#287db5",
            width=540,
        )
        self.service = dict(service or {})
        intro = QLabel(
            "Publish a local development service through its own v3 Onion address. "
            "Only loopback targets are accepted; start your web server before enabling the service.",
            self.body_host,
        )
        intro.setObjectName("dialogMessage")
        intro.setWordWrap(True)
        self.body_layout.addWidget(intro)

        self.name_input = QLineEdit(self.body_host)
        self.name_input.setPlaceholderText("My local website")
        self.name_input.setText(str(self.service.get("display_name", "")))

        self.host_input = QLineEdit(self.body_host)
        self.host_input.setText(str(self.service.get("local_host", "127.0.0.1")))
        self.host_input.setPlaceholderText("127.0.0.1")

        self.local_port_input = QSpinBox(self.body_host)
        self.local_port_input.setRange(1, 65535)
        self.local_port_input.setValue(int(self.service.get("local_port", 8000)))

        self.onion_port_input = QSpinBox(self.body_host)
        self.onion_port_input.setRange(1, 65535)
        self.onion_port_input.setValue(int(self.service.get("onion_port", 80)))

        self.persistence_input = QComboBox(self.body_host)
        self.persistence_input.addItem("Persistent · keep the same Onion address", True)
        self.persistence_input.addItem("Temporary · remove when TorProxy exits", False)
        self.persistence_input.setCurrentIndex(0 if self.service.get("persistent", True) else 1)

        self.access_input = QComboBox(self.body_host)
        self.access_input.addItem("Public · anyone with the address", "public")
        self.access_input.addItem("Private · requires a client authorization key", "private")
        index = self.access_input.findData(self.service.get("access_mode", "public"))
        self.access_input.setCurrentIndex(max(0, index))

        self.auto_start_input = QCheckBox("Start this service automatically when Developer Tor starts", self.body_host)
        self.auto_start_input.setChecked(bool(self.service.get("auto_start", True)))

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)
        form.addRow("Service name", self.name_input)
        form.addRow("Local IP address", self.host_input)
        form.addRow("Local port", self.local_port_input)
        form.addRow("Onion port", self.onion_port_input)
        form.addRow("Lifetime", self.persistence_input)
        form.addRow("Access", self.access_input)
        self.body_layout.addLayout(form)
        self.body_layout.addWidget(self.auto_start_input)

        warning = QLabel(
            "Privacy note: Onion routing hides the host IP from visitors, but the website itself can still "
            "reveal identifying information through pages, files, analytics, or server behavior. "
            "TorProxy does not sandbox your web application.",
            self.body_host,
        )
        warning.setObjectName("dialogHint")
        warning.setWordWrap(True)
        self.body_layout.addWidget(warning)

        self._values = None
        self.add_footer_spacer()
        self.add_button("Cancel", primary=False, callback=self.reject)
        self.save_button = self.add_button(
            "Save changes" if editing else "Create service",
            primary=True,
            callback=self._accept_form,
        )
        self.setStyleSheet(self.styleSheet() + """
            QLineEdit, QComboBox, QSpinBox {
                min-height: 32px; padding: 2px 8px;
                border: 1px solid #657386; border-radius: 7px;
                background: palette(base); color: palette(text);
            }
            QCheckBox { spacing: 8px; }
        """)
        self.resize(560, 545)
        self._remember_preferred_size()

    def _accept_form(self):
        name = self.name_input.text().strip()
        host = self.host_input.text().strip()
        if not name:
            QMessageBox.warning(self, "Service name required", "Enter a name for this Onion Service.")
            self.name_input.setFocus()
            return
        if not host:
            QMessageBox.warning(self, "Local address required", "Enter 127.0.0.1 or ::1 as the local target.")
            self.host_input.setFocus()
            return
        self._values = {
            "display_name": name,
            "local_host": host,
            "local_port": int(self.local_port_input.value()),
            "onion_port": int(self.onion_port_input.value()),
            "persistent": bool(self.persistence_input.currentData()),
            "access_mode": str(self.access_input.currentData()),
            "auto_start": bool(self.auto_start_input.isChecked()),
        }
        self.accept()

    def values(self) -> dict:
        return dict(self._values or {})


class DeveloperTorSettingsDialog(_FramelessDialog):
    """Network and transport settings for the independent Developer Tor runtime."""

    def __init__(self, parent, settings: dict):
        super().__init__(parent, "Developer Tor Settings", "fa6s.sliders", "#287db5", width=640)
        values = dict(settings or {})
        scroll = QScrollArea(self.body_host)
        scroll.setObjectName("dialogScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget(scroll)
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(3, 3, 8, 8)
        content_layout.setSpacing(10)

        intro = QLabel(
            "Configure the network used by the dedicated Developer Tor process. "
            "These preferences do not modify Main Tor or Custom Tor settings.",
            content,
        )
        intro.setObjectName("dialogMessage")
        intro.setWordWrap(True)
        content_layout.addWidget(intro)

        bridge_title = QLabel("Connection and bridges", content)
        bridge_title.setObjectName("shortcutCategory")
        content_layout.addWidget(bridge_title)
        bridge_form = QFormLayout()
        bridge_form.setHorizontalSpacing(14)
        bridge_form.setVerticalSpacing(8)
        self.bridge_mode = QComboBox(content)
        self.bridge_mode.addItem("Direct connection", "direct")
        self.bridge_mode.addItem("Use custom Developer Tor bridges", "custom")
        self.bridge_mode.addItem("Reuse the saved Main Tor bridge list", "main")
        selected_mode = self.bridge_mode.findData(values.get("bridge_mode", "direct"))
        self.bridge_mode.setCurrentIndex(max(0, selected_mode))
        bridge_form.addRow("Connection mode", self.bridge_mode)
        content_layout.addLayout(bridge_form)

        self.bridge_editor = QTextEdit(content)
        self.bridge_editor.setObjectName("developerBridgeEditor")
        self.bridge_editor.setAcceptRichText(False)
        self.bridge_editor.setPlaceholderText(
            "Paste complete Bridge records, one per line…\n"
            "Example: obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=… iat-mode=0"
        )
        self.bridge_editor.setPlainText(str(values.get("bridges", "")))
        self.bridge_editor.setMinimumHeight(105)
        content_layout.addWidget(self.bridge_editor)
        self.bridge_hint = QLabel("", content)
        self.bridge_hint.setObjectName("dialogHint")
        self.bridge_hint.setWordWrap(True)
        content_layout.addWidget(self.bridge_hint)

        sni_form = QFormLayout()
        self.sni_input = QLineEdit(content)
        self.sni_input.setPlaceholderText("Use the hostname from each WebTunnel url= field")
        self.sni_input.setText(str(values.get("webtunnel_sni_imitation", "")))
        sni_form.addRow("WebTunnel SNI imitation", self.sni_input)
        content_layout.addLayout(sni_form)
        sni_note = QLabel(
            "Optional. This is applied only to WebTunnel Bridge records and takes effect after restarting Developer Tor.",
            content,
        )
        sni_note.setObjectName("dialogHint")
        sni_note.setWordWrap(True)
        content_layout.addWidget(sni_note)

        self.webtunnel_default_tls = QCheckBox(
            "Use Go's native TLS fingerprint (WebTunnel compatibility mode)", content
        )
        self.webtunnel_default_tls.setObjectName("developerWebtunnelDefaultTls")
        self.webtunnel_default_tls.setChecked(bool(values.get("webtunnel_use_default_tls", True)))
        self.webtunnel_default_tls.setToolTip(
            "Adds utls=none to WebTunnel Bridge records, replacing uTLS ClientHello impersonation "
            "with Go's native TLS fingerprint. Recommended for Lyrebird unsupported-curve errors."
        )
        content_layout.addWidget(self.webtunnel_default_tls)
        webtunnel_tls_note = QLabel(
            "Compatibility workaround for Lyrebird's unsupported TLS curve error. Only WebTunnel records "
            "are changed; obfs4, Snowflake and vanilla bridges are unaffected. SNI is retained. "
            "Applies after restarting Developer Tor.",
            content,
        )
        webtunnel_tls_note.setObjectName("dialogHint")
        webtunnel_tls_note.setWordWrap(True)
        content_layout.addWidget(webtunnel_tls_note)

        advanced_title = QLabel("Advanced network", content)
        advanced_title.setObjectName("shortcutCategory")
        content_layout.addWidget(advanced_title)
        advanced_form = QFormLayout()
        advanced_form.setHorizontalSpacing(14)
        advanced_form.setVerticalSpacing(8)
        self.max_dirtiness = QSpinBox(content)
        self.max_dirtiness.setRange(10, 86400)
        self.max_dirtiness.setValue(int(values.get("max_circuit_dirtiness_seconds", 600)))
        self.circuit_period = QSpinBox(content)
        self.circuit_period.setRange(10, 86400)
        self.circuit_period.setValue(int(values.get("new_circuit_period_seconds", 60)))
        self.startup_timeout = QSpinBox(content)
        self.startup_timeout.setRange(15, 900)
        self.startup_timeout.setValue(int(values.get("startup_timeout_seconds", 180)))
        self.shutdown_timeout = QSpinBox(content)
        self.shutdown_timeout.setRange(1, 60)
        self.shutdown_timeout.setValue(int(values.get("shutdown_timeout_seconds", 5)))
        advanced_form.addRow("Max circuit dirtiness (seconds)", self.max_dirtiness)
        advanced_form.addRow("New circuit period (seconds)", self.circuit_period)
        advanced_form.addRow("Startup timeout (seconds)", self.startup_timeout)
        advanced_form.addRow("Shutdown timeout (seconds)", self.shutdown_timeout)
        content_layout.addLayout(advanced_form)

        family_row = QHBoxLayout()
        self.ipv4_enabled = QCheckBox("Allow IPv4", content)
        self.ipv4_enabled.setChecked(bool(values.get("client_use_ipv4", True)))
        self.ipv6_enabled = QCheckBox("Allow IPv6", content)
        self.ipv6_enabled.setChecked(bool(values.get("client_use_ipv6", True)))
        family_row.addWidget(self.ipv4_enabled)
        family_row.addWidget(self.ipv6_enabled)
        family_row.addStretch(1)
        content_layout.addLayout(family_row)

        proxy_title = QLabel("Upstream proxy (optional)", content)
        proxy_title.setObjectName("shortcutCategory")
        content_layout.addWidget(proxy_title)
        proxy_form = QFormLayout()
        proxy_form.setHorizontalSpacing(14)
        proxy_form.setVerticalSpacing(8)
        self.proxy_type = QComboBox(content)
        self.proxy_type.addItem("No upstream proxy", "none")
        self.proxy_type.addItem("SOCKS5 proxy", "socks5")
        self.proxy_type.addItem("HTTP CONNECT proxy", "https")
        proxy_index = self.proxy_type.findData(values.get("upstream_proxy_type", "none"))
        self.proxy_type.setCurrentIndex(max(0, proxy_index))
        self.proxy_host = QLineEdit(content)
        self.proxy_host.setPlaceholderText("127.0.0.1 or proxy.example.net")
        self.proxy_host.setText(str(values.get("upstream_proxy_host", "")))
        self.proxy_port = QSpinBox(content)
        self.proxy_port.setRange(1, 65535)
        self.proxy_port.setValue(int(values.get("upstream_proxy_port", 1080)))
        self.proxy_username = QLineEdit(content)
        self.proxy_username.setText(str(values.get("upstream_proxy_username", "")))
        self.proxy_password = QLineEdit(content)
        self.proxy_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.proxy_password.setText(str(values.get("upstream_proxy_password", "")))
        self.proxy_password.setPlaceholderText("Stored separately from config.json")
        proxy_form.addRow("Proxy type", self.proxy_type)
        proxy_form.addRow("Proxy host", self.proxy_host)
        proxy_form.addRow("Proxy port", self.proxy_port)
        proxy_form.addRow("Username (optional)", self.proxy_username)
        proxy_form.addRow("Password (optional)", self.proxy_password)
        content_layout.addLayout(proxy_form)
        proxy_note = QLabel(
            "Tor connects to the network through this proxy. Credentials are stored in a separate per-user file "
            "with restrictive permissions and are written to the protected Developer Tor torrc only while starting. "
            "The proxy host itself is resolved by the local system.",
            content,
        )
        proxy_note.setObjectName("dialogHint")
        proxy_note.setWordWrap(True)
        content_layout.addWidget(proxy_note)

        scroll.setWidget(content)
        self.body_layout.addWidget(scroll, 1)
        self.bridge_mode.currentIndexChanged.connect(self._sync_bridge_mode)
        self.proxy_type.currentIndexChanged.connect(self._sync_proxy_fields)
        self._sync_bridge_mode()
        self._sync_proxy_fields()

        self._values = None
        self.add_footer_spacer()
        self.add_button("Cancel", primary=False, callback=self.reject)
        self.add_button("Save settings", primary=True, callback=self._accept_form)
        self.setStyleSheet(self.styleSheet() + f"""
            QLineEdit, QComboBox, QSpinBox, QTextEdit {{
                min-height: 31px; padding: 3px 8px;
                border: 1px solid {self._colors["border"]};
                border-radius: 7px; background: {self._colors["panel"]};
                color: {self._colors["text"]};
            }}
            QTextEdit {{ min-height: 100px; padding: 7px; }}
            QCheckBox {{ color: {self._colors["text"]}; spacing: 8px; }}
        """)
        self.resize(660, 690)
        self._remember_preferred_size()

    def _sync_bridge_mode(self, *_args):
        mode = self.bridge_mode.currentData()
        self.bridge_editor.setEnabled(mode == "custom")
        if mode == "main":
            self.bridge_hint.setText(
                "The saved Main Tor bridge list is read when Developer Tor starts. "
                "Main Tor must have bridge mode enabled; Main Tor's process and DataDirectory are not reused."
            )
        elif mode == "custom":
            self.bridge_hint.setText(
                "These records are stored separately and are used only by Developer Tor. "
                "Supported transports: obfs4, Snowflake, WebTunnel and meek_lite."
            )
        else:
            self.bridge_hint.setText("Direct mode does not configure Bridge records.")

    def _sync_proxy_fields(self, *_args):
        enabled = self.proxy_type.currentData() != "none"
        for widget in (self.proxy_host, self.proxy_port, self.proxy_username, self.proxy_password):
            widget.setEnabled(enabled)

    def _accept_form(self):
        mode = str(self.bridge_mode.currentData())
        raw_bridges = self.bridge_editor.toPlainText()
        parsed = parse_bridge_text(raw_bridges) if mode == "custom" else None
        if parsed is not None and parsed.invalid_records:
            QMessageBox.warning(
                self,
                "Invalid Bridge records",
                "Correct the invalid records before saving: " + " ".join(parsed.errors[:3]),
            )
            self.bridge_editor.setFocus()
            return
        if mode == "custom" and not parsed.records:
            QMessageBox.warning(self, "Bridge list required", "Add at least one complete Bridge record or choose another connection mode.")
            self.bridge_editor.setFocus()
            return
        try:
            sni = normalize_sni_hostname(self.sni_input.text())
        except (TypeError, ValueError) as exc:
            QMessageBox.warning(self, "Invalid WebTunnel SNI", str(exc))
            self.sni_input.setFocus()
            return
        if not self.ipv4_enabled.isChecked() and not self.ipv6_enabled.isChecked():
            QMessageBox.warning(self, "Address family required", "Enable IPv4, IPv6, or both.")
            return
        proxy_type = str(self.proxy_type.currentData())
        proxy_host = self.proxy_host.text().strip()
        username = self.proxy_username.text()
        password = self.proxy_password.text()
        if proxy_type != "none" and not proxy_host:
            QMessageBox.warning(self, "Proxy host required", "Enter the upstream proxy host.")
            self.proxy_host.setFocus()
            return
        if proxy_type != "none" and bool(username) != bool(password):
            QMessageBox.warning(self, "Proxy authentication", "Enter both username and password, or leave both empty.")
            return
        if proxy_type == "https" and (":" in username or ":" in password):
            QMessageBox.warning(self, "Proxy authentication", "HTTP CONNECT proxy credentials cannot contain a colon.")
            return
        self._values = {
            "bridge_mode": mode,
            "bridges": "\n".join(parsed.records) if parsed and parsed.records else raw_bridges.strip(),
            "webtunnel_sni_imitation": sni,
            "webtunnel_use_default_tls": bool(self.webtunnel_default_tls.isChecked()),
            "max_circuit_dirtiness_seconds": int(self.max_dirtiness.value()),
            "new_circuit_period_seconds": int(self.circuit_period.value()),
            "startup_timeout_seconds": int(self.startup_timeout.value()),
            "shutdown_timeout_seconds": int(self.shutdown_timeout.value()),
            "client_use_ipv4": bool(self.ipv4_enabled.isChecked()),
            "client_use_ipv6": bool(self.ipv6_enabled.isChecked()),
            "upstream_proxy_type": proxy_type,
            "upstream_proxy_host": proxy_host,
            "upstream_proxy_port": int(self.proxy_port.value()),
            "upstream_proxy_username": username if proxy_type != "none" else "",
            "upstream_proxy_password": password if proxy_type != "none" else "",
        }
        self.accept()

    def values(self) -> dict:
        return dict(self._values or {})


class OnionHostingPage(QWidget):
    """Developer Tor dashboard. It never reuses the Main or Custom Tor pools."""

    runtime_progress = Signal(object)

    def __init__(self, proxy, app_window=None, parent=None):
        super().__init__(parent)
        self._proxy = proxy
        self._app_window = app_window
        self._workers: dict[str, Worker] = {}
        self._worker_relays: dict[str, _WorkerResultRelay] = {}
        self._service_card_widgets: list[QWidget] = []
        self._last_snapshot = None
        self._last_services = None
        self._thread_pool = QThreadPool(self)
        self._thread_pool.setMaxThreadCount(2)
        self.runtime_progress.connect(self._on_runtime_progress)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 12, 20, 12)
        root.setSpacing(9)

        hero = QFrame(self)
        hero.setObjectName("onionPageHero")
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(13, 8, 13, 8)
        hero_layout.setSpacing(10)

        hero_icon = QLabel(hero)
        hero_icon.setObjectName("onionHeroIcon")
        hero_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hero_icon.setFixedSize(34, 34)
        hero_icon.setPixmap(qta.icon("fa6s.code", color="#ffffff").pixmap(18, 18))
        hero_layout.addWidget(hero_icon)

        hero_copy = QVBoxLayout()
        hero_copy.setContentsMargins(0, 0, 0, 0)
        hero_copy.setSpacing(1)
        self.page_title = QLabel("Developer Tor", hero)
        self.page_title.setObjectName("onionPageTitle")
        self.description = QLabel(
            "Publish local applications as v3 Onion Services · Separate from Main and Custom Tor.",
            hero,
        )
        self.description.setObjectName("onionHeroDescription")
        self.description.setWordWrap(True)
        hero_copy.addWidget(self.page_title)
        hero_copy.addWidget(self.description)
        hero_layout.addLayout(hero_copy, 1)

        self.settings_button = QPushButton("Settings", hero)
        self.settings_button.setObjectName("onionActionButton")
        self.settings_button.setIcon(qta.icon("fa6s.sliders"))
        self.settings_button.setMinimumHeight(32)
        self.settings_button.clicked.connect(self.open_settings)
        hero_layout.addWidget(self.settings_button, 0, Qt.AlignmentFlag.AlignVCenter)
        root.addWidget(hero)

        runtime = QFrame(self)
        runtime.setObjectName("onionRuntimeCard")
        runtime_layout = QVBoxLayout(runtime)
        runtime_layout.setContentsMargins(13, 10, 13, 10)
        runtime_layout.setSpacing(6)
        runtime_header = QHBoxLayout()
        runtime_title = QLabel("DEVELOPER TOR RUNTIME", runtime)
        runtime_title.setObjectName("onionSectionTitle")
        runtime_header.addWidget(runtime_title)
        runtime_header.addStretch(1)
        self.runtime_state = QLabel("STOPPED", runtime)
        self.runtime_state.setObjectName("onionRuntimeState")
        runtime_header.addWidget(self.runtime_state)
        runtime_layout.addLayout(runtime_header)

        details = QHBoxLayout()
        self.runtime_message = QLabel("Developer Tor is stopped.", runtime)
        self.runtime_message.setObjectName("onionRuntimeMessage")
        self.runtime_message.setWordWrap(True)
        details.addWidget(self.runtime_message, 1)
        self.runtime_metrics = QLabel("", runtime)
        self.runtime_metrics.setObjectName("onionRuntimeMetrics")
        self.runtime_metrics.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        details.addWidget(self.runtime_metrics)
        runtime_layout.addLayout(details)
        self.runtime_network = QLabel(
            "Saved connection settings will apply when Developer Tor starts.",
            runtime,
        )
        self.runtime_network.setObjectName("onionMuted")
        self.runtime_network.setWordWrap(True)
        runtime_layout.addWidget(self.runtime_network)

        actions = QHBoxLayout()
        actions.setSpacing(6)
        self.start_runtime_button = QPushButton("Start runtime", runtime)
        self.start_runtime_button.setObjectName("onionActionPrimary")
        self.start_runtime_button.setIcon(qta.icon("fa6s.play"))
        self.start_runtime_button.clicked.connect(self.start_runtime)
        actions.addWidget(self.start_runtime_button)
        self.stop_runtime_button = QPushButton("Stop runtime", runtime)
        self.stop_runtime_button.setObjectName("onionActionButton")
        self.stop_runtime_button.setIcon(qta.icon("fa6s.stop"))
        self.stop_runtime_button.clicked.connect(self.stop_runtime)
        actions.addWidget(self.stop_runtime_button)
        self.restart_runtime_button = QPushButton("Restart", runtime)
        self.restart_runtime_button.setObjectName("onionActionButton")
        self.restart_runtime_button.setIcon(qta.icon("fa6s.rotate"))
        self.restart_runtime_button.clicked.connect(self.restart_runtime)
        actions.addWidget(self.restart_runtime_button)
        self.runtime_logs_button = QPushButton("Runtime logs", runtime)
        self.runtime_logs_button.setObjectName("onionActionButton")
        self.runtime_logs_button.setIcon(qta.icon("fa6s.file-lines"))
        self.runtime_logs_button.clicked.connect(self.open_runtime_logs)
        actions.addWidget(self.runtime_logs_button)
        actions.addStretch(1)
        runtime_layout.addLayout(actions)
        root.addWidget(runtime)

        service_header = QHBoxLayout()
        service_title = QLabel("Onion Services", self)
        service_title.setObjectName("onionSectionTitle")
        service_header.addWidget(service_title)
        self.services_count_label = QLabel("0 services", self)
        self.services_count_label.setObjectName("onionCountPill")
        service_header.addWidget(self.services_count_label)
        service_header.addStretch(1)
        self.add_service_button = QPushButton("Create Onion Service", self)
        self.add_service_button.setObjectName("onionActionPrimary")
        self.add_service_button.setIcon(qta.icon("fa6s.plus"))
        self.add_service_button.clicked.connect(self.create_service)
        service_header.addWidget(self.add_service_button)
        self.refresh_button = QPushButton("Refresh", self)
        self.refresh_button.setObjectName("onionActionButton")
        self.refresh_button.setIcon(qta.icon("fa6s.rotate"))
        self.refresh_button.clicked.connect(self.refresh_dashboard)
        service_header.addWidget(self.refresh_button)
        root.addLayout(service_header)

        self.services_scroll = QScrollArea(self)
        self.services_scroll.setWidgetResizable(True)
        self.services_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.services_scroll.setObjectName("onionServicesScroll")
        self.services_host = QWidget(self.services_scroll)
        self.services_layout = QVBoxLayout(self.services_host)
        self.services_layout.setContentsMargins(0, 0, 4, 0)
        self.services_layout.setSpacing(7)
        self.services_scroll.setWidget(self.services_host)
        root.addWidget(self.services_scroll, 1)

        self.empty_label = QLabel(
            "No Onion Services yet. Create one to publish a local web application.",
            self.services_host,
        )
        self.empty_label.setObjectName("onionMuted")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.services_layout.addWidget(self.empty_label)
        self.services_layout.addStretch(1)

        self.status_label = QLabel(
            "Developer Tor is separate from Main Tor and Custom Tor. Closing the window to the tray keeps it running; Exit TorProxy stops it.",
            self,
        )
        self.status_label.setObjectName("onionMuted")
        self.status_label.setWordWrap(True)
        root.addWidget(self.status_label)

        self._apply_theme(CONFIG["mode"])
        self._timer = QTimer(self)
        self._timer.setInterval(1200)
        self._timer.timeout.connect(self.refresh_dashboard)
        self._timer.start()
        self.refresh_dashboard()

    def apply_theme(self, mode):
        self._apply_theme(mode)

    def _manager(self):
        return self._proxy._ensure_onion_hosting_manager()

    def _apply_theme(self, mode):
        dark = str(mode).lower() == "dark"
        border = "#344254" if dark else "#dbe4ef"
        panel = "#202a38" if dark else "#ffffff"
        text = "#edf3fa" if dark else "#243247"
        muted = "#9eacbd" if dark else "#66778d"
        field = "#182230" if dark else "#f5f8fc"
        accent = "#4b9fe7" if dark else "#2878c8"
        hover = "rgba(75, 159, 231, 0.15)" if dark else "rgba(40, 120, 200, 0.09)"
        self.settings_button.setIcon(qta.icon("fa6s.sliders", color=text))
        self.setStyleSheet(f"""
            QWidget {{ color: {text}; background: transparent; }}
            QFrame#onionPageHero, QFrame#onionRuntimeCard, QFrame#onionServiceCard {{
                background: {panel}; border: 1px solid {border}; border-radius: 12px;
            }}
            QLabel#onionHeroIcon {{
                background: {accent}; border: 1px solid {accent}; border-radius: 10px;
            }}
            QLabel#onionPageTitle {{ color: {text}; font-size: 17px; font-weight: 800; }}
            QLabel#onionHeroDescription {{ color: {muted}; font-size: 9px; }}
            QLabel#onionSectionTitle {{ color: {text}; font-size: 13px; font-weight: 800; }}
            QLabel#onionMuted {{ color: {muted}; font-size: 9px; }}
            QFrame#onionRuntimeCard {{ border-left: 3px solid {accent}; }}
            QFrame#onionServiceCard:hover {{ border-color: {accent}; }}
            QLabel#onionRuntimeState, QLabel#onionCountPill {{
                color: {muted}; background: {field}; border: 1px solid {border};
                border-radius: 7px; padding: 3px 8px; font-size: 8px; font-weight: 800;
            }}
            QLabel#onionRuntimeState[runtimeState="ready"] {{
                color: #31b981; border-color: rgba(49,185,129,0.45); background: rgba(49,185,129,0.08);
            }}
            QLabel#onionRuntimeState[runtimeState="failed"] {{
                color: #e36b75; border-color: rgba(227,107,117,0.45); background: rgba(227,107,117,0.08);
            }}
            QLabel#onionRuntimeMessage {{ color: {text}; font-size: 10px; font-weight: 650; }}
            QLabel#onionRuntimeMetrics {{
                color: {accent}; background: {field}; border: 1px solid {border};
                border-radius: 8px; padding: 4px 8px; font-size: 8px; font-weight: 700;
            }}
            QPushButton#onionActionButton {{
                min-height: 30px; padding: 0 10px; border: 1px solid {border};
                border-radius: 8px; background: {field}; color: {text}; font-weight: 700;
            }}
            QPushButton#onionActionButton:hover {{
                border-color: {accent}; background: {hover};
            }}
            QPushButton#onionActionPrimary {{
                min-height: 32px; padding: 0 12px; border: 1px solid {accent};
                border-radius: 8px; background: {accent}; color: #ffffff; font-weight: 800;
            }}
            QPushButton#onionActionPrimary:hover {{ background: #176b9f; }}
            QPushButton#onionActionButton:disabled, QPushButton#onionActionPrimary:disabled {{
                color: {muted}; background: {field}; border-color: {border};
            }}
            QScrollArea#onionServicesScroll {{ background: transparent; border: none; }}
            QLabel#onionServiceName {{ color: {text}; font-size: 12px; font-weight: 800; }}
            QLabel#onionServiceDetail {{ color: {muted}; font-size: 9px; }}
            QLabel#onionServiceAddress {{
                color: {text}; background: {field}; border: 1px solid {border};
                border-radius: 8px; padding: 6px 8px; font-family: Consolas, monospace;
                font-size: 9px; selection-background-color: {accent};
            }}
            QLabel#onionStatusPill {{
                color: {muted}; background: {field}; border: 1px solid {border};
                border-radius: 7px; padding: 3px 8px; font-size: 8px; font-weight: 800;
            }}
            QLineEdit, QComboBox, QSpinBox, QTextEdit {{
                min-height: 30px; padding: 2px 8px; border: 1px solid {border};
                border-radius: 8px; background: {field}; color: {text};
            }}
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QTextEdit:focus {{
                border-color: {accent};
            }}
        """)

    def _run(self, key: str, callback, *args, finished=None):
        if key in self._workers:
            return
        worker = Worker(callback, *args)
        relay = _WorkerResultRelay(self, key, finished)
        worker.signals.finished.connect(relay.on_finished)
        worker.signals.error.connect(relay.on_error)
        worker.signals.cancelled.connect(relay.on_cancelled)
        self._workers[key] = worker
        self._worker_relays[key] = relay
        self._update_action_states()
        self._thread_pool.start(worker)

    def _release_worker(self, key: str):
        self._workers.pop(key, None)
        relay = self._worker_relays.pop(key, None)
        if relay is not None:
            relay.deleteLater()

    @Slot(str, str, object)
    def _on_worker_finished(self, key: str, result: str, callback=None):
        self._release_worker(key)
        if callback is not None:
            try:
                callback(result)
            except Exception:
                logger.exception("Developer Tor UI completion handler failed.")
        self.refresh_dashboard()
        self._update_action_states()

    @Slot(str, str)
    def _on_worker_error(self, key: str, error: str):
        self._release_worker(key)
        self.status_label.setText(error)
        logger.warning("Developer Tor operation '%s' failed: %s", key, error)
        self.refresh_dashboard()
        self._update_action_states()
        QMessageBox.warning(self, "Developer Tor", error)

    @Slot(str, str)
    def _on_worker_cancelled(self, key: str, detail: str):
        self._release_worker(key)
        self.status_label.setText(detail or "Developer Tor operation cancelled.")
        self.refresh_dashboard()
        self._update_action_states()

    @Slot(object)
    def _on_runtime_progress(self, update):
        state, progress, message = update
        text = str(message or state.title())
        if progress is not None:
            text = f"{int(progress)}% · {text}"
        self.runtime_message.setText(text)
        self.runtime_state.setText(str(state).replace("_", " ").upper())
        self.runtime_state.setProperty("runtimeState", str(state).lower())
        self.runtime_state.style().unpolish(self.runtime_state)
        self.runtime_state.style().polish(self.runtime_state)

    def _runtime_callback(self, state, progress, message):
        self.runtime_progress.emit((state, progress, message))

    def start_runtime(self):
        self.status_label.setText("Starting the independent Developer Tor process…")
        self._run(
            "runtime",
            self._manager().start_runtime,
            self._runtime_callback,
            finished=lambda _result: self.status_label.setText("Developer Tor is ready."),
        )

    def stop_runtime(self):
        snapshot = self._manager().runtime_snapshot()
        if snapshot["state"] == "stopped":
            return
        self.status_label.setText("Stopping Onion Services and Developer Tor…")
        self._run(
            "runtime",
            self._manager().stop_runtime,
            finished=lambda _result: self.status_label.setText("Developer Tor has stopped."),
        )

    def restart_runtime(self):
        manager = self._manager()
        self.status_label.setText("Restarting Developer Tor…")
        def restart():
            manager.stop_runtime()
            manager.start_runtime(self._runtime_callback)
        self._run(
            "runtime", restart,
            finished=lambda _result: self.status_label.setText("Developer Tor restarted."),
        )

    def _update_action_states(self):
        busy = "runtime" in self._workers
        self.settings_button.setEnabled(not busy)
        self.start_runtime_button.setEnabled(not busy)
        self.stop_runtime_button.setEnabled(not busy)
        self.restart_runtime_button.setEnabled(not busy)
        self.add_service_button.setEnabled(not busy)
        self.refresh_button.setEnabled(not busy)

    def open_settings(self):
        manager = self._manager()
        try:
            saved_settings = manager.settings_snapshot()
        except Exception as exc:
            QMessageBox.warning(self, "Developer Tor settings unavailable", str(exc))
            return
        dialog = DeveloperTorSettingsDialog(self, saved_settings)
        if dialog.exec() != dialog.DialogCode.Accepted:
            return
        try:
            manager.save_settings(dialog.values())
            state = manager.runtime_snapshot()["state"]
            if state == "stopped":
                self.status_label.setText("Developer Tor settings saved. They will apply on the next start.")
            else:
                self.status_label.setText("Developer Tor settings saved. Restart the runtime to apply them.")
                QMessageBox.information(
                    self,
                    "Settings saved",
                    "The active Developer Tor process is unchanged. Restart Developer Tor to apply the new network settings.",
                )
            self.refresh_dashboard()
        except Exception as exc:
            QMessageBox.warning(self, "Could not save Developer Tor settings", str(exc))

    def create_service(self):
        dialog = OnionServiceDialog(self)
        if dialog.exec() != dialog.DialogCode.Accepted:
            return
        values = dialog.values()
        try:
            service_id = self._manager().create_service(**values)
            self.status_label.setText("Onion Service profile saved.")
            self.refresh_dashboard()
            if values.get("auto_start") and self._manager().runtime_snapshot()["state"] == "ready":
                self._run(f"service:{service_id}", self._manager().start_service, service_id)
        except Exception as exc:
            QMessageBox.warning(self, "Could not create Onion Service", str(exc))

    def edit_service(self, service: dict):
        if service.get("running"):
            QMessageBox.information(self, "Stop before editing", "Stop this Onion Service before changing its settings.")
            return
        dialog = OnionServiceDialog(self, service)
        if dialog.exec() != dialog.DialogCode.Accepted:
            return
        try:
            self._manager().update_service(service["id"], **dialog.values())
            self.status_label.setText("Onion Service settings saved.")
            self.refresh_dashboard()
        except Exception as exc:
            QMessageBox.warning(self, "Could not update Onion Service", str(exc))

    def start_service(self, service_id: str):
        manager = self._manager()
        if manager.runtime_snapshot()["state"] != "ready":
            QMessageBox.information(
                self, "Developer Tor is not ready",
                "Start Developer Tor and wait for bootstrap to reach 100% before starting an Onion Service.",
            )
            return
        self.status_label.setText("Checking the local web server and creating the Onion Service…")
        self._run(f"service:{service_id}", manager.start_service, service_id)

    def stop_service(self, service_id: str):
        self._run(f"service:{service_id}", self._manager().stop_service, service_id)

    def delete_service(self, service: dict):
        choice = QMessageBox.question(
            self, "Delete Onion Service",
            f"Delete '{service['display_name']}' and remove its stored identity keys? This cannot be undone.",
            StandardButton.Yes | StandardButton.No,
            StandardButton.No,
        )
        if choice != StandardButton.Yes:
            return
        self._run(f"service:{service['id']}", self._manager().delete_service, service["id"])

    def copy_address(self, address: str):
        if not address:
            return
        QApplication.clipboard().setText("http://" + address)
        self.status_label.setText("Onion URL copied.")

    def copy_client_auth(self, service_id: str):
        try:
            value = self._manager().client_auth_private_file(service_id)
            QApplication.clipboard().setText(value)
            self.status_label.setText(
                "Private client authorization key copied. Treat it like a password and share it only with the intended visitor."
            )
        except Exception as exc:
            QMessageBox.warning(self, "Client authorization unavailable", str(exc))

    def open_address(self, address: str):
        if address:
            QDesktopServices.openUrl(QUrl("http://" + address))

    def open_runtime_logs(self):
        manager = self._manager()
        TorLogDialog(self, manager.log_path, manager=manager.manager).exec()

    def refresh_dashboard(self):
        try:
            manager = self._manager()
            runtime = manager.runtime_snapshot()
            services = manager.services_snapshot()
        except Exception as exc:
            self.runtime_message.setText(str(exc))
            return
        if runtime != self._last_snapshot:
            self._last_snapshot = dict(runtime)
            state = str(runtime["state"]).lower()
            self.runtime_state.setText(state.replace("_", " ").upper())
            self.runtime_state.setProperty("runtimeState", state)
            self.runtime_state.style().unpolish(self.runtime_state)
            self.runtime_state.style().polish(self.runtime_state)
            self.runtime_message.setText(str(runtime["message"]))
            self.runtime_network.setText(str(runtime.get("network_summary") or "Network diagnostics unavailable."))
            if state == "ready" and runtime.get("progress") is not None:
                self.runtime_message.setText(f"{runtime['progress']}% · {runtime['message']}")
            version = runtime.get("version") or "version unavailable"
            memory = int(runtime.get("memory_bytes") or 0)
            memory_text = f"{memory / (1024 * 1024):.1f} MiB" if memory else "—"
            uptime = int(runtime.get("uptime_seconds") or 0)
            self.runtime_metrics.setText(f"{version}  ·  {memory_text}  ·  {uptime // 3600:02d}:{(uptime % 3600) // 60:02d}:{uptime % 60:02d}")
        self.services_count_label.setText(
            f"{len(services)} service" + ("" if len(services) == 1 else "s")
        )
        if services != self._last_services:
            self._last_services = [dict(item) for item in services]
            self._rebuild_service_cards(services)
        state = str(runtime["state"]).lower()
        self.start_runtime_button.setEnabled(state in {"stopped", "failed"} and "runtime" not in self._workers)
        self.stop_runtime_button.setEnabled(state not in {"stopped"} and "runtime" not in self._workers)
        self.restart_runtime_button.setEnabled(state != "stopped" and "runtime" not in self._workers)

    def _rebuild_service_cards(self, services: list[dict]):
        # The empty-state label is permanent. Only remove cards created by the
        # previous snapshot; deleting the placeholder left a live Python wrapper
        # around an already-destroyed QLabel and crashed the next refresh.
        for card in self._service_card_widgets:
            self.services_layout.removeWidget(card)
            card.hide()
            card.deleteLater()
        self._service_card_widgets.clear()

        self.empty_label.setVisible(not services)
        for service in services:
            card = self._service_card(service)
            self._service_card_widgets.append(card)
            # Keep the placeholder at index 0 and the stretch at the end.
            self.services_layout.insertWidget(self.services_layout.count() - 1, card)

    def _service_card(self, service: dict) -> QWidget:
        card = QFrame(self.services_host)
        card.setObjectName("onionServiceCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(13, 10, 13, 10)
        layout.setSpacing(7)

        header = QHBoxLayout()
        name = QLabel(str(service["display_name"]), card)
        name.setObjectName("onionServiceName")
        header.addWidget(name)
        header.addStretch(1)
        state = "RUNNING" if service.get("running") else "STOPPED"
        if service.get("error"):
            state = "ERROR"
        pill = QLabel(state, card)
        pill.setObjectName("onionStatusPill")
        header.addWidget(pill)
        layout.addLayout(header)

        address = str(service.get("address") or "Address will be assigned when the service starts")
        address_label = QLabel(address, card)
        address_label.setObjectName("onionServiceAddress")
        address_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        address_label.setWordWrap(True)
        layout.addWidget(address_label)

        lifetime = "Persistent" if service.get("persistent") else "Temporary"
        access = "Private access" if service.get("access_mode") == "private" else "Public access"
        detail = QLabel(
            f"{service['local_host']}:{service['local_port']}  →  Onion port {service['onion_port']}  ·  {lifetime}  ·  {access}",
            card,
        )
        detail.setObjectName("onionServiceDetail")
        layout.addWidget(detail)
        if service.get("error"):
            error = QLabel(str(service["error"]), card)
            error.setObjectName("onionServiceDetail")
            error.setWordWrap(True)
            layout.addWidget(error)

        actions = QHBoxLayout()
        if service.get("running"):
            start = QPushButton("Stop", card)
            start.setIcon(qta.icon("fa6s.stop"))
            start.clicked.connect(lambda _checked=False, key=service["id"]: self.stop_service(key))
        else:
            start = QPushButton("Start", card)
            start.setIcon(qta.icon("fa6s.play"))
            start.setEnabled(self._last_snapshot is not None and self._last_snapshot.get("state") == "ready")
            start.clicked.connect(lambda _checked=False, key=service["id"]: self.start_service(key))
        start.setObjectName("onionActionButton")
        actions.addWidget(start)

        copy = QPushButton("Copy address", card)
        copy.setObjectName("onionActionButton")
        copy.setIcon(qta.icon("fa6s.copy"))
        copy.setEnabled(bool(service.get("address")))
        copy.clicked.connect(lambda _checked=False, value=service.get("address", ""): self.copy_address(value))
        actions.addWidget(copy)

        if service.get("access_mode") == "private":
            auth = QPushButton("Copy client key", card)
            auth.setObjectName("onionActionButton")
            auth.setIcon(qta.icon("fa6s.key"))
            auth.setEnabled(bool(service.get("address")))
            auth.clicked.connect(lambda _checked=False, key=service["id"]: self.copy_client_auth(key))
            actions.addWidget(auth)

        open_button = QPushButton("Open address", card)
        open_button.setObjectName("onionActionButton")
        open_button.setIcon(qta.icon("fa6s.arrow-up-right-from-square"))
        open_button.setEnabled(bool(service.get("address")))
        open_button.setToolTip("The default browser must be configured to route .onion addresses through Tor.")
        open_button.clicked.connect(lambda _checked=False, value=service.get("address", ""): self.open_address(value))
        actions.addWidget(open_button)

        logs = QPushButton("Logs", card)
        logs.setObjectName("onionActionButton")
        logs.setIcon(qta.icon("fa6s.file-lines"))
        logs.clicked.connect(self.open_runtime_logs)
        actions.addWidget(logs)

        edit = QPushButton("Edit", card)
        edit.setObjectName("onionActionButton")
        edit.setIcon(qta.icon("fa6s.pen"))
        edit.setEnabled(not service.get("running"))
        edit.clicked.connect(lambda _checked=False, data=dict(service): self.edit_service(data))
        actions.addWidget(edit)

        delete = QPushButton("Delete", card)
        delete.setObjectName("onionActionButton")
        delete.setIcon(qta.icon("fa6s.trash-can"))
        delete.clicked.connect(lambda _checked=False, data=dict(service): self.delete_service(data))
        actions.addWidget(delete)
        actions.addStretch(1)
        layout.addLayout(actions)
        return card
