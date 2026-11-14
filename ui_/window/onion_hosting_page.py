"""Home dashboard for the independent Developer Tor Onion Hosting runtime."""
from __future__ import annotations

import json
import logging

import qtawesome as qta
from PySide6.QtCore import Qt, QThreadPool, QTimer, Signal, QUrl, QObject, Slot
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from config import CONFIG
from torproxy.paths import user_directories
from ui_.window.numeric_controls import NoWheelSpinBox
from torproxy.bridges import normalize_sni_hostname, parse_bridge_text
from torproxy.onion_hosting import OnionHostingError, validate_loopback_target
from ui_.worker.worker import Worker
from ui_.window.dialogs import QMessageBox, StandardButton, _FramelessDialog
from ui_.window.tor_log_dialog import TorLogDialog
from ui_.window.qr_display import QrCodeButton

logger = logging.getLogger(__name__)


def _format_bytes(value: int | float) -> str:
    amount = max(0.0, float(value or 0))
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TiB"


class OnionServiceActivityDialog(_FramelessDialog):
    """Live, service-scoped access and connection history (never the Tor runtime log)."""

    def __init__(self, parent, manager, service: dict):
        super().__init__(
            parent,
            f"Request logs · {service.get('display_name', 'Onion Service')}",
            "fa6s.list-ul",
            "#287db5",
            width=940,
        )
        self._manager = manager
        self._service_id = str(service["id"])
        self._last_events = None

        intro = QLabel(
            "Requests and connection activity for this Onion Service only. "
            "The Tor runtime log is available once in the Developer Tor runtime panel.",
            self.body_host,
        )
        intro.setObjectName("dialogMessage")
        intro.setWordWrap(True)
        self.body_layout.addWidget(intro)

        self.summary = QLabel("", self.body_host)
        self.summary.setObjectName("onionActivitySummary")
        self.body_layout.addWidget(self.summary)

        privacy = QLabel(
            "Privacy: visitor IPs, headers, request bodies and query strings are not stored. "
            "HTTPS paths stay encrypted; HTTPS entries show connection and traffic details only. "
            "For plaintext HTTP, only the first HTTP request line on each TCP connection is detected; "
            "later keep-alive requests are not counted individually.",
            self.body_host,
        )
        privacy.setObjectName("dialogHint")
        privacy.setWordWrap(True)
        self.body_layout.addWidget(privacy)

        self.table = QTableWidget(0, 8, self.body_host)
        self.table.setObjectName("onionActivityTable")
        self.table.setHorizontalHeaderLabels(
            ["Time (UTC)", "Onion port", "Protocol", "First request line / connection", "Status", "In", "Out", "Duration"]
        )
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        for column in (5, 6, 7):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.body_layout.addWidget(self.table, 1)

        self.add_footer_spacer()
        self.add_button("Refresh", primary=False, callback=self.refresh)
        self.add_button("Close", primary=True, callback=self.accept)
        self.resize(960, 650)
        self._remember_preferred_size()

        self._timer = QTimer(self)
        self._timer.setInterval(1500)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()
        self.refresh()

    def refresh(self):
        try:
            stats = self._manager.traffic_snapshot(self._service_id)
            events = self._manager.traffic_events(self._service_id, limit=250)
        except Exception as exc:
            self.summary.setText(f"Could not load service activity: {exc}")
            return

        self.summary.setText(
            f"IN  {_format_bytes(stats['incoming_bytes'])}     "
            f"OUT  {_format_bytes(stats['outgoing_bytes'])}     "
            f"HTTP sessions  {stats['http_requests']:,}     "
            f"Connections  {stats['connections']:,}     "
            f"Errors  {stats['errors']:,}     "
            f"Active  {stats['active_connections']:,}"
        )
        if events == self._last_events:
            return
        self._last_events = events
        self.table.setRowCount(len(events))
        for row, event in enumerate(events):
            method = str(event.get("method") or "")
            path = str(event.get("path") or "")
            request = f"{method} {path}".strip() if method else f"{event.get('protocol', 'TCP')} connection"
            if event.get("error"):
                request = f"{request}  ·  {event['error']}"
            values = (
                str(event.get("occurred_at", "")).replace("T", " ").replace("+00:00", ""),
                str(event.get("onion_port") or "—"),
                str(event.get("protocol") or "TCP"),
                request,
                str(event.get("status_code") or "—"),
                _format_bytes(event.get("incoming_bytes", 0)),
                _format_bytes(event.get("outgoing_bytes", 0)),
                f"{int(event.get('duration_ms') or 0):,} ms",
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column in {1, 4, 5, 6, 7}:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                if column == 4:
                    code = event.get("status_code")
                    if code is not None and int(code) >= 400:
                        item.setForeground(QColor(Qt.GlobalColor.red))
                self.table.setItem(row, column, item)
        self.table.scrollToTop()


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

        self.local_port_input = NoWheelSpinBox(self.body_host)
        self.local_port_input.setRange(1, 65535)
        self.local_port_input.setValue(int(self.service.get("local_port", 8000)))

        self.onion_port_input = NoWheelSpinBox(self.body_host)
        self.onion_port_input.setRange(1, 65535)
        self.onion_port_input.setValue(int(self.service.get("onion_port", 80)))

        # Older profiles contain only local_host/local_port/onion_port. Newer
        # profiles may add mappings; show only the extra rows in this editor.
        primary_mapping = (
            str(self.service.get("local_host", "127.0.0.1")),
            int(self.service.get("local_port", 8000)),
            int(self.service.get("onion_port", 80)),
        )
        additional_lines = []
        for mapping in self.service.get("port_mappings", []) or []:
            try:
                mapped_host = str(mapping.get("local_host", primary_mapping[0]))
                mapped_port = int(mapping["local_port"])
                mapped_onion = int(mapping["onion_port"])
                if (mapped_host, mapped_port, mapped_onion) == primary_mapping:
                    continue
                endpoint = (
                    f"[{mapped_host}]:{mapped_port}"
                    if ":" in mapped_host
                    else f"{mapped_host}:{mapped_port}"
                )
                if mapped_host == primary_mapping[0]:
                    endpoint = str(mapped_port)
                additional_lines.append(f"{mapped_onion}={endpoint}")
            except (AttributeError, KeyError, TypeError, ValueError):
                continue
        self.additional_ports_input = QTextEdit(self.body_host)
        self.additional_ports_input.setAcceptRichText(False)
        self.additional_ports_input.setFixedHeight(76)
        self.additional_ports_input.setPlaceholderText(
            "Optional additional mappings, one per line:\n"
            "443=8443  (same loopback host, local port 8443)\n"
            "8443=127.0.0.1:9443  or  [::1]:9443"
        )
        self.additional_ports_input.setPlainText("\n".join(additional_lines))

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
        mapping_hint = QLabel(
            "One Onion address can expose several TCP ports, each forwarded to a local loopback service. "
            "The additional rows are validated before Tor is asked to publish anything.",
            self.body_host,
        )
        mapping_hint.setObjectName("dialogHint")
        mapping_hint.setWordWrap(True)
        self.body_layout.addWidget(mapping_hint)
        self.body_layout.addWidget(self.additional_ports_input)
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
        local_port = int(self.local_port_input.value())
        onion_port = int(self.onion_port_input.value())
        try:
            normalized_host, _ = validate_loopback_target(host, local_port)
            mappings = []
            seen_onion = {onion_port}
            seen_targets = {(normalized_host, local_port)}
            raw_mappings = self.additional_ports_input.toPlainText()
            for line_number, line in enumerate(raw_mappings.splitlines(), start=1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    raise ValueError(f"Additional mapping line {line_number} must use onion_port=local_port.")
                left, right = (part.strip() for part in line.split("=", 1))
                try:
                    mapped_onion = int(left)
                except ValueError as exc:
                    raise ValueError(f"Additional mapping line {line_number} has an invalid Onion port.") from exc
                if not 1 <= mapped_onion <= 65535 or mapped_onion in seen_onion:
                    raise ValueError(f"Additional mapping line {line_number} must use a unique port from 1 to 65535.")
                mapped_host = normalized_host
                if right.isdecimal():
                    mapped_port = int(right)
                elif right.startswith("["):
                    closing = right.find("]")
                    if closing < 0 or right[closing + 1:closing + 2] != ":":
                        raise ValueError(f"Additional mapping line {line_number} has an invalid IPv6 target.")
                    mapped_host = right[1:closing]
                    try:
                        mapped_port = int(right[closing + 2:])
                    except ValueError as exc:
                        raise ValueError(f"Additional mapping line {line_number} has an invalid local port.") from exc
                else:
                    mapped_host, separator, raw_port = right.rpartition(":")
                    if not separator:
                        raise ValueError(f"Additional mapping line {line_number} must include a local port.")
                    try:
                        mapped_port = int(raw_port)
                    except ValueError as exc:
                        raise ValueError(f"Additional mapping line {line_number} has an invalid local port.") from exc
                mapped_host, mapped_port = validate_loopback_target(mapped_host, mapped_port)
                target = (mapped_host, mapped_port)
                if target in seen_targets:
                    raise ValueError(f"Additional mapping line {line_number} duplicates a local target.")
                seen_onion.add(mapped_onion)
                seen_targets.add(target)
                mappings.append({
                    "onion_port": mapped_onion,
                    "local_host": mapped_host,
                    "local_port": mapped_port,
                })
            if len(mappings) > 15:
                raise ValueError("A single Onion Service can publish at most 16 port mappings.")
        except (TypeError, ValueError, OnionHostingError) as exc:
            QMessageBox.warning(self, "Invalid port mappings", str(exc))
            self.additional_ports_input.setFocus()
            return
        self._values = {
            "display_name": name,
            "local_host": normalized_host,
            "local_port": local_port,
            "onion_port": onion_port,
            "port_mappings": mappings,
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
        self.max_dirtiness = NoWheelSpinBox(content)
        self.max_dirtiness.setRange(10, 86400)
        self.max_dirtiness.setValue(int(values.get("max_circuit_dirtiness_seconds", 600)))
        self.circuit_period = NoWheelSpinBox(content)
        self.circuit_period.setRange(10, 86400)
        self.circuit_period.setValue(int(values.get("new_circuit_period_seconds", 60)))
        self.startup_timeout = NoWheelSpinBox(content)
        self.startup_timeout.setRange(15, 900)
        self.startup_timeout.setValue(int(values.get("startup_timeout_seconds", 180)))
        self.shutdown_timeout = NoWheelSpinBox(content)
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
        self.proxy_port = NoWheelSpinBox(content)
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
        self._service_traffic_widgets: dict[str, dict[str, QLabel]] = {}
        self._last_snapshot = None
        self._last_services = None
        self._last_visible_service_ids: tuple[str, ...] = ()
        self._last_rendered_services: list[dict] | None = None
        self._last_traffic_snapshots: dict = {}
        self._dashboard_initialized = False
        self._dashboard_refresh_in_progress = False
        self._dashboard_refresh_pending = False
        self._dashboard_worker = None
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
        self.runtime_logs_button = QPushButton("Tor runtime logs", runtime)
        self.runtime_logs_button.setObjectName("onionActionButton")
        self.runtime_logs_button.setIcon(qta.icon("fa6s.file-lines"))
        self.runtime_logs_button.clicked.connect(self.open_runtime_logs)
        actions.addWidget(self.runtime_logs_button)
        actions.addStretch(1)
        runtime_layout.addLayout(actions)
        root.addWidget(runtime)

        traffic_summary = QFrame(self)
        traffic_summary.setObjectName("onionTrafficSummary")
        traffic_summary_layout = QHBoxLayout(traffic_summary)
        traffic_summary_layout.setContentsMargins(10, 7, 10, 7)
        traffic_summary_layout.setSpacing(8)
        self._global_traffic_labels: dict[str, QLabel] = {}
        for key, title in (
            ("incoming_bytes", "TOTAL IN"),
            ("outgoing_bytes", "TOTAL OUT"),
            ("http_requests", "HTTP SESSIONS"),
            ("connections", "CONNECTIONS"),
            ("errors", "ERRORS"),
            ("active_connections", "ACTIVE"),
        ):
            metric = QFrame(traffic_summary)
            metric.setObjectName("onionTrafficMetric")
            if key == "incoming_bytes":
                metric.setToolTip("Bytes received from Onion visitors by the hosted applications.")
            elif key == "outgoing_bytes":
                metric.setToolTip("Bytes sent from the hosted applications back to Onion visitors.")
            elif key == "http_requests":
                metric.setToolTip("Detected plaintext HTTP sessions, one first request line per TCP connection.")
            metric_layout = QVBoxLayout(metric)
            metric_layout.setContentsMargins(9, 4, 9, 4)
            metric_layout.setSpacing(2)
            caption = QLabel(title, metric)
            caption.setObjectName("onionTrafficCaption")
            value = QLabel("0", metric)
            value.setObjectName("onionTrafficValue")
            metric_layout.addWidget(caption)
            metric_layout.addWidget(value)
            traffic_summary_layout.addWidget(metric, 1)
            self._global_traffic_labels[key] = value
        root.addWidget(traffic_summary)

        service_header = QHBoxLayout()
        service_title = QLabel("Onion Services", self)
        service_title.setObjectName("onionSectionTitle")
        service_header.addWidget(service_title)
        self.services_count_label = QLabel("0 services", self)
        self.services_count_label.setObjectName("onionCountPill")
        service_header.addWidget(self.services_count_label)
        service_header.addStretch(1)

        self.service_search = QLineEdit(self)
        self.service_search.setObjectName("onionServiceSearch")
        self.service_search.setPlaceholderText("Filter services…")
        self.service_search.setClearButtonEnabled(True)
        self.service_search.setFixedWidth(190)
        self.service_search.textChanged.connect(lambda _text: self._refresh_cached_service_cards())
        service_header.addWidget(self.service_search)

        self.service_filter = QComboBox(self)
        self.service_filter.setObjectName("onionServiceFilter")
        self.service_filter.addItem("All states", "all")
        self.service_filter.addItem("Running", "running")
        self.service_filter.addItem("Stopped", "stopped")
        self.service_filter.addItem("Errors", "error")
        self.service_filter.setFixedWidth(112)
        self.service_filter.currentIndexChanged.connect(lambda _index: self._refresh_cached_service_cards())
        service_header.addWidget(self.service_filter)

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
        self._timer.setInterval(2500)
        self._timer.timeout.connect(self.refresh_dashboard)
        for button in (
            self.start_runtime_button, self.stop_runtime_button,
            self.restart_runtime_button, self.runtime_logs_button,
            self.add_service_button,
        ):
            button.setEnabled(False)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._timer.start()
        self.refresh_dashboard()

    def hideEvent(self, event) -> None:
        self._timer.stop()
        super().hideEvent(event)

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
            QFrame#onionPageHero, QFrame#onionRuntimeCard, QFrame#onionServiceCard,
            QFrame#onionTrafficSummary {{
                background: {panel}; border: 1px solid {border}; border-radius: 12px;
            }}
            QFrame#onionTrafficMetric {{
                background: {field}; border: 1px solid {border}; border-radius: 8px;
            }}
            QLabel#onionTrafficCaption {{
                color: {muted}; font-size: 8px; font-weight: 800; letter-spacing: 0.5px;
            }}
            QLabel#onionTrafficValue {{
                color: {text}; font-size: 13px; font-weight: 800;
            }}
            QLabel#onionServiceTraffic {{
                color: {muted}; font-size: 9px; padding: 2px 3px;
            }}
            QLineEdit#onionServiceSearch, QComboBox#onionServiceFilter {{
                min-height: 30px; padding: 2px 8px; border: 1px solid {border};
                border-radius: 8px; background: {field}; color: {text};
            }}
            QLineEdit#onionServiceSearch:focus, QComboBox#onionServiceFilter:focus {{
                border-color: {accent};
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
            QPushButton#onionQrButton {{
                min-width: 36px; max-width: 36px; min-height: 36px; max-height: 36px;
                padding: 0; border: 1px solid {border}; border-radius: 9px;
                background: {field}; color: {accent};
            }}
            QPushButton#onionQrButton:hover {{
                border-color: {accent}; background: {hover};
            }}
            QPushButton#onionQrButton:disabled {{
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
            QTableWidget#onionActivityTable {{
                background: {field}; alternate-background-color: {panel};
                color: {text}; gridline-color: {border};
                border: 1px solid {border}; border-radius: 8px;
                selection-background-color: {accent}; selection-color: #ffffff;
            }}
            QHeaderView::section {{
                background: {panel}; color: {muted}; border: none;
                border-bottom: 1px solid {border}; padding: 7px 8px;
                font-size: 9px; font-weight: 750;
            }}
            QLabel#onionActivitySummary {{
                color: {accent}; background: {field}; border: 1px solid {border};
                border-radius: 8px; padding: 8px 10px; font-size: 10px; font-weight: 800;
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

    def rotate_service_address(self, service: dict):
        choice = QMessageBox.question(
            self,
            "Generate a new Onion address",
            "This replaces the service's Tor identity. The current .onion address will stop working "
            "and cannot be restored. If the service is running, it will be stopped and republished "
            "with a short interruption. The local target and private client authorization key "
            "will be preserved. Continue?",
            StandardButton.Yes | StandardButton.No,
            StandardButton.No,
        )
        if choice != StandardButton.Yes:
            return

        manager = self._manager()
        service_id = str(service["id"])

        def rotate_and_restart():
            current = next(
                (item for item in manager.services_snapshot() if str(item["id"]) == service_id),
                None,
            )
            if current is None:
                raise OnionHostingError("The selected Onion Service no longer exists.")
            if current.get("running"):
                manager.stop_service(service_id)
            manager.rotate_service_identity(service_id)
            if manager.runtime_snapshot()["state"] == "ready":
                return manager.start_service(service_id)
            return ""

        def completed(result):
            address = str(result or "").strip().strip('"')
            if address and address.endswith(".onion"):
                extra = (
                    " Export/share a fresh client authorization line."
                    if service.get("access_mode") == "private" else ""
                )
                self.status_label.setText(
                    f"New Onion address created: {address}. Share the new address with visitors.{extra}"
                )
            else:
                self.status_label.setText(
                    "The old identity was removed. Start the service to create its new Onion address."
                )

        self.status_label.setText("Rotating the Onion Service identity…")
        self._run(f"service:{service_id}", rotate_and_restart, finished=completed)

    def open_service_activity(self, service: dict):
        manager = self._manager()
        OnionServiceActivityDialog(self, manager, service).exec()

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

    def _filtered_services(self, services: list[dict]) -> list[dict]:
        query = self.service_search.text().strip().casefold()
        selected_state = str(self.service_filter.currentData() or "all")
        result = []
        for service in services:
            state = (
                "error" if service.get("error")
                else "running" if service.get("running")
                else "stopped"
            )
            if selected_state != "all" and state != selected_state:
                continue
            searchable = " ".join((
                str(service.get("display_name", "")),
                str(service.get("address", "")),
                str(service.get("id", "")),
                str(service.get("local_host", "")),
                str(service.get("local_port", "")),
            )).casefold()
            if query and query not in searchable:
                continue
            result.append(service)
        return result

    def _refresh_traffic_metrics(self, snapshots: dict) -> None:
        totals = snapshots.get("global") or {}
        for key, label in self._global_traffic_labels.items():
            value = totals.get(key, 0)
            label.setText(
                _format_bytes(value)
                if key in {"incoming_bytes", "outgoing_bytes"}
                else f"{int(value):,}"
            )
        per_service = snapshots.get("services") or {}
        for service_id, labels in self._service_traffic_widgets.items():
            snapshot = per_service.get(service_id) or {}
            labels["incoming_bytes"].setText(_format_bytes(snapshot.get("incoming_bytes", 0)))
            labels["outgoing_bytes"].setText(_format_bytes(snapshot.get("outgoing_bytes", 0)))
            labels["http_requests"].setText(f"{int(snapshot.get('http_requests', 0)):,}")
            labels["errors"].setText(f"{int(snapshot.get('errors', 0)):,}")
            labels["active_connections"].setText(f"{int(snapshot.get('active_connections', 0)):,}")

    def _collect_dashboard_snapshot(self) -> str:
        """Collect runtime, profile inventory and SQLite counters off the GUI thread."""
        manager = self._manager()
        runtime = manager.runtime_snapshot()
        services = manager.services_snapshot()
        service_ids = [str(service["id"]) for service in services]
        batch_snapshot = getattr(manager, "traffic_snapshots", None)
        if callable(batch_snapshot):
            traffic = batch_snapshot(service_ids)
        else:
            # Keep the page usable with older manager implementations and test doubles.
            traffic = {
                "global": manager.traffic_snapshot(),
                "services": {
                    service_id: manager.traffic_snapshot(service_id)
                    for service_id in service_ids
                },
            }
        return json.dumps(
            {"runtime": runtime, "services": services, "traffic": traffic},
            separators=(",", ":"), default=str,
        )

    def refresh_dashboard(self):
        if not self.isVisible():
            return
        if self._dashboard_refresh_in_progress:
            self._dashboard_refresh_pending = True
            return
        self._dashboard_refresh_in_progress = True
        worker = Worker(self._collect_dashboard_snapshot)
        worker.signals.finished.connect(self._on_dashboard_snapshot)
        worker.signals.error.connect(self._on_dashboard_snapshot_failed)
        self._dashboard_worker = worker
        self._thread_pool.start(worker)

    def _on_dashboard_snapshot(self, result: str) -> None:
        self._dashboard_refresh_in_progress = False
        self._dashboard_worker = None
        try:
            payload = json.loads(result)
            runtime = payload["runtime"]
            services = payload.get("services") or []
            traffic = payload.get("traffic") or {}
        except (TypeError, ValueError, KeyError) as exc:
            self._on_dashboard_snapshot_failed(f"Invalid dashboard snapshot: {exc}")
            return

        self._dashboard_initialized = True
        self._last_traffic_snapshots = traffic
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
            self.runtime_metrics.setText(
                f"{version}  ·  {memory_text}  ·  {uptime // 3600:02d}:{(uptime // 60) % 60:02d}:{uptime % 60:02d}"
            )

        self._last_services = [dict(item) for item in services]
        self.services_count_label.setText(
            f"{len(services)} service" + ("" if len(services) == 1 else "s")
        )
        self._refresh_cached_service_cards()
        state = str(runtime["state"]).lower()
        self.start_runtime_button.setEnabled(state in {"stopped", "failed"} and "runtime" not in self._workers)
        self.stop_runtime_button.setEnabled(state != "stopped" and "runtime" not in self._workers)
        self.restart_runtime_button.setEnabled(state != "stopped" and "runtime" not in self._workers)
        self.runtime_logs_button.setEnabled(True)
        self.add_service_button.setEnabled(True)

        if self._dashboard_refresh_pending:
            self._dashboard_refresh_pending = False
            QTimer.singleShot(0, self.refresh_dashboard)

    def _on_dashboard_snapshot_failed(self, error: str) -> None:
        self._dashboard_refresh_in_progress = False
        self._dashboard_worker = None
        self.runtime_message.setText(f"Dashboard refresh failed: {error}")
        logger.warning("Developer Tor dashboard refresh failed: %s", error)
        if self._dashboard_refresh_pending and self.isVisible():
            self._dashboard_refresh_pending = False
            QTimer.singleShot(0, self.refresh_dashboard)

    def _refresh_cached_service_cards(self) -> None:
        if self._last_services is None:
            return
        visible = self._filtered_services(self._last_services)
        visible_ids = tuple(str(item["id"]) for item in visible)
        if visible != self._last_rendered_services or visible_ids != self._last_visible_service_ids:
            self._last_rendered_services = [dict(item) for item in visible]
            self._last_visible_service_ids = visible_ids
            self._rebuild_service_cards(visible, total_count=len(self._last_services))
        self._refresh_traffic_metrics(self._last_traffic_snapshots)

    def _rebuild_service_cards(self, services: list[dict], *, total_count: int = 0):
        # The empty-state label is permanent. Only remove cards created by the
        # previous snapshot; deleting the placeholder left a live Python wrapper
        # around an already-destroyed QLabel and crashed the next refresh.
        for card in self._service_card_widgets:
            self.services_layout.removeWidget(card)
            card.hide()
            card.deleteLater()
        self._service_card_widgets.clear()
        self._service_traffic_widgets.clear()

        self.empty_label.setText(
            "No Onion Services yet. Create one to publish a local web application."
            if total_count == 0 else "No services match the current search or state filter."
        )
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
        address_row = QHBoxLayout()
        address_row.setContentsMargins(0, 0, 0, 0)
        address_row.setSpacing(8)
        address_label = QLabel(address, card)
        address_label.setObjectName("onionServiceAddress")
        address_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        address_label.setWordWrap(True)
        address_row.addWidget(address_label, 1)

        private_service = service.get("access_mode") == "private"
        qr_description = (
            "Scan with Tor Browser to open this Onion Service. "
            "This is a private service, so visitors also need its client authorization key."
            if private_service else
            "Scan with Tor Browser to open this Onion Service address."
        )
        qr_button = QrCodeButton(
            f"http://{address}" if service.get("address") else "",
            parent=card,
            button_text="",
            title=f"Share · {service.get('display_name', 'Onion Service')}",
            description=qr_description,
            display_value=address if service.get("address") else None,
            center_icon="fa6s.shield-halved",
        )
        qr_button.setObjectName("onionQrButton")
        qr_button.setFixedSize(36, 36)
        qr_button.setToolTip("Show Onion address as a QR code")
        qr_button.setEnabled(bool(service.get("address")))
        address_row.addWidget(qr_button, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(address_row)

        lifetime = "Persistent" if service.get("persistent") else "Temporary"
        access = "Private access" if service.get("access_mode") == "private" else "Public access"
        mappings = service.get("port_mappings") or [{
            "onion_port": service["onion_port"],
            "local_host": service["local_host"],
            "local_port": service["local_port"],
        }]
        mapping_summary = " · ".join(
            f"{item.get('onion_port')}→{item.get('local_host')}:{item.get('local_port')}"
            for item in mappings
        )
        detail = QLabel(
            f"{mapping_summary}  ·  {lifetime}  ·  {access}",
            card,
        )
        detail.setObjectName("onionServiceDetail")
        layout.addWidget(detail)

        traffic_row = QHBoxLayout()
        traffic_row.setContentsMargins(0, 0, 0, 0)
        traffic_row.setSpacing(14)
        traffic_labels = {}
        for key, caption in (
            ("incoming_bytes", "IN"),
            ("outgoing_bytes", "OUT"),
            ("http_requests", "HTTP"),
            ("errors", "ERR"),
            ("active_connections", "ACTIVE"),
        ):
            metric = QHBoxLayout()
            metric.setContentsMargins(0, 0, 0, 0)
            metric.setSpacing(5)
            title = QLabel(caption, card)
            title.setObjectName("onionTrafficCaption")
            value = QLabel("0", card)
            value.setObjectName("onionServiceTraffic")
            value.setToolTip(
                "Detected plaintext HTTP sessions (one first request line per TCP connection)."
                if key == "http_requests" else
                "Failed or aborted local relay connections." if key == "errors" else caption.title()
            )
            metric.addWidget(title)
            metric.addWidget(value)
            traffic_row.addLayout(metric)
            traffic_labels[key] = value
        traffic_row.addStretch(1)
        layout.addLayout(traffic_row)
        self._service_traffic_widgets[str(service["id"])] = traffic_labels

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

        activity = QPushButton("Request logs", card)
        activity.setObjectName("onionActionButton")
        activity.setIcon(qta.icon("fa6s.chart-line"))
        activity.setToolTip("Open request and traffic history for this Onion Service")
        activity.clicked.connect(
            lambda _checked=False, data=dict(service): self.open_service_activity(data)
        )
        actions.addWidget(activity)

        new_address = QPushButton("New address", card)
        new_address.setObjectName("onionActionButton")
        new_address.setIcon(qta.icon("fa6s.arrows-rotate"))
        new_address.setToolTip(
            "Rotate the identity. A running service is stopped and republished with a short interruption."
        )
        new_address.setEnabled(
            bool(service.get("address")) and f"service:{service['id']}" not in self._workers
        )
        new_address.clicked.connect(
            lambda _checked=False, data=dict(service): self.rotate_service_address(data)
        )
        actions.addWidget(new_address)

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
