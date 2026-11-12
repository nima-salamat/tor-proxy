from __future__ import annotations

import logging
import re
from pathlib import Path

import qtawesome as qta
from PySide6.QtCore import Qt, QThreadPool, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QToolButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from config import CONFIG
from torproxy.bridges import parse_bridge_text
from torproxy.service_pool import TorServicePoolError
from torproxy.service_credentials import (
    read_upstream_credentials,
    write_upstream_credentials,
    delete_upstream_credentials,
)
from ui_.worker.worker import Worker
from ui_.window.dialogs import QMessageBox, _FramelessDialog
from ui_.window.tor_log_dialog import TorLogDialog
from torproxy.paths import user_directories

logger = logging.getLogger(__name__)
_SERVICE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class TorServicesSettingsPage(QWidget):
    """Persistent configuration controls for the Custom Tor manager."""

    def __init__(self, parent=None, *, app_window=None):
        super().__init__(parent)
        self._app_window = app_window
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        title = QLabel("Custom Tor configuration")
        title.setObjectName("settingsSectionTitle")
        layout.addWidget(title)
        description = QLabel(
            "Configure how the primary Tor connection and custom Tor services use system resources. "
            "Service profiles, listener ports, bridges and start/stop controls are managed on the separate Custom Tor page."
        )
        description.setObjectName("settingsDescription")
        description.setWordWrap(True)
        layout.addWidget(description)

        self._spins: dict[str, QSpinBox] = {}
        self._status = QLabel("Settings are saved automatically when changed.")
        self._status.setObjectName("settingsDescription")
        self._status.setWordWrap(True)

        self._add_setting(layout, "Main Tor instances", "Number of isolated Tor workers behind the primary SOCKS endpoint.", "primary_tor_instances", 1, 4, " instances", 2)
        self._add_choice_setting(
            layout,
            "Backend selection strategy",
            "Balanced distributes new connections across healthy instances; Low latency prefers the lowest rolling end-to-end delay.",
            "tor_backend_selection_mode",
            (("Balanced", "balanced"), ("Low latency", "latency")),
            "balanced",
        )
        self._add_setting(layout, "Concurrent bridge probes", "Maximum number of parallel bridge preflight checks (CPU/memory use increases with this value).", "bridge_probe_workers", 1, 8, " workers", 8)
        self._add_setting(layout, "Concurrent service operations", "Maximum number of independent custom Tor services started or stopped together.", "tor_service_workers", 1, 8, " workers", 4)

        health_title = QLabel("Primary connection health")
        health_title.setObjectName("settingsSectionTitle")
        layout.addWidget(health_title)
        self.primary_health = QLabel("Primary Tor pool is not running.")
        self.primary_health.setObjectName("settingsDescription")
        self.primary_health.setWordWrap(True)
        layout.addWidget(self.primary_health)

        management = QFrame(self)
        management.setObjectName("settingsRowCard")
        management_layout = QHBoxLayout(management)
        management_layout.setContentsMargins(14, 10, 14, 10)
        management_layout.setSpacing(12)
        copy = QVBoxLayout()
        copy.setSpacing(3)
        management_title = QLabel("Manage custom Tor services")
        management_title.setObjectName("settingsFieldLabel")
        management_description = QLabel("Create profiles, assign listener ports, start or stop Tor processes and inspect live logs from the Custom Tor page.")
        management_description.setObjectName("settingsDescription")
        management_description.setWordWrap(True)
        copy.addWidget(management_title)
        copy.addWidget(management_description)
        management_layout.addLayout(copy, 1)
        self.open_manager_button = QPushButton("Open Custom Tor", management)
        self.open_manager_button.setObjectName("settingsActionButton")
        self.open_manager_button.setIcon(qta.icon("fa6s.arrow-up-right-from-square"))
        self.open_manager_button.clicked.connect(self._open_manager)
        management_layout.addWidget(self.open_manager_button)
        layout.addWidget(management)
        layout.addWidget(self._status)
        layout.addStretch(1)

        proxy = getattr(app_window, "proxyWidget", None)
        primary_tor = getattr(proxy, "tor", None)
        signal = getattr(primary_tor, "bridge_usage_changed", None)
        connect = getattr(signal, "connect", None)
        if callable(connect):
            connect(self._update_primary_health)
        snapshot = getattr(primary_tor, "pool_health_snapshot", None)
        if isinstance(snapshot, dict):
            self._update_primary_health(snapshot)

    def _add_setting(self, layout, title, description, key, minimum, maximum, suffix, fallback):
        row = QFrame(self)
        row.setObjectName("settingsRowCard")
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(14, 10, 14, 10)
        row_layout.setSpacing(12)
        copy = QVBoxLayout()
        copy.setSpacing(3)
        label = QLabel(title)
        label.setObjectName("settingsFieldLabel")
        detail = QLabel(description)
        detail.setObjectName("settingsDescription")
        detail.setWordWrap(True)
        copy.addWidget(label)
        copy.addWidget(detail)
        row_layout.addLayout(copy, 1)
        spin = QSpinBox(row)
        spin.setRange(minimum, maximum)
        spin.setSuffix(suffix)
        spin.setValue(int(CONFIG[key] or fallback))
        spin.valueChanged.connect(lambda value, setting=key, control=spin: self._save_setting(setting, value, control))
        row_layout.addWidget(spin)
        self._spins[key] = spin
        layout.addWidget(row)

    def _add_choice_setting(self, layout, title, description, key, choices, fallback):
        row = QFrame(self)
        row.setObjectName("settingsRowCard")
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(14, 10, 14, 10)
        row_layout.setSpacing(12)
        copy = QVBoxLayout()
        copy.setSpacing(3)
        label = QLabel(title)
        label.setObjectName("settingsFieldLabel")
        detail = QLabel(description)
        detail.setObjectName("settingsDescription")
        detail.setWordWrap(True)
        copy.addWidget(label)
        copy.addWidget(detail)
        row_layout.addLayout(copy, 1)
        combo = QComboBox(row)
        for label_text, value in choices:
            combo.addItem(label_text, value)
        current = str(CONFIG[key] or fallback)
        index = combo.findData(current)
        combo.setCurrentIndex(index if index >= 0 else 0)
        combo.currentIndexChanged.connect(
            lambda _index, setting=key, control=combo: self._save_choice_setting(
                setting, control.currentData(), control
            )
        )
        row_layout.addWidget(combo)
        layout.addWidget(row)

    def _save_choice_setting(self, key: str, value: str, control: QComboBox) -> None:
        previous = str(CONFIG[key] or "balanced")
        tor_runner = None
        try:
            proxy = getattr(self._app_window, "proxyWidget", None)
            tor_runner = getattr(proxy, "tor", None)
            setter = getattr(tor_runner, "set_backend_selection_mode", None)
            if callable(setter):
                setter(value)
            CONFIG[key] = value
            self._status.setText(
                "Saved backend selection strategy. It applies immediately to new connections."
            )
        except Exception as exc:
            setter = getattr(tor_runner, "set_backend_selection_mode", None)
            if callable(setter):
                try:
                    setter(previous)
                except Exception:
                    logger.exception("Could not roll back the primary Tor backend selection strategy.")
            blocked = control.blockSignals(True)
            old_index = control.findData(previous)
            if old_index >= 0:
                control.setCurrentIndex(old_index)
            control.blockSignals(blocked)
            self._status.setText(f"Could not save {key.replace('_', ' ')}: {exc}")
            QMessageBox.warning(self, "Settings could not be saved", str(exc))

    def _save_setting(self, key: str, value: int, control: QSpinBox) -> None:
        previous = int(CONFIG[key] or control.minimum())
        pool = None
        try:
            if key == "tor_service_workers":
                proxy = getattr(self._app_window, "proxyWidget", None)
                pool = getattr(proxy, "tor_service_pool", None)
                if pool is not None:
                    pool.set_max_workers(int(value))
                dashboard = getattr(self._app_window, "customTorWidget", None)
                set_stop_limit = getattr(dashboard, "set_stop_worker_limit", None)
                if callable(set_stop_limit):
                    set_stop_limit(int(value))
            CONFIG[key] = int(value)
            self._status.setText(f"Saved {key.replace('_', ' ')}: {value}.")
        except Exception as exc:
            # The runtime pool and the on-disk preference are one logical setting.
            # If config persistence fails after the pool changes, restore both.
            if key == "tor_service_workers":
                if pool is not None:
                    try:
                        pool.set_max_workers(previous)
                    except Exception:
                        logger.exception("Could not roll back the custom Tor pool worker limit.")
                dashboard = getattr(self._app_window, "customTorWidget", None)
                set_stop_limit = getattr(dashboard, "set_stop_worker_limit", None)
                if callable(set_stop_limit):
                    set_stop_limit(previous)
            blocked = control.blockSignals(True)
            control.setValue(previous)
            control.blockSignals(blocked)
            self._status.setText(f"Could not save {key.replace('_', ' ')}: {exc}")
            QMessageBox.warning(self, "Settings could not be saved", str(exc))

    def _update_primary_health(self, health) -> None:
        if not isinstance(health, dict):
            return
        ready = max(0, int(health.get("ready_instances", 0) or 0))
        total = max(0, int(health.get("total_instances", 0) or 0))
        if total <= 0:
            self.primary_health.setText("Primary Tor pool is not running.")
            return
        details = []
        for item in health.get("instances", []):
            if not isinstance(item, dict):
                continue
            try:
                index = int(item.get("index", len(details) + 1) or len(details) + 1)
                latency_value = item.get("latency_p50_ms")
                if latency_value is None:
                    latency_value = item.get("latency_ms")
                latency = float(latency_value) if latency_value is not None else None
            except (TypeError, ValueError):
                index, latency = len(details) + 1, None
            if item.get("healthy"):
                verification = "Tor Check verified" if item.get("verified_tor") else "reachable"
                quality_parts = [verification]
                if latency is not None:
                    quality_parts.append(f"median {latency:.0f} ms")
                for metric_key, label in (
                    ("latency_p95_ms", "P95"),
                    ("jitter_ms", "jitter"),
                ):
                    metric = item.get(metric_key)
                    if metric is not None:
                        try:
                            quality_parts.append(f"{label} {float(metric):.0f} ms")
                        except (TypeError, ValueError):
                            pass
                failure_ratio = item.get("probe_failure_ratio")
                if failure_ratio is not None:
                    try:
                        quality_parts.append(f"probe failures {float(failure_ratio) * 100:.0f}%")
                    except (TypeError, ValueError):
                        pass
                health_label = (
                    "Degraded"
                    if str(item.get("state", "")).lower() == "degraded"
                    else "Healthy"
                )
                state = health_label + " · " + " · ".join(quality_parts)
            else:
                state = str(item.get("state", "starting")).replace("-", " ").title()
            circuit = item.get("circuit_metrics") or {}
            if isinstance(circuit, dict):
                failed_circuits = int(circuit.get("circuits_failed", 0) or 0)
                built_circuits = int(circuit.get("circuits_built", 0) or 0)
                failed_streams = int(circuit.get("streams_failed", 0) or 0)
                state += f" · circuits built {built_circuits} / failed {failed_circuits} · streams failed {failed_streams}"
            circuit_failure = item.get("circuit_failure_ratio")
            if circuit_failure is not None:
                try:
                    state += f" · recent circuit failures {float(circuit_failure) * 100:.0f}%"
                except (TypeError, ValueError):
                    pass
            or_failure = item.get("or_connection_failure_ratio")
            if or_failure is not None:
                try:
                    state += f" · recent OR connection failures {float(or_failure) * 100:.0f}%"
                except (TypeError, ValueError):
                    pass
            details.append(f"Instance {index}: {state}")
        self.primary_health.setText(
            f"{ready}/{total} usable primary Tor instance(s)\n" + "  |  ".join(details)
        )

    def refresh_health(self) -> None:
        proxy = getattr(self._app_window, "proxyWidget", None)
        primary_tor = getattr(proxy, "tor", None)
        snapshot = getattr(primary_tor, "pool_health_snapshot", None)
        if isinstance(snapshot, dict):
            self._update_primary_health(snapshot)

    def _open_manager(self) -> None:
        show = getattr(self._app_window, "_show_custom_tor", None)
        if callable(show):
            show()


class TorServiceEditorDialog(_FramelessDialog):
    """Create or edit one persisted, independently isolated Tor profile."""

    def __init__(self, profile: dict | None = None, parent=None):
        editing = profile is not None
        super().__init__(
            parent,
            "Edit custom Tor service" if editing else "Create custom Tor service",
            "fa6s.server",
            "#287db5",
            width=560,
        )
        self._source_profile = dict(profile or {})
        self.profile: dict | None = None
        primary_tor = getattr(parent, "_primary_tor", None)
        self._legacy_max_circuit_dirtiness = int(getattr(primary_tor, "MaxCircuitDirtiness", 600) or 600)
        self._legacy_new_circuit_period = int(getattr(primary_tor, "NewCircuitPeriod", 60) or 60)
        layout = self.body_layout
        intro = QLabel(
            "Each profile runs its own Tor process with a separate DataDirectory, "
            "ControlPort cookie, log file and listener ports."
        )
        intro.setWordWrap(True)
        intro.setObjectName("settingsDescription")
        layout.addWidget(intro)

        form = QFormLayout()
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(10)
        layout.addLayout(form)

        self.inp_id = QLineEdit(str(self._source_profile.get("id", "")))
        self.inp_id.setMaxLength(64)
        self.inp_id.setPlaceholderText("e.g. personal or work")
        if editing:
            self.inp_id.setReadOnly(True)
        form.addRow("Profile ID", self.inp_id)

        self.inp_display_name = QLineEdit(
            str(self._source_profile.get("display_name") or self._source_profile.get("id", ""))
        )
        self.inp_display_name.setMaxLength(80)
        self.inp_display_name.setPlaceholderText("A readable name")
        form.addRow("Display name", self.inp_display_name)

        suggested_socks, suggested_control = self._suggest_listener_ports()
        self.inp_socks_port = self._port_spin(
            self._source_profile.get("socks_port", suggested_socks), minimum=1
        )
        self.inp_control_port = self._port_spin(
            self._source_profile.get("control_port", suggested_control), minimum=1
        )
        self.inp_dns_port = self._port_spin(
            self._source_profile.get("dns_port") or 0, minimum=0
        )
        form.addRow("SOCKS port", self.inp_socks_port)
        form.addRow("ControlPort", self.inp_control_port)
        dns_row = QWidget(self)
        dns_layout = QHBoxLayout(dns_row)
        dns_layout.setContentsMargins(0, 0, 0, 0)
        dns_layout.addWidget(self.inp_dns_port)
        dns_hint = QLabel("0 disables DNSPort")
        dns_hint.setObjectName("settingsDescription")
        dns_layout.addWidget(dns_hint, 1)
        form.addRow("DNS port", dns_row)

        self.chk_use_primary_bridges = QCheckBox(
            "Use the primary Tor service's bridge settings"
        )
        self.chk_use_primary_bridges.setChecked(
            bool(self._source_profile.get("use_primary_bridges", True))
        )
        form.addRow("Bridge source", self.chk_use_primary_bridges)

        self.chk_bridges_enabled = QCheckBox("Enable bridges for this profile")
        self.chk_bridges_enabled.setChecked(bool(self._source_profile.get("bridge_enabled", False)))
        form.addRow("Profile bridges", self.chk_bridges_enabled)

        self.txt_bridges = QTextEdit()
        self.txt_bridges.setAcceptRichText(False)
        self.txt_bridges.setFixedHeight(112)
        self.txt_bridges.setPlaceholderText(
            "Paste one complete Tor bridge record per line.\n"
            "Used only when the primary bridge settings option is unchecked."
        )
        self.txt_bridges.setPlainText(str(self._source_profile.get("bridges") or ""))
        form.addRow("Bridge records", self.txt_bridges)

        path_row = QWidget(self)
        path_layout = QHBoxLayout(path_row)
        path_layout.setContentsMargins(0, 0, 0, 0)
        self.inp_data_directory = QLineEdit(
            str(self._source_profile.get("data_directory") or "")
        )
        self.inp_data_directory.setPlaceholderText(
            "Automatic: user data / tor-services / profile-id"
        )
        self.btn_browse_data = QPushButton("Browse…", path_row)
        self.btn_browse_data.setObjectName("settingsActionButton")
        self.btn_browse_data.clicked.connect(self._browse_data_directory)
        path_layout.addWidget(self.inp_data_directory, 1)
        path_layout.addWidget(self.btn_browse_data)
        form.addRow("Data directory", path_row)

        self.btn_advanced_network = QToolButton(self)
        self.btn_advanced_network.setText("Advanced network options")
        self.btn_advanced_network.setCheckable(True)
        self.btn_advanced_network.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.btn_advanced_network.setIcon(qta.icon("fa6s.sliders"))
        layout.addWidget(self.btn_advanced_network)
        self.network_options_container = QWidget(self)
        network_options_layout = QVBoxLayout(self.network_options_container)
        network_options_layout.setContentsMargins(10, 2, 0, 2)
        network_options_layout.setSpacing(8)
        network_title = QLabel("Network options")
        network_title.setObjectName("settingsSectionTitle")
        network_options_layout.addWidget(network_title)
        self.inp_upstream_proxy_type = QComboBox(self)
        self.inp_upstream_proxy_type.addItem("Direct · no upstream proxy", "none")
        self.inp_upstream_proxy_type.addItem("SOCKS5 proxy", "socks5")
        self.inp_upstream_proxy_type.addItem("HTTP CONNECT proxy", "https")
        self.inp_upstream_proxy_type.setCurrentIndex(max(0, self.inp_upstream_proxy_type.findData(
            self._source_profile.get("upstream_proxy_type", "none")
        )))
        self.inp_upstream_proxy_host = QLineEdit(str(self._source_profile.get("upstream_proxy_host", "")))
        self.inp_upstream_proxy_host.setPlaceholderText("127.0.0.1 or proxy.example.net")
        self.inp_upstream_proxy_port = self._port_spin(self._source_profile.get("upstream_proxy_port", 1080), minimum=1)
        try:
            saved_credentials = read_upstream_credentials(str(self._source_profile.get("id", "pending")))
        except Exception:
            saved_credentials = {"upstream_proxy_username": "", "upstream_proxy_password": ""}
        self.inp_upstream_proxy_username = QLineEdit(saved_credentials["upstream_proxy_username"])
        self.inp_upstream_proxy_password = QLineEdit(saved_credentials["upstream_proxy_password"])
        self.inp_upstream_proxy_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.inp_upstream_proxy_password.setPlaceholderText("Stored outside config.json")
        network_form = QFormLayout()
        network_form.setHorizontalSpacing(14)
        network_form.setVerticalSpacing(8)
        network_form.addRow("Upstream proxy", self.inp_upstream_proxy_type)
        network_form.addRow("Proxy host", self.inp_upstream_proxy_host)
        network_form.addRow("Proxy port", self.inp_upstream_proxy_port)
        network_form.addRow("Proxy username", self.inp_upstream_proxy_username)
        network_form.addRow("Proxy password", self.inp_upstream_proxy_password)
        network_options_layout.addLayout(network_form)

        self.chk_client_ipv4 = QCheckBox("Allow IPv4")
        self.chk_client_ipv4.setChecked(bool(self._source_profile.get("client_use_ipv4", True)))
        self.chk_client_ipv6 = QCheckBox("Allow IPv6")
        self.chk_client_ipv6.setChecked(bool(self._source_profile.get("client_use_ipv6", True)))
        family_row = QHBoxLayout()
        family_row.addWidget(self.chk_client_ipv4)
        family_row.addWidget(self.chk_client_ipv6)
        family_row.addStretch(1)
        network_options_layout.addLayout(family_row)

        timing_form = QFormLayout()
        self.spin_max_circuit_dirtiness = QSpinBox(self)
        self.spin_max_circuit_dirtiness.setRange(10, 86400)
        self.spin_max_circuit_dirtiness.setSuffix(" sec")
        self.spin_max_circuit_dirtiness.setValue(int(self._source_profile.get("max_circuit_dirtiness_seconds", self._legacy_max_circuit_dirtiness)))
        self.spin_new_circuit_period = QSpinBox(self)
        self.spin_new_circuit_period.setRange(10, 86400)
        self.spin_new_circuit_period.setSuffix(" sec")
        self.spin_new_circuit_period.setValue(int(self._source_profile.get("new_circuit_period_seconds", self._legacy_new_circuit_period)))
        self.spin_startup_timeout = QSpinBox(self)
        self.spin_startup_timeout.setRange(15, 900)
        self.spin_startup_timeout.setSuffix(" sec")
        self.spin_startup_timeout.setValue(int(self._source_profile.get("startup_timeout_seconds", 180)))
        self.spin_shutdown_timeout = QSpinBox(self)
        self.spin_shutdown_timeout.setRange(1, 60)
        self.spin_shutdown_timeout.setSuffix(" sec")
        self.spin_shutdown_timeout.setValue(int(self._source_profile.get("shutdown_timeout_seconds", 5)))
        timing_form.addRow("Max circuit dirtiness", self.spin_max_circuit_dirtiness)
        timing_form.addRow("New circuit period", self.spin_new_circuit_period)
        timing_form.addRow("Startup timeout", self.spin_startup_timeout)
        timing_form.addRow("Shutdown timeout", self.spin_shutdown_timeout)
        network_options_layout.addLayout(timing_form)

        network_hint = QLabel(
            "Network settings are isolated per profile. Proxy credentials are stored in a permission-restricted file, "
            "not in config.json. Changing these values requires the profile to be stopped and restarted.",
            self,
        )
        network_hint.setObjectName("settingsDescription")
        network_hint.setWordWrap(True)
        network_options_layout.addWidget(network_hint)
        layout.addWidget(self.network_options_container)
        advanced_options_used = (
            self.inp_upstream_proxy_type.currentData() != "none"
            or not self.chk_client_ipv4.isChecked()
            or not self.chk_client_ipv6.isChecked()
            or self.spin_max_circuit_dirtiness.value() != self._legacy_max_circuit_dirtiness
            or self.spin_new_circuit_period.value() != self._legacy_new_circuit_period
            or self.spin_startup_timeout.value() != 180
            or self.spin_shutdown_timeout.value() != 5
        )
        self.btn_advanced_network.setChecked(advanced_options_used)
        self.btn_advanced_network.toggled.connect(self._toggle_network_options)
        self._toggle_network_options(advanced_options_used)

        self.lbl_error = QLabel("")
        self.lbl_error.setObjectName("settingsDescription")
        self.lbl_error.setWordWrap(True)
        layout.addWidget(self.lbl_error)

        self.add_footer_spacer()
        self.add_button("Cancel", primary=False, callback=self.reject)
        self.add_button("Save changes" if editing else "Create service", primary=True, callback=self.accept)
        self.resize(620, 680)
        if self.btn_advanced_network.isChecked():
            self.adjustSize()
        self._remember_preferred_size()
        self.setStyleSheet(self.styleSheet() + f"""
            QLineEdit, QTextEdit, QSpinBox {{
                background: {self._colors['panel']}; color: {self._colors['text']};
                border: 1px solid {self._colors['border']}; border-radius: 7px; padding: 7px 9px;
            }}
            QLineEdit:focus, QTextEdit:focus, QSpinBox:focus {{ border-color: {self._accent}; }}
            QCheckBox {{ color: {self._colors['text']}; spacing: 7px; }}
        """)

        self.chk_use_primary_bridges.toggled.connect(self._sync_bridge_controls)
        self.chk_bridges_enabled.toggled.connect(self._sync_bridge_controls)
        self.inp_upstream_proxy_type.currentIndexChanged.connect(self._sync_network_controls)
        self._sync_bridge_controls()
        self._sync_network_controls()

    def _toggle_network_options(self, expanded: bool) -> None:
        self.network_options_container.setVisible(bool(expanded))
        self.btn_advanced_network.setText(
            "Hide advanced network options" if expanded else "Advanced network options"
        )
        self.adjustSize()
        self._remember_preferred_size()

    def _sync_network_controls(self, *_args) -> None:
        enabled = self.inp_upstream_proxy_type.currentData() != "none"
        for widget in (
            self.inp_upstream_proxy_host,
            self.inp_upstream_proxy_port,
            self.inp_upstream_proxy_username,
            self.inp_upstream_proxy_password,
        ):
            widget.setEnabled(enabled)

    def _suggest_listener_ports(self) -> tuple[int, int]:
        """Suggest a free adjacent SOCKS/ControlPort pair for a new profile."""
        used = set()
        for item in CONFIG["tor_services"] or []:
            if not isinstance(item, dict):
                continue
            for key in ("socks_port", "control_port", "dns_port"):
                value = item.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value:
                    used.add(value)
        proxy = getattr(self.parent(), "_proxy", None)
        if proxy is not None:
            used.update(
                int(value) for value in (
                    getattr(proxy, "tor_socks_port", None),
                    getattr(proxy, "tor_control_port", None),
                    getattr(proxy, "tor_dns_port", None),
                    getattr(proxy, "proxy_port", None),
                ) if value
            )
        candidate = 19155
        while candidate < 65534:
            if candidate not in used and candidate + 1 not in used:
                return candidate, candidate + 1
            candidate += 2
        return 49155, 49156

    @staticmethod
    def _port_spin(value, *, minimum: int) -> QSpinBox:
        spin = QSpinBox()
        spin.setRange(minimum, 65535)
        spin.setSingleStep(1)
        spin.setValue(int(value))
        spin.setMaximumWidth(180)
        return spin

    def _sync_bridge_controls(self, *_args) -> None:
        use_primary = self.chk_use_primary_bridges.isChecked()
        self.chk_bridges_enabled.setEnabled(not use_primary)
        custom_enabled = not use_primary and self.chk_bridges_enabled.isChecked()
        self.txt_bridges.setEnabled(custom_enabled)
        self.txt_bridges.setToolTip(
            "The profile's own bridge list is used when enabled."
            if custom_enabled
            else "Enable profile-specific bridges and disable primary bridge inheritance to edit this list."
        )

    def _browse_data_directory(self) -> None:
        selected = QFileDialog.getExistingDirectory(
            self,
            "Choose an isolated Tor DataDirectory",
            self.inp_data_directory.text().strip() or str(Path.home()),
        )
        if selected:
            self.inp_data_directory.setText(str(Path(selected).expanduser().resolve(strict=False)))

    def _validated_profile(self) -> dict:
        service_id = self.inp_id.text().strip()
        if not _SERVICE_ID_PATTERN.fullmatch(service_id):
            raise ValueError(
                "Profile ID must start with a letter or digit and contain only letters, digits, '.', '_' or '-'."
            )
        display_name = self.inp_display_name.text().strip() or service_id
        if len(display_name) > 80:
            raise ValueError("Display name must contain at most 80 characters.")

        socks_port = self.inp_socks_port.value()
        control_port = self.inp_control_port.value()
        dns_port = self.inp_dns_port.value() or None
        ports = [socks_port, control_port] + ([dns_port] if dns_port else [])
        if len(ports) != len(set(ports)):
            raise ValueError("SOCKS, ControlPort and DNSPort must use different ports.")

        use_primary = self.chk_use_primary_bridges.isChecked()
        bridge_enabled = self.chk_bridges_enabled.isChecked() if not use_primary else False
        bridge_text = self.txt_bridges.toPlainText()
        parsed = parse_bridge_text(bridge_text)
        if bridge_text.strip() and parsed.invalid_records:
            details = " ".join(parsed.errors[:3])
            raise ValueError(f"One or more bridge records are invalid. {details}")
        if bridge_enabled and not parsed.records:
            raise ValueError("Add at least one valid bridge record or disable profile-specific bridges.")

        directory = self.inp_data_directory.text().strip()
        if directory:
            directory = str(Path(directory).expanduser().resolve(strict=False))

        proxy_type = str(self.inp_upstream_proxy_type.currentData())
        proxy_host = self.inp_upstream_proxy_host.text().strip()
        proxy_username = self.inp_upstream_proxy_username.text()
        proxy_password = self.inp_upstream_proxy_password.text()
        if proxy_type != "none" and not proxy_host:
            raise ValueError("Enter the upstream proxy host or choose Direct.")
        if proxy_type == "none":
            proxy_host = ""
            proxy_username = proxy_password = ""
        elif bool(proxy_username) != bool(proxy_password):
            raise ValueError("Enter both upstream proxy username and password, or leave both empty.")
        elif proxy_username and (
            len(proxy_username) > 255
            or len(proxy_password) > 255
            or any(ord(char) < 32 or ord(char) == 127 for char in proxy_username + proxy_password)
        ):
            raise ValueError("Upstream proxy credentials must be 1–255 printable characters.")
        if proxy_type == "https" and (":" in proxy_username or ":" in proxy_password):
            raise ValueError("HTTP CONNECT proxy credentials cannot contain a colon.")
        if not self.chk_client_ipv4.isChecked() and not self.chk_client_ipv6.isChecked():
            raise ValueError("At least one of IPv4 or IPv6 must be allowed.")

        return {
            "id": service_id,
            "display_name": display_name,
            "socks_port": socks_port,
            "control_port": control_port,
            "dns_port": dns_port,
            "use_primary_bridges": use_primary,
            "bridge_enabled": bridge_enabled,
            "bridges": "\n".join(parsed.records),
            "data_directory": directory or None,
            "upstream_proxy_type": proxy_type,
            "upstream_proxy_host": proxy_host,
            "upstream_proxy_port": int(self.inp_upstream_proxy_port.value()),
            # These two values are transient form data. _save_profile removes
            # them before config persistence and writes them to protected storage.
            "upstream_proxy_username": proxy_username,
            "upstream_proxy_password": proxy_password,
            "client_use_ipv4": bool(self.chk_client_ipv4.isChecked()),
            "client_use_ipv6": bool(self.chk_client_ipv6.isChecked()),
            "max_circuit_dirtiness_seconds": int(self.spin_max_circuit_dirtiness.value()),
            "new_circuit_period_seconds": int(self.spin_new_circuit_period.value()),
            "startup_timeout_seconds": int(self.spin_startup_timeout.value()),
            "shutdown_timeout_seconds": int(self.spin_shutdown_timeout.value()),
        }

    def accept(self) -> None:
        try:
            self.profile = self._validated_profile()
        except (TypeError, ValueError, OSError) as exc:
            self.lbl_error.setText(str(exc))
            return
        super().accept()


class TorServicesPage(QWidget):
    """Dedicated Custom Tor page for creating and managing isolated profiles."""

    def __init__(self, parent=None, *, app_window=None, management_only: bool = False):
        super().__init__(parent)
        self._app_window = app_window
        self._management_only = bool(management_only)
        self._proxy = getattr(app_window, "proxyWidget", None)
        self._primary_tor = getattr(self._proxy, "tor", None)
        self._thread_pool = QThreadPool(self)
        # Stop/Force Stop must never queue behind a long-running Start worker.
        self._stop_thread_pool = QThreadPool(self)
        self._stop_thread_pool.setMaxThreadCount(max(1, min(8, int(CONFIG["tor_service_workers"] or 4))))
        self._workers: dict[str, Worker] = {}
        self._busy_services: set[str] = set()
        self._stop_workers: dict[str, Worker] = {}
        self._force_stop_workers: dict[str, Worker] = {}
        self._pending_stops: set[str] = set()
        self._pending_force_stops: set[str] = set()
        self._busy_all = False
        self._service_cards_layout: QVBoxLayout | None = None
        self._service_state_labels: dict[str, QLabel] = {}
        self._service_health_labels: dict[str, QLabel] = {}
        self._service_start_buttons: dict[str, QPushButton] = {}
        self._service_stop_buttons: dict[str, QPushButton] = {}
        self._service_force_stop_buttons: dict[str, QPushButton] = {}
        self._service_logs_buttons: dict[str, QPushButton] = {}
        self._health_refresh_timer = QTimer(self)
        self._health_refresh_timer.setInterval(5000)
        self._health_refresh_timer.timeout.connect(self._refresh_live_service_health)
        self._health_refresh_timer.start()

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(20, 12, 20, 12)
        root_layout.setSpacing(8)
        self._management_hero_layout = None
        if self._management_only:
            hero = QFrame(self)
            hero.setObjectName("customTorHero")
            hero_layout = QHBoxLayout(hero)
            hero_layout.setContentsMargins(13, 8, 13, 8)
            hero_layout.setSpacing(8)
            self._management_hero_layout = hero_layout

            hero_icon = QLabel(hero)
            hero_icon.setObjectName("customTorHeroIcon")
            hero_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
            hero_icon.setFixedSize(34, 34)
            hero_icon.setPixmap(qta.icon("fa6s.server", color="#ffffff").pixmap(18, 18))
            hero_layout.addWidget(hero_icon)

            hero_copy = QVBoxLayout()
            hero_copy.setContentsMargins(0, 0, 0, 0)
            hero_copy.setSpacing(1)
            page_title = QLabel("Custom Tor", hero)
            page_title.setObjectName("customTorPageTitle")
            hero_subtitle = QLabel("Independent Tor profiles", hero)
            hero_subtitle.setObjectName("customTorHeroSubtitle")
            hero_copy.addWidget(page_title)
            hero_copy.addWidget(hero_subtitle)
            hero_layout.addLayout(hero_copy, 1)

            self.profile_count_label = QLabel("0 profiles", hero)
            self.profile_count_label.setObjectName("customTorProfileCount")
            hero_layout.addWidget(self.profile_count_label, 0, Qt.AlignmentFlag.AlignVCenter)
            root_layout.addWidget(hero)

        scroll = QScrollArea(self)
        scroll.setObjectName("customTorScrollArea")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        content = QWidget(scroll)
        content.setObjectName("customTorContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(2, 1, 10, 3)
        layout.setSpacing(8)
        scroll.setWidget(content)
        root_layout.addWidget(scroll, 1)

        self.page_heading = self._section_title("Custom Tor" if self._management_only else "Tor services")
        layout.addWidget(self.page_heading)
        description = QLabel(
            "Create and manage independent Tor processes for separate applications or identities. "
            "Each profile has its own SOCKS, ControlPort, optional DNSPort, DataDirectory, control cookie and live log."
        )
        description.setObjectName("settingsDescription")
        description.setWordWrap(True)
        self.page_description = description
        layout.addWidget(description)

        self.primary_settings_heading = self._section_title("Primary connection redundancy")
        layout.addWidget(self.primary_settings_heading)
        primary_pool_card = QFrame(self)
        primary_pool_card.setObjectName("settingsRowCard")
        primary_pool_layout = QHBoxLayout(primary_pool_card)
        primary_pool_layout.setContentsMargins(14, 10, 14, 10)
        primary_pool_layout.setSpacing(12)
        primary_pool_copy = QVBoxLayout()
        primary_pool_copy.setSpacing(3)
        primary_pool_title = QLabel("Main Tor instances")
        primary_pool_title.setObjectName("settingsFieldLabel")
        primary_pool_description = QLabel(
            "Number of isolated Tor processes behind the stable SOCKS endpoint used by the main HTTP proxy "
            "and System Tunnel. New connections fail over to a healthy instance; existing TCP connections "
            "cannot be moved and may need to reconnect. Applies on the next connection."
        )
        primary_pool_description.setObjectName("settingsDescription")
        primary_pool_description.setWordWrap(True)
        primary_pool_copy.addWidget(primary_pool_title)
        primary_pool_copy.addWidget(primary_pool_description)
        primary_pool_layout.addLayout(primary_pool_copy, 1)
        self.spin_primary_instances = QSpinBox(self)
        self.spin_primary_instances.setRange(1, 4)
        self.spin_primary_instances.setSuffix(" instances")
        self.spin_primary_instances.setValue(int(CONFIG["primary_tor_instances"] or 2))
        self.spin_primary_instances.setToolTip("Number of Tor workers backing the primary connection. Allowed range: 1–4.")
        self.spin_primary_instances.valueChanged.connect(self._save_primary_tor_instances)
        primary_pool_layout.addWidget(self.spin_primary_instances)
        self.primary_settings_card = primary_pool_card
        layout.addWidget(primary_pool_card)
        self.lbl_primary_pool_health = QLabel("Primary Tor pool is not running.")
        self.lbl_primary_pool_health.setObjectName("settingsDescription")
        self.lbl_primary_pool_health.setWordWrap(True)
        layout.addWidget(self.lbl_primary_pool_health)
        self.primary_health_label = self.lbl_primary_pool_health
        if self._primary_tor is not None:
            health_signal = getattr(self._primary_tor, "bridge_usage_changed", None)
            connect_health = getattr(health_signal, "connect", None)
            if callable(connect_health):
                connect_health(self._update_primary_pool_health)
            snapshot = getattr(self._primary_tor, "pool_health_snapshot", None)
            if isinstance(snapshot, dict):
                self._update_primary_pool_health(snapshot)

        self.bridge_settings_heading = self._section_title("Parallel bridge checks")
        layout.addWidget(self.bridge_settings_heading)
        bridge_card = QFrame(self)
        bridge_card.setObjectName("settingsRowCard")
        bridge_layout = QHBoxLayout(bridge_card)
        bridge_layout.setContentsMargins(14, 10, 14, 10)
        bridge_layout.setSpacing(12)
        bridge_copy = QVBoxLayout()
        bridge_copy.setSpacing(3)
        bridge_title = QLabel("Concurrent bridge probes")
        bridge_title.setObjectName("settingsFieldLabel")
        bridge_description = QLabel(
            "When Auto prune is enabled, bridge preflight runs in parallel using a bounded thread pool: each unique record is "
            "tested once in its own temporary Tor process. Higher concurrency can finish faster, but uses "
            "more CPU, memory and sockets."
        )
        bridge_description.setObjectName("settingsDescription")
        bridge_description.setWordWrap(True)
        bridge_copy.addWidget(bridge_title)
        bridge_copy.addWidget(bridge_description)
        bridge_layout.addLayout(bridge_copy, 1)
        self.spin_bridge_workers = QSpinBox(self)
        self.spin_bridge_workers.setRange(1, 8)
        self.spin_bridge_workers.setSuffix(" workers")
        self.spin_bridge_workers.setValue(int(CONFIG["bridge_probe_workers"] or 8))
        self.spin_bridge_workers.setToolTip("Maximum parallel bridge checks. Allowed range: 1–8.")
        self.spin_bridge_workers.valueChanged.connect(self._save_bridge_workers)
        bridge_layout.addWidget(self.spin_bridge_workers)
        self.bridge_settings_card = bridge_card
        layout.addWidget(bridge_card)

        self.service_settings_heading = self._section_title("Service operations")
        layout.addWidget(self.service_settings_heading)
        service_workers_card = QFrame(self)
        service_workers_card.setObjectName("settingsRowCard")
        worker_layout = QHBoxLayout(service_workers_card)
        worker_layout.setContentsMargins(14, 10, 14, 10)
        worker_layout.setSpacing(12)
        worker_copy = QVBoxLayout()
        worker_title = QLabel("Concurrent service operations")
        worker_title.setObjectName("settingsFieldLabel")
        worker_description = QLabel(
            "Maximum number of isolated services started or stopped in parallel by Start all / Stop all."
        )
        worker_description.setObjectName("settingsDescription")
        worker_description.setWordWrap(True)
        worker_copy.addWidget(worker_title)
        worker_copy.addWidget(worker_description)
        worker_layout.addLayout(worker_copy, 1)
        self.spin_service_workers = QSpinBox(self)
        self.spin_service_workers.setRange(1, 8)
        self.spin_service_workers.setSuffix(" workers")
        self.spin_service_workers.setValue(int(CONFIG["tor_service_workers"] or 4))
        self.spin_service_workers.valueChanged.connect(self._save_service_workers)
        worker_layout.addWidget(self.spin_service_workers)
        self.service_settings_card = service_workers_card
        layout.addWidget(service_workers_card)

        actions = QHBoxLayout()
        actions.setSpacing(6)
        self.btn_add = QPushButton("Create service", self)
        self.btn_add.setObjectName("customTorPrimaryButton")
        self.btn_add.setIcon(qta.icon("fa6s.plus"))
        self.btn_add.setToolTip("Create a new isolated Custom Tor profile.")
        self.btn_add.clicked.connect(self.add_service)
        actions.addWidget(self.btn_add)
        self.btn_start_all = QPushButton("Start all", self)
        self.btn_start_all.setObjectName("settingsActionButton")
        self.btn_start_all.setIcon(qta.icon("fa6s.play"))
        self.btn_start_all.clicked.connect(self.start_all)
        actions.addWidget(self.btn_start_all)
        self.btn_stop_all = QPushButton("Stop all", self)
        self.btn_stop_all.setObjectName("settingsActionButton")
        self.btn_stop_all.setIcon(qta.icon("fa6s.stop"))
        self.btn_stop_all.clicked.connect(self.stop_all)
        actions.addWidget(self.btn_stop_all)
        self.btn_refresh = QPushButton("Refresh", self)
        self.btn_refresh.setObjectName("settingsActionButton")
        self.btn_refresh.setIcon(qta.icon("fa6s.rotate"))
        self.btn_refresh.clicked.connect(self.refresh_services)
        actions.addWidget(self.btn_refresh)
        actions.addStretch(1)
        if self._management_only and self._management_hero_layout is not None:
            self._management_hero_layout.addLayout(actions)
        else:
            layout.addLayout(actions)

        self.lbl_runtime_status = QLabel("")
        self.lbl_runtime_status.setObjectName("settingsDescription")
        self.lbl_runtime_status.setWordWrap(True)
        layout.addWidget(self.lbl_runtime_status)

        self.service_cards = QWidget(self)
        self._service_cards_layout = QVBoxLayout(self.service_cards)
        self._service_cards_layout.setContentsMargins(0, 0, 0, 0)
        self._service_cards_layout.setSpacing(8)
        layout.addWidget(self.service_cards)
        layout.addStretch(1)
        if self._management_only:
            self.page_heading.hide()
            self.page_description.hide()
            for widget in (
                self.primary_settings_heading, self.primary_settings_card, self.primary_health_label,
                self.bridge_settings_heading, self.bridge_settings_card,
                self.service_settings_heading, self.service_settings_card,
            ):
                widget.hide()
        self.apply_theme(CONFIG["mode"])
        self.refresh_services()

    def set_stop_worker_limit(self, value: int) -> None:
        self._stop_thread_pool.setMaxThreadCount(max(1, min(8, int(value))))

    def apply_theme(self, mode: str) -> None:
        dark = str(mode).lower() == "dark"
        border = "#344254" if dark else "#dbe4ef"
        accent = "#4b9fe7" if dark else "#2878c8"
        panel = "#202a38" if dark else "#ffffff"
        field = "#182230" if dark else "#f5f8fc"
        text = "#edf3fa" if dark else "#243247"
        muted = "#9eacbd" if dark else "#66778d"
        hover = "rgba(75, 159, 231, 0.15)" if dark else "rgba(40, 120, 200, 0.09)"
        self.setStyleSheet(f"""
            QWidget#customTorContent {{ background: transparent; }}
            QFrame#customTorHero {{
                background: {panel}; border: 1px solid {border}; border-radius: 12px;
            }}
            QLabel#customTorHeroIcon {{
                background: {accent}; border: 1px solid {accent}; border-radius: 10px;
            }}
            QLabel#customTorPageTitle {{
                color: {text}; background: transparent; font-size: 17px; font-weight: 800;
            }}
            QLabel#customTorHeroSubtitle {{
                color: {muted}; background: transparent; font-size: 9px;
            }}
            QLabel#customTorProfileCount {{
                color: {accent}; background: {field}; border: 1px solid {border};
                border-radius: 7px; padding: 3px 8px; font-size: 8px; font-weight: 800;
            }}
            QLabel#settingsSectionTitle {{ color: {text}; background: transparent; font-size: 14px; font-weight: 850; }}
            QLabel#settingsDescription {{ color: {muted}; background: transparent; font-size: 10px; }}
            QLabel#settingsFieldLabel {{ color: {text}; background: transparent; font-weight: 750; }}
            QFrame#settingsRowCard, QFrame#torServiceCard {{
                background: {panel}; border: 1px solid {border}; border-radius: 12px;
            }}
            QFrame#torServiceCard:hover {{ border-color: {accent}; }}
            QLabel#torServiceStatus {{
                color: {muted}; background: {field}; border: 1px solid {border};
                border-radius: 7px; padding: 3px 8px; font-size: 8px; font-weight: 800;
            }}
            QLabel#torServiceStatus[serviceState="ready"] {{
                color: #31b981; background: rgba(49,185,129,0.08); border-color: rgba(49,185,129,0.4);
            }}
            QLabel#torServiceStatus[serviceState="failed"] {{
                color: #e36b75; background: rgba(227,107,117,0.08); border-color: rgba(227,107,117,0.4);
            }}
            QPushButton#settingsActionButton, QPushButton#customTorPrimaryButton {{
                min-height: 31px; padding: 0 10px; border: 1px solid {border};
                border-radius: 8px; background: {field}; color: {text}; font-weight: 700;
            }}
            QPushButton#settingsActionButton:hover {{
                background: {hover}; border-color: {accent};
            }}
            QPushButton#customTorPrimaryButton {{
                background: {accent}; color: #ffffff; border-color: {accent}; font-weight: 800;
            }}
            QPushButton#customTorPrimaryButton:hover {{ background: #176b9f; }}
            QPushButton#settingsActionButton:disabled, QPushButton#customTorPrimaryButton:disabled {{
                color: {muted}; background: {field}; border-color: {border};
            }}
        """)
        for button, name in (
            (getattr(self, "btn_add", None), "fa6s.plus"),
            (getattr(self, "btn_start_all", None), "fa6s.play"),
            (getattr(self, "btn_stop_all", None), "fa6s.stop"),
            (getattr(self, "btn_refresh", None), "fa6s.rotate"),
        ):
            if button is not None:
                button.setIcon(qta.icon(name, color=text))

    @staticmethod
    def _section_title(title: str) -> QLabel:
        label = QLabel(title)
        label.setObjectName("settingsSectionTitle")
        return label

    def _profiles(self) -> list[dict]:
        value = CONFIG["tor_services"] or []
        return [dict(item) for item in value if isinstance(item, dict)]

    def _pool(self, *, create: bool = False):
        if self._proxy is None:
            return None
        pool = getattr(self._proxy, "tor_service_pool", None)
        if pool is not None or not create:
            return pool
        return self._proxy._ensure_tor_service_pool()

    def _update_primary_pool_health(self, health) -> None:
        """Show the individually verified state of each primary Tor worker."""
        if not isinstance(health, dict):
            return
        try:
            ready = max(0, int(health.get("ready_instances", 0)))
            total = max(0, int(health.get("total_instances", 0)))
        except (TypeError, ValueError):
            return
        if total <= 0:
            self.lbl_primary_pool_health.setText("Primary Tor pool is not running.")
            return

        labels = []
        for item in health.get("instances", []):
            if not isinstance(item, dict):
                continue
            try:
                index = int(item.get("index", len(labels) + 1))
            except (TypeError, ValueError):
                index = len(labels) + 1
            state = str(item.get("state", "unknown")).lower()
            if item.get("healthy"):
                latency = item.get("latency_p50_ms")
                if latency is None:
                    latency = item.get("latency_ms")
                try:
                    suffix = f" · P50 {float(latency):.0f} ms" if latency is not None else ""
                except (TypeError, ValueError):
                    suffix = ""
                description = (
                    "Tor Check verified" if item.get("verified_tor")
                    else "Reachable · Tor Check unverified"
                ) + suffix
            elif state == "ready-checking":
                description = "Tor process ready · checking network"
            elif state == "unhealthy":
                description = "Process running · Tor network unavailable"
            elif state in {"failed", "stopped"}:
                description = state.title()
            else:
                description = "Starting or bootstrapping"
            try:
                bridge_count = max(0, int(item.get("bridge_count", 0) or 0))
            except (TypeError, ValueError):
                bridge_count = 0
            bridge_suffix = f" · {bridge_count} bridge record(s)" if bridge_count else ""
            try:
                active_connections = max(0, int(item.get("active_connections", 0) or 0))
                backend_failures = max(0, int(item.get("gateway_failures", 0) or 0))
                cooldown = max(0.0, float(item.get("cooldown_remaining_seconds", 0.0) or 0.0))
            except (TypeError, ValueError):
                active_connections = backend_failures = 0
                cooldown = 0.0
            load_suffix = f" · {active_connections} active connection(s)"
            if backend_failures:
                load_suffix += f" · {backend_failures} recent gateway failure(s)"
            if cooldown > 0:
                load_suffix += f" · fallback cooldown {cooldown:.0f}s"
            labels.append(f"Instance {index}: {description}{bridge_suffix}{load_suffix}")

        detail = "  |  ".join(labels) if labels else "Waiting for instance status."
        gateway = health.get("gateway")
        if isinstance(gateway, dict):
            try:
                active_sessions = max(0, int(gateway.get("active_sessions", 0) or 0))
                max_sessions = max(0, int(gateway.get("max_sessions", 0) or 0))
                rejected_sessions = max(0, int(gateway.get("rejected_sessions", 0) or 0))
            except (TypeError, ValueError):
                active_sessions = max_sessions = rejected_sessions = 0
            if max_sessions:
                detail += (
                    f"\nSOCKS gateway: {active_sessions}/{max_sessions} active sessions; "
                    f"{rejected_sessions} rejected by the capacity limit."
                )
        distribution = health.get("bridge_distribution")
        distribution_note = ""
        if isinstance(distribution, dict):
            try:
                records = max(0, int(distribution.get("unique_records", 0)))
                groups = max(0, int(distribution.get("unique_groups", 0)))
                shared = max(0, int(distribution.get("shared_groups", 0)))
            except (TypeError, ValueError):
                records = groups = shared = 0
            if records:
                if shared:
                    distribution_note = (
                        f"\nBridge pool: {records} unique records in {groups} groups; "
                        f"{shared} group(s) are reused because the pool is small or to share verified coverage across workers."
                    )
                else:
                    distribution_note = (
                        f"\nBridge pool: {records} unique records in {groups} groups; "
                        "assignments are isolated between instances."
                    )
        self.lbl_primary_pool_health.setText(
            f"Primary connection · {ready}/{total} usable instances\n{detail}{distribution_note}"
        )

    def _save_primary_tor_instances(self, value: int) -> None:
        previous = int(CONFIG["primary_tor_instances"] or 2)
        try:
            CONFIG["primary_tor_instances"] = int(value)
        except (ValueError, OSError, KeyError) as exc:
            self._restore_spin(self.spin_primary_instances, previous)
            QMessageBox.warning(self, "Primary Tor pool", str(exc))

    def _save_bridge_workers(self, value: int) -> None:
        previous = int(CONFIG["bridge_probe_workers"] or 8)
        try:
            CONFIG["bridge_probe_workers"] = int(value)
        except (ValueError, OSError, KeyError) as exc:
            self._restore_spin(self.spin_bridge_workers, previous)
            QMessageBox.warning(self, "Settings could not be saved", str(exc))

    def _save_service_workers(self, value: int) -> None:
        previous = int(CONFIG["tor_service_workers"] or 4)
        pool = self._pool()
        try:
            if pool is not None:
                pool.set_max_workers(int(value))
            CONFIG["tor_service_workers"] = int(value)
        except (ValueError, OSError, KeyError, TorServicePoolError) as exc:
            if pool is not None:
                try:
                    pool.set_max_workers(previous)
                except TorServicePoolError:
                    pass
            self._restore_spin(self.spin_service_workers, previous)
            QMessageBox.warning(self, "Service concurrency", str(exc))

    @staticmethod
    def _restore_spin(spin: QSpinBox, value: int) -> None:
        blocked = spin.blockSignals(True)
        spin.setValue(value)
        spin.blockSignals(blocked)

    def _register_profile(self, profile: dict, pool) -> None:
        if profile["id"] not in pool.service_ids:
            self._proxy._register_tor_service_profile(profile, pool=pool)

    def _save_profile(self, profile: dict, *, old_profile: dict | None = None) -> bool:
        profiles = self._profiles()
        profile = dict(profile)
        service_id = profile["id"]
        credentials = {
            "username": profile.pop("upstream_proxy_username", ""),
            "password": profile.pop("upstream_proxy_password", ""),
        }
        try:
            previous_credentials = read_upstream_credentials(service_id)
        except Exception as exc:
            QMessageBox.warning(self, "Proxy credentials unavailable", str(exc))
            return False
        pool = self._pool(create=False)
        old_registered = bool(pool is not None and service_id in pool.service_ids)
        old_was_unregistered = False
        new_registered = False

        if old_profile is None and any(item.get("id") == service_id for item in profiles):
            QMessageBox.warning(self, "Duplicate profile", f"A Tor service with ID '{service_id}' already exists.")
            return False

        if old_profile is not None and old_registered:
            try:
                current_state = pool.status(service_id)["state"]
                if current_state != "stopped":
                    raise TorServicePoolError(
                        "Stop this isolated Tor service before editing its ports or configuration."
                    )
                pool.unregister(service_id)
                old_was_unregistered = True
            except Exception as exc:
                QMessageBox.warning(self, "Cannot edit active service", str(exc))
                return False

        credentials_updated = False
        try:
            # Credentials must be available before _register_profile builds the
            # immutable TorSettings snapshot; they never enter profile metadata.
            write_upstream_credentials(service_id, credentials["username"], credentials["password"])
            credentials_updated = True
            if pool is None:
                # Creating a profile is still useful before a bundle is installed.
                # It will be registered automatically when a compatible bundle exists.
                try:
                    pool = self._pool(create=True)
                except Exception:
                    pool = None

            # Pool creation may restore the old persisted version of this profile.
            # Detect and replace that late registration before writing the edited copy.
            if old_profile is not None and pool is not None and not old_registered:
                if service_id in pool.service_ids:
                    current_state = pool.status(service_id)["state"]
                    if current_state != "stopped":
                        raise TorServicePoolError(
                            "Stop this isolated Tor service before editing its ports or configuration."
                        )
                    pool.unregister(service_id)
                    old_was_unregistered = True

            if pool is not None:
                self._register_profile(profile, pool)
                new_registered = True

            updated = [
                dict(profile) if item.get("id") == service_id else item
                for item in profiles
            ]
            if old_profile is None:
                updated.append(dict(profile))
            elif not any(item.get("id") == service_id for item in profiles):
                updated.append(dict(profile))
            CONFIG.update_many({"tor_services": updated})
        except Exception as exc:
            if credentials_updated:
                try:
                    write_upstream_credentials(
                        service_id,
                        previous_credentials["upstream_proxy_username"],
                        previous_credentials["upstream_proxy_password"],
                    )
                except Exception:
                    logger.exception("Could not restore previous Custom Tor proxy credentials.")
            if new_registered and pool is not None and service_id in pool.service_ids:
                try:
                    pool.unregister(service_id)
                except Exception:
                    logger.exception("Could not roll back failed Tor profile save.")
            if old_profile is not None and old_was_unregistered and pool is not None:
                try:
                    self._proxy._register_tor_service_profile(old_profile, pool=pool)
                except Exception:
                    logger.exception("Could not restore the previous Tor profile after an edit failure.")
            QMessageBox.warning(self, "Tor profile could not be saved", str(exc))
            return False

        if self._proxy is not None:
            getattr(self._proxy, "tor_service_profile_errors", {}).pop(service_id, None)
        self.lbl_runtime_status.setText(f"Saved profile '{profile.get('display_name') or service_id}'.")
        self.refresh_services()
        return True

    def add_service(self) -> None:
        dialog = TorServiceEditorDialog(parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.profile is not None:
            self._save_profile(dialog.profile)

    def edit_service(self, profile: dict) -> None:
        dialog = TorServiceEditorDialog(profile, self)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.profile is not None:
            self._save_profile(dialog.profile, old_profile=profile)

    def remove_service(self, profile: dict) -> None:
        service_id = profile["id"]
        answer = QMessageBox.question(
            self,
            "Remove Tor service",
            f"Remove the saved profile '{profile.get('display_name') or service_id}'? "
            "Its DataDirectory and log files will be left on disk.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        pool = self._pool()
        if pool is not None and service_id in pool.service_ids:
            try:
                if pool.status(service_id)["state"] != "stopped":
                    raise TorServicePoolError("Stop the service before removing its profile.")
                pool.unregister(service_id)
            except Exception as exc:
                QMessageBox.warning(self, "Cannot remove active service", str(exc))
                return
        updated = [item for item in self._profiles() if item.get("id") != service_id]
        try:
            CONFIG.update_many({"tor_services": updated})
        except Exception as exc:
            QMessageBox.warning(self, "Profile could not be removed", str(exc))
            return
        try:
            delete_upstream_credentials(service_id)
        except Exception:
            logger.exception("Could not remove saved proxy credentials for deleted profile '%s'.", service_id)
        if self._proxy is not None:
            getattr(self._proxy, "tor_service_profile_errors", {}).pop(service_id, None)
        self.lbl_runtime_status.setText(f"Removed profile '{service_id}'. Its DataDirectory and logs were preserved.")
        self.refresh_services()

    def _run_operation(self, operation_key: str, function, *args) -> None:
        if operation_key in self._workers or self._busy_all or (
            operation_key == "__all__" and self._workers
        ):
            return
        worker = Worker(function, *args)
        worker.signals.finished.connect(
            lambda result, key=operation_key: self._on_operation_finished(key, result)
        )
        worker.signals.error.connect(
            lambda error, key=operation_key: self._on_operation_failed(key, error)
        )
        self._workers[operation_key] = worker
        if operation_key == "__all__":
            self._busy_all = True
        else:
            self._busy_services.add(operation_key)
        self._update_global_actions()
        self.refresh_services()
        self._thread_pool.start(worker)

    def _on_operation_finished(self, operation_key: str, result: str) -> None:
        self._workers.pop(operation_key, None)
        if operation_key == "__all__":
            self._busy_all = False
        else:
            self._busy_services.discard(operation_key)
        if result:
            self.lbl_runtime_status.setText(result[:500])
        self.refresh_services()

    def _on_operation_failed(self, operation_key: str, error: str) -> None:
        self._workers.pop(operation_key, None)
        if operation_key == "__all__":
            self._busy_all = False
        else:
            self._busy_services.discard(operation_key)
        self.lbl_runtime_status.setText(error)
        self.refresh_services()
        QMessageBox.warning(self, "Tor service operation failed", error)

    def _update_global_actions(self) -> None:
        busy = self._busy_all or bool(self._workers)
        stopping = bool(self._pending_stops or self._pending_force_stops)
        pool = self._pool()
        self.btn_add.setEnabled(not busy and not stopping)
        self.btn_start_all.setEnabled(not busy and not stopping)
        self.btn_stop_all.setEnabled(bool(pool and pool.service_ids) and not stopping)
        self.btn_refresh.setEnabled(not busy and not stopping)

    def _service_operation(self, service_id: str, operation: str) -> None:
        if operation in {"stop", "force_stop"}:
            self._request_service_stop(service_id, force=operation == "force_stop")
            return
        try:
            pool = self._pool(create=True)
            profile = next((item for item in self._profiles() if item.get("id") == service_id), None)
            if profile is None:
                raise TorServicePoolError(f"Unknown saved Tor service '{service_id}'.")
            self._register_profile(profile, pool)
            if service_id in self._pending_stops:
                return
            self._run_operation(service_id, pool.start_service, service_id)
        except Exception as exc:
            self.lbl_runtime_status.setText(str(exc))
            QMessageBox.warning(self, "Tor service", str(exc))
            self.refresh_services()

    def _request_service_stop(self, service_id: str, *, force: bool = False) -> None:
        """Stop independently of an in-flight start; Force Stop can escalate a graceful Stop."""
        workers = self._force_stop_workers if force else self._stop_workers
        if service_id in workers:
            return
        if not force and service_id in self._pending_force_stops:
            return
        try:
            pool = self._pool(create=False)
            if pool is None:
                raise TorServicePoolError("Custom Tor services are not registered; install a Tor bundle first.")
            if service_id not in pool.service_ids:
                profile = next((item for item in self._profiles() if item.get("id") == service_id), None)
                if profile is None:
                    raise TorServicePoolError(f"Unknown saved Tor service '{service_id}'.")
                self._register_profile(profile, pool)
            method = pool.force_stop_service if force else pool.stop_service
            worker = Worker(method, service_id)
            worker.signals.finished.connect(
                lambda result, key=service_id, forced=force: self._on_stop_finished(key, forced, result)
            )
            worker.signals.error.connect(
                lambda error, key=service_id, forced=force: self._on_stop_failed(key, forced, error)
            )
            workers[service_id] = worker
            (self._pending_force_stops if force else self._pending_stops).add(service_id)
            self.lbl_runtime_status.setText(
                f"{'Force-stopping' if force else 'Stopping'} '{service_id}'…"
            )
            self.refresh_services()
            self._stop_thread_pool.start(worker)
        except Exception as exc:
            self.lbl_runtime_status.setText(str(exc))
            QMessageBox.warning(self, "Tor service stop", str(exc))
            self.refresh_services()

    def _on_stop_finished(self, service_id: str, force: bool, result: str) -> None:
        workers = self._force_stop_workers if force else self._stop_workers
        workers.pop(service_id, None)
        (self._pending_force_stops if force else self._pending_stops).discard(service_id)
        self.lbl_runtime_status.setText(
            f"{'Force-stopped' if force else 'Stopped'} '{service_id}'."
        )
        self.refresh_services()

    def _on_stop_failed(self, service_id: str, force: bool, error: str) -> None:
        workers = self._force_stop_workers if force else self._stop_workers
        workers.pop(service_id, None)
        (self._pending_force_stops if force else self._pending_stops).discard(service_id)
        self.lbl_runtime_status.setText(error)
        self.refresh_services()
        QMessageBox.warning(self, "Tor service force-stop failed" if force else "Tor service stop failed", error)

    def open_service_logs(self, service_id: str) -> None:
        """Open the real per-profile Tor log, including while startup is in progress."""
        manager = None
        pool = self._pool(create=False)
        if pool is not None and service_id in pool.service_ids:
            try:
                manager = pool.get(service_id)
            except Exception:
                logger.exception("Could not obtain the manager for Tor profile '%s'.", service_id)
        path = getattr(manager, "log_path", None) or (
            user_directories().logs / "tor-services" / service_id / "tor.log"
        )
        TorLogDialog(self, path, manager=manager).exec()

    def start_all(self) -> None:
        try:
            pool = self._pool(create=True)
        except Exception as exc:
            self.lbl_runtime_status.setText(str(exc))
            QMessageBox.warning(self, "Tor service pool", str(exc))
            self.refresh_services()
            return
        if pool is None:
            QMessageBox.warning(self, "Tor service pool", "Tor services are not available until a Tor bundle is installed.")
            return

        def start_registered():
            results = pool.start_all()
            failures = {key: value for key, value in results.items() if value}
            if failures:
                raise RuntimeError(
                    "Some services could not start: "
                    + "; ".join(f"{key}: {value}" for key, value in failures.items())
                )
            return f"Started {len(results)} isolated Tor service(s)."

        self._run_operation("__all__", start_registered)

    def stop_all(self) -> None:
        pool = self._pool(create=False)
        if pool is None:
            return
        for service_id in pool.service_ids:
            self._request_service_stop(service_id)

    def refresh_services(self) -> None:
        if self._primary_tor is not None:
            snapshot = getattr(self._primary_tor, "pool_health_snapshot", None)
            if isinstance(snapshot, dict):
                self._update_primary_pool_health(snapshot)
        if self._service_cards_layout is None:
            return
        while self._service_cards_layout.count():
            item = self._service_cards_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        profiles = self._profiles()
        pool = self._pool()
        pool_error = ""
        if pool is None and self._proxy is not None:
            try:
                pool = self._pool(create=True)
            except Exception as exc:
                pool_error = str(exc)

        statuses = pool.status() if pool is not None else {}
        self._service_state_labels.clear()
        self._service_health_labels.clear()
        self._service_start_buttons.clear()
        self._service_stop_buttons.clear()
        self._service_force_stop_buttons.clear()
        self._service_logs_buttons.clear()
        restore_errors = getattr(self._proxy, "tor_service_profile_errors", {}) if self._proxy else {}
        self.lbl_runtime_status.setText(
            pool_error or (
                "The primary Tor bundle is ready. Additional profiles use independent Tor processes."
                if pool is not None
                else "Install or select a Tor Expert Bundle to start isolated service profiles."
            )
        )
        if hasattr(self, "profile_count_label"):
            self.profile_count_label.setText(
                f"{len(profiles)} profile" + ("" if len(profiles) == 1 else "s")
            )

        if not profiles:
            empty = QLabel("No isolated Tor profiles yet. Add one to create a separate Tor instance.")
            empty.setObjectName("bridgeEmptyState")
            empty.setWordWrap(True)
            self._service_cards_layout.addWidget(empty)
        for profile in profiles:
            service_id = str(profile.get("id", ""))
            status = statuses.get(service_id, {})
            state = str(status.get("state") or (
                "needs attention" if service_id in restore_errors
                else "bundle unavailable" if pool is None
                else "not registered"
            ))
            self._service_cards_layout.addWidget(
                self._create_service_card(profile, state, status, restore_errors.get(service_id, ""))
            )
        self._update_global_actions()

    @staticmethod
    def _service_health_text(status: dict) -> str:
        health = str(status.get("network_health") or "unchecked").lower()
        latency = status.get("latency_ms")
        try:
            latency_text = f" · {float(latency):.0f} ms" if latency is not None else ""
        except (TypeError, ValueError):
            latency_text = ""
        if health == "healthy":
            return "Tor egress verified" + latency_text
        if health == "reachable_unverified":
            return "Tor SOCKS reachable · Tor Check unavailable (unverified)" + latency_text
        if health == "degraded":
            return "Tor egress degraded · one failed check; endpoint retained temporarily"
        if health == "unhealthy":
            detail = str(status.get("last_health_error") or "Tor egress could not be verified.")
            return "Tor network unavailable · " + detail
        if health == "checking":
            return "Checking real Tor network connectivity…"
        if health == "stopped":
            return "Tor service is stopped."
        if health == "not_ready":
            return "Tor process is not ready for network checks."
        return "Network health has not been verified yet."

    def _refresh_live_service_health(self) -> None:
        """Refresh health labels without rebuilding cards or disturbing scroll position."""
        if not self.isVisible():
            return
        if self._primary_tor is not None:
            snapshot = getattr(self._primary_tor, "pool_health_snapshot", None)
            if isinstance(snapshot, dict):
                self._update_primary_pool_health(snapshot)
        pool = self._pool()
        if pool is None:
            return
        try:
            statuses = pool.status()
        except Exception:
            return
        for service_id, status in statuses.items():
            health_label = self._service_health_labels.get(service_id)
            if health_label is not None:
                health_label.setText(self._service_health_text(status))
            state_label = self._service_state_labels.get(service_id)
            if state_label is None:
                continue
            manager_state = str(status.get("state") or "unknown").lower()
            health_state = str(status.get("network_health") or "unchecked").lower()
            is_busy = self._busy_all or service_id in self._busy_services
            start_button = self._service_start_buttons.get(service_id)
            stop_button = self._service_stop_buttons.get(service_id)
            if start_button is not None:
                start_button.setEnabled(bool(pool) and manager_state == "stopped" and not is_busy)
            can_stop = manager_state not in {"stopped", "bundle unavailable", "not registered"}
            pending_stop = service_id in self._pending_stops
            pending_force = service_id in self._pending_force_stops
            if stop_button is not None:
                stop_button.setEnabled(bool(pool) and can_stop and not pending_stop and not pending_force)
            force_button = self._service_force_stop_buttons.get(service_id)
            if force_button is not None:
                force_button.setEnabled(bool(pool) and can_stop and not pending_force)
            if manager_state == "ready" and health_state == "healthy":
                state_label.setText("TOR VERIFIED")
                service_state = "ready"
            elif manager_state == "ready" and health_state == "reachable_unverified":
                state_label.setText("SOCKS REACHABLE · UNVERIFIED")
                service_state = "ready"
            elif manager_state == "ready" and health_state == "unhealthy":
                state_label.setText("NO TOR EGRESS")
                service_state = "failed"
            elif manager_state == "ready" and health_state == "degraded":
                state_label.setText("DEGRADED")
                service_state = "ready"
            elif manager_state == "ready":
                state_label.setText("CHECKING NETWORK")
                service_state = "ready"
            elif manager_state == "failed":
                state_label.setText("PROCESS EXITED · STOP TO RECONCILE")
                service_state = "failed"
            else:
                state_label.setText(manager_state.replace("_", " ").upper())
                service_state = manager_state
            state_label.setProperty("serviceState", service_state)
            state_label.style().unpolish(state_label)
            state_label.style().polish(state_label)

    def _create_service_card(self, profile: dict, state: str, status: dict, error: str):
        card = QFrame(self)
        card.setObjectName("torServiceCard")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(13, 10, 13, 10)
        outer.setSpacing(7)

        header = QHBoxLayout()
        name = QLabel(str(profile.get("display_name") or profile.get("id", "Tor service")))
        name.setObjectName("settingsFieldLabel")
        header.addWidget(name, 1)
        state_label = QLabel(state.replace("_", " ").upper())
        state_label.setObjectName("torServiceStatus")
        health_state = str(status.get("network_health") or "unchecked").lower()
        if state == "ready":
            state_label.setText({
                "healthy": "TOR VERIFIED",
                "reachable_unverified": "SOCKS REACHABLE · UNVERIFIED",
                "degraded": "DEGRADED",
                "unhealthy": "NO TOR EGRESS",
                "checking": "CHECKING NETWORK",
            }.get(health_state, "READY · UNVERIFIED"))
        state_label.setProperty(
            "serviceState",
            "failed" if state == "failed" or health_state == "unhealthy" else state,
        )
        header.addWidget(state_label)
        service_id = str(profile.get("id", ""))
        self._service_state_labels[service_id] = state_label
        outer.addLayout(header)

        dns = profile.get("dns_port")
        socks_endpoint = f"127.0.0.1:{profile.get('socks_port')}"
        detail = (
            f"SOCKS endpoint  {socks_endpoint}    ·    "
            f"Control  127.0.0.1:{profile.get('control_port')}    ·    "
            f"DNS  {dns if dns else 'off'}"
        )
        details = QLabel(detail)
        details.setObjectName("settingsDescription")
        outer.addWidget(details)
        health_label = QLabel(self._service_health_text(status))
        health_label.setObjectName("settingsDescription")
        health_label.setWordWrap(True)
        outer.addWidget(health_label)
        self._service_health_labels[service_id] = health_label

        directory = status.get("data_directory") or profile.get("data_directory") or (
            f"Automatic · tor-services/{profile.get('id')}"
        )
        directory_label = QLabel(f"Data: {directory}")
        directory_label.setObjectName("settingsDescription")
        directory_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        directory_label.setWordWrap(True)
        outer.addWidget(directory_label)

        if error:
            error_label = QLabel(error)
            error_label.setObjectName("settingsDescription")
            error_label.setWordWrap(True)
            outer.addWidget(error_label)

        actions = QHBoxLayout()
        actions.setSpacing(6)
        service_id = str(profile.get("id", ""))
        copy_button = QPushButton("Copy SOCKS endpoint", card)
        copy_button.setObjectName("settingsActionButton")
        copy_button.setIcon(qta.icon("fa6s.copy"))
        copy_button.setToolTip("Copy the loopback SOCKS endpoint for this isolated Tor profile.")
        copy_button.clicked.connect(
            lambda _checked=False, endpoint=socks_endpoint: QApplication.clipboard().setText(endpoint)
        )
        actions.addWidget(copy_button)
        is_busy = self._busy_all or service_id in self._busy_services
        # A failed service must be explicitly stopped/reconciled before restart.
        # This avoids retrying against a child that may still own its ports or data lock.
        can_start = state in {"stopped", "not registered", "needs attention"}
        can_stop = state not in {"stopped", "bundle unavailable", "not registered", "needs attention"}
        if pool := self._pool():
            can_start = can_start and not is_busy

        start_button = QPushButton("Start", card)
        start_button.setObjectName("settingsActionButton")
        start_button.setIcon(qta.icon("fa6s.play"))
        start_button.setEnabled(bool(pool) and can_start and not self._busy_all and service_id not in self._pending_stops and service_id not in self._pending_force_stops)
        self._service_start_buttons[service_id] = start_button
        start_button.clicked.connect(lambda _checked=False, key=service_id: self._service_operation(key, "start"))
        actions.addWidget(start_button)

        stop_button = QPushButton("Stop", card)
        stop_button.setObjectName("settingsActionButton")
        stop_button.setIcon(qta.icon("fa6s.stop"))
        stop_button.setEnabled(bool(pool) and can_stop and service_id not in self._pending_stops and service_id not in self._pending_force_stops)
        stop_button.setToolTip("Stop this service, including cancelling an ongoing startup.")
        self._service_stop_buttons[service_id] = stop_button
        stop_button.clicked.connect(lambda _checked=False, key=service_id: self._service_operation(key, "stop"))
        actions.addWidget(stop_button)

        force_button = QPushButton("Force stop", card)
        force_button.setObjectName("settingsActionButton")
        force_button.setIcon(qta.icon("fa6s.bolt"))
        force_button.setToolTip("Immediately terminate the managed Tor process. Use if normal Stop does not complete.")
        force_button.setEnabled(bool(pool) and can_stop and service_id not in self._pending_force_stops)
        self._service_force_stop_buttons[service_id] = force_button
        force_button.clicked.connect(lambda _checked=False, key=service_id: self._service_operation(key, "force_stop"))
        actions.addWidget(force_button)

        logs_button = QPushButton("Logs", card)
        logs_button.setObjectName("settingsActionButton")
        logs_button.setIcon(qta.icon("fa6s.file-lines"))
        logs_button.setToolTip("View this service's live Tor log, including startup output.")
        self._service_logs_buttons[service_id] = logs_button
        logs_button.clicked.connect(lambda _checked=False, key=service_id: self.open_service_logs(key))
        actions.addWidget(logs_button)

        edit_button = QPushButton("Edit", card)
        edit_button.setObjectName("settingsActionButton")
        edit_button.setIcon(qta.icon("fa6s.pen"))
        edit_button.setEnabled(not is_busy and state in {"stopped", "bundle unavailable", "not registered", "needs attention"})
        edit_button.clicked.connect(lambda _checked=False, item=dict(profile): self.edit_service(item))
        actions.addWidget(edit_button)

        remove_button = QPushButton("Remove", card)
        remove_button.setObjectName("settingsActionButton")
        remove_button.setIcon(qta.icon("fa6s.trash"))
        remove_button.setEnabled(not is_busy and state in {"stopped", "bundle unavailable", "not registered", "needs attention"})
        remove_button.clicked.connect(lambda _checked=False, item=dict(profile): self.remove_service(item))
        actions.addWidget(remove_button)
        actions.addStretch(1)
        outer.addLayout(actions)
        return card
