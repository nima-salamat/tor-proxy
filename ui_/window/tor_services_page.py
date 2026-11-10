from __future__ import annotations

import logging
import re
from pathlib import Path

import qtawesome as qta
from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from config import CONFIG
from torproxy.bridges import parse_bridge_text
from torproxy.service_pool import TorServicePoolError
from ui_.worker.worker import Worker

logger = logging.getLogger(__name__)
_SERVICE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class TorServiceEditorDialog(QDialog):
    """Create or edit one persisted, independently isolated Tor profile."""

    def __init__(self, profile: dict | None = None, parent=None):
        super().__init__(parent)
        self._source_profile = dict(profile or {})
        self.profile: dict | None = None
        editing = profile is not None
        self.setWindowTitle("Edit Tor service" if editing else "Add Tor service")
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(12)
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

        self.inp_socks_port = self._port_spin(
            self._source_profile.get("socks_port", 19155), minimum=1
        )
        self.inp_control_port = self._port_spin(
            self._source_profile.get("control_port", 19156), minimum=1
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

        self.lbl_error = QLabel("")
        self.lbl_error.setObjectName("settingsDescription")
        self.lbl_error.setWordWrap(True)
        layout.addWidget(self.lbl_error)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel,
            parent=self,
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.chk_use_primary_bridges.toggled.connect(self._sync_bridge_controls)
        self.chk_bridges_enabled.toggled.connect(self._sync_bridge_controls)
        self._sync_bridge_controls()

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
        }

    def accept(self) -> None:
        try:
            self.profile = self._validated_profile()
        except (TypeError, ValueError, OSError) as exc:
            self.lbl_error.setText(str(exc))
            return
        super().accept()


class TorServicesPage(QWidget):
    """Settings page for concurrent bridge probes and isolated Tor profiles."""

    def __init__(self, parent=None, *, app_window=None):
        super().__init__(parent)
        self._app_window = app_window
        self._proxy = getattr(app_window, "proxyWidget", None)
        self._thread_pool = QThreadPool(self)
        self._workers: dict[str, Worker] = {}
        self._busy_services: set[str] = set()
        self._busy_all = False
        self._service_cards_layout: QVBoxLayout | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        layout.addWidget(self._section_title("Tor services"))
        description = QLabel(
            "Create independent Tor processes for separate applications or identities. "
            "Profiles keep their own SOCKS, ControlPort, optional DNSPort, state directory, "
            "control cookie and log. They can run alongside the primary Tor connection."
        )
        description.setObjectName("settingsDescription")
        description.setWordWrap(True)
        layout.addWidget(description)

        layout.addWidget(self._section_title("Parallel bridge checks"))
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
            "How many bridge records may be tested at the same time before a Tor connection. "
            "Higher values can finish faster, but use more CPU and sockets."
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
        layout.addWidget(bridge_card)

        layout.addWidget(self._section_title("Service operations"))
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
        layout.addWidget(service_workers_card)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.btn_add = QPushButton("Add Tor service", self)
        self.btn_add.setObjectName("settingsActionButton")
        self.btn_add.setIcon(qta.icon("fa6s.plus"))
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
        self.refresh_services()

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
        service_id = profile["id"]
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

        try:
            if pool is None:
                # Creating a profile is still useful before a bundle is installed.
                # It will be registered automatically when a compatible bundle exists.
                try:
                    pool = self._pool(create=True)
                except Exception:
                    pool = None
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
            CONFIG["tor_services"] = updated
        except Exception as exc:
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
            CONFIG["tor_services"] = updated
        except Exception as exc:
            QMessageBox.warning(self, "Profile could not be removed", str(exc))
            return
        if self._proxy is not None:
            getattr(self._proxy, "tor_service_profile_errors", {}).pop(service_id, None)
        self.lbl_runtime_status.setText(f"Removed profile '{service_id}'. Its files were preserved.")
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
        self.btn_add.setEnabled(not busy)
        self.btn_start_all.setEnabled(not busy)
        self.btn_stop_all.setEnabled(not busy)
        self.btn_refresh.setEnabled(not busy)

    def _service_operation(self, service_id: str, operation: str) -> None:
        pool = self._pool(create=True)
        profile = next((item for item in self._profiles() if item.get("id") == service_id), None)
        if profile is None:
            raise TorServicePoolError(f"Unknown saved Tor service '{service_id}'.")
        self._register_profile(profile, pool)
        method = pool.start_service if operation == "start" else pool.stop_service
        self._run_operation(service_id, method, service_id)

    def start_all(self) -> None:
        pool = self._pool(create=True)
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

        def stop_registered():
            results = pool.stop_all()
            failures = {key: value for key, value in results.items() if value}
            if failures:
                raise RuntimeError(
                    "Some services could not stop: "
                    + "; ".join(f"{key}: {value}" for key, value in failures.items())
                )
            return f"Stopped {len(results)} isolated Tor service(s)."

        self._run_operation("__all__", stop_registered)

    def refresh_services(self) -> None:
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
        restore_errors = getattr(self._proxy, "tor_service_profile_errors", {}) if self._proxy else {}
        self.lbl_runtime_status.setText(
            pool_error or (
                "The primary Tor bundle is ready. Additional profiles use independent Tor processes."
                if pool is not None
                else "Install or select a Tor Expert Bundle to start isolated service profiles."
            )
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

    def _create_service_card(self, profile: dict, state: str, status: dict, error: str):
        card = QFrame(self)
        card.setObjectName("torServiceCard")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(14, 11, 14, 11)
        outer.setSpacing(7)

        header = QHBoxLayout()
        name = QLabel(str(profile.get("display_name") or profile.get("id", "Tor service")))
        name.setObjectName("settingsFieldLabel")
        header.addWidget(name, 1)
        state_label = QLabel(state.replace("_", " ").upper())
        state_label.setObjectName("torServiceStatus")
        state_label.setProperty("serviceState", state)
        header.addWidget(state_label)
        outer.addLayout(header)

        dns = profile.get("dns_port")
        detail = (
            f"SOCKS  {profile.get('socks_port')}    ·    "
            f"Control  {profile.get('control_port')}    ·    "
            f"DNS  {dns if dns else 'off'}"
        )
        details = QLabel(detail)
        details.setObjectName("settingsDescription")
        outer.addWidget(details)

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
        actions.setSpacing(7)
        service_id = str(profile.get("id", ""))
        is_busy = self._busy_all or service_id in self._busy_services
        can_start = state not in {"ready", "starting", "bootstrapping"}
        can_stop = state not in {"stopped", "bundle unavailable", "not registered", "needs attention"}
        if pool := self._pool():
            can_start = can_start and not is_busy
            can_stop = can_stop and not is_busy

        start_button = QPushButton("Start", card)
        start_button.setObjectName("settingsActionButton")
        start_button.setIcon(qta.icon("fa6s.play"))
        start_button.setEnabled(bool(pool) and can_start and not self._busy_all)
        start_button.clicked.connect(lambda _checked=False, key=service_id: self._service_operation(key, "start"))
        actions.addWidget(start_button)

        stop_button = QPushButton("Stop", card)
        stop_button.setObjectName("settingsActionButton")
        stop_button.setIcon(qta.icon("fa6s.stop"))
        stop_button.setEnabled(bool(pool) and can_stop and not is_busy)
        stop_button.clicked.connect(lambda _checked=False, key=service_id: self._service_operation(key, "stop"))
        actions.addWidget(stop_button)

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
