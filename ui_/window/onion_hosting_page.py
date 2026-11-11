"""Home dashboard for the independent Developer Tor Onion Hosting runtime."""
from __future__ import annotations

import logging

import qtawesome as qta
from PySide6.QtCore import Qt, QThreadPool, QTimer, Signal, QUrl
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
    QVBoxLayout,
    QWidget,
)

from config import CONFIG
from torproxy.paths import user_directories
from ui_.worker.worker import Worker
from ui_.window.dialogs import QMessageBox, StandardButton, _FramelessDialog
from ui_.window.tor_log_dialog import TorLogDialog

logger = logging.getLogger(__name__)


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


class OnionHostingPage(QWidget):
    """Developer Tor dashboard. It never reuses the Main or Custom Tor pools."""

    runtime_progress = Signal(object)

    def __init__(self, proxy, app_window=None, parent=None):
        super().__init__(parent)
        self._proxy = proxy
        self._app_window = app_window
        self._workers: dict[str, Worker] = {}
        self._last_snapshot = None
        self._last_services = None
        self._thread_pool = QThreadPool(self)
        self._thread_pool.setMaxThreadCount(2)
        self.runtime_progress.connect(self._on_runtime_progress)

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 18, 24, 16)
        root.setSpacing(12)

        header = QHBoxLayout()
        self.back_button = QPushButton("Back to Home", self)
        self.back_button.setObjectName("onionBackButton")
        self.back_button.setIcon(qta.icon("fa6s.arrow-left"))
        self.back_button.clicked.connect(self._back_home)
        header.addWidget(self.back_button)
        header.addStretch(1)
        self.page_title = QLabel("Developer Tor", self)
        self.page_title.setObjectName("onionPageTitle")
        header.addWidget(self.page_title)
        root.addLayout(header)

        self.description = QLabel(
            "Publish local applications as v3 Onion Services using a separate Tor process. "
            "Main Tor and Custom Tor settings, bridges, ports, and lifecycles are not shared.",
            self,
        )
        self.description.setObjectName("onionMuted")
        self.description.setWordWrap(True)
        root.addWidget(self.description)

        runtime = QFrame(self)
        runtime.setObjectName("onionRuntimeCard")
        runtime_layout = QVBoxLayout(runtime)
        runtime_layout.setContentsMargins(16, 13, 16, 13)
        runtime_layout.setSpacing(8)
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
        self.runtime_metrics.setObjectName("onionMuted")
        self.runtime_metrics.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        details.addWidget(self.runtime_metrics)
        runtime_layout.addLayout(details)

        actions = QHBoxLayout()
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
        self.services_layout.setSpacing(9)
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

    def _back_home(self):
        callback = getattr(self._app_window, "_show_home", None)
        if callable(callback):
            callback()

    def _apply_theme(self, mode):
        dark = str(mode).lower() == "dark"
        border = "#3b4552" if dark else "#d9e0e8"
        panel = "#202630" if dark else "#ffffff"
        text = "#e8edf3" if dark else "#253041"
        muted = "#aab5c4" if dark else "#667487"
        field = "#171c23" if dark else "#f5f7fa"
        accent = "#2385c3"
        hover = "rgba(71, 163, 242, 0.14)" if dark else "rgba(24, 118, 191, 0.08)"
        self.setStyleSheet(f"""
            QWidget {{ color: {text}; background: transparent; }}
            QLabel#onionPageTitle {{ font-size: 16px; font-weight: 800; }}
            QLabel#onionSectionTitle {{ font-size: 12px; font-weight: 800; letter-spacing: .5px; }}
            QLabel#onionMuted {{ color: {muted}; font-size: 10px; }}
            QFrame#onionRuntimeCard, QFrame#onionServiceCard {{
                background: {panel}; border: 1px solid {border}; border-radius: 11px;
            }}
            QLabel#onionRuntimeState {{
                background: {field}; border: 1px solid {border}; border-radius: 7px;
                padding: 4px 9px; font-size: 9px; font-weight: 800;
            }}
            QLabel#onionRuntimeState[runtimeState="ready"] {{ color: #31b981; border-color: #31b981; }}
            QLabel#onionRuntimeState[runtimeState="failed"] {{ color: #e36b75; border-color: #e36b75; }}
            QLabel#onionRuntimeMessage {{ color: {text}; font-size: 10px; }}
            QPushButton#onionBackButton, QPushButton#onionActionButton {{
                min-height: 31px; padding: 0 11px; border: 1px solid {border};
                border-radius: 7px; background: {panel}; color: {text}; font-weight: 650;
            }}
            QPushButton#onionBackButton:hover, QPushButton#onionActionButton:hover {{
                border-color: {accent}; background: {hover};
            }}
            QPushButton#onionActionPrimary {{
                min-height: 32px; padding: 0 12px; border: 1px solid {accent};
                border-radius: 7px; background: {accent}; color: white; font-weight: 750;
            }}
            QPushButton#onionActionPrimary:hover {{ background: #176b9f; }}
            QPushButton#onionActionButton:disabled, QPushButton#onionActionPrimary:disabled {{
                color: {muted}; background: {field}; border-color: {border};
            }}
            QScrollArea#onionServicesScroll {{ background: transparent; }}
            QLabel#onionServiceName {{ font-size: 12px; font-weight: 750; }}
            QLabel#onionServiceDetail {{ color: {muted}; font-size: 10px; }}
            QLabel#onionServiceAddress {{
                color: {text}; background: {field}; border: 1px solid {border};
                border-radius: 6px; padding: 7px; font-family: Consolas, monospace; font-size: 9px;
            }}
            QLabel#onionStatusPill {{
                color: {muted}; background: {field}; border: 1px solid {border};
                border-radius: 6px; padding: 3px 7px; font-size: 8px; font-weight: 750;
            }}
            QLineEdit, QComboBox, QSpinBox {{
                min-height: 30px; padding: 2px 8px; border: 1px solid {border};
                border-radius: 7px; background: {field}; color: {text};
            }}
        """)

    def _run(self, key: str, callback, *args, finished=None):
        if key in self._workers:
            return
        worker = Worker(callback, *args)
        worker.signals.finished.connect(
            lambda result, op=key, done=finished: self._on_worker_finished(op, result, done)
        )
        worker.signals.error.connect(
            lambda error, op=key: self._on_worker_error(op, error)
        )
        self._workers[key] = worker
        self._update_action_states()
        self._thread_pool.start(worker)

    def _on_worker_finished(self, key: str, result: str, callback=None):
        self._workers.pop(key, None)
        if callback is not None:
            try:
                callback(result)
            except Exception:
                logger.exception("Developer Tor UI completion handler failed.")
        self.refresh_dashboard()
        self._update_action_states()

    def _on_worker_error(self, key: str, error: str):
        self._workers.pop(key, None)
        self.status_label.setText(error)
        logger.warning("Developer Tor operation '%s' failed: %s", key, error)
        self.refresh_dashboard()
        self._update_action_states()
        QMessageBox.warning(self, "Developer Tor", error)

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
        self.start_runtime_button.setEnabled(not busy)
        self.stop_runtime_button.setEnabled(not busy)
        self.restart_runtime_button.setEnabled(not busy)
        self.add_service_button.setEnabled(not busy)
        self.refresh_button.setEnabled(not busy)

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
            if state == "ready" and runtime.get("progress") is not None:
                self.runtime_message.setText(f"{runtime['progress']}% · {runtime['message']}")
            version = runtime.get("version") or "version unavailable"
            memory = int(runtime.get("memory_bytes") or 0)
            memory_text = f"{memory / (1024 * 1024):.1f} MiB" if memory else "—"
            uptime = int(runtime.get("uptime_seconds") or 0)
            self.runtime_metrics.setText(f"{version}  ·  {memory_text}  ·  {uptime // 3600:02d}:{(uptime % 3600) // 60:02d}:{uptime % 60:02d}")
        if services != self._last_services:
            self._last_services = [dict(item) for item in services]
            self._rebuild_service_cards(services)
        state = str(runtime["state"]).lower()
        self.start_runtime_button.setEnabled(state in {"stopped", "failed"} and "runtime" not in self._workers)
        self.stop_runtime_button.setEnabled(state not in {"stopped"} and "runtime" not in self._workers)
        self.restart_runtime_button.setEnabled(state != "stopped" and "runtime" not in self._workers)

    def _rebuild_service_cards(self, services: list[dict]):
        while self.services_layout.count() > 1:
            item = self.services_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self.empty_label.setVisible(not services)
        if not services:
            self.services_layout.insertWidget(0, self.empty_label)
            return
        for service in services:
            self.services_layout.insertWidget(self.services_layout.count() - 1, self._service_card(service))

    def _service_card(self, service: dict) -> QWidget:
        card = QFrame(self.services_host)
        card.setObjectName("onionServiceCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 11, 14, 12)
        layout.setSpacing(8)

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
