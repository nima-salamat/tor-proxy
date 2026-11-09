"""Versioned manager for the verified sing-box system tunnel engine."""
from __future__ import annotations

import ast
from datetime import datetime, timezone

import qtawesome as qta
from PySide6.QtCore import Qt, QThreadPool, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QPalette, QColor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from config import CONFIG
from torproxy.network import tor_socks_proxy_url
from torproxy.system_tunnel import (
    SING_BOX_LATEST_VERSION,
    SUPPORTED_SING_BOX_VERSIONS,
    SystemTunnelError,
)
from ui_.worker.worker import Worker


class TunnelManagerWindow(QWidget):
    """Install, select, verify and operate the pinned sing-box TUN engine."""

    progress_changed = Signal(str, int, int, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._parent = parent
        self.proxy = getattr(parent, "proxyWidget", None)
        self.manager = getattr(self.proxy, "system_tunnel_manager", None)
        self._platform_supported = False
        self._pool = QThreadPool(self)
        self._busy = False
        self._operation = ""
        self._worker = None
        self._latest_worker = None
        self._latest_info: dict | None = None
        self._upstream_unpinned_version: str | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 18)
        root.setSpacing(14)

        header = QHBoxLayout()
        header.setSpacing(12)
        self.title_icon = QLabel()
        self.title_icon.setFixedSize(32, 32)
        self.title_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.addWidget(self.title_icon)

        titles = QVBoxLayout()
        titles.setSpacing(2)
        title = QLabel("System tunnel")
        title.setObjectName("tunnelPageTitle")
        subtitle = QLabel("Manage the sing-box engine and system-wide Tor routing.")
        subtitle.setObjectName("tunnelPageSubtitle")
        titles.addWidget(title)
        titles.addWidget(subtitle)
        header.addLayout(titles, 1)

        self.btn_open_release = QPushButton("Official releases")
        self.btn_open_release.setObjectName("tunnelSecondaryButton")
        self.btn_open_release.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_open_release.setIcon(qta.icon("fa6s.arrow-up-right-from-square"))
        self.btn_open_release.clicked.connect(self.open_release_page)
        header.addWidget(self.btn_open_release)
        root.addLayout(header)

        self.latest_label = QLabel(
            f"Latest verified stable release: v{SING_BOX_LATEST_VERSION}"
        )
        self.latest_label.setObjectName("tunnelLatestNotice")
        self.latest_label.setWordWrap(True)
        root.addWidget(self.latest_label)

        content = QHBoxLayout()
        content.setSpacing(14)

        self.release_panel = QFrame(self)
        self.release_panel.setObjectName("tunnelReleasePanel")
        self.release_panel.setMinimumWidth(220)
        self.release_panel.setMaximumWidth(300)
        release_layout = QVBoxLayout(self.release_panel)
        release_layout.setContentsMargins(14, 14, 14, 14)
        release_layout.setSpacing(9)
        release_heading = QLabel("AVAILABLE VERSIONS")
        release_heading.setObjectName("tunnelSectionLabel")
        release_layout.addWidget(release_heading)
        self.versions_list = QListWidget(self.release_panel)
        self.versions_list.setObjectName("tunnelVersionsList")
        self.versions_list.setUniformItemSizes(True)
        self.versions_list.currentItemChanged.connect(self._on_version_changed)
        release_layout.addWidget(self.versions_list, 1)
        self.btn_check_latest = QPushButton("Check latest release")
        self.btn_check_latest.setObjectName("tunnelSecondaryButton")
        self.btn_check_latest.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_check_latest.setIcon(qta.icon("fa6s.rotate"))
        self.btn_check_latest.clicked.connect(self.check_latest_release)
        release_layout.addWidget(self.btn_check_latest)
        content.addWidget(self.release_panel, 0)

        details_panel = QFrame(self)
        details_panel.setObjectName("tunnelDetailsPanel")
        details_layout = QVBoxLayout(details_panel)
        details_layout.setContentsMargins(18, 16, 18, 16)
        details_layout.setSpacing(12)

        self.selected_title = QLabel("sing-box")
        self.selected_title.setObjectName("tunnelSelectedTitle")
        details_layout.addWidget(self.selected_title)

        self.version_meta = QLabel("")
        self.version_meta.setObjectName("tunnelVersionMeta")
        details_layout.addWidget(self.version_meta)

        self.installed_state = QLabel("Checking engine installation…")
        self.installed_state.setObjectName("tunnelInstalledState")
        self.installed_state.setWordWrap(True)
        details_layout.addWidget(self.installed_state)

        self.description = QLabel(
            "The selected release is downloaded from the official SagerNet release and checked "
            "against a SHA-256 digest pinned in TorProxy. The privileged helper validates the same "
            "archive and executable before starting the TUN interface."
        )
        self.description.setObjectName("tunnelDescription")
        self.description.setWordWrap(True)
        details_layout.addWidget(self.description)

        route_card = QFrame(details_panel)
        route_card.setObjectName("tunnelInfoCard")
        route_layout = QVBoxLayout(route_card)
        route_layout.setContentsMargins(12, 10, 12, 10)
        route_layout.setSpacing(4)
        route_title = QLabel("WHAT THE TUNNEL DOES")
        route_title.setObjectName("tunnelSectionLabel")
        route_body = QLabel(
            "System TCP traffic is routed through Tor. DNS uses HTTPS over Tor. UDP is rejected "
            "rather than sent directly. Tor must already be connected before the tunnel can start."
        )
        route_body.setWordWrap(True)
        route_body.setObjectName("tunnelRouteDescription")
        route_layout.addWidget(route_title)
        route_layout.addWidget(route_body)
        details_layout.addWidget(route_card)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.btn_install = QPushButton("Install selected version")
        self.btn_install.setObjectName("tunnelPrimaryButton")
        self.btn_install.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_install.setIcon(qta.icon("fa6s.download", color="#ffffff"))
        self.btn_install.clicked.connect(self.install_selected)
        buttons.addWidget(self.btn_install)

        self.btn_start_stop = QPushButton("Start system tunnel")
        self.btn_start_stop.setObjectName("tunnelSecondaryButton")
        self.btn_start_stop.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_start_stop.clicked.connect(self.toggle_tunnel)
        buttons.addWidget(self.btn_start_stop)
        details_layout.addLayout(buttons)

        self.progress = QProgressBar(details_panel)
        self.progress.setObjectName("tunnelProgress")
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        self.progress.hide()
        details_layout.addWidget(self.progress)

        self.status = QLabel("Select a verified version to install or manage the tunnel.")
        self.status.setObjectName("tunnelOperationStatus")
        self.status.setWordWrap(True)
        details_layout.addWidget(self.status)
        details_layout.addStretch(1)

        content.addWidget(details_panel, 1)
        root.addLayout(content, 1)

        self.progress_changed.connect(self._on_progress)
        self._populate_versions()
        self._apply_local_styles(CONFIG.get("mode", "dark"))

    def _populate_versions(self) -> None:
        if self.manager is None:
            self.status.setText("The system tunnel manager is unavailable.")
            return
        installed = self.manager.installed_version
        selected_version = (
            installed if installed in SUPPORTED_SING_BOX_VERSIONS
            else SING_BOX_LATEST_VERSION
        )
        self.versions_list.blockSignals(True)
        self.versions_list.clear()
        for version in self.manager.supported_versions():
            metadata = self.manager.release_metadata(version)
            published = self._format_date(metadata.get("published_at", ""))
            suffix = []
            if version == SING_BOX_LATEST_VERSION:
                suffix.append("Latest stable")
            if version == installed:
                suffix.append("Installed")
            label = f"v{version}"
            if suffix:
                label += "   ·   " + " · ".join(suffix)
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, version)
            item.setToolTip(f"sing-box {version}\nReleased {published}\nOfficial pinned SHA-256")
            self.versions_list.addItem(item)
            if version == selected_version:
                self.versions_list.setCurrentItem(item)
        self.versions_list.blockSignals(False)
        if self.versions_list.currentItem() is None and self.versions_list.count():
            self.versions_list.setCurrentRow(0)
        self._on_version_changed(self.versions_list.currentItem(), None)

    @staticmethod
    def _format_date(value: str) -> str:
        if not value:
            return "Release date unavailable"
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.astimezone(timezone.utc).strftime("%d %b %Y")
        except (TypeError, ValueError):
            return str(value)

    def _selected_version(self) -> str:
        item = self.versions_list.currentItem()
        return str(item.data(Qt.ItemDataRole.UserRole)) if item else SING_BOX_LATEST_VERSION

    def _on_version_changed(self, current, _previous) -> None:
        if self.manager is None or current is None or self._busy:
            return
        version = str(current.data(Qt.ItemDataRole.UserRole) or "")
        try:
            self.manager.select_version(version)
        except SystemTunnelError as exc:
            self.status.setText(str(exc))
            return
        metadata = self.manager.release_metadata(version)
        self.selected_title.setText(f"sing-box v{version}")
        try:
            asset = self.manager.platform_asset
            platform_name = "Windows x64" if asset["archive"] == "zip" else "Linux x64"
            platform_key = "Windows" if platform_name.startswith("Windows") else "Linux"
            size = int(metadata.get("asset_sizes", {}).get(platform_key, 0))
            self.version_meta.setText(
                f"{self._format_date(metadata.get('published_at', ''))}  ·  {platform_name}  ·  "
                f"{size / (1024 * 1024):.1f} MiB"
            )
            self._platform_supported = True
        except SystemTunnelError as exc:
            self.version_meta.setText(str(exc))
            self._platform_supported = False
        self._refresh_state()

    def _refresh_state(self) -> None:
        if self.manager is None:
            return
        status = self.manager.status()
        installed_version = self.manager.installed_version
        selected_version = self._selected_version()
        try:
            selected_installed = self.manager.is_installed()
        except SystemTunnelError:
            selected_installed = False

        if status.get("active"):
            self.installed_state.setText(
                f"Tunnel active · sing-box v{installed_version or selected_version} · {status.get('detail', '')}"
            )
        elif not status.get("verified", True):
            self.installed_state.setText(
                f"Tunnel state needs reconciliation · {status.get('detail', '')}"
            )
        elif selected_installed:
            self.installed_state.setText(
                f"Installed and verified · sing-box v{selected_version}"
            )
        elif installed_version:
            self.installed_state.setText(
                f"Installed v{installed_version} · v{selected_version} is selected and ready to install"
            )
        else:
            self.installed_state.setText("Not installed · Download the selected engine to enable the tunnel.")

        self.versions_list.setEnabled(not self._busy and not status.get("active"))
        self.btn_install.setEnabled(
            self._platform_supported and not self._busy and not status.get("active") and not selected_installed
        )
        self.btn_install.setText(
            "Update selected version" if installed_version and selected_version != installed_version
            else "Install selected version"
        )

        if status.get("active") or not status.get("verified", True):
            self.btn_start_stop.setText("Stop / reconcile tunnel")
            self.btn_start_stop.setEnabled(not self._busy)
        elif not self._platform_supported:
            self.btn_start_stop.setText("Unsupported platform")
            self.btn_start_stop.setEnabled(False)
        elif not selected_installed:
            self.btn_start_stop.setText("Install engine first")
            self.btn_start_stop.setEnabled(False)
        elif not (self.proxy and self.proxy.running and self.proxy.connected):
            self.btn_start_stop.setText("Waiting for Tor")
            self.btn_start_stop.setEnabled(False)
        else:
            self.btn_start_stop.setText("Start system tunnel")
            self.btn_start_stop.setEnabled(not self._busy)

    def _resolve_network_route(self, purpose: str) -> tuple[str | None, bool] | None:
        """Prefer the ready Tor SOCKS listener; direct bootstrap always needs consent."""
        tor = getattr(self.proxy, "tor", None)
        state = str(getattr(tor, "state", "STOPPED") or "STOPPED").upper()
        state = state.split(".")[-1]
        if state == "READY":
            try:
                port = int(getattr(tor, "socks_port"))
                return tor_socks_proxy_url("127.0.0.1", port), False
            except (AttributeError, TypeError, ValueError, RuntimeError) as exc:
                QMessageBox.warning(
                    self, "Tor proxy unavailable",
                    f"Tor reports READY, but its SOCKS endpoint could not be validated: {exc}",
                )
                return None
        if state in {"STARTING", "BOOTSTRAPPING", "STOPPING"}:
            QMessageBox.information(
                self, "Tor is still connecting",
                f"{purpose} was not started. Wait until Tor reaches READY.",
            )
            return None
        reply = QMessageBox.question(
            self,
            "Allow direct bootstrap connection?",
            (
                f"Tor is not connected. {purpose} needs to contact the official SagerNet release service. "
                "Allow this download to connect directly, outside Tor? Your network provider may see "
                "the destination and traffic metadata. TorProxy will not fall back to a direct route "
                "if a Tor-routed download fails."
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return (None, True) if reply == QMessageBox.StandardButton.Yes else None

    def install_selected(self) -> None:
        if self._busy or self.manager is None:
            return
        version = self._selected_version()
        try:
            self.manager.select_version(version)
        except SystemTunnelError as exc:
            QMessageBox.warning(self, "Tunnel engine", str(exc))
            return
        route = self._resolve_network_route("sing-box tunnel-engine download")
        if route is None:
            return
        proxy_url, allow_direct = route
        progress_callback = lambda stage, current, total, message: self.progress_changed.emit(
            stage, current, total, message
        )
        self._run_operation(
            "install",
            self.manager.install_engine,
            version,
            progress_callback,
            proxy_url=proxy_url,
            allow_direct=allow_direct,
        )

    def toggle_tunnel_from_home(self) -> None:
        """Start the installed version from Home without changing the page selection."""
        if self._busy or self.manager is None:
            return
        state = self.manager.status()
        if not state.get("active") and state.get("verified", True):
            installed_version = self.manager.installed_version
            if installed_version:
                for index in range(self.versions_list.count()):
                    item = self.versions_list.item(index)
                    if str(item.data(Qt.ItemDataRole.UserRole)) == installed_version:
                        self.versions_list.setCurrentItem(item)
                        break
        self.toggle_tunnel()

    def toggle_tunnel(self) -> None:
        if self._busy or self.manager is None or self.proxy is None:
            return
        state = self.manager.status()
        if state.get("active") or not state.get("verified", True):
            self._run_operation("stop", self.manager.stop)
            return
        if not self.manager.is_installed():
            QMessageBox.information(
                self, "Tunnel engine not installed",
                "Open Updates → Tunnel and install a verified sing-box version first.",
            )
            return
        if not self.proxy.running or not self.proxy.connected:
            QMessageBox.information(
                self, "Tor is not ready",
                "Connect to Tor and wait for the verified SOCKS and ControlPort state before starting the system tunnel.",
            )
            return
        tor = self.proxy.tor
        tor.update_path(CONFIG.get("tor_path"))
        if not tor.tor_path:
            QMessageBox.warning(self, "Tor executable unavailable", "Choose a verified Tor Expert Bundle first.")
            return
        executables = [path for path in (tor.tor_path, tor.lyrebird_path) if path]
        self._run_operation(
            "start",
            self.manager.start,
            int(tor.socks_port),
            tor_executables=executables,
        )

    def _run_operation(self, operation: str, method, *args, **kwargs) -> None:
        self._busy = True
        self._operation = operation
        if self.proxy is not None and operation in {"start", "stop"}:
            self.proxy._system_tunnel_busy = True
        self.progress.show()
        self.progress.setRange(0, 0)
        self.progress.setFormat("Working…")
        self.status.setText({
            "install": "Downloading and verifying the selected sing-box release…",
            "start": "Requesting permission and creating the TUN interface…",
            "stop": "Stopping sing-box and verifying route cleanup…",
        }.get(operation, "Working…"))
        self._refresh_state()
        worker = Worker(method, *args, **kwargs)
        worker.signals.finished.connect(self._on_operation_finished)
        worker.signals.error.connect(self._on_operation_failed)
        self._worker = worker
        self._pool.start(worker)

    def _on_progress(self, stage: str, current: int, total: int, message: str) -> None:
        if not self._busy or self._operation != "install":
            return
        self.status.setText(message)
        if total > 0:
            self.progress.setRange(0, 100)
            self.progress.setValue(min(100, int(current * 100 / total)))
            self.progress.setFormat(f"{self.progress.value()}%")
        else:
            self.progress.setRange(0, 0)

    def _on_operation_finished(self, result) -> None:
        operation = self._operation
        self._finish_operation()
        if operation == "check-latest":
            self._apply_latest_result(result)
            return
        message = str(result or "Operation completed.")
        self.status.setText(message)
        if self.proxy is not None:
            self.proxy.logs_widget.update_log(f"System tunnel {operation}: {message}", level="success")
        self._populate_versions()

    def _on_operation_failed(self, error: str) -> None:
        operation = self._operation
        self._finish_operation()
        detail = str(error or "Unknown system tunnel error.")
        self.status.setText(f"{operation.title()} failed: {detail}")
        if self.proxy is not None:
            self.proxy.logs_widget.update_log(f"System tunnel {operation} failed: {detail}", level="error")
        QMessageBox.warning(self, "System tunnel", detail)
        self._populate_versions()

    def _finish_operation(self) -> None:
        self._busy = False
        self._operation = ""
        self._worker = None
        if self.proxy is not None:
            self.proxy._system_tunnel_busy = False
            self.proxy._update_tunnel_hint()
        self.progress.hide()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self._refresh_state()

    def check_latest_release(self) -> None:
        if self._busy or self._latest_worker is not None or self.manager is None:
            return
        route = self._resolve_network_route("sing-box latest-release check")
        if route is None:
            return
        proxy_url, allow_direct = route
        self.btn_check_latest.setEnabled(False)
        self.latest_label.setText("Checking the official sing-box stable release…")
        worker = Worker(
            self.manager.check_latest_release,
            proxy_url,
            allow_direct=allow_direct,
        )
        worker.signals.finished.connect(self._on_latest_check_finished)
        worker.signals.error.connect(self._on_latest_check_failed)
        self._latest_worker = worker
        self._pool.start(worker)

    def _on_latest_check_finished(self, result) -> None:
        self._latest_worker = None
        self.btn_check_latest.setEnabled(True)
        self._apply_latest_result(result)

    def _on_latest_check_failed(self, error: str) -> None:
        self._latest_worker = None
        self.btn_check_latest.setEnabled(True)
        self.latest_label.setText(
            "Could not refresh the upstream release information. Installed and pinned versions remain available."
        )
        self.status.setText(str(error))

    def _apply_latest_result(self, result) -> None:
        # Worker normalizes its result signal to text; decode the literal safely.
        if isinstance(result, str):
            try:
                result = ast.literal_eval(result)
            except (ValueError, SyntaxError):
                result = None
        if not isinstance(result, dict):
            self.latest_label.setText("The upstream release response was not valid.")
            return
        latest = str(result.get("version", "unknown"))
        published = self._format_date(str(result.get("published_at", "")))
        if self._upstream_unpinned_version:
            for index in range(self.versions_list.count() - 1, -1, -1):
                item = self.versions_list.item(index)
                if item.data(Qt.ItemDataRole.UserRole + 1) == "upstream-unpinned":
                    self.versions_list.takeItem(index)
            self._upstream_unpinned_version = None

        if result.get("supported"):
            message = f"Latest upstream stable: v{latest} · verified and selectable"
        else:
            message = (
                f"New upstream stable release v{latest} found ({published}), but this TorProxy build "
                "does not yet contain a pinned SHA-256 for it. Update TorProxy before installing that release."
            )
            self._upstream_unpinned_version = latest
            item = QListWidgetItem(f"v{latest}   ·   New upstream · not verified")
            item.setData(Qt.ItemDataRole.UserRole, latest)
            item.setData(Qt.ItemDataRole.UserRole + 1, "upstream-unpinned")
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled & ~Qt.ItemFlag.ItemIsSelectable)
            item.setToolTip(
                "This release is visible for update awareness only. Its platform archive SHA-256 "
                "has not been reviewed and pinned in this TorProxy build, so installation is disabled."
            )
            self.versions_list.insertItem(0, item)
        self.latest_label.setText(message)
        self._latest_info = result

    def open_release_page(self) -> None:
        QDesktopServices.openUrl(QUrl("https://github.com/SagerNet/sing-box/releases"))

    def _apply_local_styles(self, mode: str = "dark") -> None:
        dark = mode == "dark"
        surface = "#151e29" if dark else "#ffffff"
        field = "#0d151f" if dark else "#f4f6f8"
        border = "#2d3a47" if dark else "#d8dee5"
        text = "#edf2f7" if dark else "#202a35"
        muted = "#9aa8b7" if dark else "#687582"
        accent = "#1d8f88" if dark else "#087f79"
        hover = "#233444" if dark else "#eaf0f4"
        self.setStyleSheet(f"""
            QFrame#tunnelReleasePanel, QFrame#tunnelDetailsPanel {{
                background: {surface}; border: 1px solid {border}; border-radius: 12px;
            }}
            QFrame#tunnelInfoCard {{
                background: {field}; border: 1px solid {border}; border-radius: 9px;
            }}
            QLabel#tunnelPageTitle, QLabel#tunnelSelectedTitle {{
                background: transparent; color: {text}; font-size: 19px; font-weight: 750; border: none;
            }}
            QLabel#tunnelPageSubtitle, QLabel#tunnelVersionMeta, QLabel#tunnelDescription,
            QLabel#tunnelRouteDescription, QLabel#tunnelOperationStatus {{
                background: transparent; color: {muted}; border: none; font-size: 11px;
            }}
            QLabel#tunnelSectionLabel {{ background: transparent; color: {muted}; font-size: 9px; font-weight: 800; border: none; }}
            QLabel#tunnelLatestNotice {{
                background: {field}; color: {text}; border: 1px solid {border}; border-radius: 8px;
                padding: 9px 12px; font-size: 11px;
            }}
            QLabel#tunnelInstalledState {{ background: transparent; color: {accent}; border: none; font-size: 11px; font-weight: 700; }}
            QListWidget#tunnelVersionsList {{
                background: {field}; color: {text}; border: 1px solid {border}; border-radius: 8px;
                outline: none; padding: 4px;
            }}
            QListWidget#tunnelVersionsList::item {{ padding: 12px 9px; border-radius: 6px; }}
            QListWidget#tunnelVersionsList::item:selected {{ background: {accent}; color: white; }}
            QListWidget#tunnelVersionsList::item:hover:!selected {{ background: {hover}; }}
            QPushButton#tunnelPrimaryButton, QPushButton#tunnelSecondaryButton {{
                min-height: 34px; padding: 0 13px; border-radius: 8px; font-size: 11px; font-weight: 700;
            }}
            QPushButton#tunnelPrimaryButton {{ background: {accent}; color: white; border: 1px solid {accent}; }}
            QPushButton#tunnelPrimaryButton:hover {{ background: #177c76; }}
            QPushButton#tunnelSecondaryButton {{ background: {field}; color: {text}; border: 1px solid {border}; }}
            QPushButton#tunnelSecondaryButton:hover {{ background: {hover}; }}
            QPushButton:disabled {{ color: {muted}; background: {field}; border-color: {border}; }}
            QProgressBar#tunnelProgress {{
                min-height: 7px; max-height: 7px; border: none; border-radius: 4px; background: {border};
            }}
            QProgressBar#tunnelProgress::chunk {{ background: {accent}; border-radius: 4px; }}
        """)
        self.title_icon.setPixmap(qta.icon("fa6s.network-wired", color=accent).pixmap(30, 30))
        self.btn_open_release.setIcon(qta.icon("fa6s.arrow-up-right-from-square", color=text))
        self.btn_check_latest.setIcon(qta.icon("fa6s.rotate", color=text))
        self.btn_install.setIcon(qta.icon("fa6s.download", color="#ffffff"))


__all__ = ["TunnelManagerWindow"]
