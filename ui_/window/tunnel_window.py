"""Versioned manager for the verified sing-box system tunnel engine."""
from __future__ import annotations

import ast
import logging
from datetime import datetime, timezone

import qtawesome as qta
from PySide6.QtCore import Qt, QThreadPool, QUrl, Signal, QTimer
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from config import CONFIG
from ui_.window.dialogs import QMessageBox
from torproxy.network import tor_socks_proxy_url
from torproxy.system_tunnel import (
    SING_BOX_LATEST_VERSION,
    SUPPORTED_SING_BOX_VERSIONS,
    SystemTunnelError,
)
from ui_.worker.worker import Worker

logger = logging.getLogger(__name__)


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
        self._selected_release_asset: dict | None = None
        self._style_icon_color = "#dce8f4" if CONFIG.get("mode", "dark") == "dark" else "#334155"

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 7, 12, 8)
        root.setSpacing(7)

        header = QHBoxLayout()
        header.setSpacing(12)
        self.title_icon = QLabel()
        self.title_icon.setObjectName("bundlePageIcon")
        self.title_icon.setFixedSize(26, 26)
        self.title_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.addWidget(self.title_icon)

        titles = QVBoxLayout()
        titles.setSpacing(2)
        title = QLabel("System Tunnel · sing-box")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Install and manage the system-wide Tor tunnel engine.")
        subtitle.setObjectName("metadataLabel")
        titles.addWidget(title)
        titles.addWidget(subtitle)
        header.addLayout(titles, 1)

        self.btn_open_release = QPushButton("Official releases")
        self.btn_open_release.setObjectName("quietButton")
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
        content.setSpacing(10)

        self.release_panel = QFrame(self)
        self.release_panel.setObjectName("contentCard")
        self.release_panel.setMinimumWidth(220)
        self.release_panel.setMaximumWidth(420)
        release_layout = QVBoxLayout(self.release_panel)
        release_layout.setContentsMargins(12, 10, 12, 10)
        release_layout.setSpacing(6)
        release_heading_row = QHBoxLayout()
        release_heading = QLabel("Available releases")
        release_heading.setObjectName("sectionTitle")
        release_heading_row.addWidget(release_heading, 1)
        self.btn_check_latest = QPushButton("Check latest")
        self.btn_check_latest.setObjectName("quietButton")
        self.btn_check_latest.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_check_latest.setToolTip("Check GitHub for the latest stable sing-box release.")
        self.btn_check_latest.setIcon(qta.icon("fa6s.rotate"))
        self.btn_check_latest.clicked.connect(self.check_latest_release)
        release_heading_row.addWidget(self.btn_check_latest)
        release_layout.addLayout(release_heading_row)
        self.versions_list = QListWidget(self.release_panel)
        self.versions_list.setObjectName("releaseList")
        self.versions_list.setUniformItemSizes(True)
        self.versions_list.currentItemChanged.connect(self._on_version_changed)
        release_layout.addWidget(self.versions_list, 1)
        content.addWidget(self.release_panel, 1)

        details_panel = QFrame(self)
        details_panel.setObjectName("contentCard")
        details_layout = QVBoxLayout(details_panel)
        details_layout.setContentsMargins(12, 10, 12, 10)
        details_layout.setSpacing(6)

        self.selected_title = QLabel("sing-box")
        self.selected_title.setObjectName("sectionTitle")
        details_layout.addWidget(self.selected_title)

        self.version_meta = QLabel("")
        self.version_meta.setObjectName("metadataLabel")
        details_layout.addWidget(self.version_meta)

        self.installed_state = QLabel("Checking engine installation…")
        self.installed_state.setObjectName("stateLabel")
        self.installed_state.setWordWrap(True)
        details_layout.addWidget(self.installed_state)

        self.description = QLabel(
            "The selected release is downloaded from the official SagerNet release and checked "
            "against a SHA-256 digest pinned in TorProxy. The privileged helper validates the same "
            "archive and executable before starting the TUN interface."
        )
        self.description.setObjectName("mutedText")
        self.description.setWordWrap(True)
        details_layout.addWidget(self.description)

        route_card = QFrame(details_panel)
        route_card.setObjectName("infoCard")
        route_layout = QVBoxLayout(route_card)
        route_layout.setContentsMargins(12, 10, 12, 10)
        route_layout.setSpacing(4)
        route_title = QLabel("WHAT THE TUNNEL DOES")
        route_title.setObjectName("metadataLabel")
        route_body = QLabel(
            "TCP traffic is explicitly routed through Tor. Client DNS uses local FakeIP mapping, "
            "then Tor resolves the original hostname through SOCKS. UDP and unmatched traffic are blocked."
        )
        route_body.setWordWrap(True)
        route_body.setObjectName("mutedText")
        route_layout.addWidget(route_title)
        route_layout.addWidget(route_body)
        details_layout.addWidget(route_card)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.btn_install = QPushButton("Install selected version")
        self.btn_install.setObjectName("primaryButton")
        self.btn_install.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_install.setIcon(qta.icon("fa6s.download", color="#ffffff"))
        self.btn_install.clicked.connect(self.install_selected)
        buttons.addWidget(self.btn_install)

        self.btn_start_stop = QPushButton("Start system tunnel")
        self.btn_start_stop.setObjectName("quietButton")
        self.btn_start_stop.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_start_stop.clicked.connect(self.toggle_tunnel)
        buttons.addWidget(self.btn_start_stop)

        self.btn_test_connection = QPushButton("Test traffic")
        self.btn_test_connection.setObjectName("quietButton")
        self.btn_test_connection.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_test_connection.setToolTip(
            "Test Tor SOCKS and active TUN traffic without restarting the tunnel or requesting Administrator approval."
        )
        self.btn_test_connection.clicked.connect(self.test_tunnel_traffic)
        self.btn_test_connection.setEnabled(False)
        buttons.addWidget(self.btn_test_connection)
        details_layout.addLayout(buttons)

        self.progress = QProgressBar(details_panel)
        self.progress.setObjectName("bundleProgress")
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.hide()
        details_layout.addWidget(self.progress)

        self.status = QLabel("Select a verified version to install or manage the tunnel.")
        self.status.setObjectName("statusMessage")
        self.status.setWordWrap(True)
        details_layout.addWidget(self.status)
        details_layout.addStretch(1)

        content.addWidget(details_panel, 2)
        root.addLayout(content, 1)

        self.progress_changed.connect(self._on_progress)
        self._populate_versions()
        self._apply_local_styles(CONFIG.get("mode", "dark"))
        self._state_refresh_timer = QTimer(self)
        self._state_refresh_timer.setInterval(1000)
        self._state_refresh_timer.timeout.connect(self._refresh_state)
        self._state_refresh_timer.start()

    def _populate_versions(self) -> None:
        if self.manager is None:
            self.status.setText("The system tunnel manager is unavailable.")
            return
        installed = self.manager.installed_version
        installed_asset = getattr(self.manager, "installed_release_asset", None)
        pinned_versions = self.manager.supported_versions()
        selected_version = installed or SING_BOX_LATEST_VERSION

        self.versions_list.blockSignals(True)
        self.versions_list.clear()
        # Keep an already-installed newer release visible after restart, even if
        # this TorProxy build does not have its digest in the pinned release table.
        if installed and installed not in pinned_versions and isinstance(installed_asset, dict):
            item = QListWidgetItem(f"v{installed}   ·   Installed · upstream release")
            item.setData(Qt.ItemDataRole.UserRole, installed)
            item.setData(Qt.ItemDataRole.UserRole + 1, "upstream-installed")
            item.setData(Qt.ItemDataRole.UserRole + 2, installed_asset)
            item.setToolTip(
                "Installed from the official GitHub release after explicit risk confirmation. "
                "The saved asset and archive verification metadata are retained locally."
            )
            self.versions_list.addItem(item)
            self.versions_list.setCurrentItem(item)

        for version in pinned_versions:
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
            item.setToolTip(f"sing-box {version}\nReleased {published}\nTorProxy-pinned SHA-256")
            self.versions_list.addItem(item)
            if version == selected_version and not (
                installed and installed not in pinned_versions and isinstance(installed_asset, dict)
            ):
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
        release_asset = current.data(Qt.ItemDataRole.UserRole + 2)
        release_kind = current.data(Qt.ItemDataRole.UserRole + 1)
        try:
            if (
                isinstance(release_asset, dict)
                and release_kind in {"upstream-unpinned", "upstream-installed"}
            ):
                # Selecting a row only prepares the metadata; execution still
                # requires a separate, explicit risk confirmation in Install.
                self.manager.select_version(
                    version, release_asset=release_asset, allow_unpinned=True
                )
                self._selected_release_asset = dict(release_asset)
            else:
                self.manager.select_version(version)
                self._selected_release_asset = None
        except SystemTunnelError as exc:
            self.status.setText(str(exc))
            return

        if version in self.manager.supported_versions():
            metadata = self.manager.release_metadata(version)
        else:
            metadata = release_asset if isinstance(release_asset, dict) else {}
        self.selected_title.setText(f"sing-box v{version}")
        try:
            asset = self.manager.platform_asset
            platform_name = "Windows x64" if asset["archive"] == "zip" else "Linux x64"
            size = int(asset.get("size") or 0)
            if not size:
                platform_key = "Windows" if platform_name.startswith("Windows") else "Linux"
                size = int(metadata.get("asset_sizes", {}).get(platform_key, 0))
            trust = (
                "GitHub API SHA-256" if asset.get("sha256")
                else "HTTPS only · no publisher digest"
            ) if version not in self.manager.supported_versions() else "TorProxy-pinned SHA-256"
            self.version_meta.setText(
                f"{self._format_date(metadata.get('published_at', ''))}  ·  {platform_name}  ·  "
                f"{size / (1024 * 1024):.1f} MiB  ·  {trust}"
            )
            self._platform_supported = True
        except SystemTunnelError as exc:
            self.version_meta.setText(str(exc))
            self._platform_supported = False
        self._refresh_state()

    def _refresh_state(self) -> None:
        if self.manager is None:
            return
        try:
            status = self.manager.status()
            installed_version = self.manager.installed_version
        except Exception as exc:
            logger.debug("Could not refresh system tunnel state: %s", exc)
            self.installed_state.setText("Tunnel state is unavailable · inspect the event log")
            self.btn_start_stop.setText("Status unavailable")
            self.btn_start_stop.setEnabled(False)
            self.btn_test_connection.setEnabled(False)
            self.btn_start_stop.setIcon(qta.icon("fa6s.triangle-exclamation"))
            return
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

        proxy_busy = bool(
            self.proxy
            and (
                getattr(self.proxy, "_system_tunnel_busy", False)
                or getattr(self.proxy, "_stopping", False)
                or getattr(self.proxy, "_connect_operation_busy", False)
            )
        )
        self.versions_list.setEnabled(
            not self._busy and not proxy_busy and not status.get("active")
        )
        tor_ready = bool(
            self.proxy and self.proxy.running and self.proxy.connected and not proxy_busy
        )
        self.btn_test_connection.setEnabled(
            not self._busy and not proxy_busy and bool(status.get("active")) and tor_ready
        )
        self.btn_install.setEnabled(
            self._platform_supported and not self._busy and not proxy_busy
            and not status.get("active") and not selected_installed
        )
        self.btn_install.setText(
            "Update selected version" if installed_version and selected_version != installed_version
            else "Install selected version"
        )

        if status.get("active") or not status.get("verified", True):
            self.btn_start_stop.setText("Stop / reconcile tunnel")
            self.btn_start_stop.setEnabled(not self._busy and not proxy_busy)
        elif not self._platform_supported:
            self.btn_start_stop.setText("Unsupported platform")
            self.btn_start_stop.setEnabled(False)
        elif not selected_installed:
            self.btn_start_stop.setText("Install engine first")
            self.btn_start_stop.setEnabled(False)
        elif proxy_busy:
            self.btn_start_stop.setText("TorProxy is busy")
            self.btn_start_stop.setEnabled(False)
        elif not tor_ready:
            self.btn_start_stop.setText("Waiting for Tor")
            self.btn_start_stop.setEnabled(False)
        else:
            self.btn_start_stop.setText("Start system tunnel")
            self.btn_start_stop.setEnabled(not self._busy and not proxy_busy)

        if status.get("active"):
            action_icon = "fa6s.stop"
        elif not status.get("verified", True):
            action_icon = "fa6s.arrows-rotate"
        else:
            action_icon = "fa6s.play"
        self.btn_start_stop.setIcon(qta.icon(action_icon, color=self._style_icon_color))
        self.btn_test_connection.setIcon(qta.icon("fa6s.flask", color=self._style_icon_color))

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
        item = self.versions_list.currentItem()
        release_asset = item.data(Qt.ItemDataRole.UserRole + 2) if item is not None else None
        upstream_unpinned = (
            version not in self.manager.supported_versions()
            and isinstance(release_asset, dict)
        )
        if upstream_unpinned:
            digest = str(release_asset.get("sha256") or "")
            digest_note = (
                f"GitHub Releases API SHA-256: {digest}"
                if digest else
                "GitHub did not publish a SHA-256 digest for this asset. TorProxy can verify the HTTPS transfer, "
                "safe archive structure and local file hash, but cannot independently authenticate the publisher."
            )
            reply = QMessageBox.warning(
                self,
                "Install newer upstream sing-box release?",
                (
                    f"v{version} is newer than the releases pinned in this TorProxy build.\n\n"
                    "The exact platform archive will be downloaded from the official "
                    "github.com/SagerNet/sing-box release.\n\n"
                    f"{digest_note}\n\n"
                    "This release has not been independently reviewed or pinned by TorProxy. "
                    "A GitHub API digest is served by the same release service and is not an independent "
                    "publisher signature. Installing this version is your choice and risk. Continue?"
                ),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
            try:
                self.manager.select_version(
                    version, release_asset=release_asset, allow_unpinned=True
                )
            except SystemTunnelError as exc:
                QMessageBox.warning(self, "Tunnel engine", str(exc))
                return
        else:
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
            release_asset=release_asset if upstream_unpinned else None,
            allow_unpinned=upstream_unpinned,
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
        if (
            getattr(self.proxy, "_system_tunnel_busy", False)
            or getattr(self.proxy, "_stopping", False)
            or getattr(self.proxy, "_connect_operation_busy", False)
        ):
            self.status.setText("Wait for the current Tor or tunnel recovery operation to finish.")
            self._refresh_state()
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

    def test_tunnel_traffic(self) -> None:
        """Run the optional connectivity diagnostic without changing privileged state."""
        if self._busy or self.manager is None or self.proxy is None:
            return
        state = self.manager.status()
        if not state.get("active") or not state.get("verified"):
            QMessageBox.information(
                self, "Tunnel is not active",
                "Start the system tunnel before testing its traffic.",
            )
            return
        tor = getattr(self.proxy, "tor", None)
        if not (self.proxy.running and self.proxy.connected and tor is not None):
            QMessageBox.information(
                self, "Tor is not ready",
                "Reconnect to Tor before testing tunnel traffic.",
            )
            return
        self._run_operation(
            "test",
            self.manager.test_connection,
            int(tor.socks_port),
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
            "test": "Testing Tor SOCKS and traffic through the active TUN…",
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
        platform_asset = result.get("platform_asset")
        if self._upstream_unpinned_version:
            for index in range(self.versions_list.count() - 1, -1, -1):
                item = self.versions_list.item(index)
                if item.data(Qt.ItemDataRole.UserRole + 1) == "upstream-unpinned":
                    self.versions_list.takeItem(index)
            self._upstream_unpinned_version = None

        if result.get("supported"):
            message = f"Latest upstream stable: v{latest} · TorProxy-pinned and selectable"
        elif isinstance(platform_asset, dict):
            self._upstream_unpinned_version = latest
            digest = str(platform_asset.get("sha256") or "")
            digest_label = "GitHub API SHA-256 available" if digest else "HTTPS only · no API digest"
            item = QListWidgetItem(f"v{latest}   ·   New upstream · {digest_label}")
            item.setData(Qt.ItemDataRole.UserRole, latest)
            item.setData(Qt.ItemDataRole.UserRole + 1, "upstream-unpinned")
            item.setData(Qt.ItemDataRole.UserRole + 2, platform_asset)
            item.setToolTip(
                "This is the exact current-platform asset from the official SagerNet GitHub release. "
                "Select it and choose Install to review and accept the risk warning before downloading."
            )
            self.versions_list.insertItem(0, item)
            message = (
                f"New upstream stable v{latest} found ({published}). It can be installed after you "
                "review the warning and explicitly accept the risk. No TorProxy update is required."
            )
        else:
            message = (
                f"New upstream stable v{latest} found ({published}), but GitHub does not publish a "
                "matching Windows/Linux x64 asset for this device."
            )
        self.latest_label.setText(message)
        self._latest_info = result

    def open_release_page(self) -> None:
        QDesktopServices.openUrl(QUrl("https://github.com/SagerNet/sing-box/releases"))

    def _apply_local_styles(self, mode: str = "dark") -> None:
        """Use the compact surfaces and visual language of the Tor bundle manager."""
        dark = mode == "dark"
        accent = "#3daee9" if dark else "#287db5"
        border = "#414a56" if dark else "#d5dbe2"
        surface = "#20252b" if dark else "#ffffff"
        field = "#171c23" if dark else "#f8fafc"
        text = "#eff1f4" if dark else "#202832"
        muted = "#a6afb9" if dark else "#647080"
        icon_color = "#dce8f4" if dark else "#334155"
        self._style_icon_color = icon_color
        self.setStyleSheet(f"""
            QLabel#pageTitle {{ color: {text}; font-size: 20px; font-weight: 750; background: transparent; }}
            QLabel#bundlePageIcon {{ background: transparent; border: none; }}
            QLabel#sectionTitle {{ color: {text}; font-size: 13px; font-weight: 700; background: transparent; }}
            QLabel#metadataLabel, QLabel#stateLabel {{ color: {muted}; font-size: 11px; background: transparent; }}
            QLabel#mutedText {{ color: {muted}; font-size: 10px; background: transparent; }}
            QLabel#statusMessage {{ color: {text}; font-size: 11px; background: transparent; }}
            QLabel#tunnelLatestNotice {{ background: {surface}; color: {muted}; border: 1px solid {border}; border-radius: 8px; padding: 7px 11px; font-size: 11px; }}
            QFrame#infoCard, QFrame#contentCard {{ background: {surface}; border: 1px solid {border}; border-radius: 9px; }}
            QListWidget#releaseList {{ background: {field}; border: 1px solid {border}; border-radius: 7px; padding: 4px; color: {text}; outline: none; }}
            QListWidget#releaseList::item {{ min-height: 34px; padding: 6px 8px; border-radius: 5px; }}
            QListWidget#releaseList::item:hover {{ background: rgba(61, 174, 233, 0.10); }}
            QListWidget#releaseList::item:selected {{ background: {accent}; color: #ffffff; }}
            QPushButton {{ min-height: 28px; padding: 0 9px; border-radius: 6px; }}
            QPushButton#primaryButton {{ font-weight: 650; }}
            QPushButton#quietButton {{ min-height: 25px; }}
            QPushButton:disabled {{ color: {muted}; }}
            QProgressBar#bundleProgress {{ min-height: 7px; max-height: 7px; border: none; border-radius: 4px; background: {border}; }}
            QProgressBar#bundleProgress::chunk {{ background: {accent}; border: none; border-radius: 4px; }}
            QFrame#contentCard QLabel {{ background: transparent; }}
        """)
        self.title_icon.setPixmap(qta.icon("fa6s.network-wired", color=accent).pixmap(22, 22))
        self.btn_open_release.setIcon(qta.icon("fa6s.arrow-up-right-from-square", color=icon_color))
        self.btn_check_latest.setIcon(qta.icon("fa6s.rotate", color=icon_color))
        self.btn_install.setIcon(qta.icon("fa6s.download", color="#ffffff"))
        self.btn_start_stop.setIcon(qta.icon("fa6s.play", color=icon_color))
        self.btn_test_connection.setIcon(qta.icon("fa6s.flask", color=icon_color))
        self._refresh_state()



__all__ = ["TunnelManagerWindow"]
