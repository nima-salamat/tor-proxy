"""Modern Tor bundle manager with lazy artifact checks and stage-aware progress."""
from __future__ import annotations

import ast
import logging
import json
import os
from pathlib import Path
from threading import Event

from PySide6.QtCore import Qt, QThreadPool, Signal, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtGui import QPalette
import qtawesome as qta
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFrame,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from config import BUNDLE_DIR, CONFIG, TOR_BUNDLE_BASE_URL
from ui_.window.dialogs import QMessageBox
from torproxy.bundle import BundleProgress
from updater import (
    delete_bundle,
    download_file,
    get_bundle_links,
    get_own_bundles,
    get_tor_versions,
    get_version_by_bundle,
    import_local_bundle as import_bundle_archive,
    tor_version_channel,
)
from torproxy.network import tor_socks_proxy_url
from utils import extract_tar_gz_file
from ui_.worker.worker import Worker

logger = logging.getLogger(__name__)


class UpdaterWindow(QWidget):
    """Manage official and local Tor bundles with explicit trust and network routes."""

    progress_event = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_ = parent
        self.thread_pool = QThreadPool(self)
        self.worker = None
        self.cancel_event: Event | None = None
        self._busy = False
        self._available_versions: list[str] = []
        self._verified_bundles_cache: list[str] = []
        self._bundle_scan_in_progress = False
        self._bundle_scan_worker = None
        self._last_download: tuple[str, str, bool] | None = None
        self._operation_route: tuple[str | None, bool] | None = None
        self._missing_bundle_notified = False

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 7, 12, 8)
        root.setSpacing(7)

        title_row = QHBoxLayout()
        title_row.setContentsMargins(2, 0, 2, 0)
        title_row.setSpacing(9)
        title_icon = QLabel()
        title_icon.setObjectName("bundlePageIcon")
        title_icon.setFixedSize(26, 26)
        title_row.addWidget(title_icon)
        title = QLabel("Tor Bundles & Updates")
        title.setObjectName("pageTitle")
        title_row.addWidget(title, 1)

        source_label = QLabel("Official source")
        source_label.setObjectName("metadataLabel")
        source_label.setToolTip("Official Tor Expert Bundle release listing used for discovery and downloads.")
        title_row.addWidget(source_label)
        self.bundle_source_url = QLineEdit(TOR_BUNDLE_BASE_URL)
        self.bundle_source_url.setObjectName("bundleSourceUrl")
        self.bundle_source_url.setReadOnly(True)
        self.bundle_source_url.setFixedSize(272, 27)
        self.bundle_source_url.setToolTip(
            "Official Tor Expert Bundle release index. Use the adjacent button to copy this URL."
        )
        title_row.addWidget(self.bundle_source_url)
        self.btn_copy_bundle_source = QPushButton()
        self.btn_copy_bundle_source.setObjectName("copySourceButton")
        self.btn_copy_bundle_source.setFixedSize(28, 27)
        self.btn_copy_bundle_source.setIcon(qta.icon("fa6s.copy", color="#334155"))
        self.btn_copy_bundle_source.setToolTip("Copy the official Tor release index URL")
        self.btn_copy_bundle_source.setAccessibleName("Copy official Tor release index URL")
        self.btn_copy_bundle_source.clicked.connect(self._copy_bundle_source_url)
        title_row.addWidget(self.btn_copy_bundle_source)

        root.addLayout(title_row)
        self._title_icon = title_icon

        platform_card = QFrame()
        platform_card.setObjectName("infoCard")
        platform_row = QHBoxLayout(platform_card)
        platform_row.setContentsMargins(12, 7, 12, 7)
        self.lbl_platform = QLabel(self._platform_summary())
        self.lbl_platform.setObjectName("metadataLabel")
        self.lbl_install_state = QLabel()
        self.lbl_install_state.setObjectName("stateLabel")
        self.lbl_install_state.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        platform_row.addWidget(self.lbl_platform, 1)
        platform_row.addWidget(self.lbl_install_state)
        root.addWidget(platform_card)

        columns = QHBoxLayout()
        columns.setSpacing(10)
        root.addLayout(columns, 1)

        available_card = QFrame()
        available_card.setObjectName("contentCard")
        available_layout = QVBoxLayout(available_card)
        available_layout.setContentsMargins(12, 10, 12, 10)
        available_layout.setSpacing(6)
        heading_row = QHBoxLayout()
        section_title = QLabel("Available releases")
        section_title.setObjectName("sectionTitle")
        heading_row.addWidget(section_title, 1)
        self.btn_get_versions = QPushButton("Refresh")
        self.btn_get_versions.setObjectName("primaryButton")
        self.btn_get_versions.setIcon(qta.icon("fa6s.arrows-rotate", color="#ffffff"))
        self.btn_get_versions.clicked.connect(self.get_available_versions)
        heading_row.addWidget(self.btn_get_versions)
        available_layout.addLayout(heading_row)
        self.search_versions = QLineEdit()
        self.search_versions.setPlaceholderText("Search versions…")
        self.search_versions.setClearButtonEnabled(True)
        self.search_versions.textChanged.connect(self._filter_versions)
        available_layout.addWidget(self.search_versions)
        self.chk_prereleases = QCheckBox("Include alpha prereleases")
        self.chk_prereleases.setChecked(True)
        self.chk_prereleases.toggled.connect(self._filter_versions)
        available_layout.addWidget(self.chk_prereleases)
        self.updates_list = QListWidget()
        self.updates_list.setObjectName("releaseList")
        self.updates_list.setUniformItemSizes(True)
        self.updates_list.setMinimumHeight(250)
        self.updates_list.setSelectionMode(QListWidget.SingleSelection)
        self.updates_list.itemClicked.connect(self.selected_version)
        available_layout.addWidget(self.updates_list, 1)
        self.lbl_discovery = QLabel("Refresh to retrieve the official Tor release directories.")
        self.lbl_discovery.setObjectName("mutedText")
        self.lbl_discovery.setWordWrap(False)
        self.lbl_discovery.setMaximumHeight(18)
        self.lbl_discovery.setToolTip("Refresh to retrieve official Tor release directories. Stable releases are sorted before alpha prereleases.")
        available_layout.addWidget(self.lbl_discovery)
        columns.addWidget(available_card, 3)

        installed_card = QFrame()
        installed_card.setObjectName("contentCard")
        installed_layout = QVBoxLayout(installed_card)
        installed_layout.setContentsMargins(12, 10, 12, 10)
        installed_layout.setSpacing(6)
        local_heading = QHBoxLayout()
        local_title = QLabel("Installed bundles")
        local_title.setObjectName("sectionTitle")
        local_heading.addWidget(local_title, 1)
        self.btn_import_bundle = QPushButton("Import .tar.gz")
        self.btn_import_bundle.setObjectName("quietButton")
        self.btn_import_bundle.setIcon(qta.icon("fa6s.file-import", color="#dce8f4"))
        self.btn_import_bundle.setToolTip(
            "Import a local Tor Expert Bundle archive. A matching .asc file is used when signature verification is enabled."
        )
        self.btn_import_bundle.clicked.connect(self.choose_local_bundle)
        local_heading.addWidget(self.btn_import_bundle)
        self.btn_refresh_version = QPushButton("Rescan")
        self.btn_refresh_version.setIcon(qta.icon("fa6s.rotate", color="#dce8f4"))
        self.btn_refresh_version.clicked.connect(self.refresh_version)
        local_heading.addWidget(self.btn_refresh_version)
        installed_layout.addLayout(local_heading)
        self.list_tor_versions = QListWidget()
        self.list_tor_versions.setObjectName("releaseList")
        self.list_tor_versions.setMinimumHeight(250)
        self.list_tor_versions.setSelectionMode(QListWidget.SingleSelection)
        self.list_tor_versions.setToolTip(
            "Only bundles with a valid integrity marker, matching archive digest, compatible executable and safe layout are listed. Trust method is shown per bundle."
        )
        installed_layout.addWidget(self.list_tor_versions, 1)
        self.lbl_default = QLabel()
        self.lbl_default.setObjectName("mutedText")
        self.lbl_default.setWordWrap(False)
        self.lbl_default.setMaximumHeight(18)
        installed_layout.addWidget(self.lbl_default)
        action_row = QHBoxLayout()
        self.btn_set_default_version = QPushButton("Use as default")
        self.btn_set_default_version.setObjectName("primaryButton")
        self.btn_set_default_version.setIcon(qta.icon("fa6s.check", color="#ffffff"))
        self.btn_set_default_version.clicked.connect(self.set_default_version)
        self.btn_delete_version = QPushButton("Delete")
        self.btn_delete_version.setObjectName("dangerButton")
        self.btn_delete_version.setIcon(qta.icon("fa6s.trash", color="#d94c4c"))
        self.btn_delete_version.clicked.connect(self.delete_version)
        action_row.addWidget(self.btn_set_default_version, 1)
        action_row.addWidget(self.btn_delete_version)
        installed_layout.addLayout(action_row)
        columns.addWidget(installed_card, 2)

        progress_card = QFrame()
        progress_card.setObjectName("contentCard")
        progress_layout = QVBoxLayout(progress_card)
        progress_layout.setContentsMargins(12, 5, 12, 5)
        progress_layout.setSpacing(3)
        status_row = QHBoxLayout()
        self.lbl_status = QLabel("Ready. Select a release to check whether a signed bundle is available.")
        self.lbl_status.setObjectName("statusMessage")
        self.lbl_status.setWordWrap(False)
        self.lbl_status.setMaximumHeight(21)
        status_row.addWidget(self.lbl_status, 1)
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setObjectName("quietButton")
        self.btn_cancel.setIcon(qta.icon("fa6s.xmark", color="#dce8f4"))
        self.btn_cancel.clicked.connect(self.cancel_operation)
        self.btn_cancel.hide()
        status_row.addWidget(self.btn_cancel)
        self.btn_retry = QPushButton("Retry")
        self.btn_retry.setObjectName("primaryButton")
        self.btn_retry.setIcon(qta.icon("fa6s.rotate-right", color="#ffffff"))
        self.btn_retry.clicked.connect(self._retry_last_download)
        self.btn_retry.hide()
        status_row.addWidget(self.btn_retry)
        self.btn_gpg_help = QPushButton("Get GnuPG")
        self.btn_gpg_help.setObjectName("quietButton")
        self.btn_gpg_help.setIcon(qta.icon("fa6s.download", color="#dce8f4"))
        self.btn_gpg_help.setToolTip("Open the official GnuPG download page.")
        self.btn_gpg_help.clicked.connect(self._open_gpg_setup)
        self.btn_gpg_help.hide()
        status_row.addWidget(self.btn_gpg_help)
        progress_layout.addLayout(status_row)
        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("bundleProgress")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(7)
        self.progress_bar.setFormat("Idle")
        progress_layout.addWidget(self.progress_bar)
        self.lbl_progress_details = QLabel("")
        self.lbl_progress_details.setObjectName("mutedText")
        self.lbl_progress_details.setWordWrap(False)
        self.lbl_progress_details.setMaximumHeight(18)
        self.lbl_progress_details.setToolTip("Transfer details, speed and estimated time remain available here during an operation.")
        progress_layout.addWidget(self.lbl_progress_details)
        root.addWidget(progress_card)

        self.progress_event.connect(self._on_progress)
        self._apply_local_styles()
        self.refresh_version()
        self._update_install_state()

    def _platform_summary(self) -> str:
        import platform

        os_name = "Windows" if os.name == "nt" else platform.system()
        machine = platform.machine() or "unknown CPU"
        return "This device: {} · {} · signed Expert Bundles only".format(os_name, machine)

    def _apply_local_styles(self, mode: str | None = None) -> None:
        """Compact bundle-manager styles with high-contrast controls in both themes."""
        dark = (mode or CONFIG["mode"]) == "dark"
        accent = "#3daee9" if dark else "#287db5"
        border = "#414a56" if dark else "#d5dbe2"
        surface = "#20252b" if dark else "#ffffff"
        field = "#171c23" if dark else "#f8fafc"
        text = "#eff1f4" if dark else "#202832"
        muted = "#a6afb9" if dark else "#647080"
        placeholder = "#8593a5" if dark else "#758295"
        icon_color = "#dce8f4" if dark else "#334155"
        self.setStyleSheet(f"""
            QLabel#pageTitle {{ color: {text}; font-size: 20px; font-weight: 750; background: transparent; }}
            QLabel#bundlePageIcon {{ background: transparent; border: none; }}
            QLineEdit#bundleSourceUrl {{ min-height: 27px; max-height: 27px; font-size: 10px; }}
            QPushButton#copySourceButton {{
                min-height: 27px; max-height: 27px; min-width: 28px; max-width: 28px; padding: 0;
            }}
            QFrame#infoCard, QFrame#contentCard {{ background: {surface}; border: 1px solid {border}; border-radius: 9px; }}
            QLabel#sectionTitle {{ color: {text}; font-size: 13px; font-weight: 700; background: transparent; }}
            QLabel#metadataLabel, QLabel#stateLabel {{ color: {muted}; font-size: 11px; background: transparent; }}
            QLabel#mutedText {{ color: {muted}; font-size: 10px; background: transparent; }}
            QLabel#statusMessage {{ color: {text}; font-size: 11px; background: transparent; }}
            QListWidget#releaseList {{ background: {field}; border: 1px solid {border}; border-radius: 7px; padding: 4px; color: {text}; }}
            QListWidget#releaseList::item {{ min-height: 34px; padding: 6px 8px; border-radius: 5px; }}
            QListWidget#releaseList::item:hover {{ background: rgba(61, 174, 233, 0.10); }}
            QListWidget#releaseList::item:selected {{ background: {accent}; color: #ffffff; }}
            QPushButton {{ min-height: 28px; padding: 0 9px; border-radius: 6px; }}
            QPushButton#primaryButton {{ font-weight: 650; }}
            QPushButton#dangerButton {{ color: #d94c4c; }}
            QPushButton#quietButton {{ min-height: 25px; }}
            QLineEdit {{
                min-height: 29px; padding: 0 9px; border: 1px solid {border};
                border-radius: 6px; color: {text}; background: {field};
                selection-background-color: {accent}; selection-color: #ffffff;
            }}
            QCheckBox {{ color: {text}; background: transparent; spacing: 6px; font-size: 11px; }}
            QProgressBar {{ min-height: 7px; max-height: 7px; border: none; border-radius: 4px; background: {border}; }}
            QProgressBar::chunk {{ background: {accent}; border: none; border-radius: 4px; }}
            QFrame#contentCard QLabel {{ background: transparent; }}
        """)
        for widget in self.findChildren(QLineEdit):
            palette = widget.palette()
            from PySide6.QtGui import QColor
            palette.setColor(QPalette.ColorRole.Text, QColor(text))
            palette.setColor(QPalette.ColorRole.Base, QColor(field))
            palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(placeholder))
            widget.setPalette(palette)
        self._title_icon.setPixmap(qta.icon("fa6s.boxes-stacked", color=accent).pixmap(22, 22))
        self.btn_get_versions.setIcon(qta.icon("fa6s.arrows-rotate", color="#ffffff" if dark else "#ffffff"))
        self.btn_copy_bundle_source.setIcon(qta.icon("fa6s.copy", color=icon_color))
        self.btn_import_bundle.setIcon(qta.icon("fa6s.file-import", color=icon_color))
        self.btn_refresh_version.setIcon(qta.icon("fa6s.rotate", color=icon_color))
        self.btn_set_default_version.setIcon(qta.icon("fa6s.check", color="#ffffff"))
        self.btn_delete_version.setIcon(qta.icon("fa6s.trash", color="#d94c4c"))
        self.btn_cancel.setIcon(qta.icon("fa6s.xmark", color=icon_color))
        self.btn_retry.setIcon(qta.icon("fa6s.rotate-right", color="#ffffff"))
        self.btn_gpg_help.setIcon(qta.icon("fa6s.download", color=icon_color))

    def _copy_bundle_source_url(self) -> None:
        """Copy the official Tor release index without adding another page row."""
        QApplication.clipboard().setText(TOR_BUNDLE_BASE_URL)
        self.lbl_status.setText("Copied the official Tor release index URL to the clipboard.")

    def _parse_result(self, data, expected_type):
        try:
            value = ast.literal_eval(data) if isinstance(data, str) else data
        except (ValueError, SyntaxError, TypeError):
            return expected_type()
        return value if isinstance(value, expected_type) else expected_type()

    def _set_busy(self, busy: bool, cancellable: bool = False) -> None:
        self._busy = busy
        self.btn_get_versions.setEnabled(not busy)
        self.btn_import_bundle.setEnabled(not busy and not self._bundle_scan_in_progress)
        self.btn_refresh_version.setEnabled(not busy and not self._bundle_scan_in_progress)
        self.updates_list.setEnabled(not busy and not self._bundle_scan_in_progress)
        self.list_tor_versions.setEnabled(not busy and not self._bundle_scan_in_progress)
        self.search_versions.setEnabled(not busy)
        self.chk_prereleases.setEnabled(not busy)
        self.btn_cancel.setVisible(busy and cancellable)
        self.btn_cancel.setEnabled(busy and cancellable)
        self.btn_retry.setEnabled(not busy)
        self.btn_gpg_help.setEnabled(not busy)
        if busy:
            self.btn_retry.hide()
            self.btn_gpg_help.hide()
        if not busy and not self.progress_bar.isHidden():
            self.progress_bar.setRange(0, 100)
        self._update_install_state()

    def _filter_versions(self, *_args) -> None:
        query = self.search_versions.text().strip().lower()
        include_alpha = self.chk_prereleases.isChecked()
        for index in range(self.updates_list.count()):
            item = self.updates_list.item(index)
            version = str(item.data(Qt.ItemDataRole.UserRole) or "")
            alpha = tor_version_channel(version).startswith("Alpha")
            item.setHidden(bool((not include_alpha and alpha) or (query and query not in version.lower())))

    @staticmethod
    def _bundle_signature_verified(path: str | Path) -> bool:
        try:
            metadata = json.loads((Path(path) / ".torproxy-verified.json").read_text(encoding="utf-8"))
            return (
                metadata.get("signature_verified") is True
                and metadata.get("verification_method", "openpgp") == "openpgp"
            )
        except (OSError, ValueError, AttributeError):
            return False

    @staticmethod
    def _bundle_verification_method(path: str | Path) -> str:
        try:
            metadata = json.loads(
                (Path(path) / ".torproxy-verified.json").read_text(encoding="utf-8")
            )
            return str(metadata.get("verification_method", ""))
        except (OSError, ValueError, AttributeError):
            return ""

    @classmethod
    def _bundle_trust_label(cls, path: str | Path) -> str:
        method = cls._bundle_verification_method(path)
        if method == "openpgp" and cls._bundle_signature_verified(path):
            return "SIGNED"
        if method == "local_unverified":
            return "LOCAL · UNSIGNED"
        return "HTTPS ONLY · UNSIGNED"

    def _resolve_network_route(self, purpose: str) -> tuple[str | None, bool] | None:
        """Use live Tor SOCKS when ready; direct bootstrap requires a separate opt-in."""
        proxy_widget = getattr(self.parent_, "proxyWidget", None)
        tor_runner = getattr(proxy_widget, "tor", None)
        state = str(getattr(tor_runner, "state", "STOPPED") or "STOPPED").upper()
        state = state.split(".")[-1]
        if state == "READY":
            try:
                port = int(getattr(tor_runner, "socks_port"))
                route = (tor_socks_proxy_url("127.0.0.1", port), False)
                self._operation_route = route
                return route
            except (AttributeError, TypeError, ValueError, RuntimeError) as exc:
                QMessageBox.warning(
                    self, "Tor proxy unavailable",
                    "Tor reports READY, but its SOCKS endpoint could not be validated: {}".format(exc),
                )
                return None
        if state in {"STARTING", "BOOTSTRAPPING", "STOPPING"}:
            QMessageBox.information(
                self, "Tor is still connecting",
                "{} was not started. Wait until Tor reaches READY; TorProxy will not bypass a connecting Tor instance.".format(purpose),
            )
            return None
        if CONFIG["kill_switch_enabled"]:
            QMessageBox.information(
                self, "Kill Switch is active",
                "The system-wide Kill Switch blocks direct bootstrap traffic. Connect Tor first, or deliberately disable the Kill Switch before using direct bootstrap.",
            )
            return None
        reply = QMessageBox.question(
            self,
            "Allow direct bootstrap connection?",
            (
                "Tor is not connected. {} needs to contact the official Tor distribution service. "
                "Allow this operation to connect directly, outside Tor? Your network provider may see "
                "the destination and traffic metadata. No automatic direct fallback will occur if a Tor "
                "connection fails."
            ).format(purpose),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        route = (None, True) if reply == QMessageBox.StandardButton.Yes else None
        return route

    def _update_install_state(self) -> None:
        if self._bundle_scan_in_progress and not self._verified_bundles_cache:
            self.lbl_install_state.setText("CHECKING LOCAL BUNDLES")
            self.lbl_default.setText(
                "Checking bundle metadata and archive digests; OpenPGP is "
                + ("enabled." if CONFIG["verify_tor_signatures"] else "disabled in Settings.")
            )
            return
        available = self._verified_bundles_cache
        selected = str(CONFIG["tor_path"] or "")
        active_path = None
        if selected:
            target = os.path.normcase(str(Path(selected).resolve()))
            active_path = next((
                path for path in available
                if os.path.normcase(str(Path(path).resolve())) == target
            ), None)
        if active_path:
            self.lbl_install_state.setText(
                "SIGNED DEFAULT" if self._bundle_signature_verified(active_path)
                else self._bundle_trust_label(active_path) + " DEFAULT"
            )
        elif available:
            self.lbl_install_state.setText("{} installed bundle(s)".format(len(available)))
        elif self._bundle_scan_in_progress:
            self.lbl_install_state.setText("CHECKING LOCAL BUNDLES")
        else:
            self.lbl_install_state.setText("No compatible bundle installed")
        if selected:
            method = self._bundle_verification_method(selected)
            trust = (
                "OpenPGP signature checked" if self._bundle_signature_verified(selected)
                else "manually imported; publisher signature not checked" if method == "local_unverified"
                else "HTTPS only; publisher signature not checked" if method == "https_only"
                else "signature not checked / external path"
            )
            self.lbl_default.setText("Default: {} · {}".format(Path(selected).name, trust))
        else:
            self.lbl_default.setText("Default: not configured")

    def refresh_version(self) -> None:
        if self._bundle_scan_in_progress:
            return
        self._bundle_scan_in_progress = True
        self.btn_refresh_version.setEnabled(False)
        self.list_tor_versions.setEnabled(False)
        self.updates_list.setEnabled(False)
        self.lbl_install_state.setText("CHECKING LOCAL BUNDLES")
        self.lbl_default.setText("Checking installed bundle metadata and archive digests…")
        self._bundle_scan_worker = Worker(get_own_bundles)
        self._bundle_scan_worker.signals.finished.connect(self._on_bundle_scan_finished)
        self._bundle_scan_worker.signals.error.connect(self._on_bundle_scan_failed)
        self.thread_pool.start(self._bundle_scan_worker)

    def _on_bundle_scan_finished(self, data: str) -> None:
        bundles = self._parse_result(data, list)
        self._verified_bundles_cache = [item for item in bundles if isinstance(item, str)]
        self._bundle_scan_in_progress = False
        self.btn_refresh_version.setEnabled(not self._busy)
        self.list_tor_versions.setEnabled(not self._busy)
        self.updates_list.setEnabled(not self._busy)
        self.list_tor_versions.clear()
        configured = str(CONFIG["tor_path"] or "")
        for path in self._verified_bundles_cache:
            signed = self._bundle_signature_verified(path)
            trust_label = self._bundle_trust_label(path)
            method = self._bundle_verification_method(path)
            item = QListWidgetItem("{}  ·  {}".format(Path(path).name, trust_label))
            item.setData(Qt.ItemDataRole.UserRole, path)
            detail = (
                "Detached OpenPGP signature matched the pinned Tor key."
                if signed else
                "Manually imported from a local archive; publisher signature was not checked."
                if method == "local_unverified" else
                "Downloaded over HTTPS; publisher signature was not checked."
            )
            item.setToolTip(path + "\n" + detail)
            if configured and os.path.normcase(str(Path(configured).resolve())) == os.path.normcase(str(Path(path).resolve())):
                item.setText("{}  ·  {}  ·  DEFAULT".format(Path(path).name, trust_label))
            self.list_tor_versions.addItem(item)
        self._update_install_state()
        if self._verified_bundles_cache:
            self._missing_bundle_notified = False
        elif not self._missing_bundle_notified:
            self._missing_bundle_notified = True
            notify = getattr(self.parent_, "notify_user", None)
            if callable(notify):
                notify(
                    "Tor bundle required",
                    "No compatible Tor Expert Bundle is installed. Open Bundles to download one. OpenPGP publisher-signature verification is "
                    + ("enabled." if CONFIG["verify_tor_signatures"] else "disabled in Settings → Advanced."),
                    "warning",
                )

    def _on_bundle_scan_failed(self, error: str) -> None:
        logger.error("Could not inspect installed Tor bundles: %s", error)
        self._bundle_scan_in_progress = False
        self.btn_refresh_version.setEnabled(not self._busy)
        self.list_tor_versions.setEnabled(not self._busy)
        self.updates_list.setEnabled(not self._busy)
        if not self._verified_bundles_cache:
            self.lbl_install_state.setText("Bundle inspection failed")
            self.lbl_default.setText("Could not verify local bundle metadata. Rescan or inspect the application log.")

    def set_default_version(self) -> None:
        item = self.list_tor_versions.currentItem()
        if item is None:
            QMessageBox.information(self, "Select a bundle", "Select an installed bundle first.")
            return
        path = str(item.data(Qt.ItemDataRole.UserRole) or "")
        if path not in self._verified_bundles_cache:
            QMessageBox.warning(self, "Bundle unavailable", "This bundle is not in the latest compatible scan. Rescan the list.")
            self.refresh_version()
            return
        signed = self._bundle_signature_verified(path)
        method = self._bundle_verification_method(path)
        if signed:
            title = "Set default Tor bundle"
            prompt = "Use this OpenPGP-verified bundle for future Tor starts?\n\n{}".format(Path(path).name)
        elif method == "local_unverified":
            title = "Use locally imported bundle without signature?"
            prompt = (
                "This archive was supplied manually and its publisher signature was NOT checked. "
                "A modified archive could execute malicious code. Use it only if you trust its source.\n\n{}"
            ).format(Path(path).name)
        else:
            title = "Use HTTPS-only bundle?"
            prompt = (
                "This bundle was downloaded via HTTPS, but Tor's OpenPGP publisher signature was NOT checked. "
                "A compromised distribution or connection could deliver malicious code. Use it only if you accept "
                "this reduced security guarantee.\n\n{}"
            ).format(Path(path).name)
        reply = QMessageBox.question(
            self, title, prompt,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            tor_runner = getattr(getattr(self.parent_, "proxyWidget", None), "tor", None)
            if tor_runner is not None and not tor_runner.update_path(path):
                raise ValueError("The selected bundle failed a fresh executable and integrity check.")
            CONFIG["tor_path"] = path
            self.lbl_status.setText("Default bundle saved. Restart Tor if a process is already running.")
            self.refresh_version()
        except (OSError, ValueError, KeyError) as exc:
            logger.exception("Could not select the default Tor bundle.")
            QMessageBox.warning(self, "Could not select bundle", str(exc))

    def delete_version(self) -> None:
        item = self.list_tor_versions.currentItem()
        if item is None:
            QMessageBox.information(self, "Select a bundle", "Select a local verified bundle to delete.")
            return
        path = str(item.data(Qt.ItemDataRole.UserRole) or "")
        reply = QMessageBox.question(
            self, "Delete Tor bundle",
            "Delete this verified local bundle and its downloaded archive?\n\n{}".format(Path(path).name),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            configured = str(CONFIG["tor_path"] or "")
            if configured and os.path.normcase(str(Path(configured).resolve())) == os.path.normcase(str(Path(path).resolve())):
                CONFIG["tor_path"] = None
                tor_runner = getattr(getattr(self.parent_, "proxyWidget", None), "tor", None)
                if tor_runner is not None:
                    tor_runner.update_path(None)
            delete_bundle(path)
            self.refresh_version()
            self.lbl_status.setText("Bundle deleted.")
        except (OSError, ValueError) as exc:
            logger.exception("Could not delete Tor bundle.")
            QMessageBox.warning(self, "Could not delete bundle", str(exc))

    def choose_local_bundle(self) -> None:
        """Select and safely import a local Tor Expert Bundle archive."""
        if self._busy:
            return
        filename, _filter = QFileDialog.getOpenFileName(
            self, "Import Tor Expert Bundle", "",
            "Tor Expert Bundle archives (*.tar.gz);;All files (*)",
        )
        if not filename:
            return
        source = Path(filename)
        try:
            version = get_version_by_bundle(source.name)
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Tor bundle", str(exc))
            return

        has_signature = source.with_name(source.name + ".asc").is_file()
        verify_signature = bool(CONFIG["verify_tor_signatures"] and has_signature)
        if verify_signature:
            trust_text = (
                "The matching .asc file was found. TorProxy will verify it against the pinned Tor signing key."
            )
        else:
            reason = "The matching .asc file is missing." if not has_signature else (
                "OpenPGP verification is disabled in Settings."
            )
            reply = QMessageBox.question(
                self, "Import without publisher verification?",
                "{} The archive will be marked LOCAL · UNSIGNED. Its publisher identity will not be "
                "authenticated. Only continue if you trust the source of this file.\n\n{}".format(reason, source.name),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
            trust_text = "The local archive will be safely extracted and marked LOCAL · UNSIGNED."

        route: tuple[str | None, bool] = (None, False)
        if verify_signature:
            selected_route = self._resolve_network_route("Tor signing-key retrieval for local bundle verification")
            if selected_route is None:
                return
            route = selected_route
        proxy_url, allow_direct = route
        self.cancel_event = Event()
        self._set_busy(True, cancellable=True)
        self.lbl_status.setText("Importing local Tor bundle…")
        self.lbl_progress_details.setText(trust_text)
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFormat("Importing local archive…")
        self.worker = Worker(
            self._import_local_bundle_worker, filename, version, self.cancel_event,
            self.progress_event.emit, verify_signature, proxy_url, allow_direct,
        )
        self.worker.signals.finished.connect(self._on_local_import_finished)
        self.worker.signals.error.connect(self._on_local_import_error)
        self.thread_pool.start(self.worker)

    @staticmethod
    def _import_local_bundle_worker(
        filename: str, version: str, cancel_event: Event, progress_callback,
        verify_signature: bool, proxy_url: str | None, allow_direct: bool,
    ) -> str:
        installed = import_bundle_archive(
            filename, verify_signature=verify_signature,
            proxy_url=proxy_url, allow_direct=allow_direct,
            progress_callback=progress_callback, cancel_event=cancel_event,
        )
        progress_callback(BundleProgress(
            version, "import", "installation_complete", percentage=100,
            message="Local archive import completed.",
        ))
        if verify_signature:
            return "Imported and OpenPGP-verified Tor Expert Bundle {}".format(Path(installed).name)
        return "Imported local Tor Expert Bundle {} · LOCAL UNSIGNED".format(Path(installed).name)

    def _on_local_import_finished(self, message: str) -> None:
        self._set_busy(False)
        self.cancel_event = None
        self._operation_route = None
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("Imported")
        self.lbl_status.setText(message)
        self.lbl_progress_details.setText(
            "Detached signature matched the pinned Tor key."
            if "OpenPGP-verified" in message else
            "Local archive imported and safely extracted; publisher signature was not checked."
        )
        self.refresh_version()
        self._update_install_state()

    def _on_local_import_error(self, error: str) -> None:
        self._set_busy(False)
        self.cancel_event = None
        self._operation_route = None
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Import failed")
        self.lbl_status.setText("The local bundle was not installed.")
        self.lbl_progress_details.setText(str(error))
        QMessageBox.warning(self, "Local Tor bundle import failed", str(error))

    def get_available_versions(self) -> None:
        if self._busy:
            return
        route = self._resolve_network_route("Tor release discovery")
        if route is None:
            return
        proxy_url, allow_direct = route
        self._set_busy(True)
        self.lbl_discovery.setText("Contacting the official Tor distribution index…")
        self.lbl_status.setText("Discovering release directories. Artifact checks happen only when a release is selected.")
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFormat("Discovering releases…")
        self.lbl_progress_details.setText("")
        self.worker = Worker(get_tor_versions, proxy_url=proxy_url, allow_direct=allow_direct)
        self.worker.signals.finished.connect(self.set_tor_versions)
        self.worker.signals.error.connect(self._on_discovery_error)
        self.thread_pool.start(self.worker)

    def set_tor_versions(self, data) -> None:
        versions = self._parse_result(data, list)
        versions = [item.strip().strip("/") for item in versions if isinstance(item, str)]
        valid_versions = []
        for version in versions:
            try:
                tor_version_channel(version)
                valid_versions.append(version)
            except ValueError:
                logger.warning("Ignoring invalid Tor version returned by discovery.")
        self._available_versions = valid_versions
        self.updates_list.clear()
        for version in valid_versions:
            channel = tor_version_channel(version)
            label = "{}  ·  {}".format(version, channel.upper())
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, version)
            item.setToolTip("Release directory found. Select to check a compatible Expert Bundle using the current Advanced signature-verification setting.")
            self.updates_list.addItem(item)
        self.lbl_discovery.setText(
            "{} recognized release directories found. Stable releases appear before alpha prereleases.".format(
                len(valid_versions)
            )
        )
        self._filter_versions()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Idle")
        self._set_busy(False)
        self.lbl_status.setText("Choose a release to check compatible artifact availability and the selected trust method.")

    def _on_discovery_error(self, error: str) -> None:
        # Keep installed bundles intact: discovery needs the network, local bundles do not.
        self._set_busy(False)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Discovery failed")
        self.lbl_discovery.setText("The official release list could not be retrieved.")
        self.lbl_status.setText(
            "Discovery failed. Installed bundles remain available; check the network route and retry."
        )
        QMessageBox.warning(self, "Tor release discovery failed", error)

    def selected_version(self, item: QListWidgetItem) -> None:
        if self._busy:
            return
        version = str(item.data(Qt.ItemDataRole.UserRole) or "").strip()
        if not version:
            return
        route = self._resolve_network_route("Tor bundle availability check")
        if route is None:
            return
        proxy_url, allow_direct = route
        verify_signature = bool(CONFIG["verify_tor_signatures"])
        self._set_busy(True)
        self.lbl_status.setText(
            "Checking for a compatible Expert Bundle"
            + (" and detached signature…" if verify_signature else "…")
        )
        self.lbl_progress_details.setText("A release directory alone does not mean a compatible archive is available.")
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFormat("Checking artifact…")
        self.worker = Worker(self._check_selected_release, version, verify_signature, proxy_url, allow_direct)
        self.worker.signals.finished.connect(self._on_links_checked)
        self.worker.signals.error.connect(self._on_discovery_error)
        self.thread_pool.start(self.worker)

    def _check_selected_release(
        self, version: str, verify_signature: bool = True,
        proxy_url: str | None = None, allow_direct: bool = False,
    ):
        links = get_bundle_links(
            version, require_signature=verify_signature,
            proxy_url=proxy_url, allow_direct=allow_direct,
        )
        return version, links, bool(verify_signature), proxy_url, bool(allow_direct)

    def _on_links_checked(self, data: str) -> None:
        result = self._parse_result(data, tuple)
        version = str(result[0]) if len(result) >= 1 else ""
        links = result[1] if len(result) >= 2 and isinstance(result[1], list) else []
        verify_signature = bool(result[2]) if len(result) >= 3 else bool(CONFIG["verify_tor_signatures"])
        self._operation_route = (
            result[3] if len(result) >= 4 else None,
            bool(result[4]) if len(result) >= 5 else False,
        )
        already_installed = any(
            Path(path).name.endswith("-" + version) for path in self._verified_bundles_cache
        )
        if already_installed:
            self._set_busy(False)
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(100)
            self.progress_bar.setFormat("Already installed")
            self.lbl_status.setText(
                "Tor Expert Bundle {} is already installed on this device.".format(version)
            )
            self.lbl_progress_details.setText(
                "No download was started. Select the installed bundle on the right to make it the default."
            )
            return
        if not links:
            self._set_busy(False)
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("Unavailable")
            self.lbl_status.setText(
                "{} has no compatible Expert Bundle{} for this OS/CPU.".format(
                    version, " with a listed detached signature" if verify_signature else ""
                )
            )
            message = (
                "The release directory exists, but TorProxy did not find the expected Expert Bundle archive "
                + ("and its matching .asc signature for this platform." if verify_signature else " for this platform.")
                + " No download was attempted."
            )
            notify = getattr(self.parent_, "notify_user", None)
            if callable(notify):
                notify("No compatible bundle", message, "warning")
            else:
                QMessageBox.information(self, "No compatible bundle", message)
            return
        bundle = links[0]
        if verify_signature:
            title = "Download and verify Tor bundle"
            trust_note = (
                "OpenPGP verification is enabled. The detached signature must match Tor's pinned signing key; "
                "installation stops if the check fails."
            )
        else:
            title = "Download Tor bundle (OpenPGP off)"
            trust_note = (
                "OpenPGP verification is disabled in Settings. TorProxy will use the official HTTPS host and "
                "safe archive checks, but will NOT authenticate the publisher's signature. This is less secure."
            )
        reply = QMessageBox.question(
            self, title,
            "Download the {} release for this device?\n\n{}\n\n{}".format(
                tor_version_channel(version), bundle, trust_note
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        self._set_busy(False)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Ready")
        if reply != QMessageBox.StandardButton.Yes:
            self.lbl_status.setText("Download cancelled before starting.")
            return
        self._start_download(bundle, version, verify_signature)

    def _start_download(self, bundle: str, version: str, verify_signature: bool | None = None) -> None:
        if self._busy:
            return
        route = self._resolve_network_route("Tor bundle download")
        if route is None:
            return
        proxy_url, allow_direct = route
        verify_signature = bool(CONFIG["verify_tor_signatures"]) if verify_signature is None else bool(verify_signature)
        self.cancel_event = Event()
        self._last_download = (bundle, version, verify_signature)
        self._set_busy(True, cancellable=True)
        self.lbl_status.setText("Preparing Tor bundle download…")
        self.lbl_progress_details.setText(
            "Publisher signature will be checked before extraction."
            if verify_signature else
            "OpenPGP is off: HTTPS transport and safe extraction are used, but publisher identity is not authenticated."
        )
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFormat("Preparing…")
        self.worker = Worker(
            self.download_bundle, bundle, version, self.cancel_event,
            self.progress_event.emit, verify_signature, proxy_url, allow_direct
        )
        self.worker.signals.finished.connect(self._on_download_finished)
        self.worker.signals.error.connect(self._on_download_error)
        self.thread_pool.start(self.worker)

    def download_bundle(
        self,
        bundle: str,
        version: str,
        cancel_event: Event,
        progress_callback,
        verify_signature: bool = True,
        proxy_url: str | None = None,
        allow_direct: bool = False,
    ):
        logger.info("Downloading Tor Expert Bundle %s (OpenPGP verification=%s)", bundle, verify_signature)
        archive = download_file(
            bundle, version, progress_callback=progress_callback, cancel_event=cancel_event,
            verify_signature=verify_signature, proxy_url=proxy_url, allow_direct=allow_direct,
        )
        if cancel_event.is_set():
            raise RuntimeError("Tor bundle installation was cancelled.")
        base_path = os.path.join(BUNDLE_DIR, os.path.basename(bundle).replace(".tar.gz", ""))
        extract_tar_gz_file(
            archive, base_path, progress_callback=progress_callback,
            cancel_event=cancel_event, version=version, verify_signature=verify_signature,
            proxy_url=proxy_url, allow_direct=allow_direct,
        )
        message = (
            "OpenPGP signature verified and bundle installed."
            if verify_signature else
            "Bundle installed over HTTPS only; OpenPGP signature was NOT checked."
        )
        progress_callback(BundleProgress(
            version, "install", "installation_complete", percentage=100, message=message,
        ))
        return (
            "Installed and OpenPGP-verified Tor Expert Bundle {}".format(bundle)
            if verify_signature else
            "Installed Tor Expert Bundle {} via HTTPS only; OpenPGP signature was NOT checked.".format(bundle)
        )

    def _on_progress(self, event: BundleProgress) -> None:
        if not isinstance(event, BundleProgress):
            logger.warning("Ignoring malformed Tor bundle progress event.")
            return
        labels = {
            "checking_verification_runtime": "Checking signature-verification runtime",
            "signature_verification_skipped": "OpenPGP signature check skipped (Settings)",
            "archive_downloaded_https_only": "Archive downloaded over HTTPS; signature not checked",
            "downloading_archive": "Downloading Tor archive",
            "downloading_signature": "Downloading detached signature",
            "downloading_signing_key": "Retrieving pinned-key material",
            "copying_local_archive": "Copying local Tor archive",
            "verifying_signature": "Verifying OpenPGP signature",
            "signature_verified": "Signature verified",
            "archive_validated": "Archive saved; installation pending",
            "extracting_archive": "Safely extracting archive",
            "installation_complete": "Installation complete",
            "already_verified": "Existing archive verified",
        }
        self.lbl_status.setText(labels.get(event.stage, event.message or event.stage.replace("_", " ").title()))
        self.lbl_status.setToolTip(event.message)
        if event.stage in {"checking_verification_runtime", "verifying_signature", "extracting_archive"}:
            self.btn_cancel.setEnabled(False)
            self.progress_bar.setRange(0, 0)
            self.progress_bar.setFormat(labels.get(event.stage, "Working…"))
        elif event.total_bytes and event.percentage is not None:
            self.btn_cancel.setEnabled(event.stage in {"downloading_archive", "downloading_signature", "downloading_signing_key"})
            self.progress_bar.setRange(0, 100)
            # A transfer reaching 100% is not installation success; the stage label remains explicit.
            self.progress_bar.setValue(min(99, max(0, event.percentage)))
            self.progress_bar.setFormat("{}%".format(min(99, max(0, event.percentage))))
        else:
            self.btn_cancel.setEnabled(event.stage in {"downloading_archive", "downloading_signature", "downloading_signing_key"})
            self.progress_bar.setRange(0, 0)
            self.progress_bar.setFormat("Receiving bytes…" if event.stage.startswith("downloading_") else "Working…")
        size_text = "{} received".format(self._format_bytes(event.bytes_received))
        if event.total_bytes:
            size_text += " / {}".format(self._format_bytes(event.total_bytes))
        else:
            size_text += " · total size unknown"
        details = [size_text]
        if event.speed_bytes_per_second:
            details.append("{}/s".format(self._format_bytes(event.speed_bytes_per_second)))
        if event.eta_seconds is not None and event.total_bytes:
            details.append("~{} remaining".format(self._format_duration(event.eta_seconds)))
        if event.message:
            details.append(event.message)
        self.lbl_progress_details.setText(" · ".join(details))

    @staticmethod
    def _format_bytes(value: float | int) -> str:
        amount = float(value)
        for unit in ("B", "KB", "MB", "GB"):
            if amount < 1024 or unit == "GB":
                return "{:.1f} {}".format(amount, unit)
            amount /= 1024
        return "{:.1f} GB".format(amount)

    @staticmethod
    def _format_duration(seconds: int) -> str:
        seconds = max(0, int(seconds))
        if seconds < 60:
            return "{}s".format(seconds)
        if seconds < 3600:
            return "{}m {}s".format(seconds // 60, seconds % 60)
        return "{}h {}m".format(seconds // 3600, (seconds % 3600) // 60)

    def cancel_operation(self) -> None:
        if self.cancel_event is not None:
            self.cancel_event.set()
            self.btn_cancel.setEnabled(False)
            self.lbl_status.setText("Cancellation requested; waiting for the current network read to return.")
            self.lbl_progress_details.setText("The partial archive will not be installed or marked as verified.")

    def _on_download_finished(self, message: str) -> None:
        self._set_busy(False)
        self.cancel_event = None
        self.btn_retry.hide()
        self.btn_gpg_help.hide()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("Complete")
        self.lbl_status.setText(message)
        self.lbl_progress_details.setText(
            "Detached OpenPGP signature checked against Tor's pinned key."
            if "OpenPGP-verified" in message else
            "Downloaded from the official HTTPS host and safely extracted; publisher signature was not checked."
        )
        self._operation_route = None
        self.refresh_version()
        self._update_install_state()

    def _on_download_error(self, error: str) -> None:
        logger.error("Tor bundle download/verification failed: %s", error)
        self._set_busy(False)
        self.cancel_event = None
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Failed")
        message = str(error)
        if "cancelled" in message.lower():
            self._operation_route = None
            self.lbl_status.setText("Operation cancelled. Temporary download files were removed; no bundle was installed.")
            self.lbl_progress_details.setText(message)
            self.btn_retry.setVisible(self._last_download is not None)
            return
        self._operation_route = None
        self.lbl_status.setText("Download or installation failed. The bundle was not reported as installed.")
        self.lbl_progress_details.setText(message)
        self.btn_retry.setVisible(self._last_download is not None)
        if "gnupg" in message.lower() and any(
            term in message.lower() for term in ("could not be found", "could not be started", "install gnu")
        ):
            self.btn_gpg_help.show()
        QMessageBox.warning(self, "Tor bundle operation failed", message)

    def _retry_last_download(self) -> None:
        if self._busy or self._last_download is None:
            return
        bundle, version, verify_signature = self._last_download
        self._start_download(bundle, version, verify_signature)

    def _open_gpg_setup(self) -> None:
        # Only opens the official project page after an explicit user click.
        QDesktopServices.openUrl(QUrl("https://gnupg.org/download/"))

