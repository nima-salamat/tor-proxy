"""Modern Tor bundle manager with lazy artifact checks and stage-aware progress."""
from __future__ import annotations

import ast
import logging
import os
from pathlib import Path
from threading import Event

from PySide6.QtCore import Qt, QThreadPool, Signal
from PySide6.QtGui import QPalette
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from config import BUNDLE_DIR, CONFIG, IS_WINDOWS
from torproxy.bundle import BundleProgress
from updater import (
    delete_bundle,
    download_file,
    get_bundle_links,
    get_own_bundles,
    get_tor_versions,
    get_version_by_bundle,
    tor_version_channel,
)
from utils import extract_tar_gz_file

logger = logging.getLogger(__name__)


class UpdaterWindow(QWidget):
    """Discover official releases on demand; only verified extracted bundles are selectable."""

    progress_event = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_ = parent
        self.thread_pool = QThreadPool(self)
        self.worker = None
        self.cancel_event: Event | None = None
        self._busy = False
        self._available_versions: list[str] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 24)
        root.setSpacing(16)

        heading = QVBoxLayout()
        title = QLabel("Tor Bundles & Updates")
        title.setObjectName("pageTitle")
        subtitle = QLabel(
            "Browse official release channels, verify signed Expert Bundles, and manage the active runtime."
        )
        subtitle.setObjectName("pageSubtitle")
        subtitle.setWordWrap(True)
        heading.addWidget(title)
        heading.addWidget(subtitle)
        root.addLayout(heading)

        platform_card = QFrame()
        platform_card.setObjectName("infoCard")
        platform_row = QHBoxLayout(platform_card)
        platform_row.setContentsMargins(16, 11, 16, 11)
        self.lbl_platform = QLabel(self._platform_summary())
        self.lbl_platform.setObjectName("metadataLabel")
        self.lbl_install_state = QLabel()
        self.lbl_install_state.setObjectName("stateLabel")
        self.lbl_install_state.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        platform_row.addWidget(self.lbl_platform, 1)
        platform_row.addWidget(self.lbl_install_state)
        root.addWidget(platform_card)

        columns = QHBoxLayout()
        columns.setSpacing(16)
        root.addLayout(columns, 1)

        available_card = QFrame()
        available_card.setObjectName("contentCard")
        available_layout = QVBoxLayout(available_card)
        available_layout.setContentsMargins(16, 16, 16, 16)
        available_layout.setSpacing(10)
        heading_row = QHBoxLayout()
        section_title = QLabel("Available releases")
        section_title.setObjectName("sectionTitle")
        heading_row.addWidget(section_title, 1)
        self.btn_get_versions = QPushButton("Refresh")
        self.btn_get_versions.setObjectName("primaryButton")
        self.btn_get_versions.clicked.connect(self.get_available_versions)
        heading_row.addWidget(self.btn_get_versions)
        available_layout.addLayout(heading_row)
        self.search_versions = QLineEdit()
        self.search_versions.setPlaceholderText("Search version, e.g. 15.0.26 or 16.0a14")
        self.search_versions.textChanged.connect(self._filter_versions)
        available_layout.addWidget(self.search_versions)
        self.chk_prereleases = QCheckBox("Include alpha prereleases")
        self.chk_prereleases.setChecked(True)
        self.chk_prereleases.toggled.connect(self._filter_versions)
        available_layout.addWidget(self.chk_prereleases)
        self.updates_list = QListWidget()
        self.updates_list.setObjectName("releaseList")
        self.updates_list.setUniformItemSizes(True)
        self.updates_list.setSelectionMode(QListWidget.SingleSelection)
        self.updates_list.itemClicked.connect(self.selected_version)
        available_layout.addWidget(self.updates_list, 1)
        self.lbl_discovery = QLabel("Refresh to retrieve the official Tor release directories.")
        self.lbl_discovery.setObjectName("mutedText")
        self.lbl_discovery.setWordWrap(True)
        available_layout.addWidget(self.lbl_discovery)
        columns.addWidget(available_card, 3)

        installed_card = QFrame()
        installed_card.setObjectName("contentCard")
        installed_layout = QVBoxLayout(installed_card)
        installed_layout.setContentsMargins(16, 16, 16, 16)
        installed_layout.setSpacing(10)
        local_heading = QHBoxLayout()
        local_title = QLabel("Installed bundles")
        local_title.setObjectName("sectionTitle")
        local_heading.addWidget(local_title, 1)
        self.btn_refresh_version = QPushButton("Rescan")
        self.btn_refresh_version.clicked.connect(self.refresh_version)
        local_heading.addWidget(self.btn_refresh_version)
        installed_layout.addLayout(local_heading)
        self.list_tor_versions = QListWidget()
        self.list_tor_versions.setObjectName("releaseList")
        self.list_tor_versions.setSelectionMode(QListWidget.SingleSelection)
        self.list_tor_versions.setToolTip("Only signed, structurally validated bundles are listed here.")
        installed_layout.addWidget(self.list_tor_versions, 1)
        self.lbl_default = QLabel()
        self.lbl_default.setObjectName("mutedText")
        self.lbl_default.setWordWrap(True)
        installed_layout.addWidget(self.lbl_default)
        action_row = QHBoxLayout()
        self.btn_set_default_version = QPushButton("Use as default")
        self.btn_set_default_version.setObjectName("primaryButton")
        self.btn_set_default_version.clicked.connect(self.set_default_version)
        self.btn_delete_version = QPushButton("Delete")
        self.btn_delete_version.setObjectName("dangerButton")
        self.btn_delete_version.clicked.connect(self.delete_version)
        action_row.addWidget(self.btn_set_default_version, 1)
        action_row.addWidget(self.btn_delete_version)
        installed_layout.addLayout(action_row)
        columns.addWidget(installed_card, 2)

        progress_card = QFrame()
        progress_card.setObjectName("contentCard")
        progress_layout = QVBoxLayout(progress_card)
        progress_layout.setContentsMargins(16, 14, 16, 14)
        progress_layout.setSpacing(8)
        status_row = QHBoxLayout()
        self.lbl_status = QLabel("Ready. Select a release to check whether a signed bundle is available.")
        self.lbl_status.setObjectName("statusMessage")
        self.lbl_status.setWordWrap(True)
        status_row.addWidget(self.lbl_status, 1)
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setObjectName("quietButton")
        self.btn_cancel.clicked.connect(self.cancel_operation)
        self.btn_cancel.hide()
        status_row.addWidget(self.btn_cancel)
        progress_layout.addLayout(status_row)
        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("bundleProgress")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Idle")
        progress_layout.addWidget(self.progress_bar)
        self.lbl_progress_details = QLabel("")
        self.lbl_progress_details.setObjectName("mutedText")
        self.lbl_progress_details.setWordWrap(True)
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

    def _apply_local_styles(self) -> None:
        """Style reusable surfaces while deriving highlight colours from the active theme."""
        palette = QApplication.palette() if QApplication.instance() else self.palette()
        accent = palette.color(QPalette.Highlight).name()
        border = palette.color(QPalette.Mid).name()
        surface = palette.color(QPalette.Base).name()
        text = palette.color(QPalette.WindowText).name()
        muted = palette.color(QPalette.PlaceholderText).name()
        self.setStyleSheet("""
            QWidget#pageTitle { font-size: 22px; font-weight: 700; }
            QLabel#pageSubtitle { color: %s; font-size: 12px; }
            QFrame#infoCard, QFrame#contentCard { border: 1px solid %s; border-radius: 10px; }
            QLabel#sectionTitle { font-size: 14px; font-weight: 650; }
            QLabel#metadataLabel, QLabel#stateLabel { font-size: 12px; }
            QLabel#mutedText { color: %s; font-size: 11px; }
            QLabel#statusMessage { font-size: 12px; }
            QListWidget#releaseList { background: %s; border: 1px solid %s; border-radius: 7px; padding: 4px; }
            QListWidget#releaseList::item { min-height: 34px; padding: 6px 8px; border-radius: 5px; }
            QListWidget#releaseList::item:selected { background: %s; color: white; }
            QPushButton { min-height: 30px; padding: 0 12px; border-radius: 6px; }
            QPushButton#primaryButton { font-weight: 600; }
            QPushButton#dangerButton { color: #d94c4c; }
            QPushButton#quietButton { min-height: 26px; }
            QLineEdit { min-height: 32px; padding: 0 9px; border: 1px solid %s; border-radius: 6px; }
            QProgressBar { min-height: 18px; border: 1px solid %s; border-radius: 5px; text-align: center; }
            QProgressBar::chunk { background: %s; border-radius: 4px; }
        """ % (muted, border, muted, surface, border, accent, border, border, accent))

    def _parse_result(self, data, expected_type):
        try:
            value = ast.literal_eval(data) if isinstance(data, str) else data
        except (ValueError, SyntaxError, TypeError):
            return expected_type()
        return value if isinstance(value, expected_type) else expected_type()

    def _set_busy(self, busy: bool, cancellable: bool = False) -> None:
        self._busy = busy
        self.btn_get_versions.setEnabled(not busy)
        self.btn_refresh_version.setEnabled(not busy)
        self.updates_list.setEnabled(not busy)
        self.list_tor_versions.setEnabled(not busy)
        self.search_versions.setEnabled(not busy)
        self.chk_prereleases.setEnabled(not busy)
        self.btn_cancel.setVisible(busy and cancellable)
        self.btn_cancel.setEnabled(busy and cancellable)
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
            item.setHidden((not include_alpha and alpha) or (query and query not in version.lower()))

    def _update_install_state(self) -> None:
        available = get_own_bundles()
        selected = str(CONFIG["tor_path"] or "")
        active = any(
            os.path.normcase(str(Path(path).resolve())) == os.path.normcase(str(Path(selected).resolve()))
            for path in available
        ) if selected else False
        if active:
            self.lbl_install_state.setText("VERIFIED DEFAULT")
        elif available:
            self.lbl_install_state.setText("{} verified bundle(s)".format(len(available)))
        else:
            self.lbl_install_state.setText("No verified bundle installed")
        self.lbl_default.setText(
            "Default: {}".format(Path(selected).name if selected else "not configured")
        )

    def refresh_version(self) -> None:
        self.list_tor_versions.clear()
        verified = get_own_bundles()
        configured = str(CONFIG["tor_path"] or "")
        for path in verified:
            item = QListWidgetItem(Path(path).name)
            item.setData(Qt.ItemDataRole.UserRole, path)
            item.setToolTip(str(path))
            if configured and os.path.normcase(str(Path(configured).resolve())) == os.path.normcase(str(Path(path).resolve())):
                item.setText("{}  ·  DEFAULT".format(Path(path).name))
            self.list_tor_versions.addItem(item)
        self._update_install_state()

    def set_default_version(self) -> None:
        item = self.list_tor_versions.currentItem()
        if item is None:
            QMessageBox.information(self, "Select a bundle", "Select a verified installed bundle first.")
            return
        path = str(item.data(Qt.ItemDataRole.UserRole) or "")
        if path not in get_own_bundles():
            QMessageBox.warning(self, "Bundle is not verified", "This bundle is no longer verified. Rescan the list.")
            self.refresh_version()
            return
        reply = QMessageBox.question(
            self, "Set default Tor bundle",
            "Use this verified bundle for future Tor starts?\n\n{}".format(Path(path).name),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            CONFIG["tor_path"] = path
            tor_runner = getattr(getattr(self.parent_, "proxyWidget", None), "tor", None)
            if tor_runner is not None:
                tor_runner.update_path(path)
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

    def get_available_versions(self) -> None:
        if self._busy:
            return
        self._set_busy(True)
        self.lbl_discovery.setText("Contacting the official Tor distribution index…")
        self.lbl_status.setText("Discovering release directories. Artifact checks happen only when a release is selected.")
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFormat("Discovering releases…")
        self.lbl_progress_details.setText("")
        self.worker = Worker(get_tor_versions)
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
            item.setToolTip("Release directory found. Select to check for a compatible signed Expert Bundle.")
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
        self.lbl_status.setText("Choose a release to check compatible artifact and signature availability.")

    def _on_discovery_error(self, error: str) -> None:
        logger.error("Tor release discovery failed: %s", error)
        self._set_busy(False)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Discovery failed")
        self.lbl_discovery.setText("The official release list could not be retrieved.")
        self.lbl_status.setText("Discovery failed. Check network connectivity and the application log.")
        QMessageBox.warning(self, "Tor release discovery failed", error)

    def selected_version(self, item: QListWidgetItem) -> None:
        if self._busy:
            return
        version = str(item.data(Qt.ItemDataRole.UserRole) or "").strip()
        if not version:
            return
        self._set_busy(True)
        self.lbl_status.setText("Checking for the exact compatible Expert Bundle and its detached signature…")
        self.lbl_progress_details.setText("A release directory alone does not mean a bundle is available.")
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFormat("Checking artifact…")
        self.worker = Worker(self._check_selected_release, version)
        self.worker.signals.finished.connect(self._on_links_checked)
        self.worker.signals.error.connect(self._on_discovery_error)
        self.thread_pool.start(self.worker)

    def _check_selected_release(self, version: str):
        return version, get_bundle_links(version)

    def _on_links_checked(self, data: str) -> None:
        result = self._parse_result(data, tuple)
        version = str(result[0]) if len(result) >= 1 else ""
        links = result[1] if len(result) >= 2 and isinstance(result[1], list) else []
        if not links:
            self._set_busy(False)
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("Unavailable")
            self.lbl_status.setText(
                "{} has no compatible Expert Bundle with a listed detached signature for this OS/CPU.".format(version)
            )
            QMessageBox.information(
                self, "No compatible bundle",
                "The release directory exists, but TorProxy did not find both the expected Expert Bundle archive "
                "and its matching .asc signature for this platform. No download was attempted."
            )
            return
        bundle = links[0]
        reply = QMessageBox.question(
            self, "Download and verify Tor bundle",
            "Download the {} release for this device?\n\n{}\n\nThe pinned OpenPGP signature is mandatory; "
            "installation stops if verification fails.".format(tor_version_channel(version), bundle),
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
        self._start_download(bundle, version)

    def _start_download(self, bundle: str, version: str) -> None:
        if self._busy:
            return
        self.cancel_event = Event()
        self._set_busy(True, cancellable=True)
        self.lbl_status.setText("Preparing secure download…")
        self.lbl_progress_details.setText("No bundle is considered installed until signature and archive checks finish.")
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFormat("Preparing…")
        self.worker = Worker(
            self.download_bundle, bundle, version, self.cancel_event, self.progress_event.emit
        )
        self.worker.signals.finished.connect(self._on_download_finished)
        self.worker.signals.error.connect(self._on_download_error)
        self.thread_pool.start(self.worker)

    def download_bundle(self, bundle: str, version: str, cancel_event: Event, progress_callback):
        logger.info("Downloading and verifying Tor Expert Bundle %s", bundle)
        archive = download_file(
            bundle, version, progress_callback=progress_callback, cancel_event=cancel_event
        )
        if cancel_event.is_set():
            raise RuntimeError("Tor bundle installation was cancelled.")
        progress_callback(BundleProgress(
            version, "install", "extracting_archive",
            message="Signature verified. Safely extracting the archive to a temporary directory.",
        ))
        base_path = os.path.join(BUNDLE_DIR, os.path.basename(bundle).replace(".tar.gz", ""))
        # The extraction helper repeats signature verification and writes its verification marker.
        extract_tar_gz_file(archive, base_path)
        if cancel_event.is_set():
            # Extraction itself is atomic; do not report success if cancellation arrived at the end.
            raise RuntimeError("Tor bundle installation was cancelled after extraction.")
        progress_callback(BundleProgress(
            version, "install", "installation_complete", percentage=100,
            message="Signature verified, archive validated, and bundle installation completed.",
        ))
        return "Installed and verified Tor Expert Bundle {}".format(bundle)

    def _on_progress(self, event: BundleProgress) -> None:
        if not isinstance(event, BundleProgress):
            logger.warning("Ignoring malformed Tor bundle progress event.")
            return
        labels = {
            "downloading_archive": "Downloading Tor archive",
            "downloading_signature": "Downloading detached signature",
            "downloading_signing_key": "Retrieving pinned-key material",
            "verifying_signature": "Verifying OpenPGP signature",
            "signature_verified": "Signature verified",
            "archive_validated": "Archive saved; installation pending",
            "extracting_archive": "Safely extracting archive",
            "installation_complete": "Installation complete",
            "already_verified": "Existing archive verified",
        }
        self.lbl_status.setText(labels.get(event.stage, event.message or event.stage.replace("_", " ").title()))
        self.lbl_status.setToolTip(event.message)
        if event.stage in {"verifying_signature", "downloading_signing_key", "extracting_archive"}:
            self.progress_bar.setRange(0, 0)
            self.progress_bar.setFormat(labels.get(event.stage, "Working…"))
        elif event.total_bytes and event.percentage is not None:
            self.progress_bar.setRange(0, 100)
            # A transfer reaching 100% is not installation success; the stage label remains explicit.
            self.progress_bar.setValue(min(99, max(0, event.percentage)))
            self.progress_bar.setFormat("{}%".format(min(99, max(0, event.percentage))))
        else:
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
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("Complete")
        self.lbl_status.setText(message)
        self.lbl_progress_details.setText(
            "The installed bundle passed detached-signature verification and structural checks."
        )
        self.refresh_version()
        self._update_install_state()

    def _on_download_error(self, error: str) -> None:
        logger.error("Tor bundle download/verification failed: %s", error)
        self._set_busy(False)
        self.cancel_event = None
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Failed")
        self.lbl_status.setText("Download or installation failed. The bundle was not reported as installed.")
        self.lbl_progress_details.setText(str(error))
        QMessageBox.warning(self, "Tor bundle operation failed", str(error))

