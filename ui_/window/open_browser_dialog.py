"""Browser chooser using TorProxy's shared custom dialog shell."""
from __future__ import annotations

import hashlib
import logging
import os
import re
from pathlib import Path

import qtawesome as qta
from PySide6.QtCore import QFileInfo, QSize, Qt, QThreadPool, QTimer
from PySide6.QtGui import QColor, QIcon, QPainter, QPen
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFileIconProvider,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from torproxy.browsers import (
    Browser,
    BrowserDetector,
    BrowserInventoryStore,
    BrowserLaunchError,
    BrowserLauncher,
)
from ui_.worker.browser_discovery import BrowserDiscoveryWorker
from ui_.window.dialogs import _FramelessDialog

logger = logging.getLogger(__name__)


_BRAND_ICON_NAMES = {
    "chrome": "fa6b.chrome",
    "chromium": "fa6s.globe",
    "edge": "fa6b.edge",
    "brave": "fa6b.brave",
    "vivaldi": "fa6b.vivaldi",
    "opera": "fa6b.opera",
    "opera_gx": "fa6b.opera",
    "firefox": "fa6b.firefox-browser",
    "firefox_esr": "fa6b.firefox-browser",
    "librewolf": "fa6b.firefox-browser",
    "waterfox": "fa6b.firefox-browser",
    "floorp": "fa6s.globe",
    "zen": "fa6s.globe",
    "yandex": "fa6s.globe",
    "ungoogled_chromium": "fa6s.globe",
}


class _BrowserScanSpinner(QWidget):
    """Small native Qt spinner that animates without blocking the GUI thread."""

    def __init__(self, color: str, parent=None):
        super().__init__(parent)
        self._color = QColor(color)
        self._angle = 0
        self.setFixedSize(18, 18)
        self._timer = QTimer(self)
        self._timer.setInterval(75)
        self._timer.timeout.connect(self._advance)
        self.hide()

    def start(self) -> None:
        self._angle = 0
        self.show()
        if not self._timer.isActive():
            self._timer.start()

    def stop(self) -> None:
        self._timer.stop()
        self.hide()

    def _advance(self) -> None:
        self._angle = (self._angle + 30) % 360
        self.update()

    def paintEvent(self, _event) -> None:
        if not self.isVisible():
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        center_x = self.width() / 2
        center_y = self.height() / 2
        painter.translate(center_x, center_y)
        for index in range(12):
            color = QColor(self._color)
            color.setAlpha(35 + index * 18)
            pen = QPen(color, 2.2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            painter.save()
            painter.rotate(self._angle + index * 30)
            painter.drawLine(0, -3, 0, -7)
            painter.restore()


class _BrowserEngineDialog(_FramelessDialog):
    """Small engine picker that follows the shared application popup style."""

    def __init__(self, parent=None):
        super().__init__(
            parent,
            "Add a browser",
            "fa6s.plus",
            "#287db5",
            width=420,
        )
        prompt = QLabel(
            "Choose the browser engine used by the executable you are adding.",
            self.body_host,
        )
        prompt.setObjectName("dialogMessage")
        prompt.setWordWrap(True)
        self.body_layout.addWidget(prompt)

        self.engine_combo = QComboBox(self.body_host)
        self.engine_combo.setObjectName("browserEngineCombo")
        self.engine_combo.addItem("Chromium-based", "chromium")
        self.engine_combo.addItem("Firefox-based", "firefox")
        self.body_layout.addWidget(self.engine_combo)

        self.add_footer_spacer()
        self.add_button("Cancel", primary=False, callback=self.reject)
        self.add_button("Continue", primary=True, callback=self.accept)
        self.setStyleSheet(self.styleSheet() + self._extra_styles())
        self.adjustSize()
        self._remember_preferred_size()

    @property
    def family(self) -> str:
        return str(self.engine_combo.currentData())

    def _extra_styles(self) -> str:
        return f"""
            QComboBox#browserEngineCombo {{
                color: {self._colors["text"]};
                background: {self._colors["panel"]};
                border: 1px solid {self._colors["border"]};
                border-radius: 8px;
                padding: 7px 10px;
                min-height: 30px;
            }}
        """


class OpenBrowserDialog(_FramelessDialog):
    """Browse installed browsers and launch one through the active TorProxy HTTP listener."""

    def __init__(
        self, parent=None, *, proxy_port: int, detector=None, launcher=None, inventory=None
    ):
        super().__init__(
            parent,
            "Open Browser",
            "fa6s.globe",
            "#287db5",
            width=620,
        )
        self.setMinimumSize(600, 520)
        self.setMaximumSize(1100, 1000)
        self.resize(760, 720)
        self._remember_preferred_size()

        self.proxy_port = int(proxy_port)
        self.detector = detector or BrowserDetector()
        self.launcher = launcher or BrowserLauncher()
        self.inventory = inventory or BrowserInventoryStore()
        try:
            # This is a tiny local SQLite read only. Full OS discovery runs
            # after the dialog is constructed, on QThreadPool.
            self.browsers = self.inventory.load()
        except Exception:
            logger.exception("Could not load the cached browser inventory.")
            self.browsers = []
        self._cards: list[tuple[QFrame, str, str, Browser]] = []
        self._icon_provider = QFileIconProvider()
        self._scan_running = False
        self._scan_pending = True
        self._scan_worker = None
        self._closing = False

        heading = QHBoxLayout()
        heading.setSpacing(10)
        intro = QLabel(
            "Choose an installed browser. TorProxy opens it with a dedicated profile and the active local proxy.",
            self.body_host,
        )
        intro.setObjectName("dialogMessage")
        intro.setWordWrap(True)
        heading.addWidget(intro, 1)

        self.ready_badge = QLabel("TOR READY", self.body_host)
        self.ready_badge.setObjectName("browserReadyBadge")
        heading.addWidget(self.ready_badge, 0, Qt.AlignmentFlag.AlignTop)
        self.body_layout.addLayout(heading)

        connection_row = QHBoxLayout()
        connection_row.setSpacing(8)
        local_label = QLabel("Local HTTP proxy", self.body_host)
        local_label.setObjectName("dialogHint")
        connection_row.addWidget(local_label)
        connection_row.addStretch(1)
        self.endpoint_label = QLabel(f"127.0.0.1:{self.proxy_port}", self.body_host)
        self.endpoint_label.setObjectName("browserProxyEndpoint")
        connection_row.addWidget(self.endpoint_label)
        self.body_layout.addLayout(connection_row)

        scan_row = QHBoxLayout()
        scan_row.setSpacing(8)
        self.scan_spinner = _BrowserScanSpinner(self._accent, self.body_host)
        self.scan_spinner.start()
        scan_row.addWidget(self.scan_spinner)
        self.scan_status = QLabel("Loading saved browsers…", self.body_host)
        self.scan_status.setObjectName("dialogHint")
        scan_row.addWidget(self.scan_status, 1)
        self.refresh_button = QPushButton("Refresh", self.body_host)
        self.refresh_button.setObjectName("browserRefreshButton")
        self.refresh_button.setIcon(qta.icon("fa6s.rotate", color=self._colors["text"]))
        self.refresh_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.refresh_button.clicked.connect(self._start_scan)
        scan_row.addWidget(self.refresh_button)
        self.body_layout.addLayout(scan_row)

        search_row = QHBoxLayout()
        search_row.setSpacing(8)
        self.search = QLineEdit(self.body_host)
        self.search.setObjectName("browserSearch")
        self.search.setClearButtonEnabled(True)
        self.search.setPlaceholderText("Search installed browsers…")
        self.search.addAction(
            qta.icon("fa6s.magnifying-glass", color=self._colors["muted"]),
            QLineEdit.ActionPosition.LeadingPosition,
        )
        self.search.textChanged.connect(self._filter_cards)
        search_row.addWidget(self.search, 1)
        self.count_label = QLabel(self.body_host)
        self.count_label.setObjectName("dialogHint")
        search_row.addWidget(self.count_label)
        self.body_layout.addLayout(search_row)

        start_row = QHBoxLayout()
        start_label = QLabel("Start page", self.body_host)
        start_label.setObjectName("dialogHint")
        start_row.addWidget(start_label)
        self.start_page_input = QLineEdit(self.body_host)
        self.start_page_input.setObjectName("browserStartPage")
        self.start_page_input.setText("https://check.torproject.org/")
        self.start_page_input.setPlaceholderText("https://example.com/")
        self.start_page_input.setClearButtonEnabled(True)
        start_row.addWidget(self.start_page_input, 1)
        self.body_layout.addLayout(start_row)

        self.scroll = QScrollArea(self.body_host)
        self.scroll.setObjectName("dialogScroll")
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.content = QWidget(self.scroll)
        self.content.setObjectName("browserListContent")
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(1, 2, 7, 2)
        self.content_layout.setSpacing(8)
        self.scroll.setWidget(self.content)
        self.body_layout.addWidget(self.scroll, 1)

        self.notice = QLabel(
            "Each browser uses a separate TorProxy profile. A normal browser does not provide Tor Browser's "
            "anti-fingerprinting protections; some WebRTC media features may also be restricted.",
            self.body_host,
        )
        self.notice.setObjectName("dialogHint")
        self.notice.setWordWrap(True)
        self.body_layout.addWidget(self.notice)

        self.add_button("Add custom browser", primary=False, callback=self._add_custom_browser).setIcon(
            qta.icon("fa6s.plus", color=self._colors["text"])
        )
        self.add_footer_spacer()
        self.add_button("Close", primary=True, callback=self.accept)
        self.setStyleSheet(self.styleSheet() + self._extra_styles())
        self.adjustSize()
        self.resize(760, max(600, self.sizeHint().height()))
        self._remember_preferred_size()
        self._build_cards()
        # Let Qt paint the dialog and its cached rows before the OS scan begins.
        QTimer.singleShot(0, self._start_scan)

    def _extra_styles(self) -> str:
        return f"""
            QLabel#browserReadyBadge {{
                color: #1f9d68;
                background: rgba(31, 157, 104, 0.12);
                border: 1px solid rgba(31, 157, 104, 0.28);
                border-radius: 8px;
                padding: 5px 9px;
                font-size: 8pt;
                font-weight: 800;
                letter-spacing: 0.4px;
            }}
            QLabel#browserProxyEndpoint {{
                color: {self._colors["text"]};
                background: {self._colors["panel"]};
                border: 1px solid {self._colors["border"]};
                border-radius: 7px;
                padding: 5px 9px;
                font-family: Consolas, monospace;
                font-weight: 700;
            }}
            QLineEdit#browserSearch, QLineEdit#browserStartPage {{
                color: {self._colors["text"]};
                background: {self._colors["panel"]};
                border: 1px solid {self._colors["border"]};
                border-radius: 8px;
                padding: 7px 9px;
                min-height: 28px;
                selection-background-color: {self._accent};
            }}
            QLineEdit#browserSearch:focus, QLineEdit#browserStartPage:focus {{
                border-color: {self._accent};
            }}
            QPushButton#browserRefreshButton {{
                color: {self._colors["text"]};
                background: {self._colors["panel"]};
                border: 1px solid {self._colors["border"]};
                border-radius: 7px;
                padding: 0 10px;
                min-height: 29px;
                font-weight: 650;
            }}
            QPushButton#browserRefreshButton:hover {{
                background: {self._colors["hover"]};
                border-color: {self._accent};
            }}
            QPushButton#browserRefreshButton:disabled {{
                color: {self._colors["muted"]};
            }}
            QLabel#browserGroupHeading {{
                color: {self._accent};
                background: transparent;
                font-size: 8.5pt;
                font-weight: 800;
                padding: 7px 2px 1px;
            }}
            QFrame#browserCard {{
                background: {self._colors["panel"]};
                border: 1px solid {self._colors["border"]};
                border-radius: 10px;
            }}
            QFrame#browserCard:hover {{
                border-color: {self._accent};
                background: {self._colors["hover"]};
            }}
            QFrame#browserIconFrame {{
                background: {self._colors["surface"]};
                border: 1px solid {self._colors["border"]};
                border-radius: 9px;
            }}
            QLabel#browserName {{
                color: {self._colors["text"]};
                background: transparent;
                font-size: 9.5pt;
                font-weight: 750;
            }}
            QLabel#browserSource {{
                color: {self._colors["muted"]};
                background: transparent;
                font-size: 7.5pt;
            }}
            QPushButton#browserOpenButton {{
                color: #ffffff;
                background: {self._accent};
                border: 1px solid {self._accent};
                border-radius: 7px;
                padding: 0 15px;
                min-height: 31px;
                font-weight: 750;
            }}
            QPushButton#browserOpenButton:hover {{ background: #236b9b; }}
            QLabel#browserEmptyState {{
                color: {self._colors["muted"]};
                background: {self._colors["panel"]};
                border: 1px dashed {self._colors["border"]};
                border-radius: 10px;
                padding: 18px;
            }}
            QLabel#browserErrorNotice {{
                color: #dc5656;
                background: rgba(220, 86, 86, 0.10);
                border: 1px solid rgba(220, 86, 86, 0.28);
                border-radius: 8px;
                padding: 8px 10px;
            }}
        """

    def _browser_icon(self, browser: Browser) -> QIcon:
        """Use the real installed application icon before falling back to a family glyph."""
        if browser.icon:
            icon_path = Path(browser.icon).expanduser()
            if icon_path.is_file():
                icon = QIcon(str(icon_path))
                if not icon.isNull():
                    return icon
                try:
                    native_icon = self._icon_provider.icon(QFileInfo(str(icon_path)))
                except (OSError, RuntimeError, TypeError):
                    native_icon = QIcon()
                if not native_icon.isNull():
                    return native_icon
            themed = QIcon.fromTheme(browser.icon)
            if not themed.isNull():
                return themed

        for candidate in (browser.executable, browser.desktop_file):
            if not candidate:
                continue
            try:
                icon = self._icon_provider.icon(QFileInfo(candidate))
            except (OSError, RuntimeError, TypeError):
                continue
            if not icon.isNull():
                return icon

        icon_name = _BRAND_ICON_NAMES.get(browser.id, "fa6s.globe")
        try:
            return qta.icon(icon_name, color=self._accent)
        except Exception:
            return qta.icon("fa6s.globe", color=self._accent)

    def _build_cards(self) -> None:
        while self.content_layout.count():
            item = self.content_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self._cards.clear()

        groups = (
            ("chromium", "Chromium browsers"),
            ("firefox", "Firefox browsers"),
        )
        for family, heading_text in groups:
            matches = [browser for browser in self.browsers if browser.family == family]
            if not matches:
                continue
            heading = QLabel(heading_text, self.content)
            heading.setObjectName("browserGroupHeading")
            self.content_layout.addWidget(heading)
            for browser in matches:
                card = self._create_card(browser)
                self.content_layout.addWidget(card)
                self._cards.append((card, browser.name.casefold(), family, browser))

        if not self.browsers:
            empty_text = (
                "Searching for installed browsers…"
                if self._scan_running or self._scan_pending
                else "No supported browser was detected. Use “Add custom browser” to select an executable."
            )
            empty = QLabel(empty_text, self.content)
            empty.setObjectName("browserEmptyState")
            empty.setWordWrap(True)
            self.content_layout.addWidget(empty)
        self.content_layout.addStretch(1)
        self._update_count_label()

    def _create_card(self, browser: Browser) -> QFrame:
        card = QFrame(self.content)
        card.setObjectName("browserCard")
        row = QHBoxLayout(card)
        row.setContentsMargins(11, 9, 11, 9)
        row.setSpacing(11)

        icon_frame = QFrame(card)
        icon_frame.setObjectName("browserIconFrame")
        icon_frame.setFixedSize(48, 48)
        icon_layout = QHBoxLayout(icon_frame)
        icon_layout.setContentsMargins(5, 5, 5, 5)
        icon_label = QLabel(icon_frame)
        icon_label.setObjectName("browserIconLabel")
        icon_label.setProperty("browserId", browser.id)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setPixmap(self._browser_icon(browser).pixmap(QSize(36, 36)))
        icon_layout.addWidget(icon_label)
        row.addWidget(icon_frame)

        text_column = QVBoxLayout()
        text_column.setSpacing(3)
        name = QLabel(browser.name, card)
        name.setObjectName("browserName")
        source = QLabel(self._source_label(browser), card)
        source.setObjectName("browserSource")
        source.setWordWrap(True)
        text_column.addWidget(name)
        text_column.addWidget(source)
        row.addLayout(text_column, 1)

        open_button = QPushButton("Open", card)
        open_button.setObjectName("browserOpenButton")
        open_button.setCursor(Qt.CursorShape.PointingHandCursor)
        open_button.clicked.connect(lambda _checked=False, selected=browser: self._launch(selected))
        row.addWidget(open_button)
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        return card

    @staticmethod
    def _source_label(browser: Browser) -> str:
        labels = {
            "registry": "Windows application registration",
            "registry-app-paths": "Windows registered executable",
            "start-menu-registration": "Windows Start Menu browser list",
            "start-menu-shortcut": "Windows Start Menu shortcut",
            "uninstall-registry": "Windows installed application record",
            "known-path": "Standard installation location",
            "desktop-entry": "Linux desktop application entry",
            "PATH": "Detected from PATH",
            "custom": "Custom executable",
        }
        return labels.get(browser.source, "Installed browser")

    def _update_count_label(self) -> None:
        visible = sum(not card.isHidden() for card, _name, _family, _browser in self._cards)
        total = len(self._cards)
        suffix = " cached" if self._scan_running or self._scan_pending else " installed"
        self.count_label.setText(f"{visible} of {total}{suffix}")

    def _filter_cards(self, query: str) -> None:
        needle = str(query or "").strip().casefold()
        for card, name, family, browser in self._cards:
            haystack = " ".join((name, family, browser.id, browser.executable)).casefold()
            card.setVisible(not needle or needle in haystack)
        self._update_count_label()

    def _start_scan(self) -> None:
        """Start/resume an OS scan without delaying popup presentation."""
        if self._closing or self._scan_running:
            return
        self._scan_pending = False
        self._scan_running = True
        self.scan_spinner.start()
        self.scan_status.setText("Checking installed browsers in the background…")
        self.refresh_button.setEnabled(False)
        if not self.browsers:
            self._build_cards()
        worker = BrowserDiscoveryWorker(self.detector, self.inventory)
        worker.signals.completed.connect(self._on_scan_completed)
        worker.signals.failed.connect(self._on_scan_failed)
        self._scan_worker = worker
        QThreadPool.globalInstance().start(worker)

    def _on_scan_completed(self, browsers) -> None:
        if self._closing:
            return
        self._scan_running = False
        self._scan_worker = None
        self.browsers = list(browsers or [])
        self.scan_spinner.stop()
        self.refresh_button.setEnabled(True)
        count = len(self.browsers)
        self.scan_status.setText(
            f"System check complete · {count} browser{'s' if count != 1 else ''} found"
        )
        self.notice.setText(
            "Each browser uses a separate TorProxy profile. A normal browser does not provide Tor Browser's "
            "anti-fingerprinting protections; some WebRTC media features may also be restricted."
        )
        self.notice.setObjectName("dialogHint")
        self.notice.style().unpolish(self.notice)
        self.notice.style().polish(self.notice)
        self._build_cards()
        self._filter_cards(self.search.text())

    def _on_scan_failed(self, message: str) -> None:
        if self._closing:
            return
        self._scan_running = False
        self._scan_worker = None
        self.scan_spinner.stop()
        self.refresh_button.setEnabled(True)
        self.scan_status.setText("System scan failed · saved browser list retained")
        self._show_error(
            "Could not refresh the installed browser list. The last saved list is still available. "
            f"Details: {message}"
        )
        self._build_cards()
        self._filter_cards(self.search.text())

    def _remove_stale_browser(self, browser: Browser) -> None:
        """Remove a deleted installation immediately, even before discovery completes."""
        try:
            self.inventory.remove(browser.id, browser.executable)
        except Exception:
            logger.exception("Could not remove stale browser from the inventory database.")
        if browser.source == "custom":
            custom_store = getattr(self.detector, "custom_store", None)
            remove_custom = getattr(custom_store, "remove", None)
            if callable(remove_custom):
                try:
                    remove_custom(browser.id, browser.executable)
                except Exception:
                    logger.exception("Could not remove stale custom browser registration.")
        self.browsers = [
            item for item in self.browsers
            if not (item.id == browser.id and item.executable == browser.executable)
        ]
        self._build_cards()
        self._filter_cards(self.search.text())

    @staticmethod
    def _is_executable_available(browser: Browser) -> bool:
        executable = Path(browser.executable).expanduser()
        if not executable.is_file():
            return False
        return os.name == "nt" or os.access(executable, os.X_OK)

    def closeEvent(self, event) -> None:
        self._closing = True
        self.scan_spinner.stop()
        super().closeEvent(event)

    def _show_error(self, message: str) -> None:
        self.notice.setText(message)
        self.notice.setObjectName("browserErrorNotice")
        self.notice.style().unpolish(self.notice)
        self.notice.style().polish(self.notice)

    def _launch(self, browser: Browser) -> None:
        # The saved snapshot can be older than an uninstall. Check the exact
        # executable before launch rather than waiting for the background scan.
        if not self._is_executable_available(browser):
            self._remove_stale_browser(browser)
            self._show_error(
                f"{browser.name} is no longer installed or its executable was moved. "
                "The saved entry has been removed; the background scan will refresh the list."
            )
            return
        try:
            start_url = self.start_page_input.text().strip() or None
            self.launcher.launch(browser, self.proxy_port, start_url)
        except (BrowserLaunchError, OSError, ValueError) as exc:
            if not self._is_executable_available(browser):
                self._remove_stale_browser(browser)
                self._show_error(
                    f"{browser.name} was removed before it could be started. "
                    "Its saved entry has been removed from the list."
                )
                return
            self._show_error(f"Could not open {browser.name}: {exc}")
            return
        self.accept()

    def _add_custom_browser(self) -> None:
        engine_dialog = _BrowserEngineDialog(self)
        if engine_dialog.exec() != _FramelessDialog.DialogCode.Accepted:
            return
        selected, _filter = QFileDialog.getOpenFileName(
            self,
            "Select browser executable",
            str(Path.home()),
            "Applications (*.exe)" if os.name == "nt" else "Applications (*)",
        )
        if not selected:
            return
        path = Path(selected).expanduser()
        if not path.is_file():
            self._show_error("The selected executable does not exist.")
            return
        safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "-", path.stem).strip(".-") or "browser"
        browser_identity = f"{path.stem} {path.resolve()}".casefold()
        if any(marker in browser_identity for marker in ("tor browser", "tor-browser", "torbrowser")):
            self._show_error(
                "Tor Browser manages its own Tor process and browser profile. "
                "Launch it separately instead of routing it through this generic launcher."
            )
            return

        digest = hashlib.sha256(str(path.resolve()).encode("utf-8")).hexdigest()[:10]
        browser = Browser(
            id=f"custom-{safe_name}-{digest}",
            name=path.stem,
            family=engine_dialog.family,
            executable=str(path.resolve()),
            source="custom",
            icon=str(path.resolve()),
        )
        try:
            self.detector.register_custom(browser)
            self.inventory.upsert(browser)
        except Exception as exc:
            self._show_error(f"Could not save this browser: {exc}")
            return
        self.browsers = [
            item for item in self.browsers
            if item.id != browser.id
        ] + [browser]
        self.notice.setText("Custom browser saved. It will remain available in this list.")
        self.notice.setObjectName("dialogHint")
        self.notice.style().unpolish(self.notice)
        self.notice.style().polish(self.notice)
        self._build_cards()
        self._filter_cards(self.search.text())
