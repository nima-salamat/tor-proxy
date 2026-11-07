"""Browser chooser dialog with isolated TorProxy profiles."""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

import qtawesome as qta
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from torproxy.browsers import Browser, BrowserDetector, BrowserLaunchError, BrowserLauncher


class OpenBrowserDialog(QDialog):
    def __init__(self, parent=None, *, proxy_port: int, detector=None, launcher=None):
        super().__init__(parent)
        self.setWindowTitle("Open Browser through Tor")
        self.setObjectName("openBrowserDialog")
        self.setModal(True)
        self.resize(680, 650)
        self.setMinimumSize(520, 440)
        self.proxy_port = int(proxy_port)
        self.detector = detector or BrowserDetector()
        self.launcher = launcher or BrowserLauncher()
        self.browsers = self.detector.detect()
        self._cards: list[tuple[QFrame, str, str]] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 18)
        root.setSpacing(12)

        title_row = QHBoxLayout()
        title_text = QVBoxLayout()
        title = QLabel("Open Browser")
        title.setObjectName("browserDialogTitle")
        subtitle = QLabel("Choose an installed browser to launch with your TorProxy connection.")
        subtitle.setObjectName("browserDialogSubtitle")
        subtitle.setWordWrap(True)
        title_text.addWidget(title)
        title_text.addWidget(subtitle)
        title_row.addLayout(title_text, 1)
        connected = QLabel("● TOR READY")
        connected.setObjectName("browserReadyBadge")
        title_row.addWidget(connected, 0, Qt.AlignmentFlag.AlignTop)
        root.addLayout(title_row)

        proxy_panel = QFrame(self)
        proxy_panel.setObjectName("browserProxyPanel")
        proxy_layout = QHBoxLayout(proxy_panel)
        proxy_layout.setContentsMargins(12, 8, 12, 8)
        proxy_layout.addWidget(QLabel("Local HTTP proxy"))
        proxy_layout.addStretch(1)
        endpoint = QLabel(f"127.0.0.1:{self.proxy_port}")
        endpoint.setObjectName("browserProxyEndpoint")
        proxy_layout.addWidget(endpoint)
        root.addWidget(proxy_panel)

        self.search = QLineEdit(self)
        self.search.setObjectName("browserSearch")
        self.search.setClearButtonEnabled(True)
        self.search.setPlaceholderText("Search installed browsers…")
        self.search.textChanged.connect(self._filter_cards)
        root.addWidget(self.search)

        start_page_label = QLabel("Start page")
        start_page_label.setObjectName("browserGroupHeading")
        root.addWidget(start_page_label)
        self.start_page_input = QLineEdit(self)
        self.start_page_input.setObjectName("browserStartPage")
        self.start_page_input.setText("https://check.torproject.org/")
        self.start_page_input.setPlaceholderText("https://example.com/")
        self.start_page_input.setClearButtonEnabled(True)
        root.addWidget(self.start_page_input)

        self.scroll = QScrollArea(self)
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(2, 2, 8, 2)
        self.content_layout.setSpacing(9)
        self._build_cards()
        self.scroll.setWidget(self.content)
        root.addWidget(self.scroll, 1)

        self.notice = QLabel(
            "A separate TorProxy profile is used. Regular browsers do not gain Tor Browser's "
            "anti-fingerprinting protections. WebRTC's non-proxied UDP paths are restricted; "
            "some real-time media features may not work. Tor Browser is intentionally excluded because it runs its own Tor stack."
        )
        self.notice.setObjectName("browserPrivacyNotice")
        self.notice.setWordWrap(True)
        root.addWidget(self.notice)

        footer = QHBoxLayout()
        self.add_button = QPushButton(qta.icon("fa6s.plus"), " Add custom browser")
        self.add_button.setObjectName("browserAddButton")
        self.add_button.clicked.connect(self._add_custom_browser)
        footer.addWidget(self.add_button)
        footer.addStretch(1)
        close_button = QPushButton("Close")
        close_button.setObjectName("browserCloseButton")
        close_button.clicked.connect(self.reject)
        footer.addWidget(close_button)
        root.addLayout(footer)
        self._apply_styles()

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
            heading = QLabel(heading_text)
            heading.setObjectName("browserGroupHeading")
            self.content_layout.addWidget(heading)
            for browser in matches:
                card = self._create_card(browser)
                self.content_layout.addWidget(card)
                self._cards.append((card, browser.name.casefold(), family))

        if not self.browsers:
            empty = QLabel(
                "No supported browser was detected. Use “Add custom browser” to select an executable."
            )
            empty.setObjectName("browserEmptyState")
            empty.setWordWrap(True)
            self.content_layout.addWidget(empty)
        self.content_layout.addStretch(1)

    def _create_card(self, browser: Browser) -> QFrame:
        card = QFrame(self.content)
        card.setObjectName("browserCard")
        row = QHBoxLayout(card)
        row.setContentsMargins(12, 10, 12, 10)
        row.setSpacing(12)

        glyph = QLabel()
        glyph.setObjectName("browserGlyph")
        glyph.setPixmap(qta.icon("fa6s.globe", color="#47a3f2").pixmap(25, 25))
        glyph.setFixedSize(36, 36)
        row.addWidget(glyph)

        text_column = QVBoxLayout()
        name = QLabel(browser.name)
        name.setObjectName("browserName")
        source = QLabel(self._source_label(browser))
        source.setObjectName("browserSource")
        text_column.addWidget(name)
        text_column.addWidget(source)
        row.addLayout(text_column, 1)

        open_button = QPushButton("Open")
        open_button.setObjectName("browserOpenButton")
        open_button.setCursor(Qt.CursorShape.PointingHandCursor)
        open_button.clicked.connect(lambda _checked=False, selected=browser: self._launch(selected))
        row.addWidget(open_button)
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        return card

    @staticmethod
    def _source_label(browser: Browser) -> str:
        labels = {
            "registry": "Detected from Windows application registration",
            "known-path": "Detected in a standard installation location",
            "desktop-entry": "Detected from Linux desktop application metadata",
            "PATH": "Detected from PATH",
            "custom": "Custom executable",
        }
        return labels.get(browser.source, "Installed browser")

    def _filter_cards(self, query: str) -> None:
        needle = str(query or "").strip().casefold()
        for card, name, family in self._cards:
            show = not needle or needle in name or needle in family
            card.setVisible(show)

    def _launch(self, browser: Browser) -> None:
        try:
            self.notice.setText(f"Starting {browser.name} with the isolated TorProxy profile…")
            self.notice.setObjectName("browserPrivacyNotice")
            start_url = self.start_page_input.text().strip() or None
            self.launcher.launch(browser, self.proxy_port, start_url)
        except (BrowserLaunchError, OSError, ValueError) as exc:
            self.notice.setText(f"Could not open {browser.name}: {exc}")
            self.notice.setObjectName("browserErrorNotice")
            self.notice.style().unpolish(self.notice)
            self.notice.style().polish(self.notice)
            return
        self.accept()

    def _add_custom_browser(self) -> None:
        family, accepted = QInputDialog.getItem(
            self,
            "Custom browser type",
            "Choose the browser engine:",
            ["Chromium-based", "Firefox-based"],
            0,
            False,
        )
        if not accepted:
            return
        selected, _filter = QFileDialog.getOpenFileName(
            self,
            "Select browser executable",
            str(Path.home()),
            "Applications (*)" if os.name != "nt" else "Applications (*.exe)",
        )
        if not selected:
            return
        path = Path(selected).expanduser()
        safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "-", path.stem).strip(".-") or "browser"
        browser_identity = f"{path.stem} {path.resolve()}".casefold()
        if any(marker in browser_identity for marker in ("tor browser", "tor-browser", "torbrowser")):
            self.notice.setText(
                "Tor Browser manages its own Tor process and browser profile. "
                "Launch it separately instead of routing it through this generic browser launcher."
            )
            self.notice.setObjectName("browserErrorNotice")
            self.notice.style().unpolish(self.notice)
            self.notice.style().polish(self.notice)
            return
        digest = hashlib.sha256(str(path.resolve()).encode("utf-8")).hexdigest()[:10]
        browser = Browser(
            id=f"custom-{safe_name}-{digest}",
            name=path.stem,
            family="chromium" if family.startswith("Chromium") else "firefox",
            executable=str(path.resolve()),
            source="custom",
        )
        try:
            self.detector.register_custom(browser)
            self.browsers = self.detector.detect()
        except Exception as exc:
            self.notice.setText(f"Could not save this browser: {exc}")
            self.notice.setObjectName("browserErrorNotice")
            self.notice.style().unpolish(self.notice)
            self.notice.style().polish(self.notice)
            return
        self._build_cards()
        self._filter_cards(self.search.text())

    def _apply_styles(self) -> None:
        self.setStyleSheet("""
            QDialog#openBrowserDialog { background: palette(window); }
            QLabel#browserDialogTitle { font-size: 17pt; font-weight: 750; }
            QLabel#browserDialogSubtitle, QLabel#browserSource { color: palette(mid); }
            QLabel#browserReadyBadge {
                color: #20a66a; background: rgba(32,166,106,0.12);
                border: 1px solid rgba(32,166,106,0.28); border-radius: 9px;
                padding: 6px 9px; font-size: 9pt; font-weight: 750;
            }
            QFrame#browserProxyPanel, QFrame#browserCard {
                background: palette(base); border: 1px solid palette(midlight); border-radius: 10px;
            }
            QLabel#browserProxyEndpoint { font-weight: 700; }
            QLabel#browserGroupHeading { font-size: 10pt; font-weight: 750; padding: 5px 2px 1px; }
            QLabel#browserName { font-size: 10pt; font-weight: 700; }
            QLabel#browserSource { font-size: 8pt; }
            QLabel#browserPrivacyNotice {
                color: palette(mid); background: palette(alternate-base);
                border: 1px solid palette(midlight); border-radius: 8px; padding: 9px;
            }
            QLabel#browserErrorNotice {
                color: #d9534f; background: rgba(217,83,79,0.10);
                border: 1px solid rgba(217,83,79,0.30); border-radius: 8px; padding: 9px;
            }
            QPushButton#browserOpenButton {
                min-width: 76px; min-height: 31px; border-radius: 7px;
                background: #287db5; color: white; border: none; font-weight: 700;
            }
            QPushButton#browserOpenButton:hover { background: #3797d2; }
            QPushButton#browserAddButton, QPushButton#browserCloseButton {
                min-height: 32px; padding: 0 11px; border-radius: 7px;
            }
        """)


