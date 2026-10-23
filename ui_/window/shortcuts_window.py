"""Dedicated in-app keyboard-shortcuts page."""
from __future__ import annotations

import qtawesome as qta
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from config import CONFIG, IS_WINDOWS


class ShortcutsWindow(QWidget):
    """Explain app shortcuts with keycap controls, not a text message box."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._parent = parent
        self._shortcut_rows = []
        self._icon_specs = []

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 22)
        root.setSpacing(16)

        header = QHBoxLayout()
        header.setSpacing(14)

        self.page_icon = QLabel(self)
        self.page_icon.setObjectName("shortcutsPageIcon")
        self.page_icon.setFixedSize(50, 50)
        self.page_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.addWidget(self.page_icon)

        title_column = QVBoxLayout()
        title_column.setSpacing(4)
        self.page_title = QLabel("Keyboard shortcuts", self)
        self.page_title.setObjectName("shortcutsPageTitle")
        self.page_subtitle = QLabel(
            "A quick reference for navigating TorProxy and controlling the application.",
            self,
        )
        self.page_subtitle.setObjectName("shortcutsPageSubtitle")
        self.page_subtitle.setWordWrap(True)
        title_column.addWidget(self.page_title)
        title_column.addWidget(self.page_subtitle)
        header.addLayout(title_column, 1)

        self.f1_hint = QLabel("F1  ·  SHORTCUTS", self)
        self.f1_hint.setObjectName("shortcutsHeaderHint")
        self.f1_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.addWidget(self.f1_hint, 0, Qt.AlignmentFlag.AlignVCenter)
        root.addLayout(header)

        separator = QFrame(self)
        separator.setObjectName("shortcutsDivider")
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFixedHeight(1)
        root.addWidget(separator)

        scroll = QScrollArea(self)
        scroll.setObjectName("shortcutsScroll")
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        content = QWidget(scroll)
        content.setObjectName("shortcutsContent")
        self.content_layout = QVBoxLayout(content)
        self.content_layout.setContentsMargins(0, 0, 8, 0)
        self.content_layout.setSpacing(2)

        self._add_category(
            "NAVIGATION",
            [
                ("Home", "Open the connection dashboard", ("Ctrl", "H"), "fa6s.house"),
                ("Settings", "Configure Tor and application behavior", ("Ctrl", "S"), "fa6s.gear"),
                ("Block Host", "Manage blocked host rules", ("Ctrl", "B"), "fa6s.shield-halved"),
                ("Exclude Host", "Manage bypass rules", ("Ctrl", "E"), "fa6s.route"),
                ("Bundles", "Browse Tor releases and local bundles", ("Ctrl", "U"), "fa6s.boxes-stacked"),
                ("Keyboard shortcuts", "Open this reference page", ("F1",), "fa6s.keyboard"),
            ],
        )
        self._add_category(
            "APPLICATION",
            [
                ("Exit TorProxy", "Confirm and close the application", ("Ctrl", "Q"), "fa6s.right-from-bracket"),
            ],
        )
        if IS_WINDOWS:
            self._add_category(
                "GLOBAL",
                [
                    ("Show / hide TorProxy", "Toggle the main window from anywhere", ("Ctrl", "Alt", "P"), "fa6s.eye"),
                ],
            )
        self.content_layout.addStretch(1)
        scroll.setWidget(content)
        root.addWidget(scroll, 1)

        self.footer_label = QLabel(
            "Navigation shortcuts work while TorProxy is focused.  Ctrl + Alt + P is global on Windows.",
            self,
        )
        self.footer_label.setObjectName("shortcutsFooter")
        self.footer_label.setWordWrap(True)
        root.addWidget(self.footer_label)

        self.apply_theme(CONFIG["mode"])

    def _add_category(self, heading, entries):
        category = QLabel(heading, self)
        category.setObjectName("shortcutsCategory")
        self.content_layout.addWidget(category)
        for title, description, keys, icon_name in entries:
            row = QFrame(self)
            row.setObjectName("shortcutsRow")
            layout = QHBoxLayout(row)
            layout.setContentsMargins(8, 9, 8, 9)
            layout.setSpacing(12)

            icon_label = QLabel(row)
            icon_label.setFixedSize(24, 24)
            icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(icon_label)
            self._icon_specs.append((icon_label, icon_name))

            copy = QVBoxLayout()
            copy.setContentsMargins(0, 0, 0, 0)
            copy.setSpacing(2)
            name_label = QLabel(title, row)
            name_label.setObjectName("shortcutsRowTitle")
            desc_label = QLabel(description, row)
            desc_label.setObjectName("shortcutsRowDescription")
            desc_label.setWordWrap(True)
            copy.addWidget(name_label)
            copy.addWidget(desc_label)
            layout.addLayout(copy, 1)

            key_layout = QHBoxLayout()
            key_layout.setContentsMargins(0, 0, 0, 0)
            key_layout.setSpacing(4)
            key_caps = []
            for index, key in enumerate(keys):
                if index:
                    plus = QLabel("+", row)
                    plus.setObjectName("shortcutsPlus")
                    key_layout.addWidget(plus)
                key_cap = QLabel(key, row)
                key_cap.setObjectName("shortcutsKeycap")
                key_cap.setAlignment(Qt.AlignmentFlag.AlignCenter)
                key_layout.addWidget(key_cap)
                key_caps.append(key_cap)
            layout.addLayout(key_layout)
            self.content_layout.addWidget(row)
            self._shortcut_rows.append((row, key_caps))

    def apply_theme(self, mode):
        dark = mode == "dark"
        accent = "#287db5"
        border = "#3b4552" if dark else "#d7dee7"
        surface = "#272c33" if dark else "#ffffff"
        panel = "#202630" if dark else "#f4f7fb"
        text = "#e8edf3" if dark else "#253041"
        muted = "#9ba7b5" if dark else "#657386"
        hover = "rgba(71, 163, 242, 0.10)" if dark else "rgba(24, 118, 191, 0.07)"
        self.setStyleSheet(f"""
            QWidget {{ background: {surface}; color: {text}; }}
            QLabel#shortcutsPageTitle {{ color: {text}; background: transparent; font-size: 23px; font-weight: 800; }}
            QLabel#shortcutsPageSubtitle {{ color: {muted}; background: transparent; font-size: 12px; }}
            QLabel#shortcutsPageIcon {{ background: rgba(40, 125, 181, 0.14); border: 1px solid {border}; border-radius: 14px; }}
            QLabel#shortcutsHeaderHint {{ color: {accent}; background: {panel}; border: 1px solid {border}; border-radius: 8px; padding: 8px 12px; font-size: 10px; font-weight: 800; }}
            QFrame#shortcutsDivider {{ background: {border}; border: none; }}
            QScrollArea#shortcutsScroll, QWidget#shortcutsContent {{ background: transparent; border: none; }}
            QLabel#shortcutsCategory {{ color: {accent}; background: transparent; font-size: 10px; font-weight: 850; padding: 14px 8px 4px; }}
            QFrame#shortcutsRow {{ background: transparent; border: none; border-bottom: 1px solid {border}; border-radius: 6px; }}
            QFrame#shortcutsRow:hover {{ background: {hover}; }}
            QLabel#shortcutsRowTitle {{ color: {text}; background: transparent; font-size: 12px; font-weight: 700; }}
            QLabel#shortcutsRowDescription {{ color: {muted}; background: transparent; font-size: 10px; }}
            QLabel#shortcutsKeycap {{ color: {text}; background: {panel}; border: 1px solid {border}; border-bottom: 2px solid {border}; border-radius: 5px; padding: 4px 7px; min-width: 18px; font-size: 10px; font-weight: 800; }}
            QLabel#shortcutsPlus {{ color: {muted}; background: transparent; font-size: 10px; }}
            QLabel#shortcutsFooter {{ color: {muted}; background: transparent; font-size: 10px; padding-top: 3px; }}
        """)
        self.page_icon.setPixmap(qta.icon("fa6s.keyboard", color=accent).pixmap(26, 26))
        for label, icon_name in self._icon_specs:
            label.setPixmap(qta.icon(icon_name, color=accent).pixmap(18, 18))
