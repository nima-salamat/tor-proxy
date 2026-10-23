"""Modern UI for blocked host rules."""
from __future__ import annotations

import logging

import qtawesome as qta
from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from config import CONFIG
from proxy import load_blocked, remove_blocked, save_blocked, add_to_blocked_hosts, get_blocked
from ui_.worker.worker import Worker

logger = logging.getLogger(__name__)


class BlcokHostsWindow(QWidget):
    """Manage block rules with searchable list, clear empty states and safe deletion."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._parent = parent
        self.threadpool = QThreadPool(self)

        load_blocked()
        self._rule_icon_name = "fa6s.shield-halved"

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        heading = QHBoxLayout()
        self.page_icon = QLabel()
        self.page_icon.setObjectName("hostPageIcon")
        self.page_icon.setFixedSize(48, 48)
        self.page_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        heading.addWidget(self.page_icon)

        heading_text = QVBoxLayout()
        heading_text.setSpacing(3)
        title = QLabel("Blocked Hosts")
        title.setObjectName("hostPageTitle")
        subtitle = QLabel("Rules that prevent selected hosts from using the TorProxy route.")
        subtitle.setObjectName("hostPageSubtitle")
        subtitle.setWordWrap(True)
        heading_text.addWidget(title)
        heading_text.addWidget(subtitle)
        heading.addLayout(heading_text, 1)
        self.rule_count = QLabel("0 rules")
        self.rule_count.setObjectName("hostRuleCount")
        heading.addWidget(self.rule_count, 0, Qt.AlignmentFlag.AlignVCenter)
        root.addLayout(heading)

        self.search_box = QLineEdit(self)
        self.search_box.setObjectName("hostSearchBox")
        self.search_box.setPlaceholderText("Search blocked hosts…")
        self.search_box.setClearButtonEnabled(True)
        self.search_box.addAction(
            qta.icon("fa6s.magnifying-glass", color="#8c98a8"),
            QLineEdit.ActionPosition.LeadingPosition,
        )
        self.search_box.textChanged.connect(self._filter_rules)
        root.addWidget(self.search_box)

        self.list_panel = QFrame(self)
        self.list_panel.setObjectName("hostListPanel")
        panel_layout = QVBoxLayout(self.list_panel)
        panel_layout.setContentsMargins(10, 10, 10, 10)
        panel_layout.setSpacing(8)
        self.hosts_list = QListWidget(self.list_panel)
        self.hosts_list.setObjectName("hostRulesList")
        self.hosts_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        self.hosts_list.setUniformItemSizes(True)
        self.hosts_list.setSpacing(3)
        self.hosts_list.setIconSize(self._icon_size())
        self.hosts_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.hosts_list.customContextMenuRequested.connect(self.show_context_menu)
        panel_layout.addWidget(self.hosts_list, 1)
        self.empty_hint = QLabel("No blocked hosts yet. Add a hostname below to create your first rule.")
        self.empty_hint.setObjectName("hostEmptyHint")
        self.empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_hint.setWordWrap(True)
        panel_layout.addWidget(self.empty_hint)
        root.addWidget(self.list_panel, 1)

        add_panel = QFrame(self)
        add_panel.setObjectName("hostAddPanel")
        add_layout = QHBoxLayout(add_panel)
        add_layout.setContentsMargins(12, 10, 12, 10)
        add_layout.setSpacing(10)
        add_copy = QVBoxLayout()
        add_copy.setSpacing(2)
        add_title = QLabel("Add a host rule")
        add_title.setObjectName("hostAddTitle")
        add_desc = QLabel("Enter a domain or host supported by the current rule validator.")
        add_desc.setObjectName("hostPageSubtitle")
        add_desc.setWordWrap(True)
        add_copy.addWidget(add_title)
        add_copy.addWidget(add_desc)
        add_layout.addLayout(add_copy, 1)
        self.inp_host = QLineEdit(add_panel)
        self.inp_host.setObjectName("hostEntry")
        self.inp_host.setPlaceholderText("example.com")
        self.inp_host.setClearButtonEnabled(True)
        self.inp_host.returnPressed.connect(self.add_to_list)
        add_layout.addWidget(self.inp_host, 1)
        self.btn_add = QPushButton("Add rule", add_panel)
        self.btn_add.setObjectName("hostPrimaryButton")
        self.btn_add.setIcon(qta.icon("fa6s.plus", color="#ffffff"))
        self.btn_add.clicked.connect(self.add_to_list)
        add_layout.addWidget(self.btn_add)
        root.addWidget(add_panel)

        self.status_label = QLabel("Changes are saved to the current host-rule list.")
        self.status_label.setObjectName("hostStatusLabel")
        root.addWidget(self.status_label)

        self.apply_theme(CONFIG["mode"])
        self._update_hosts_list()

    @staticmethod
    def _icon_size():
        from PySide6.QtCore import QSize
        return QSize(18, 18)

    def apply_theme(self, mode):
        dark = mode == "dark"
        accent = "#287db5"
        border = "#3b4552" if dark else "#d7dee7"
        panel = "#252c36" if dark else "#ffffff"
        soft = "#202630" if dark else "#f4f7fb"
        text = "#e8edf3" if dark else "#253041"
        muted = "#9ba7b5" if dark else "#657386"
        self.setStyleSheet(f"""
            QLabel#hostPageTitle {{ color: {text}; font-size: 22px; font-weight: 750; background: transparent; }}
            QLabel#hostPageSubtitle, QLabel#hostStatusLabel {{ color: {muted}; font-size: 11px; background: transparent; }}
            QLabel#hostPageIcon {{ background: rgba(40, 125, 181, 0.16); border: 1px solid {border}; border-radius: 13px; }}
            QLabel#hostRuleCount {{ background: {soft}; color: {text}; border: 1px solid {border}; border-radius: 12px; padding: 7px 11px; font-weight: 700; }}
            QLineEdit#hostSearchBox, QLineEdit#hostEntry {{ background: {panel}; color: {text}; border: 1px solid {border}; border-radius: 8px; min-height: 36px; padding: 0 11px; }}
            QLineEdit#hostSearchBox:focus, QLineEdit#hostEntry:focus {{ border-color: {accent}; }}
            QFrame#hostListPanel, QFrame#hostAddPanel {{ background: {panel}; border: 1px solid {border}; border-radius: 12px; }}
            QListWidget#hostRulesList {{ background: transparent; color: {text}; border: none; outline: none; }}
            QListWidget#hostRulesList::item {{ min-height: 34px; padding: 5px 8px; border-radius: 7px; }}
            QListWidget#hostRulesList::item:hover {{ background: rgba(40, 125, 181, 0.10); }}
            QListWidget#hostRulesList::item:selected {{ background: {accent}; color: #ffffff; }}
            QLabel#hostEmptyHint {{ background: transparent; color: {muted}; padding: 12px; }}
            QLabel#hostAddTitle {{ background: transparent; color: {text}; font-weight: 700; }}
            QPushButton#hostPrimaryButton {{ background: {accent}; color: #ffffff; border: none; border-radius: 8px; min-height: 38px; padding: 0 14px; font-weight: 700; }}
            QPushButton#hostPrimaryButton:hover {{ background: #236b9b; }}
            QMenu {{ background: {panel}; color: {text}; border: 1px solid {border}; padding: 5px; }}
            QMenu::item {{ padding: 7px 18px 7px 8px; border-radius: 5px; }}
            QMenu::item:selected {{ background: rgba(40, 125, 181, 0.18); }}
        """)
        self.page_icon.setPixmap(
            qta.icon(self._rule_icon_name, color="#56a8e0" if dark else accent).pixmap(25, 25)
        )
        self.btn_add.setIcon(qta.icon("fa6s.plus", color="#ffffff"))
        self._update_hosts_list_icons()

    def _update_hosts_list_icons(self):
        color = "#8dc8f0" if CONFIG["mode"] == "dark" else "#287db5"
        for index in range(self.hosts_list.count()):
            self.hosts_list.item(index).setIcon(qta.icon(self._rule_icon_name, color=color))

    def _update_hosts_list(self):
        self.hosts_list.clear()
        for host in get_blocked():
            self.hosts_list.addItem(QListWidgetItem(qta.icon(self._rule_icon_name, color="#8dc8f0"), host))
        self._filter_rules(self.search_box.text() if hasattr(self, "search_box") else "")

    def _filter_rules(self, query):
        needle = str(query).strip().casefold()
        total = self.hosts_list.count()
        visible = 0
        for index in range(total):
            item = self.hosts_list.item(index)
            shown = needle in item.text().casefold()
            item.setHidden(not shown)
            visible += int(shown)
        self.rule_count.setText(f"{visible} / {total} rules" if needle else f"{total} rules")
        if total == 0:
            self.empty_hint.setText("No blocked hosts yet. Add a hostname below to create your first rule.")
            self.empty_hint.show()
        elif visible == 0:
            self.empty_hint.setText("No rules match this search. Try another hostname.")
            self.empty_hint.show()
        else:
            self.empty_hint.hide()

    def show_context_menu(self, pos):
        item = self.hosts_list.itemAt(pos)
        if item is None:
            return
        menu = QMenu(self)
        remove_action = menu.addAction(qta.icon("fa6s.trash", color="#d95d67"), "Remove rule")
        chosen = menu.exec(self.hosts_list.mapToGlobal(pos))
        if chosen is remove_action:
            self._confirm_remove(item.text())

    def _confirm_remove(self, host):
        reply = QMessageBox.question(
            self, "Remove blocked host",
            f"Remove '{host}' from blocked hosts?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        remove_blocked(host)
        self._update_hosts_list()
        self.status_label.setText(f"Removed {host}. Saving changes…")
        worker = Worker(save_blocked)
        worker.signals.finished.connect(lambda *_: self.status_label.setText("Blocked-host rules saved."))
        worker.signals.error.connect(lambda error: logger.warning("Could not save blocked hosts: %s", error))
        self.threadpool.start(worker)

    def add_to_list(self):
        host = self.inp_host.text().strip()
        if not host:
            self.status_label.setText("Enter a hostname first.")
            self.inp_host.setFocus()
            return
        try:
            added = add_to_blocked_hosts(host)
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Invalid host rule", str(exc))
            self.inp_host.setFocus()
            return
        if added:
            self._update_hosts_list()
            self.inp_host.clear()
            self.inp_host.setFocus()
            self.status_label.setText(f"Added {host}. Saving changes…")
            worker = Worker(save_blocked)
            worker.signals.finished.connect(lambda *_: self.status_label.setText("Blocked-host rules saved."))
            worker.signals.error.connect(lambda error: logger.warning("Could not save blocked hosts: %s", error))
            self.threadpool.start(worker)
        else:
            self.status_label.setText(f"{host} is already in the blocked-host list.")
