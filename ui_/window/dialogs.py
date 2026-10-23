"""Shared custom frameless message dialogs for the desktop application.

All message prompts use the same layout, typography, theme, controls, and
keyboard behavior, regardless of which page raises the prompt.
"""
from __future__ import annotations

from enum import IntFlag

import qtawesome as qta
from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from config import CONFIG


class StandardButton(IntFlag):
    NoButton = 0
    Ok = 1
    Yes = 2
    No = 4
    Cancel = 8


class QMessageBox:
    """Drop-in subset of QMessageBox's static API backed by custom dialogs."""

    StandardButton = StandardButton
    NoButton = StandardButton.NoButton
    Ok = StandardButton.Ok
    Yes = StandardButton.Yes
    No = StandardButton.No
    Cancel = StandardButton.Cancel

    @staticmethod
    def information(parent, title, text, buttons=StandardButton.Ok, defaultButton=StandardButton.Ok):
        dialog = MessageDialog(parent, title, text, level="info")
        dialog.exec()
        return StandardButton.Ok

    @staticmethod
    def warning(parent, title, text, buttons=StandardButton.Ok, defaultButton=StandardButton.Ok):
        dialog = MessageDialog(parent, title, text, level="warning")
        dialog.exec()
        return StandardButton.Ok

    @staticmethod
    def critical(parent, title, text, buttons=StandardButton.Ok, defaultButton=StandardButton.Ok):
        dialog = MessageDialog(parent, title, text, level="critical")
        dialog.exec()
        return StandardButton.Ok

    @staticmethod
    def question(
        parent,
        title,
        text,
        buttons=StandardButton.Yes | StandardButton.No,
        defaultButton=StandardButton.No,
    ):
        dialog = MessageDialog(
            parent, title, text, level="question", question=True, default_button=defaultButton
        )
        dialog.exec()
        return dialog.choice


class DialogTitleBar(QWidget):
    """Small draggable title strip for custom dialogs."""

    def __init__(self, dialog: QDialog, title: str, icon_name: str, accent: str):
        super().__init__(dialog)
        self._dialog = dialog
        self._drag_origin: QPoint | None = None
        self._window_origin: QPoint | None = None
        self.setObjectName("dialogTitleBar")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 12, 12, 10)
        layout.setSpacing(10)

        self.icon = QLabel(self)
        self.icon.setFixedSize(22, 22)
        self.icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon.setPixmap(qta.icon(icon_name, color=accent).pixmap(20, 20))
        layout.addWidget(self.icon)

        self.title = QLabel(title, self)
        self.title.setObjectName("dialogTitle")
        self.title.setWordWrap(False)
        self.title.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        layout.addWidget(self.title, 1)

        self.close_button = QPushButton(self)
        self.close_button.setObjectName("dialogCloseButton")
        self.close_button.setFixedSize(30, 28)
        self.close_button.setIcon(qta.icon("fa6s.xmark", color=accent))
        self.close_button.setToolTip("Close")
        self.close_button.clicked.connect(dialog.reject)
        layout.addWidget(self.close_button)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            handle = self._dialog.windowHandle()
            if handle is not None:
                try:
                    if handle.startSystemMove():
                        event.accept()
                        return
                except (AttributeError, RuntimeError):
                    pass
            self._drag_origin = event.globalPosition().toPoint()
            self._window_origin = self._dialog.pos()
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if (
            self._drag_origin is not None
            and self._window_origin is not None
            and event.buttons() & Qt.MouseButton.LeftButton
        ):
            self._dialog.move(
                self._window_origin + event.globalPosition().toPoint() - self._drag_origin
            )
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        self._drag_origin = None
        self._window_origin = None
        super().mouseReleaseEvent(event)


class _FramelessDialog(QDialog):
    """Reusable custom shell shared by message prompts and shortcuts."""

    def __init__(
        self,
        parent: QWidget | None,
        title: str,
        icon_name: str,
        accent: str,
        *,
        width: int = 480,
    ):
        super().__init__(parent)
        dark = CONFIG["mode"] == "dark"
        self._dark = dark
        self._accent = accent
        self._colors = {
            "surface": "#202630" if dark else "#ffffff",
            "panel": "#252c36" if dark else "#f6f8fb",
            "border": "#3b4552" if dark else "#d7dee7",
            "text": "#e8edf3" if dark else "#253041",
            "muted": "#9ba7b5" if dark else "#657386",
            "hover": "rgba(71, 163, 242, 0.13)" if dark else "rgba(24, 118, 191, 0.09)",
        }
        self.setWindowTitle(title)
        self.setWindowModality(Qt.WindowModality.WindowModal if parent is not None else Qt.WindowModality.ApplicationModal)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        self.setMinimumWidth(width)
        self.setMaximumWidth(680)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.surface = QFrame(self)
        self.surface.setObjectName("dialogSurface")
        root.addWidget(self.surface)
        surface_layout = QVBoxLayout(self.surface)
        surface_layout.setContentsMargins(0, 0, 0, 0)
        surface_layout.setSpacing(0)

        self.title_bar = DialogTitleBar(self, title, icon_name, accent)
        surface_layout.addWidget(self.title_bar)

        self.body_host = QWidget(self.surface)
        self.body_host.setObjectName("dialogBody")
        self.body_layout = QVBoxLayout(self.body_host)
        self.body_layout.setContentsMargins(22, 18, 22, 16)
        self.body_layout.setSpacing(12)
        surface_layout.addWidget(self.body_host, 1)

        self.footer = QWidget(self.surface)
        self.footer.setObjectName("dialogFooter")
        self.footer_layout = QHBoxLayout(self.footer)
        self.footer_layout.setContentsMargins(20, 10, 20, 16)
        self.footer_layout.setSpacing(9)
        surface_layout.addWidget(self.footer)

        self.setStyleSheet(f"""
            QDialog {{ background: transparent; color: {self._colors["text"]}; }}
            QFrame#dialogSurface {{
                background: {self._colors["surface"]};
                border: 1px solid {self._colors["border"]};
                border-radius: 14px;
            }}
            QWidget#dialogTitleBar {{
                background: {self._colors["surface"]};
                border-bottom: 1px solid {self._colors["border"]};
                border-top-left-radius: 14px;
                border-top-right-radius: 14px;
            }}
            QLabel#dialogTitle {{
                color: {self._colors["text"]};
                font-size: 14px;
                font-weight: 750;
                background: transparent;
            }}
            QPushButton#dialogCloseButton {{
                background: transparent;
                color: {self._colors["text"]};
                border: none;
                border-radius: 7px;
            }}
            QPushButton#dialogCloseButton:hover {{ background: {self._colors["hover"]}; }}
            QWidget#dialogBody {{ background: {self._colors["surface"]}; }}
            QWidget#dialogFooter {{
                background: {self._colors["surface"]};
                border-top: 1px solid {self._colors["border"]};
                border-bottom-left-radius: 14px;
                border-bottom-right-radius: 14px;
            }}
            QLabel#dialogMessage {{ color: {self._colors["text"]}; background: transparent; font-size: 12px; }}
            QLabel#dialogHint {{ color: {self._colors["muted"]}; background: transparent; font-size: 11px; }}
            QLabel#shortcutCategory {{
                color: {self._accent};
                background: transparent;
                font-size: 11px;
                font-weight: 800;
                padding-top: 5px;
            }}
            QLabel#shortcutName {{ color: {self._colors["text"]}; background: transparent; font-size: 12px; }}
            QLabel#shortcutDescription {{ color: {self._colors["muted"]}; background: transparent; font-size: 10px; }}
            QLabel#shortcutKey {{
                color: {self._colors["text"]};
                background: {self._colors["panel"]};
                border: 1px solid {self._colors["border"]};
                border-bottom: 2px solid {self._colors["border"]};
                border-radius: 5px;
                padding: 4px 7px;
                min-width: 18px;
                font-size: 10px;
                font-weight: 750;
            }}
            QPushButton#dialogPrimaryButton {{
                background: {self._accent}; color: #ffffff;
                border: 1px solid {self._accent}; border-radius: 8px;
                min-height: 34px; padding: 0 18px; font-weight: 750;
            }}
            QPushButton#dialogPrimaryButton:hover {{ background: #236b9b; }}
            QPushButton#dialogSecondaryButton {{
                background: {self._colors["panel"]}; color: {self._colors["text"]};
                border: 1px solid {self._colors["border"]}; border-radius: 8px;
                min-height: 34px; padding: 0 16px; font-weight: 650;
            }}
            QPushButton#dialogSecondaryButton:hover {{ background: {self._colors["hover"]}; }}
            QScrollArea#dialogScroll {{ background: transparent; border: none; }}
            QScrollArea#dialogScroll QWidget {{ background: transparent; }}
            QCheckBox#dontAskAgain {{ color: {self._colors["text"]}; background: transparent; spacing: 8px; font-size: 11px; }}
            QCheckBox#dontAskAgain::indicator {{ width: 16px; height: 16px; border: 1px solid {self._colors["border"]}; border-radius: 4px; background: {self._colors["panel"]}; }}
            QCheckBox#dontAskAgain::indicator:checked {{ background: {self._accent}; border-color: {self._accent}; }}
        """)

    def add_footer_spacer(self):
        self.footer_layout.addStretch(1)

    def add_button(self, text: str, *, primary: bool, callback):
        button = QPushButton(text, self.footer)
        button.setObjectName("dialogPrimaryButton" if primary else "dialogSecondaryButton")
        button.clicked.connect(callback)
        if primary:
            button.setDefault(True)
            button.setAutoDefault(True)
        self.footer_layout.addWidget(button)
        return button

    def showEvent(self, event):
        super().showEvent(event)
        if self.parentWidget() is not None:
            center = self.parentWidget().mapToGlobal(self.parentWidget().rect().center())
            self.move(center - self.rect().center())
        else:
            screen = QApplication.primaryScreen()
            if screen is not None:
                area = screen.availableGeometry()
                self.move(area.center() - self.rect().center())


class MessageDialog(_FramelessDialog):
    """A consistent, themed replacement for QMessageBox."""

    _LEVELS = {
        "info": ("fa6s.circle-info", "#287db5"),
        "warning": ("fa6s.triangle-exclamation", "#d97706"),
        "critical": ("fa6s.circle-xmark", "#dc3545"),
        "question": ("fa6s.circle-question", "#287db5"),
    }

    def __init__(
        self,
        parent,
        title,
        message,
        *,
        level="info",
        question=False,
        default_button=StandardButton.No,
    ):
        icon_name, accent = self._LEVELS.get(level, self._LEVELS["info"])
        super().__init__(parent, str(title), icon_name, accent, width=460)
        self.choice = StandardButton.No if question else StandardButton.Ok
        self._question = question
        self._default_button = default_button

        message_label = QLabel(str(message), self.body_host)
        message_label.setObjectName("dialogMessage")
        message_label.setWordWrap(True)
        message_label.setTextFormat(Qt.TextFormat.PlainText)
        message_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        message_label.setMinimumWidth(390)
        message_label.setMaximumWidth(620)
        if len(str(message)) > 420:
            scroll = QScrollArea(self.body_host)
            scroll.setObjectName("dialogScroll")
            scroll.setWidgetResizable(True)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            scroll.setMaximumHeight(260)
            content = QWidget(scroll)
            content_layout = QVBoxLayout(content)
            content_layout.setContentsMargins(0, 0, 0, 0)
            content_layout.addWidget(message_label)
            scroll.setWidget(content)
            self.body_layout.addWidget(scroll)
        else:
            self.body_layout.addWidget(message_label)

        if question:
            self.add_footer_spacer()
            no_button = self.add_button("No", primary=False, callback=self._choose_no)
            yes_button = self.add_button("Yes", primary=True, callback=self._choose_yes)
            if default_button == StandardButton.No:
                no_button.setDefault(True)
                no_button.setFocus()
                yes_button.setAutoDefault(False)
            else:
                yes_button.setDefault(True)
                yes_button.setFocus()
                no_button.setAutoDefault(False)
            self.setMinimumHeight(170)
        else:
            self.add_footer_spacer()
            self.add_button("Got it", primary=True, callback=self.accept)
            self.setMinimumHeight(150)

        self.adjustSize()

    def _choose_yes(self):
        self.choice = StandardButton.Yes
        self.accept()

    def _choose_no(self):
        self.choice = StandardButton.No
        self.reject()

    def reject(self):
        if self._question:
            self.choice = StandardButton.No
        super().reject()



class ExitConfirmDialog(MessageDialog):
    """Custom exit confirmation with a persistent do-not-ask-again option."""

    def __init__(self, parent=None):
        super().__init__(
            parent,
            "Exit TorProxy",
            "Exit TorProxy now? Active Tor and proxy services will be stopped.",
            level="question",
            question=True,
            default_button=StandardButton.No,
        )
        self.dont_ask_checkbox = QCheckBox("Don't ask me again", self.body_host)
        self.dont_ask_checkbox.setObjectName("dontAskAgain")
        self.dont_ask_checkbox.setToolTip(
            "Save this choice. You can turn the exit confirmation back on in Settings."
        )
        self.body_layout.addWidget(self.dont_ask_checkbox)
        self.adjustSize()
