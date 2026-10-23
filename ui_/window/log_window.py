"""Theme-aware embedded event-log drawer for Home."""
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QTextEdit,
    QLabel,
    QSizePolicy,
)
import re

import qtawesome as qta
from PySide6.QtGui import QColor, QTextCharFormat, QTextCursor, QTextFormat


class LogWindow(QWidget):
    """A compact left-side pane; ProxyWindow animates its maximum width."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_ = parent
        self.setObjectName("logsDrawer")
        self.setMinimumWidth(0)
        self.setMinimumHeight(0)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 14, 12, 12)
        layout.setSpacing(10)
        header = QHBoxLayout()

        title = QLabel("EVENT LOG")
        title.setObjectName("logTitle")
        header.addWidget(title)
        header.addStretch(1)

        self.btn_open_tor_log = QPushButton(qta.icon("fa6s.file-lines"), "")
        self.btn_open_tor_log.setObjectName("logIconButton")
        self.btn_open_tor_log.setToolTip("Open the live Tor log file")
        self.btn_open_tor_log.setAccessibleName("Open live Tor log file")
        self.btn_open_tor_log.setFixedSize(30, 30)
        if self.parent_ is not None and hasattr(self.parent_, "open_tor_log_dialog"):
            self.btn_open_tor_log.clicked.connect(self.parent_.open_tor_log_dialog)
        else:
            self.btn_open_tor_log.setEnabled(False)
        header.addWidget(self.btn_open_tor_log)

        self.btn_clear = QPushButton(qta.icon("fa6s.trash"), "")
        self.btn_clear.setObjectName("logIconButton")
        self.btn_clear.setToolTip("Clear logs")
        self.btn_clear.setFixedSize(30, 30)
        self.btn_clear.clicked.connect(self._clear_logs)
        header.addWidget(self.btn_clear)

        self.btn_close = QPushButton(qta.icon("fa6s.xmark"), "")
        self.btn_close.setObjectName("logIconButton")
        self.btn_close.setToolTip("Close event log")
        self.btn_close.setFixedSize(30, 30)
        if self.parent_ is not None and hasattr(self.parent_, "show_logs"):
            self.btn_close.clicked.connect(self.parent_.show_logs)
        else:
            self.btn_close.setEnabled(False)
        header.addWidget(self.btn_close)
        layout.addLayout(header)

        subtitle = QLabel("Live Tor and proxy events")
        subtitle.setObjectName("logSubtitle")
        layout.addWidget(subtitle)

        self.text_edit = QTextEdit(self)
        self.text_edit.setObjectName("logText")
        self.text_edit.setReadOnly(True)
        self.text_edit.document().setMaximumBlockCount(2000)
        self.text_edit.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.text_edit.setPlaceholderText("Events will appear here when TorProxy is active.")
        layout.addWidget(self.text_edit, 1)

    def _clear_logs(self):
        self.text_edit.clear()

    def apply_theme(self, mode):
        dark = mode == "dark"
        self._dark_mode = dark
        surface = "#202630" if dark else "#f7f9fc"
        border = "#394352" if dark else "#dce3eb"
        text = "#e8edf3" if dark else "#253041"
        muted = "#9ba7b5" if dark else "#657386"
        editor = "#171c23" if dark else "#ffffff"
        self.setStyleSheet(f"""
            QWidget#logsDrawer {{ background: {surface}; border-right: 1px solid {border}; }}
            QLabel#logTitle {{ background: transparent; color: {text}; font-size: 11px; font-weight: 800; letter-spacing: 1px; }}
            QLabel#logSubtitle {{ background: transparent; color: {muted}; font-size: 10px; }}
            QTextEdit#logText {{ background: {editor}; color: {text}; border: 1px solid {border}; border-radius: 8px; padding: 8px; font-family: Consolas, 'Cascadia Mono', monospace; font-size: 10px; }}
            QPushButton#logIconButton {{ background: transparent; border: 1px solid {border}; border-radius: 7px; }}
            QPushButton#logIconButton:hover {{ background: rgba(71, 163, 242, 0.14); border-color: #47a3f2; }}
        """)
        self.btn_open_tor_log.setIcon(qta.icon("fa6s.file-lines", color=text))
        self.btn_clear.setIcon(qta.icon("fa6s.trash", color=text))
        self.btn_close.setIcon(qta.icon("fa6s.xmark", color=text))
        self._recolor_existing_logs()

    @staticmethod
    def _message_level(message, level=None):
        """Prefer an explicit logger level, then classify common Tor event prefixes."""
        if level is not None:
            if isinstance(level, int):
                if level >= 50:
                    return "critical"
                if level >= 40:
                    return "error"
                if level >= 30:
                    return "warning"
                if level <= 10:
                    return "debug"
                if level >= 20:
                    return "info"
            normalized = str(level).strip().lower()
            if normalized in {"critical", "fatal"}:
                return "critical"
            if normalized in {"error", "exception"}:
                return "error"
            if normalized in {"warning", "warn"}:
                return "warning"
            if normalized == "debug":
                return "debug"
            if normalized == "success":
                return "success"
            if normalized == "info":
                return "info"

        text = str(message).strip()
        prefix = re.match(
            r"^\s*\[?(DEBUG|INFO|NOTICE|WARN(?:ING)?|ERR(?:OR)?|CRITICAL|FATAL)\]?(?=\s|:|$)",
            text,
            re.I,
        )
        if prefix is None:
            without_tag = re.sub(r"^\s*\[[^]]+\]\s*", "", text)
            prefix = re.match(
                r"^(DEBUG|INFO|NOTICE|WARN(?:ING)?|ERR(?:OR)?|CRITICAL|FATAL)\b",
                without_tag,
                re.I,
            )
        if prefix:
            token = prefix.group(1).lower()
            if token in {"err", "error"}:
                return "error"
            if token in {"warn", "warning"}:
                return "warning"
            if token in {"critical", "fatal"}:
                return "critical"
            if token == "debug":
                return "debug"
            return "info"

        lowered = text.lower()
        if re.search(r"\b(critical|fatal)\b", lowered):
            return "critical"
        if re.search(r"\b(error|err|failed|failure|exception|traceback)\b", lowered) or "could not" in lowered:
            return "error"
        if re.search(r"\b(warning|warn|retrying|retry|rate-limit|rate limit)\b", lowered) or any(
            token in lowered for token in ("not accepted", "not ready")
        ):
            return "warning"
        if any(token in lowered for token in (
            "connected", "connection established", "bootstrap completed", "started successfully",
            "restored.", "proxy enabled", "tor accepted", "successfully"
        )):
            return "success"
        if any(token in lowered for token in ("debug:", "debug ")):
            return "debug"
        return "info"

    def update_log(self, message, level=None):
        """Append plain text with a severity color, without interpreting log text as HTML."""
        text = str(message)
        category = self._message_level(text, level)
        color = self._log_palette().get(category, self._log_palette()["info"])

        fmt = self._format_for_category(category)
        cursor = self.text_edit.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        if not cursor.atStart():
            cursor.insertBlock()
        cursor.insertText(text, fmt)
        self.text_edit.setTextCursor(cursor)
        self.text_edit.ensureCursorVisible()

    def _format_for_category(self, category):
        color = self._log_palette().get(category, self._log_palette()["info"])
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        fmt.setProperty(QTextFormat.Property.UserProperty, category)
        if category in {"error", "critical", "warning", "success"}:
            fmt.setFontWeight(700 if category != "warning" else 600)
        return fmt

    def _recolor_existing_logs(self):
        """Reapply severity colors after light/dark theme changes."""
        block = self.text_edit.document().begin()
        while block.isValid():
            text = block.text()
            if text:
                probe = QTextCursor(block)
                probe.movePosition(QTextCursor.MoveOperation.NextCharacter)
                stored_level = probe.charFormat().property(QTextFormat.Property.UserProperty)
                if not isinstance(stored_level, str) or stored_level not in {
                    "debug", "info", "success", "warning", "error", "critical"
                }:
                    stored_level = self._message_level(text)
                cursor = QTextCursor(block)
                cursor.select(QTextCursor.SelectionType.BlockUnderCursor)
                cursor.mergeCharFormat(self._format_for_category(stored_level))
            block = block.next()

    def _log_palette(self):
        dark = getattr(self, "_dark_mode", True)
        return {
            "debug": "#8793a3" if dark else "#778395",
            "info": "#d6e1ed" if dark else "#344357",
            "success": "#5bd49a" if dark else "#16824b",
            "warning": "#ffc857" if dark else "#a56600",
            "error": "#ff7b82" if dark else "#c62833",
            "critical": "#ff4d5a" if dark else "#a50f1b",
        }
