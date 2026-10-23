"""Live, bounded and paginated viewer for Tor's on-disk log."""
from __future__ import annotations

import logging
import re
from pathlib import Path

import qtawesome as qta
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QTextCharFormat, QTextCursor, QTextFormat
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from torproxy.tor_manager import TorManagerError
from torproxy.log_reader import READ_CHUNK_SIZE, read_log_page_before, read_log_tail
from ui_.window.dialogs import QMessageBox, StandardButton, _FramelessDialog

logger = logging.getLogger(__name__)

DEFAULT_MAX_VISIBLE_LINES = 2000
AVAILABLE_LINE_LIMITS = (500, 1000, 2000, 5000)
PAGE_SIZE = 500
INITIAL_TAIL_LINES = 500
POLL_INTERVAL_MS = 400


class TorLogDialog(_FramelessDialog):
    """Stream the current tor.log file with bounded rendering and older-page loading."""

    def __init__(self, parent: QWidget | None, path: str | Path, manager=None):
        super().__init__(
            parent,
            "Live Tor log",
            "fa6s.file-lines",
            "#287db5",
            width=680,
        )
        self.path = Path(path)
        self.manager = manager
        self.max_visible_lines = DEFAULT_MAX_VISIBLE_LINES
        self._visible_lines: list[tuple[int, str]] = []
        self._stream_offset = 0
        self._older_offset = 0
        self._pending_bytes = b""
        self._pending_start_offset = 0
        self._paused = False
        self._loading_older = False

        # _FramelessDialog provides the shared custom title bar and message styling.
        self.setMinimumSize(760, 480)
        self.setMaximumSize(1600, 1100)
        self.resize(1080, 720)
        self._remember_preferred_size()

        intro = QLabel(
            "This window reads the active Tor log file directly. New lines appear automatically; "
            "older pages can be loaded without expanding the live buffer indefinitely.",
            self.body_host,
        )
        intro.setObjectName("dialogMessage")
        intro.setWordWrap(True)
        self.body_layout.addWidget(intro)

        self.path_label = QLabel(str(self.path), self.body_host)
        self.path_label.setObjectName("torLogPath")
        self.path_label.setWordWrap(True)
        self.path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.body_layout.addWidget(self.path_label)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)
        self.load_older_button = QPushButton("Load older (500)", self.body_host)
        self.load_older_button.setObjectName("torLogAction")
        self.load_older_button.clicked.connect(self.load_older)
        toolbar.addWidget(self.load_older_button)

        self.latest_button = QPushButton("Jump to latest", self.body_host)
        self.latest_button.setObjectName("torLogAction")
        self.latest_button.clicked.connect(self.jump_to_latest)
        toolbar.addWidget(self.latest_button)

        self.stream_button = QPushButton("Pause stream", self.body_host)
        self.stream_button.setObjectName("torLogAction")
        self.stream_button.clicked.connect(self.toggle_stream)
        toolbar.addWidget(self.stream_button)

        toolbar.addStretch(1)
        self.limit_label = QLabel("Visible line limit", self.body_host)
        self.limit_label.setObjectName("torLogMuted")
        toolbar.addWidget(self.limit_label)
        self.limit_combo = QComboBox(self.body_host)
        self.limit_combo.setObjectName("torLogLimit")
        for amount in AVAILABLE_LINE_LIMITS:
            self.limit_combo.addItem(f"{amount:,}", amount)
        self.limit_combo.setCurrentIndex(AVAILABLE_LINE_LIMITS.index(self.max_visible_lines))
        self.limit_combo.currentIndexChanged.connect(self._line_limit_changed)
        toolbar.addWidget(self.limit_combo)
        self.body_layout.addLayout(toolbar)

        self.log_view = QTextEdit(self.body_host)
        self.log_view.setObjectName("torLogText")
        self.log_view.setReadOnly(True)
        self.log_view.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.log_view.setPlaceholderText("Waiting for Tor to create tor.log…")
        self.log_view.setUndoRedoEnabled(False)
        self.body_layout.addWidget(self.log_view, 1)

        self.status_label = QLabel("Opening log file…", self.body_host)
        self.status_label.setObjectName("torLogMuted")
        self.status_label.setWordWrap(True)
        self.body_layout.addWidget(self.status_label)

        self.add_footer_spacer()
        self.clear_button = self.add_button(
            "Clear log history…", primary=False, callback=self.clear_log_history
        )
        self.clear_button.setIcon(qta.icon("fa6s.trash-can", color=self._colors["text"]))
        self.close_button = self.add_button("Close", primary=True, callback=self.accept)

        self.setStyleSheet(self.styleSheet() + f"""
            QLabel#torLogPath {{
                color: {self._colors["muted"]}; background: {self._colors["panel"]};
                border: 1px solid {self._colors["border"]}; border-radius: 7px;
                padding: 8px; font-family: Consolas, 'Cascadia Mono', monospace; font-size: 8pt;
            }}
            QLabel#torLogMuted {{
                color: {self._colors["muted"]}; background: transparent; font-size: 8pt;
            }}
            QComboBox#torLogLimit {{
                color: {self._colors["text"]}; background: {self._colors["panel"]};
                border: 1px solid {self._colors["border"]}; border-radius: 7px;
                padding: 5px 8px; min-height: 25px;
            }}
            QPushButton#torLogAction {{
                color: {self._colors["text"]}; background: {self._colors["panel"]};
                border: 1px solid {self._colors["border"]}; border-radius: 7px;
                padding: 5px 9px; min-height: 28px; font-weight: 600;
            }}
            QPushButton#torLogAction:hover {{
                background: {self._colors["hover"]}; border-color: {self._accent};
            }}
            QPushButton#torLogAction:disabled {{
                color: {self._colors["muted"]}; background: transparent;
            }}
            QTextEdit#torLogText {{
                color: {self._colors["text"]}; background: #111820;
                border: 1px solid {self._colors["border"]}; border-radius: 9px;
                padding: 8px; font-family: Consolas, 'Cascadia Mono', monospace; font-size: 9pt;
                selection-background-color: {self._accent};
            }}
        """)

        self._timer = QTimer(self)
        self._timer.setInterval(POLL_INTERVAL_MS)
        self._timer.timeout.connect(self._poll_file)
        self._initialize_tail()

    def _initialize_tail(self):
        self._visible_lines, self._older_offset, self._stream_offset = read_log_tail(
            self.path, INITIAL_TAIL_LINES
        )
        # The user should see the most recent entries as soon as the popup opens.
        self._trim_visible()
        self._render_all(scroll_to_end=True)
        self._update_pagination_state()
        if self.path.exists():
            self.status_label.setText(
                f"Streaming · {len(self._visible_lines):,} visible lines · "
                f"{self.max_visible_lines:,} line buffer limit"
            )
        else:
            self.status_label.setText("Waiting for Tor to create the log file.")
        self._timer.start()

    @staticmethod
    def _severity(text: str) -> str:
        match = re.search(r"\[(DEBUG|INFO|NOTICE|WARN(?:ING)?|ERR(?:OR)?|CRITICAL|FATAL)\]", text, re.I)
        if match:
            level = match.group(1).lower()
            if level in {"warn", "warning"}:
                return "warning"
            if level in {"err", "error"}:
                return "error"
            if level in {"critical", "fatal"}:
                return "critical"
            if level == "debug":
                return "debug"
            return "info"
        lowered = text.lower()
        if any(word in lowered for word in ("fatal", "critical")):
            return "critical"
        if any(word in lowered for word in ("error", "failed", "failure", "exception", "could not")):
            return "error"
        if any(word in lowered for word in ("warning", "retry", "rate limit")):
            return "warning"
        if "bootstrapped 100%" in lowered or "successfully" in lowered:
            return "success"
        if "bootstrapped" in lowered or "bootstrap" in lowered:
            return "info"
        return "debug" if "[debug]" in lowered else "info"

    def _format_for_line(self, text: str) -> QTextCharFormat:
        palette = {
            "debug": "#8793a3" if self._dark else "#778395",
            "info": "#d6e1ed" if self._dark else "#344357",
            "success": "#5bd49a" if self._dark else "#16824b",
            "warning": "#ffc857" if self._dark else "#a56600",
            "error": "#ff7b82" if self._dark else "#c62833",
            "critical": "#ff4d5a" if self._dark else "#a50f1b",
        }
        category = self._severity(text)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(palette[category]))
        fmt.setProperty(QTextFormat.Property.UserProperty, category)
        if category in {"success", "warning", "error", "critical"}:
            fmt.setFontWeight(700 if category != "warning" else 600)
        return fmt

    def _restore_scroll_position(
        self,
        vertical_value: int,
        horizontal_value: int,
        *,
        follow_bottom: bool = False,
    ):
        """Restore the reader's viewport only after Qt has laid out inserted blocks."""
        def restore():
            vertical = self.log_view.verticalScrollBar()
            horizontal = self.log_view.horizontalScrollBar()
            vertical.setValue(vertical.maximum() if follow_bottom else min(vertical_value, vertical.maximum()))
            horizontal.setValue(min(horizontal_value, horizontal.maximum()))

        QTimer.singleShot(0, restore)

    def _append_line_widget(self, text: str):
        # Use a document cursor, not the QTextEdit's live cursor. setTextCursor()
        # at the end was moving both scroll bars every poll even if the user was
        # reading an older line in the middle of the file.
        cursor = QTextCursor(self.log_view.document())
        cursor.movePosition(QTextCursor.MoveOperation.End)
        if not cursor.atStart():
            cursor.insertBlock()
        cursor.insertText(text, self._format_for_line(text))

    def _render_all(
        self,
        *,
        vertical_value: int | None = None,
        horizontal_value: int | None = None,
        scroll_to_end: bool = False,
        restore_scroll: bool = True,
    ):
        if vertical_value is None:
            vertical_value = self.log_view.verticalScrollBar().value()
        if horizontal_value is None:
            horizontal_value = self.log_view.horizontalScrollBar().value()

        self.log_view.clear()
        cursor = QTextCursor(self.log_view.document())
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        for index, (_offset, text) in enumerate(self._visible_lines):
            if index:
                cursor.insertBlock()
            cursor.insertText(text, self._format_for_line(text))

        if restore_scroll:
            self._restore_scroll_position(
                vertical_value,
                horizontal_value,
                follow_bottom=scroll_to_end,
            )

    def _trim_visible(self):
        if len(self._visible_lines) <= self.max_visible_lines:
            self._update_pagination_state()
            return
        self._visible_lines = self._visible_lines[-self.max_visible_lines:]
        if self._visible_lines:
            self._older_offset = self._visible_lines[0][0]
        self._update_pagination_state()

    def _remove_first_document_lines(self, count: int):
        """Drop old QTextDocument blocks in place instead of rebuilding the whole viewer."""
        document = self.log_view.document()
        removable = min(max(0, int(count)), max(0, document.blockCount() - 1))
        for _ in range(removable):
            cursor = QTextCursor(document)
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.select(QTextCursor.SelectionType.BlockUnderCursor)
            cursor.removeSelectedText()
            cursor.deleteChar()

    def _update_pagination_state(self):
        exhausted = self._older_offset <= 0
        full = len(self._visible_lines) >= self.max_visible_lines
        self.load_older_button.setEnabled(not exhausted and not full)
        self.load_older_button.setText(
            "Maximum reached" if full else "No older lines" if exhausted else "Load older (500)"
        )

    def _update_status(self, prefix: str = "Streaming"):
        state = "paused" if self._paused else prefix
        file_size = 0
        try:
            file_size = self.path.stat().st_size
        except OSError:
            pass
        self.status_label.setText(
            f"{state} · {len(self._visible_lines):,}/{self.max_visible_lines:,} lines visible · "
            f"{file_size:,} bytes in file"
        )
        self._update_pagination_state()

    def _poll_file(self):
        if self._paused:
            return
        try:
            file_size = self.path.stat().st_size
        except FileNotFoundError:
            self.status_label.setText("Waiting for Tor to create the log file.")
            return
        except OSError as exc:
            self.status_label.setText(f"Cannot read the Tor log: {exc}")
            return

        if file_size < self._stream_offset:
            # The active log was cleared or truncated while this dialog was open.
            old_vertical = self.log_view.verticalScrollBar().value()
            old_horizontal = self.log_view.horizontalScrollBar().value()
            self._visible_lines = []
            self._pending_bytes = b""
            self._pending_start_offset = 0
            self._older_offset = 0
            self._stream_offset = 0
            self._render_all(
                vertical_value=old_vertical,
                horizontal_value=old_horizontal,
                scroll_to_end=False,
            )

        try:
            with self.path.open("rb") as handle:
                handle.seek(self._stream_offset)
                chunk = handle.read(READ_CHUNK_SIZE * 4)
                new_offset = handle.tell()
        except OSError as exc:
            self.status_label.setText(f"Cannot read the Tor log: {exc}")
            return
        if not chunk:
            self._update_status()
            return

        initial_offset = self._pending_start_offset if self._pending_bytes else self._stream_offset
        payload = self._pending_bytes + chunk
        parts = payload.split(b"\n")
        self._pending_bytes = parts.pop() if parts else b""
        position = initial_offset
        new_lines: list[tuple[int, str]] = []
        for raw_line in parts:
            new_lines.append((position, raw_line.rstrip(b"\r").decode("utf-8", errors="replace")))
            position += len(raw_line) + 1
        self._pending_start_offset = position
        self._stream_offset = new_offset

        if new_lines:
            vertical = self.log_view.verticalScrollBar()
            horizontal = self.log_view.horizontalScrollBar()
            old_vertical = vertical.value()
            old_horizontal = horizontal.value()
            old_maximum = vertical.maximum()
            was_at_bottom = old_vertical >= old_maximum - 2

            self._visible_lines.extend(new_lines)
            removed_lines = max(0, len(self._visible_lines) - self.max_visible_lines)
            if removed_lines:
                # Keep the widget live: append fresh rows and delete only the
                # overflow at the top. Re-rendering the full document on every
                # saturated poll was causing visible jumps and horizontal shifts.
                del self._visible_lines[:removed_lines]
                if self._visible_lines:
                    self._older_offset = self._visible_lines[0][0]
            for _line_offset, text in new_lines:
                self._append_line_widget(text)
            if removed_lines:
                self._remove_first_document_lines(removed_lines)
            line_height = max(1, self.log_view.fontMetrics().lineSpacing())
            preserved_vertical = max(0, old_vertical - removed_lines * line_height)
            self._restore_scroll_position(
                preserved_vertical,
                old_horizontal,
                follow_bottom=was_at_bottom,
            )
            self._update_pagination_state()
        self._update_status()

    def load_older(self):
        if self._loading_older or self._older_offset <= 0:
            return
        remaining = self.max_visible_lines - len(self._visible_lines)
        if remaining <= 0:
            self._update_pagination_state()
            return
        self._loading_older = True
        try:
            amount = min(PAGE_SIZE, remaining)
            older, start_offset = read_log_page_before(self.path, self._older_offset, amount)
            if not older:
                self._older_offset = 0
                self._update_pagination_state()
                self.status_label.setText("No older log entries are available.")
                return
            scrollbar = self.log_view.verticalScrollBar()
            horizontal = self.log_view.horizontalScrollBar()
            old_value = scrollbar.value()
            old_maximum = scrollbar.maximum()
            old_horizontal = horizontal.value()
            self._visible_lines = older + self._visible_lines
            self._older_offset = start_offset
            self._trim_visible()
            self._render_all(restore_scroll=False)
            def preserve_reading_position():
                new_scrollbar = self.log_view.verticalScrollBar()
                new_scrollbar.setValue(
                    min(old_value + (new_scrollbar.maximum() - old_maximum), new_scrollbar.maximum())
                )
                self.log_view.horizontalScrollBar().setValue(
                    min(old_horizontal, self.log_view.horizontalScrollBar().maximum())
                )
            QTimer.singleShot(0, preserve_reading_position)
            self._update_status("Loaded older entries · streaming")
        finally:
            self._loading_older = False

    def jump_to_latest(self):
        self._visible_lines, self._older_offset, self._stream_offset = read_log_tail(
            self.path, self.max_visible_lines
        )
        self._pending_bytes = b""
        self._pending_start_offset = self._stream_offset
        self._render_all(scroll_to_end=True)
        self._update_status()

    def toggle_stream(self):
        self._paused = not self._paused
        if self._paused:
            self._timer.stop()
            self.stream_button.setText("Resume stream")
            self.status_label.setText("Paused · new file data will be read when streaming resumes.")
        else:
            self._timer.start()
            self.stream_button.setText("Pause stream")
            self._poll_file()
            self._update_status()

    def _line_limit_changed(self, _index: int):
        value = self.limit_combo.currentData()
        if type(value) is not int or value not in AVAILABLE_LINE_LIMITS:
            return
        self.max_visible_lines = value
        self._trim_visible()
        self._render_all()
        self._update_status()

    def clear_log_history(self):
        answer = QMessageBox.question(
            self,
            "Clear Tor log history",
            "Clear the contents of the current tor.log file? This removes the previous on-disk Tor log entries. "
            "New entries will continue to stream into this window while Tor is running.",
            buttons=QMessageBox.Yes | QMessageBox.No,
            defaultButton=QMessageBox.No,
        )
        if answer != StandardButton.Yes:
            return

        try:
            if self.manager is not None and hasattr(self.manager, "clear_log_file"):
                self.manager.clear_log_file()
            else:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("wb"):
                    pass
        except (OSError, TorManagerError) as exc:
            logger.exception("Could not clear the active Tor log file.")
            QMessageBox.warning(self, "Could not clear Tor log", str(exc))
            return

        self._visible_lines.clear()
        self._pending_bytes = b""
        self._pending_start_offset = 0
        try:
            self._stream_offset = self.path.stat().st_size
        except OSError:
            self._stream_offset = 0
        self._older_offset = 0
        self._render_all(vertical_value=0, horizontal_value=0)
        self._update_status("Tor log history cleared · streaming")
        self._update_pagination_state()

    def done(self, result: int):
        if hasattr(self, "_timer"):
            self._timer.stop()
        super().done(result)
