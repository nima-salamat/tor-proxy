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
from ui_.window.dialogs import QMessageBox, StandardButton, _FramelessDialog

logger = logging.getLogger(__name__)

DEFAULT_MAX_VISIBLE_LINES = 2000
AVAILABLE_LINE_LIMITS = (500, 1000, 2000, 5000)
PAGE_SIZE = 500
INITIAL_TAIL_LINES = 500
POLL_INTERVAL_MS = 400
READ_CHUNK_SIZE = 16 * 1024


def _line_records(
    data: bytes,
    absolute_start: int,
    *,
    drop_partial_first: bool,
) -> list[tuple[int, str]]:
    """Split UTF-8 log bytes into lines while retaining each line's file offset."""
    parts = data.split(b"\n")
    positions: list[int] = []
    position = absolute_start
    for part in parts:
        positions.append(position)
        position += len(part) + 1

    if data.endswith(b"\n") and parts:
        parts.pop()
        positions.pop()
    if drop_partial_first and parts:
        parts.pop(0)
        positions.pop(0)

    return [
        (line_offset, raw.rstrip(b"\r").decode("utf-8", errors="replace"))
        for line_offset, raw in zip(positions, parts)
        if raw
    ]


def read_log_tail(path: Path, line_count: int) -> tuple[list[tuple[int, str]], int, int]:
    """Return a bounded tail, its first line offset, and the current file size."""
    try:
        size = path.stat().st_size
        cursor = size
        chunks: list[bytes] = []
        newline_count = 0
        while cursor > 0 and newline_count <= line_count:
            take = min(READ_CHUNK_SIZE, cursor)
            cursor -= take
            with path.open("rb") as handle:
                handle.seek(cursor)
                chunk = handle.read(take)
            chunks.insert(0, chunk)
            newline_count += chunk.count(b"\n")
        data = b"".join(chunks)
        lines = _line_records(data, cursor, drop_partial_first=cursor > 0)
        visible = lines[-max(1, int(line_count)):]
        first_offset = visible[0][0] if visible else size
        return visible, first_offset, size
    except FileNotFoundError:
        return [], 0, 0


def read_log_page_before(
    path: Path,
    before_offset: int,
    line_count: int = PAGE_SIZE,
) -> tuple[list[tuple[int, str]], int]:
    """Read a page immediately older than an existing line offset."""
    try:
        size = path.stat().st_size
        cursor = min(max(0, int(before_offset)), size)
        chunks: list[bytes] = []
        newline_count = 0
        while cursor > 0 and newline_count <= line_count:
            take = min(READ_CHUNK_SIZE, cursor)
            cursor -= take
            with path.open("rb") as handle:
                handle.seek(cursor)
                chunk = handle.read(take)
            chunks.insert(0, chunk)
            newline_count += chunk.count(b"\n")
        data = b"".join(chunks)
        lines = _line_records(data, cursor, drop_partial_first=cursor > 0)
        page = lines[-max(1, int(line_count)):]
        start_offset = page[0][0] if page else cursor
        return page, start_offset
    except FileNotFoundError:
        return [], 0


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
        self._render_all()
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

    def _append_line_widget(self, text: str):
        cursor = self.log_view.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        if not cursor.atStart():
            cursor.insertBlock()
        cursor.insertText(text, self._format_for_line(text))
        self.log_view.setTextCursor(cursor)

    def _render_all(self):
        self.log_view.clear()
        cursor = self.log_view.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        for index, (_offset, text) in enumerate(self._visible_lines):
            if index:
                cursor.insertBlock()
            cursor.insertText(text, self._format_for_line(text))
        self.log_view.setTextCursor(cursor)
        self.log_view.ensureCursorVisible()

    def _trim_visible(self):
        if len(self._visible_lines) <= self.max_visible_lines:
            self._update_pagination_state()
            return
        self._visible_lines = self._visible_lines[-self.max_visible_lines:]
        if self._visible_lines:
            self._older_offset = self._visible_lines[0][0]
        self._update_pagination_state()

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
            self._visible_lines = []
            self._pending_bytes = b""
            self._pending_start_offset = 0
            self._older_offset = 0
            self._stream_offset = 0
            self._render_all()

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
            scrollbar = self.log_view.verticalScrollBar()
            was_at_bottom = scrollbar.value() >= scrollbar.maximum() - 2
            self._visible_lines.extend(new_lines)
            before_trim = len(self._visible_lines)
            self._trim_visible()
            if before_trim > len(self._visible_lines):
                self._render_all()
            else:
                for _line_offset, text in new_lines:
                    self._append_line_widget(text)
            if was_at_bottom:
                scrollbar.setValue(scrollbar.maximum())
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
            old_value = scrollbar.value()
            old_maximum = scrollbar.maximum()
            self._visible_lines = older + self._visible_lines
            self._older_offset = start_offset
            self._trim_visible()
            self._render_all()
            scrollbar.setValue(old_value + (scrollbar.maximum() - old_maximum))
            self._update_status("Loaded older entries · streaming")
        finally:
            self._loading_older = False

    def jump_to_latest(self):
        self._visible_lines, self._older_offset, self._stream_offset = read_log_tail(
            self.path, self.max_visible_lines
        )
        self._pending_bytes = b""
        self._pending_start_offset = self._stream_offset
        self._render_all()
        self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())
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
        self._render_all()
        self._update_status("Tor log history cleared · streaming")
        self._update_pagination_state()

    def done(self, result: int):
        if hasattr(self, "_timer"):
            self._timer.stop()
        super().done(result)
