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
import qtawesome as qta


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
        self.btn_close.clicked.connect(self.parent_.show_logs)
        header.addWidget(self.btn_close)
        layout.addLayout(header)

        subtitle = QLabel("Live Tor and proxy events")
        subtitle.setObjectName("logSubtitle")
        layout.addWidget(subtitle)

        self.text_edit = QTextEdit(self)
        self.text_edit.setObjectName("logText")
        self.text_edit.setReadOnly(True)
        self.text_edit.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.text_edit.setPlaceholderText("Events will appear here when TorProxy is active.")
        layout.addWidget(self.text_edit, 1)

    def _clear_logs(self):
        self.text_edit.clear()

    def apply_theme(self, mode):
        dark = mode == "dark"
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
        self.btn_clear.setIcon(qta.icon("fa6s.trash", color=text))
        self.btn_close.setIcon(qta.icon("fa6s.xmark", color=text))

    def update_log(self, message):
        self.text_edit.append(str(message))
