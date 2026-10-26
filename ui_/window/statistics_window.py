"""Live proxy traffic statistics and session-local charts."""
from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass

import qtawesome as qta
from PySide6.QtCore import Qt, QTimer, QPointF, QRectF
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from config import CONFIG
from proxy import get_traffic_direction_snapshot


def _safe_non_negative_int(value) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def format_bytes(value: float, *, per_second: bool = False) -> str:
    value = max(0.0, float(value))
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    unit_index = 0
    while value >= 1024.0 and unit_index < len(units) - 1:
        value /= 1024.0
        unit_index += 1
    if unit_index == 0:
        formatted = f"{value:.0f} {units[unit_index]}"
    elif value >= 100:
        formatted = f"{value:.0f} {units[unit_index]}"
    elif value >= 10:
        formatted = f"{value:.1f} {units[unit_index]}"
    else:
        formatted = f"{value:.2f} {units[unit_index]}"
    return formatted + ("/s" if per_second else "")


def _nice_axis_max(value: float) -> float:
    if value <= 0:
        return 1.0
    power = 10 ** math.floor(math.log10(value))
    scaled = value / power
    factor = 1 if scaled <= 1 else 2 if scaled <= 2 else 5 if scaled <= 5 else 10
    return factor * power


@dataclass(frozen=True, slots=True)
class _TrafficSample:
    timestamp: float
    total_bytes: int
    upload_bytes: int
    download_bytes: int
    bytes_per_second: float


class TrafficChart(QWidget):
    """Small native Qt chart; avoids a heavyweight plotting dependency."""

    def __init__(self, chart_kind: str, parent=None):
        super().__init__(parent)
        self.chart_kind = chart_kind
        self._samples: list[_TrafficSample] = []
        self._dark = True
        self.setMinimumHeight(205)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)

    def set_samples(self, samples: list[_TrafficSample]) -> None:
        self._samples = samples
        self.update()

    def apply_theme(self, mode: str) -> None:
        self._dark = mode == "dark"
        self.update()

    def _colors(self):
        if self._dark:
            return (
                QColor("#272f3b"),
                QColor("#526174"),
                QColor("#afbac9"),
                QColor("#52a8f5"),
                QColor("#79d6b0"),
            )
        return (
            QColor("#ffffff"),
            QColor("#dce3eb"),
            QColor("#68778a"),
            QColor("#167ac6"),
            QColor("#188b68"),
        )

    def _chart_values(self, now: float) -> list[float]:
        if self.chart_kind == "rate":
            return [sample.bytes_per_second for sample in self._samples[-60:]]
        buckets = [0.0] * 60
        for sample in self._samples:
            minutes_ago = int(max(0.0, now - sample.timestamp) // 60)
            if minutes_ago < 60:
                buckets[59 - minutes_ago] += sample.total_bytes
        return buckets

    def paintEvent(self, event) -> None:
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        _background, grid_color, text_color, accent, _download_color = self._colors()
        rect = self.rect()
        plot = QRectF(56, 10, max(1, rect.width() - 70), max(1, rect.height() - 49))
        if plot.width() < 80 or plot.height() < 60:
            painter.end()
            return

        samples = self._samples
        now = samples[-1].timestamp if samples else time.monotonic()
        values = self._chart_values(now)
        max_value = _nice_axis_max(max(values, default=0.0))
        painter.setFont(QFont(self.font().family(), 8))
        painter.setPen(QPen(grid_color, 1))
        painter.setBrush(Qt.BrushStyle.NoBrush)

        for tick in range(5):
            ratio = tick / 4
            y = plot.bottom() - plot.height() * ratio
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            value = max_value * ratio
            label = format_bytes(value, per_second=self.chart_kind == "rate")
            painter.setPen(text_color)
            painter.drawText(
                QRectF(0, y - 9, 49, 18),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                label,
            )
            painter.setPen(QPen(grid_color, 1))

        if self.chart_kind == "rate":
            visible = self._samples[-60:]
            if not visible or max(sample.bytes_per_second for sample in visible) <= 0:
                painter.setPen(text_color)
                painter.drawText(
                    plot,
                    Qt.AlignmentFlag.AlignCenter,
                    "Waiting for proxied traffic…",
                )
            elif len(visible) == 1:
                y = plot.bottom() - (visible[0].bytes_per_second / max_value) * plot.height()
                painter.setPen(QPen(accent, 2))
                painter.drawPoint(QPointF(plot.center().x(), y))
            else:
                path = QPainterPath()
                for index, sample in enumerate(visible):
                    x = plot.left() + (plot.width() * index / (len(visible) - 1))
                    y = plot.bottom() - (sample.bytes_per_second / max_value) * plot.height()
                    if index == 0:
                        path.moveTo(x, y)
                    else:
                        path.lineTo(x, y)
                painter.setPen(QPen(accent, 2.4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
                painter.drawPath(path)
                last = visible[-1]
                last_y = plot.bottom() - (last.bytes_per_second / max_value) * plot.height()
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(accent)
                painter.drawEllipse(QPointF(plot.right(), last_y), 3.2, 3.2)
        else:
            painter.setPen(Qt.PenStyle.NoPen)
            for index, value in enumerate(values):
                slot = plot.width() / max(1, len(values))
                bar_width = max(1.0, slot * 0.62)
                height = plot.height() * (value / max_value)
                x = plot.left() + slot * index + (slot - bar_width) / 2
                y = plot.bottom() - height
                painter.setBrush(accent if index < len(values) - 1 else QColor("#79d6b0" if self._dark else "#188b68"))
                painter.drawRoundedRect(QRectF(x, y, bar_width, max(0.0, height)), 2.0, 2.0)
            if not any(values):
                painter.setPen(text_color)
                painter.drawText(
                    plot,
                    Qt.AlignmentFlag.AlignCenter,
                    "No traffic recorded in this window",
                )

        painter.setPen(text_color)
        labels = (
            ("60 s ago", "30 s", "now")
            if self.chart_kind == "rate"
            else ("60 min ago", "30 min", "now")
        )
        for pos, label in zip((plot.left(), plot.center().x(), plot.right()), labels):
            painter.drawText(
                QRectF(pos - 45, plot.bottom() + 7, 90, 17),
                Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                label,
            )
        painter.end()


class StatisticsWindow(QWidget):
    """Statistics page for persisted aggregate traffic and live session telemetry."""

    def __init__(self, proxy_widget, parent=None):
        super().__init__(parent)
        self.proxy_widget = proxy_widget
        self._owner = parent
        self.setObjectName("statisticsPage")
        self._dark = CONFIG["mode"] == "dark"
        self._started_at = time.monotonic()
        self._last_sample_at = self._started_at
        self._last_total_bytes = self._read_total_bytes()
        self._last_directions = self._read_directions()
        self._session_upload = 0
        self._session_download = 0
        self._current_rate = 0.0
        self._peak_rate = 0.0
        self._samples: deque[_TrafficSample] = deque(maxlen=3600)
        self._samples.append(_TrafficSample(self._started_at, 0, 0, 0, 0.0))
        self.metric_values: dict[str, QLabel] = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 20)
        root.setSpacing(12)

        header = QHBoxLayout()
        header.setSpacing(12)
        self.back_button = QPushButton("Back to Home", self)
        self.back_button.setObjectName("statisticsBackButton")
        self.back_button.setIcon(qta.icon("fa6s.arrow-left"))
        self.back_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.back_button.clicked.connect(self._back_home)
        header.addWidget(self.back_button, 0, Qt.AlignmentFlag.AlignLeft)

        title_column = QVBoxLayout()
        title_column.setSpacing(2)
        self.title_label = QLabel("Traffic statistics")
        self.title_label.setObjectName("statisticsTitle")
        self.subtitle_label = QLabel("Live proxy accounting · session history and throughput")
        self.subtitle_label.setObjectName("statisticsSubtle")
        title_column.addWidget(self.title_label)
        title_column.addWidget(self.subtitle_label)
        header.addLayout(title_column, 1)

        self.connection_state = QLabel()
        self.connection_state.setObjectName("statisticsConnectionState")
        self.connection_state.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        header.addWidget(self.connection_state)
        root.addLayout(header)

        metrics_grid = QGridLayout()
        metrics_grid.setContentsMargins(0, 0, 0, 0)
        metrics_grid.setHorizontalSpacing(12)
        metrics_grid.setVerticalSpacing(10)
        metric_specs = (
            ("lifetime", "TOTAL TRAFFIC", "Persisted across launches"),
            ("session", "THIS RUN", "Since this app started"),
            ("upload", "UPLOADED", "Client → upstream · this run"),
            ("download", "DOWNLOADED", "Upstream → client · this run"),
            ("current", "CURRENT RATE", "Approximate · 1-second samples"),
            ("peak", "PEAK RATE", "Highest observed this run"),
        )
        for index, (key, caption_text, hint_text) in enumerate(metric_specs):
            card = QFrame(self)
            card.setObjectName("statisticsMetricCard")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(14, 11, 14, 10)
            card_layout.setSpacing(3)
            caption = QLabel(caption_text, card)
            caption.setObjectName("statisticsMetricCaption")
            value = QLabel("0 B", card)
            value.setObjectName("statisticsMetricValue")
            value.setMinimumWidth(0)
            hint = QLabel(hint_text, card)
            hint.setObjectName("statisticsMetricHint")
            hint.setWordWrap(True)
            card_layout.addWidget(caption)
            card_layout.addWidget(value)
            card_layout.addWidget(hint)
            metrics_grid.addWidget(card, index // 3, index % 3)
            self.metric_values[key] = value
        root.addLayout(metrics_grid)

        charts = QGridLayout()
        charts.setContentsMargins(0, 0, 0, 0)
        charts.setHorizontalSpacing(12)
        charts.setVerticalSpacing(12)
        self.rate_chart = TrafficChart("rate", self)
        self.volume_chart = TrafficChart("volume", self)
        charts.addWidget(self._make_chart_panel(
            "LIVE THROUGHPUT", "Bytes transferred per second · recent 60 seconds", self.rate_chart
        ), 0, 0)
        charts.addWidget(self._make_chart_panel(
            "TRANSFER VOLUME", "Aggregate bytes per minute · recent 60 minutes", self.volume_chart
        ), 0, 1)
        root.addLayout(charts, 1)

        self.data_note = QLabel(
            "All-time total is persisted. Directional totals and charts are measured in this app run; "
            "rates are approximate and are not a system-wide network meter."
        )
        self.data_note.setObjectName("statisticsNote")
        self.data_note.setWordWrap(True)
        root.addWidget(self.data_note)

        self._apply_theme_styles()
        self._refresh_metrics()
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.sample_once)
        self.timer.start()

    def _make_chart_panel(self, title: str, description: str, chart: TrafficChart) -> QFrame:
        panel = QFrame(self)
        panel.setObjectName("statisticsChartPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(13, 11, 13, 8)
        layout.setSpacing(3)
        heading = QLabel(title, panel)
        heading.setObjectName("statisticsChartTitle")
        detail = QLabel(description, panel)
        detail.setObjectName("statisticsChartDetail")
        detail.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(detail)
        layout.addWidget(chart, 1)
        return panel

    @staticmethod
    def _read_total_bytes() -> int:
        try:
            return _safe_non_negative_int(CONFIG["data_usage"])
        except (KeyError, OSError, RuntimeError, TypeError, ValueError):
            return 0

    @staticmethod
    def _read_directions() -> dict[str, int]:
        try:
            raw = get_traffic_direction_snapshot()
        except (OSError, RuntimeError, TypeError, ValueError):
            raw = {}
        return {
            "upload": _safe_non_negative_int(raw.get("upload", 0)),
            "download": _safe_non_negative_int(raw.get("download", 0)),
        }

    def sample_once(self, *, now: float | None = None, total_bytes: int | None = None,
                    direction_totals: dict[str, int] | None = None) -> None:
        """Sample counters. Optional arguments make accounting behavior deterministic in tests."""
        timestamp = time.monotonic() if now is None else float(now)
        total = self._read_total_bytes() if total_bytes is None else _safe_non_negative_int(total_bytes)
        directions = self._read_directions() if direction_totals is None else {
            "upload": _safe_non_negative_int(direction_totals.get("upload", 0)),
            "download": _safe_non_negative_int(direction_totals.get("download", 0)),
        }
        elapsed = max(0.001, timestamp - self._last_sample_at)
        upload_delta = max(0, directions["upload"] - self._last_directions["upload"])
        download_delta = max(0, directions["download"] - self._last_directions["download"])
        transfer_delta = upload_delta + download_delta
        self._session_upload += upload_delta
        self._session_download += download_delta
        self._current_rate = transfer_delta / elapsed
        self._peak_rate = max(self._peak_rate, self._current_rate)
        self._samples.append(_TrafficSample(
            timestamp,
            transfer_delta,
            upload_delta,
            download_delta,
            self._current_rate,
        ))
        self._last_sample_at = timestamp
        self._last_total_bytes = total
        self._last_directions = directions
        self._refresh_metrics(total_bytes=total, now=timestamp)
        samples = list(self._samples)
        self.rate_chart.set_samples(samples)
        self.volume_chart.set_samples(samples)

    def _refresh_metrics(self, *, total_bytes: int | None = None, now: float | None = None) -> None:
        lifetime = self._read_total_bytes() if total_bytes is None else _safe_non_negative_int(total_bytes)
        timestamp = time.monotonic() if now is None else float(now)
        session = self._session_upload + self._session_download
        elapsed = max(0.001, timestamp - self._started_at)
        average_rate = session / elapsed
        self.metric_values["lifetime"].setText(format_bytes(lifetime))
        self.metric_values["session"].setText(format_bytes(session))
        self.metric_values["upload"].setText(format_bytes(self._session_upload))
        self.metric_values["download"].setText(format_bytes(self._session_download))
        self.metric_values["current"].setText(format_bytes(self._current_rate, per_second=True))
        self.metric_values["peak"].setText(format_bytes(self._peak_rate, per_second=True))
        # Keep the average available for tooltips without adding another visually noisy KPI.
        self.metric_values["session"].setToolTip(
            f"Average since launch: {format_bytes(average_rate, per_second=True)}"
        )
        self._refresh_connection_state()

    def _refresh_connection_state(self) -> None:
        running = bool(getattr(self.proxy_widget, "running", False))
        connected = bool(getattr(self.proxy_widget, "connected", False))
        if connected:
            label, state = "TOR CONNECTED", "connected"
        elif running:
            label, state = "PROXY RUNNING · TOR STARTING", "connecting"
        else:
            label, state = "PROXY STOPPED", "disconnected"
        if self.connection_state.text() != label:
            self.connection_state.setText(label)
            self.connection_state.setProperty("connectionState", state)
            self.connection_state.style().unpolish(self.connection_state)
            self.connection_state.style().polish(self.connection_state)

    def _back_home(self) -> None:
        show_home = getattr(self._owner, "_show_home", None)
        if callable(show_home):
            show_home()

    def apply_theme(self, mode: str) -> None:
        self._dark = mode == "dark"
        self._apply_theme_styles()
        self.rate_chart.apply_theme(mode)
        self.volume_chart.apply_theme(mode)

    def _apply_theme_styles(self) -> None:
        dark = self._dark
        border = "#3b4552" if dark else "#d7dee7"
        surface = "#252c36" if dark else "#ffffff"
        text = "#e8edf3" if dark else "#253041"
        muted = "#aab4c1" if dark else "#68778a"
        accent = "#52a8f5" if dark else "#167ac6"
        ok = "#55d49a" if dark else "#188b68"
        self.setStyleSheet(f"""
            QWidget#statisticsPage {{ background: transparent; }}
            QWidget#statisticsPage QLabel {{ color: {text}; background: transparent; border: none; }}
            QLabel#statisticsTitle {{ font-size: 20px; font-weight: 750; }}
            QLabel#statisticsSubtle, QLabel#statisticsNote, QLabel#statisticsChartDetail {{ color: {muted}; font-size: 10px; }}
            QLabel#statisticsMetricCaption, QLabel#statisticsChartTitle {{ color: {muted}; font-size: 10px; font-weight: 750; letter-spacing: 1px; }}
            QLabel#statisticsMetricValue {{ color: {accent}; font-size: 18px; font-weight: 750; }}
            QLabel#statisticsMetricHint {{ color: {muted}; font-size: 9px; }}
            QFrame#statisticsMetricCard, QFrame#statisticsChartPanel {{ background: {surface}; border: 1px solid {border}; border-radius: 12px; }}
            QPushButton#statisticsBackButton {{ color: {text}; background: transparent; border: 1px solid {border}; border-radius: 8px; padding: 8px 11px; font-weight: 650; }}
            QPushButton#statisticsBackButton:hover {{ border-color: {accent}; background: rgba(71, 163, 242, 0.10); }}
            QLabel#statisticsConnectionState {{ color: {muted}; font-size: 10px; font-weight: 750; padding: 5px 8px; border-radius: 6px; }}
            QLabel#statisticsConnectionState[connectionState="connected"] {{ color: {ok}; }}
            QLabel#statisticsConnectionState[connectionState="connecting"] {{ color: {accent}; }}
            QLabel#statisticsConnectionState[connectionState="disconnected"] {{ color: {muted}; }}
        """)


__all__ = ("StatisticsWindow", "TrafficChart", "format_bytes")
