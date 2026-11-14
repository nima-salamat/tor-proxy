"""Reusable dotted QR-code windows and buttons for TorProxy pages.

The display is intentionally independent from any feature page: callers only
need to provide the encoded payload and optional presentation text.
"""
from __future__ import annotations

from collections.abc import Callable

import qrcode
import qtawesome as qta
from qrcode.constants import ERROR_CORRECT_H
from qrcode.exceptions import DataOverflowError
from PySide6.QtCore import QPointF, QRectF, QSize, Qt, QTimer
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ui_.window.dialogs import _FramelessDialog


class QrCodeDotWidget(QWidget):
    """Paint a high-correction QR matrix with rounded dots and a centered icon."""

    def __init__(
        self,
        payload: str,
        *,
        center_icon: str = "fa6s.shield-halved",
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        value = str(payload or "").strip()
        if not value:
            raise ValueError("A non-empty QR payload is required.")

        qr = qrcode.QRCode(
            version=None,
            error_correction=ERROR_CORRECT_H,
            box_size=1,
            border=4,
        )
        qr.add_data(value)
        try:
            qr.make(fit=True)
        except DataOverflowError as exc:
            raise ValueError("This content is too long to fit in a QR code.") from exc

        self._matrix = tuple(tuple(bool(cell) for cell in row) for row in qr.get_matrix())
        self._center_icon = str(center_icon or "fa6s.shield-halved")
        self.setObjectName("qrCodeDotCanvas")
        self.setMinimumSize(260, 260)
        self.setMaximumSize(340, 340)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAutoFillBackground(False)

    def sizeHint(self) -> QSize:
        return QSize(320, 320)

    @staticmethod
    def _is_finder_cell(row: int, column: int, side: int) -> bool:
        """Keep the three finder patterns square-edged for reliable detection."""
        border = 4
        top = border <= row < border + 7
        bottom = side - border - 7 <= row < side - border
        left = border <= column < border + 7
        right = side - border - 7 <= column < side - border
        return (top and left) or (top and right) or (bottom and left)

    def paintEvent(self, _event) -> None:
        if not self._matrix:
            return

        painter = QPainter(self)
        if not painter.isActive():
            return
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)

        bounds = QRectF(self.rect()).adjusted(2, 2, -2, -2)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#ffffff"))
        painter.drawRoundedRect(bounds, 22, 22)

        side = len(self._matrix)
        module_size = min(bounds.width(), bounds.height()) / side
        origin_x = bounds.center().x() - (side * module_size / 2)
        origin_y = bounds.center().y() - (side * module_size / 2)
        center = side // 2
        logo_half_modules = 2.7

        ink = QLinearGradient(
            QPointF(bounds.left(), bounds.top()),
            QPointF(bounds.right(), bounds.bottom()),
        )
        ink.setColorAt(0.0, QColor("#102a43"))
        ink.setColorAt(0.56, QColor("#164c69"))
        ink.setColorAt(1.0, QColor("#087b83"))

        dots = QPainterPath()
        finder_blocks = QPainterPath()
        radius = module_size * 0.37
        for row, values in enumerate(self._matrix):
            for column, is_dark in enumerate(values):
                if not is_dark:
                    continue
                if (
                    abs(row - center) <= logo_half_modules
                    and abs(column - center) <= logo_half_modules
                ):
                    continue

                x = origin_x + column * module_size
                y = origin_y + row * module_size
                if self._is_finder_cell(row, column, side):
                    finder_blocks.addRect(QRectF(x, y, module_size, module_size))
                else:
                    dots.addEllipse(
                        QPointF(x + module_size / 2, y + module_size / 2),
                        radius,
                        radius,
                    )

        painter.setBrush(ink)
        painter.drawPath(dots)
        painter.drawPath(finder_blocks)

        # The quiet white island protects the logo from nearby modules. High
        # error correction plus this small central area keeps the code scannable.
        logo_size = module_size * 6.0
        logo_rect = QRectF(
            bounds.center().x() - logo_size / 2,
            bounds.center().y() - logo_size / 2,
            logo_size,
            logo_size,
        )
        painter.setBrush(QColor("#ffffff"))
        painter.setPen(QPen(QColor("#d8e4eb"), max(1.0, module_size * 0.12)))
        painter.drawRoundedRect(logo_rect, module_size * 0.85, module_size * 0.85)

        icon_size = max(18, int(module_size * 3.4))
        icon_pixmap = qta.icon(self._center_icon, color="#176b91").pixmap(
            icon_size, icon_size
        )
        icon_rect = QRectF(
            bounds.center().x() - icon_size / 2,
            bounds.center().y() - icon_size / 2,
            icon_size,
            icon_size,
        )
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPixmap(icon_rect.toRect(), icon_pixmap)
        painter.end()


class QrCodeDisplayDialog(_FramelessDialog):
    """Feature-agnostic modal QR display using TorProxy's shared custom window."""

    def __init__(
        self,
        parent: QWidget | None,
        payload: str,
        *,
        title: str = "Show QR code",
        description: str = "Scan this code with a compatible QR scanner.",
        display_value: str | None = None,
        center_icon: str = "fa6s.shield-halved",
    ):
        self.payload = str(payload or "").strip()
        if not self.payload:
            raise ValueError("A non-empty QR payload is required.")

        super().__init__(
            parent,
            title,
            "fa6s.qrcode",
            "#287db5",
            width=500,
        )
        self.setObjectName("qrCodeDisplayDialog")
        self.resize(530, 610)

        eyebrow = QLabel("SCAN TO OPEN", self.body_host)
        eyebrow.setObjectName("qrDisplayEyebrow")
        self.body_layout.addWidget(eyebrow)

        message = QLabel(str(description or ""), self.body_host)
        message.setObjectName("dialogHint")
        message.setWordWrap(True)
        self.body_layout.addWidget(message)

        preview = QFrame(self.body_host)
        preview.setObjectName("qrDisplayPanel")
        preview_layout = QVBoxLayout(preview)
        preview_layout.setContentsMargins(12, 12, 12, 12)
        preview_layout.setSpacing(0)
        self.qr_widget = QrCodeDotWidget(
            self.payload,
            center_icon=center_icon,
            parent=preview,
        )
        preview_layout.addWidget(self.qr_widget, 0, Qt.AlignmentFlag.AlignCenter)
        self.body_layout.addWidget(preview, 0, Qt.AlignmentFlag.AlignCenter)

        self.value_label = QLabel(
            str(display_value if display_value is not None else self.payload),
            self.body_host,
        )
        self.value_label.setObjectName("qrDisplayValue")
        self.value_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.value_label.setWordWrap(True)
        self.value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.body_layout.addWidget(self.value_label)

        self.setStyleSheet(self.styleSheet() + f"""
            QLabel#qrDisplayEyebrow {{
                color: #35a7c2; background: transparent;
                font-size: 8pt; font-weight: 850; letter-spacing: 1.3px;
            }}
            QFrame#qrDisplayPanel {{
                background: {self._colors["panel"]};
                border: 1px solid {self._colors["border"]};
                border-radius: 18px;
            }}
            QLabel#qrDisplayValue {{
                color: {self._colors["text"]};
                background: {self._colors["panel"]};
                border: 1px solid {self._colors["border"]};
                border-radius: 9px;
                padding: 8px 12px;
                font-family: Consolas, monospace;
                font-size: 8.5pt;
                font-weight: 650;
            }}
        """)

        self.add_footer_spacer()
        self.copy_button = self.add_button(
            "Copy link",
            primary=False,
            callback=self.copy_payload,
        )
        self.copy_button.setIcon(qta.icon("fa6s.copy", color=self._colors["text"]))
        self.close_button = self.add_button(
            "Close",
            primary=True,
            callback=self.accept,
        )
        self.close_button.setIcon(qta.icon("fa6s.check", color="#ffffff"))

        self._copy_timer = QTimer(self)
        self._copy_timer.setSingleShot(True)
        self._copy_timer.setInterval(1400)
        self._copy_timer.timeout.connect(self._restore_copy_button)
        self._remember_preferred_size()

    def copy_payload(self) -> None:
        QApplication.clipboard().setText(self.payload)
        self._copy_timer.stop()
        self.copy_button.setText("Copied")
        self.copy_button.setIcon(qta.icon("fa6s.check", color="#31b981"))
        self._copy_timer.start()

    def _restore_copy_button(self) -> None:
        self.copy_button.setText("Copy link")
        self.copy_button.setIcon(qta.icon("fa6s.copy", color=self._colors["text"]))


def show_qr_code(
    parent: QWidget | None,
    payload: str,
    *,
    title: str = "Show QR code",
    description: str = "Scan this code with a compatible QR scanner.",
    display_value: str | None = None,
    center_icon: str = "fa6s.shield-halved",
) -> int:
    """Open the shared QR window from any page or widget."""
    owner = parent.window() if parent is not None else None
    dialog = QrCodeDisplayDialog(
        owner,
        payload,
        title=title,
        description=description,
        display_value=display_value,
        center_icon=center_icon,
    )
    return dialog.exec()


class QrCodeButton(QPushButton):
    """Drop-in icon button that opens the reusable QR window for a payload."""

    def __init__(
        self,
        payload: str | Callable[[], str],
        parent: QWidget | None = None,
        *,
        button_text: str = "QR code",
        title: str = "Show QR code",
        description: str = "Scan this code with a compatible QR scanner.",
        display_value: str | None = None,
        center_icon: str = "fa6s.shield-halved",
    ):
        super().__init__(button_text, parent)
        self._payload = payload
        self._dialog_title = title
        self._description = description
        self._display_value = display_value
        self._center_icon = center_icon
        self.setObjectName("qrCodeButton")
        self.setIcon(qta.icon("fa6s.qrcode"))
        self.setIconSize(QSize(16, 16))
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip("Show this value as a QR code")
        if isinstance(payload, str):
            self.setEnabled(bool(payload.strip()))
        self.clicked.connect(lambda _checked=False: self.open_qr_code())

    def open_qr_code(self) -> int | None:
        value = self._payload() if callable(self._payload) else self._payload
        payload = str(value or "").strip()
        if not payload:
            return None
        return show_qr_code(
            self.window(),
            payload,
            title=self._dialog_title,
            description=self._description,
            display_value=self._display_value,
            center_icon=self._center_icon,
        )
