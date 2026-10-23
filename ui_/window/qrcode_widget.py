"""Modern live QR scanner for importing Tor bridge lines."""
from __future__ import annotations

import json
import logging
import re
import sys
from typing import Iterable

import cv2
import qtawesome as qta
from PySide6.QtCore import QThread, QTimer, Qt, Signal, QRectF
from PySide6.QtGui import QColor, QImage, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from config import CONFIG
from ui_.window.dialogs import _FramelessDialog

logger = logging.getLogger(__name__)

try:
    from pyzbar.pyzbar import decode as decode_barcodes
except (ImportError, OSError):
    # OpenCV is the required detector. pyzbar is an optional second decoder;
    # on some Windows installs its native zbar DLL may not be available.
    decode_barcodes = None


_BRIDGE_METHODS = (
    "obfs4",
    "obfs3",
    "obfs2",
    "scramblesuit",
    "meek_lite",
    "snowflake",
    "webtunnel",
    "fte",
    "vanilla",
)
_BRIDGE_LINE_RE = re.compile(
    r"^(?:(?:" + "|".join(_BRIDGE_METHODS) + r")\s+)?"
    r"(?P<host>\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+):(?P<port>\d{1,5})(?:\s+.*)?$",
    re.IGNORECASE,
)


def parse_bridge_payload(payload: str) -> list[str]:
    """Decode the common Tor QR payload shapes and reject unrelated QR codes."""
    raw = str(payload or "").strip()
    if not raw:
        return []

    value: object = raw
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        pass

    if isinstance(value, dict):
        for key in ("bridges", "bridge", "bridge_lines", "lines", "data"):
            if key in value:
                value = value[key]
                break

    if isinstance(value, str):
        candidates: Iterable[object] = value.splitlines()
    elif isinstance(value, (tuple, list)):
        candidates = value
    else:
        return []

    lines: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        for part in candidate.splitlines():
            line = part.strip()
            if not line or line.startswith("#"):
                continue
            # Accept both pasted bridge lines and lines copied from torrc.
            line = re.sub(r"^Bridge\s+", "", line, flags=re.IGNORECASE).strip()
            match = _BRIDGE_LINE_RE.fullmatch(line)
            if match is None:
                continue
            try:
                port = int(match.group("port"))
            except ValueError:
                continue
            if not 1 <= port <= 65535:
                continue
            if line not in seen:
                seen.add(line)
                lines.append(line)
    return lines


class _QrScannerThread(QThread):
    """Capture camera frames and decode QR payloads outside the UI thread."""

    frame_ready = Signal(QImage)
    camera_ready = Signal(str)
    scanner_error = Signal(str)
    qr_found = Signal(str)

    def __init__(self, camera_index: int = 0, parent=None):
        super().__init__(parent)
        self.camera_index = camera_index
        self._capture = None

    @staticmethod
    def _open_camera(index: int):
        if sys.platform == "win32":
            capture = cv2.VideoCapture(index, cv2.CAP_DSHOW)
            if capture.isOpened():
                return capture
            capture.release()
        return cv2.VideoCapture(index)

    @staticmethod
    def _decode_qr(frame, detector) -> str | None:
        try:
            value, _points, _straight = detector.detectAndDecode(frame)
            if value and value.strip():
                return value.strip()
        except cv2.error:
            logger.debug("OpenCV QR decode failed for one frame.", exc_info=True)

        if decode_barcodes is not None:
            try:
                for result in decode_barcodes(frame):
                    if getattr(result, "type", "") == "QRCODE":
                        value = result.data.decode("utf-8", errors="replace").strip()
                        if value:
                            return value
            except (OSError, ValueError, UnicodeError):
                logger.debug("Fallback QR decoding failed for one frame.", exc_info=True)
        return None

    def run(self):
        capture = None
        try:
            capture = self._open_camera(self.camera_index)
            self._capture = capture
            if capture is None or not capture.isOpened():
                if capture is not None:
                    capture.release()
                self.scanner_error.emit(
                    "TorProxy couldn't open a camera. Check camera permissions or connect a webcam, then try again."
                )
                return

            capture.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
            capture.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
            capture.set(cv2.CAP_PROP_FPS, 30)
            try:
                capture.set(cv2.CAP_PROP_BUFFERSIZE, 1)
            except cv2.error:
                pass

            backend = capture.getBackendName() if hasattr(capture, "getBackendName") else "Camera"
            self.camera_ready.emit(f"{backend} · Live preview")
            detector = cv2.QRCodeDetector()
            frame_count = 0

            while not self.isInterruptionRequested():
                ok, frame = capture.read()
                if not ok or frame is None:
                    self.msleep(35)
                    continue
                frame_count += 1

                # Detect against the unmirrored camera frame for decoder compatibility.
                payload = self._decode_qr(frame, detector)
                display_frame = cv2.flip(frame, 1)
                rgb = cv2.cvtColor(display_frame, cv2.COLOR_BGR2RGB)
                height, width, channels = rgb.shape
                image = QImage(
                    rgb.data,
                    width,
                    height,
                    channels * width,
                    QImage.Format.Format_RGB888,
                ).copy()
                # Cap UI refresh to around 20 fps while continuing to scan every frame.
                if frame_count % 2 == 0:
                    self.frame_ready.emit(image)

                if payload:
                    self.qr_found.emit(payload)
                    break
                self.msleep(8)
        except (cv2.error, OSError, RuntimeError) as exc:
            logger.exception("QR camera scanner failed.")
            self.scanner_error.emit(f"Camera error: {exc}")
        finally:
            if capture is not None:
                capture.release()
            self._capture = None

    def stop_camera(self):
        """Ask the loop to exit and release a blocking capture if necessary."""
        self.requestInterruption()
        capture = self._capture
        if capture is not None:
            try:
                capture.release()
            except cv2.error:
                logger.debug("Camera release during scanner shutdown failed.", exc_info=True)


class _ScanOverlay(QWidget):
    """Animated finder corners and scan beam drawn over the camera preview."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self._phase = 0
        self._timer = QTimer(self)
        self._timer.setInterval(35)
        self._timer.timeout.connect(self._advance)

    def start_animation(self):
        if not self._timer.isActive():
            self._timer.start()

    def stop_animation(self):
        self._timer.stop()

    def _advance(self):
        self._phase = (self._phase + 3) % 100
        self.update()

    def paintEvent(self, event):
        del event
        if self.width() < 20 or self.height() < 20:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        side = min(270, int(self.width() * 0.62), int(self.height() * 0.82))
        side = max(120, side)
        side = min(side, self.width() - 24, self.height() - 24)
        x = (self.width() - side) // 2
        y = (self.height() - side) // 2
        finder = QRectF(x, y, side, side)

        shade = QColor(4, 10, 18, 92)
        painter.fillRect(0, 0, self.width(), max(0, y), shade)
        painter.fillRect(0, y, max(0, x), side, shade)
        painter.fillRect(x + side, y, max(0, self.width() - x - side), side, shade)
        painter.fillRect(0, y + side, self.width(), max(0, self.height() - y - side), shade)

        length = max(22, side // 5)
        pen = QPen(QColor("#53d9c5"), 4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        for corner_x, corner_y, dx, dy in (
            (finder.left(), finder.top(), 1, 1),
            (finder.right(), finder.top(), -1, 1),
            (finder.left(), finder.bottom(), 1, -1),
            (finder.right(), finder.bottom(), -1, -1),
        ):
            painter.drawLine(int(corner_x), int(corner_y), int(corner_x + dx * length), int(corner_y))
            painter.drawLine(int(corner_x), int(corner_y), int(corner_x), int(corner_y + dy * length))

        beam_y = int(finder.top() + 8 + (finder.height() - 16) * self._phase / 100)
        painter.setPen(QPen(QColor(83, 217, 197, 200), 2))
        painter.drawLine(int(finder.left() + 9), beam_y, int(finder.right() - 9), beam_y)
        painter.end()


class QrCodeFloatingWindow(_FramelessDialog):
    """Focused, modal camera scanner that imports validated Tor bridge lines."""

    def __init__(self, parent=None):
        super().__init__(
            parent.window() if parent is not None else None,
            "Import bridges from QR code",
            "fa6s.qrcode",
            "#287db5",
            width=620,
        )
        self.parent_ = parent
        self._scanner: _QrScannerThread | None = None
        self._detected_bridges: list[str] = []
        self._camera_label_text = "Preparing camera…"
        self._finishing = False

        self.setObjectName("qrScannerDialog")
        self.resize(660, 610)

        intro = QLabel(
            "Point your camera at a Tor bridge QR code. Keep the code inside the frame until it's recognized.",
            self.body_host,
        )
        intro.setObjectName("qrIntro")
        intro.setWordWrap(True)
        self.body_layout.addWidget(intro)

        camera_header = QHBoxLayout()
        camera_header.setContentsMargins(0, 0, 0, 0)
        camera_header.setSpacing(8)
        self.camera_icon = QLabel(self.body_host)
        self.camera_icon.setObjectName("qrCameraIcon")
        self.camera_icon.setFixedSize(25, 25)
        self.camera_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.camera_icon.setPixmap(qta.icon("fa6s.video", color="#53d9c5").pixmap(16, 16))
        camera_header.addWidget(self.camera_icon)

        camera_title = QLabel("CAMERA PREVIEW", self.body_host)
        camera_title.setObjectName("qrEyebrow")
        camera_header.addWidget(camera_title)
        camera_header.addStretch(1)

        self.live_badge = QLabel("CONNECTING", self.body_host)
        self.live_badge.setObjectName("qrBadge")
        camera_header.addWidget(self.live_badge)
        self.body_layout.addLayout(camera_header)

        self.preview_panel = QFrame(self.body_host)
        self.preview_panel.setObjectName("qrPreviewPanel")
        self.preview_panel.setMinimumSize(500, 280)
        self.preview_panel.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        preview_layout = QVBoxLayout(self.preview_panel)
        preview_layout.setContentsMargins(0, 0, 0, 0)
        preview_layout.setSpacing(0)

        self.camera_label = QLabel(self._camera_label_text, self.preview_panel)
        self.camera_label.setObjectName("qrPreviewImage")
        self.camera_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.camera_label.setMinimumSize(0, 0)
        self.camera_label.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        preview_layout.addWidget(self.camera_label)
        self.scan_overlay = _ScanOverlay(self.preview_panel)
        self.scan_overlay.raise_()
        self.scan_overlay.hide()
        self.body_layout.addWidget(self.preview_panel, 1)

        status_row = QHBoxLayout()
        status_row.setContentsMargins(2, 2, 2, 0)
        status_row.setSpacing(8)
        self.status_dot = QLabel(self.body_host)
        self.status_dot.setObjectName("qrStatusDot")
        self.status_dot.setFixedSize(9, 9)
        status_row.addWidget(self.status_dot, 0, Qt.AlignmentFlag.AlignTop)

        self.status_label = QLabel("Waiting for camera…", self.body_host)
        self.status_label.setObjectName("qrStatusText")
        self.status_label.setWordWrap(True)
        status_row.addWidget(self.status_label, 1)
        self.body_layout.addLayout(status_row)

        self.details_label = QLabel(
            "Your QR data is checked locally. TorProxy only imports recognized bridge lines.",
            self.body_host,
        )
        self.details_label.setObjectName("qrDetails")
        self.details_label.setWordWrap(True)
        self.body_layout.addWidget(self.details_label)

        self.setStyleSheet(self.styleSheet() + f"""
            QLabel#qrIntro {{ color: {self._colors["muted"]}; background: transparent; font-size: 9pt; }}
            QLabel#qrCameraIcon {{ background: rgba(83, 217, 197, 0.11); border: 1px solid {self._colors["border"]}; border-radius: 8px; }}
            QLabel#qrEyebrow {{ color: {self._colors["muted"]}; background: transparent; font-size: 8pt; font-weight: 850; letter-spacing: 1px; }}
            QLabel#qrBadge {{ color: #53d9c5; background: rgba(83, 217, 197, 0.11); border: 1px solid rgba(83, 217, 197, 0.3); border-radius: 9px; padding: 4px 8px; font-size: 7.5pt; font-weight: 850; }}
            QFrame#qrPreviewPanel {{ background: #090f18; border: 1px solid {self._colors["border"]}; border-radius: 13px; }}
            QLabel#qrPreviewImage {{ background: #090f18; color: #a5b4c7; border-radius: 12px; font-size: 10pt; padding: 12px; }}
            QLabel#qrStatusDot {{ background: #f4b860; border-radius: 4px; }}
            QLabel#qrStatusText {{ color: {self._colors["text"]}; background: transparent; font-size: 9pt; font-weight: 650; }}
            QLabel#qrDetails {{ color: {self._colors["muted"]}; background: transparent; font-size: 8pt; }}
        """)

        self.add_footer_spacer()
        self.retry_button = self.add_button(
            "Scan again", primary=False, callback=self.start_scanning
        )
        self.retry_button.setIcon(qta.icon("fa6s.rotate", color=self._colors["text"]))
        self.retry_button.hide()

        self.cancel_button = self.add_button(
            "Cancel", primary=False, callback=self.reject
        )
        self.cancel_button.setIcon(qta.icon("fa6s.xmark", color=self._colors["text"]))

        self.import_button = self.add_button(
            "Import bridges", primary=True, callback=self.import_bridges
        )
        self.import_button.setIcon(qta.icon("fa6s.check", color="#ffffff"))
        self.import_button.hide()

        self._resize_preview_overlay()
        self._set_status("Starting camera…", level="working")
        self._remember_preferred_size()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._resize_preview_overlay()

    def _resize_preview_overlay(self):
        if hasattr(self, "scan_overlay") and hasattr(self, "camera_label"):
            self.camera_label.setGeometry(self.preview_panel.contentsRect())
            self.scan_overlay.setGeometry(self.preview_panel.contentsRect())
            self.scan_overlay.raise_()

    def showEvent(self, event):
        super().showEvent(event)
        QTimer.singleShot(0, self.start_scanning)

    def _set_status(self, message: str, *, level: str = "working"):
        palette = {
            "working": ("#f4b860", "CONNECTING", "rgba(244, 184, 96, 0.10)", "rgba(244, 184, 96, 0.35)"),
            "scanning": ("#53d9c5", "SCANNING", "rgba(83, 217, 197, 0.10)", "rgba(83, 217, 197, 0.35)"),
            "success": ("#53d9c5", "QR FOUND", "rgba(83, 217, 197, 0.10)", "rgba(83, 217, 197, 0.35)"),
            "error": ("#f07178", "CAMERA ISSUE", "rgba(240, 113, 120, 0.10)", "rgba(240, 113, 120, 0.35)"),
            "invalid": ("#f4b860", "NOT A BRIDGE", "rgba(244, 184, 96, 0.10)", "rgba(244, 184, 96, 0.35)"),
        }
        color, badge, badge_background, badge_border = palette.get(level, palette["working"])
        self.status_dot.setStyleSheet(f"background: {color}; border-radius: 4px;")
        self.live_badge.setText(badge)
        self.live_badge.setStyleSheet(
            f"color: {color}; background: {badge_background}; border: 1px solid {badge_border}; "
            "border-radius: 9px; padding: 4px 8px; font-size: 7.5pt; font-weight: 850;"
        )
        self.status_label.setText(message)

    def start_scanning(self):
        if self._finishing:
            return
        if self._scanner is not None and self._scanner.isRunning():
            self._scanner.stop_camera()
            if not self._scanner.wait(1600):
                logger.warning("Waiting for the previous camera scan to stop before retrying.")
                self._scanner.wait()
        self._detected_bridges = []
        self._finishing = False
        self.import_button.hide()
        self.retry_button.hide()
        self.details_label.setText(
            "Your QR data is checked locally. TorProxy only imports recognized bridge lines."
        )
        self.camera_label.setPixmap(QPixmap())
        self.camera_label.setText("Opening camera…")
        self.scan_overlay.hide()
        self._set_status("Connecting to your camera…", level="working")

        self._scanner = _QrScannerThread(0, self)
        self._scanner.frame_ready.connect(self._show_frame)
        self._scanner.camera_ready.connect(self._camera_started)
        self._scanner.scanner_error.connect(self._camera_failed)
        self._scanner.qr_found.connect(self._qr_detected)
        self._scanner.start()

    def _camera_started(self, backend_name: str):
        self.scan_overlay.start_animation()
        self._set_status(f"{backend_name}. Center the QR code in the frame.", level="scanning")
        self.scan_overlay.show()
        self.scan_overlay.raise_()

    def _camera_failed(self, message: str):
        self.scan_overlay.stop_animation()
        logger.warning("QR camera unavailable: %s", message)
        self.scan_overlay.hide()
        self.camera_label.setPixmap(QPixmap())
        self.camera_label.setText("Camera unavailable\n\nCheck camera access and try again.")
        self._set_status(message, level="error")
        self.details_label.setText(
            "If another app is using your camera, close it and select Scan again."
        )
        self.retry_button.show()
        self._resize_preview_overlay()

    def _show_frame(self, image: QImage):
        self.camera_label.setText("")
        self.camera_label.setPixmap(
            QPixmap.fromImage(image).scaled(
                self.camera_label.size(),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
        )

    def _qr_detected(self, payload: str):
        bridges = parse_bridge_payload(payload)
        self.scan_overlay.stop_animation()
        self.scan_overlay.hide()
        self._detected_bridges = bridges
        if not bridges:
            self._set_status(
                "A QR code was found, but it doesn't contain recognizable Tor bridge lines.",
                level="invalid",
            )
            self.details_label.setText(
                "Only bridge payloads are imported. Nothing has been changed in your settings."
            )
            self.retry_button.show()
            return

        count = len(bridges)
        self._set_status(
            f"Found {count} Tor bridge line{'s' if count != 1 else ''}. Review and import them when ready.",
            level="success",
        )
        self.details_label.setText(
            "Bridge details stay on this computer. Choose Import bridges to add them to Settings."
        )
        self.camera_label.setText(
            f"QR code recognized\n\n{count} bridge line{'s' if count != 1 else ''} ready to import"
        )
        self.camera_label.setPixmap(QPixmap())
        self.import_button.show()
        self.retry_button.show()

    def import_bridges(self):
        if not self._detected_bridges:
            return
        settings = self.parent_
        editor = getattr(settings, "inp_bridges", None)
        if editor is None:
            self._set_status("The bridge settings field is no longer available.", level="error")
            return
        editor.setPlainText("\n".join(self._detected_bridges))
        enable_checkbox = getattr(settings, "btn_bridge", None)
        if enable_checkbox is not None and not enable_checkbox.isChecked():
            enable_checkbox.setChecked(True)
        self._set_status("Bridge lines imported into Settings.", level="success")
        self.accept()

    def _stop_scanner(self):
        scanner = self._scanner
        if scanner is None:
            return
        if scanner.isRunning():
            scanner.stop_camera()
            if not scanner.wait(1600):
                logger.warning("QR scanner did not stop after camera release; waiting for safe shutdown.")
                scanner.wait()
        self._scanner = None

    def accept(self):
        self.scan_overlay.stop_animation()
        self._stop_scanner()
        super().accept()

    def reject(self):
        self.scan_overlay.stop_animation()
        self._stop_scanner()
        super().reject()

    def closeEvent(self, event):
        self.scan_overlay.stop_animation()
        self._stop_scanner()
        super().closeEvent(event)
