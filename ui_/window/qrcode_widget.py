"""Modern live QR scanner for importing Tor bridge lines."""
from __future__ import annotations

import logging
import sys

import cv2
import qtawesome as qta
from PySide6.QtCore import QThread, QTimer, Qt, Signal, QRectF, QPointF
from PySide6.QtGui import QColor, QImage, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QPlainTextEdit,
    QPushButton,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ui_.window.dialogs import _FramelessDialog

logger = logging.getLogger(__name__)

try:
    from pyzbar.pyzbar import decode as decode_barcodes
except (ImportError, OSError):
    # OpenCV is the required detector. pyzbar is an optional second decoder;
    # on some Windows installs its native zbar DLL may not be available.
    decode_barcodes = None


from torproxy.bridge_qr import bridge_import_actions, merge_bridge_lines, parse_bridge_payload


class _QrScannerThread(QThread):
    """Capture camera frames and decode QR payloads outside the UI thread."""

    frame_ready = Signal(QImage)
    camera_ready = Signal(str)
    scanner_error = Signal(str)
    qr_found = Signal(str, QImage, object)

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
    def _decode_qr(frame, detector) -> tuple[str | None, list[tuple[float, float]] | None]:
        """Return decoded text and its polygon in camera-frame coordinates."""
        try:
            value, points, _straight = detector.detectAndDecode(frame)
            if value and value.strip():
                polygon = None
                if points is not None and len(points):
                    polygon = [
                        (float(point[0]), float(point[1]))
                        for point in points.reshape(-1, 2)
                    ]
                return value.strip(), polygon
        except cv2.error:
            logger.debug("OpenCV QR decode failed for one frame.", exc_info=True)

        if decode_barcodes is not None:
            try:
                for result in decode_barcodes(frame):
                    if getattr(result, "type", "") == "QRCODE":
                        value = result.data.decode("utf-8", errors="replace").strip()
                        if value:
                            polygon = [
                                (float(point.x), float(point.y))
                                for point in getattr(result, "polygon", ())
                            ]
                            return value, polygon or None
            except (OSError, ValueError, UnicodeError):
                logger.debug("Fallback QR decoding failed for one frame.", exc_info=True)
        return None, None

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
                payload, corners = self._decode_qr(frame, detector)
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
                if payload:
                    # Keep precisely the frame where the code was detected so
                    # the UI can freeze it and draw a polygon over that QR.
                    self.qr_found.emit(payload, image, corners or [])
                    break
                # Cap UI refresh to around 20 fps while scanning every frame.
                if frame_count % 2 == 0:
                    self.frame_ready.emit(image)
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
    """One canvas for the camera frame, scan animation and detected QR marker."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        self._phase = 0.0
        self._direction = 1.0
        self._detected_corners: list[tuple[float, float]] = []
        self._source_size = (1, 1)
        self._frame: QImage | None = None
        self._placeholder = "Opening camera…"
        self._has_detection = False
        self._timer = QTimer(self)
        self._timer.setInterval(28)
        self._timer.timeout.connect(self._advance)

    def start_animation(self):
        self._detected_corners = []
        self._has_detection = False
        self._phase = 0.0
        self._direction = 1.0
        if not self._timer.isActive():
            self._timer.start()
        self.update()

    def stop_animation(self):
        self._timer.stop()

    def set_frame(self, image: QImage):
        self._frame = image.copy()
        self._source_size = (image.width(), image.height())
        self._placeholder = ""
        self.update()

    def set_placeholder(self, message: str):
        self._frame = None
        self._placeholder = message
        self._source_size = (1, 1)
        self._detected_corners = []
        self._has_detection = False
        self.update()

    def set_source_size(self, source_size):
        self._source_size = tuple(source_size) if source_size else (1, 1)
        self.update()

    def set_detected(self, corners, source_size):
        self._timer.stop()
        self._detected_corners = list(corners or [])
        self._has_detection = True
        self.set_source_size(source_size)
        self.update()

    def clear_detection(self):
        self._detected_corners = []
        self._has_detection = False
        self.update()

    def _advance(self):
        self._phase += self._direction * 1.7
        if self._phase >= 100:
            self._phase, self._direction = 100, -1.0
        elif self._phase <= 0:
            self._phase, self._direction = 0, 1.0
        self.update()

    def _image_rect(self) -> QRectF:
        source_width, source_height = self._source_size
        if source_width <= 1 or source_height <= 1:
            return QRectF(self.rect())
        scale = min(self.width() / source_width, self.height() / source_height)
        width, height = source_width * scale, source_height * scale
        return QRectF(
            (self.width() - width) / 2,
            (self.height() - height) / 2,
            width,
            height,
        )

    def _mapped_polygon(self) -> QPolygonF:
        source_width, source_height = self._source_size
        image_rect = self._image_rect()
        if source_width <= 1 or source_height <= 1:
            return QPolygonF()
        scale_x = image_rect.width() / source_width
        scale_y = image_rect.height() / source_height
        return QPolygonF([
            QPointF(
                image_rect.left() + (source_width - 1 - x) * scale_x,
                image_rect.top() + y * scale_y,
            )
            for x, y in self._detected_corners
        ])

    def paintEvent(self, event):
        del event
        if self.width() < 20 or self.height() < 20:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        if self._frame is None or self._frame.isNull():
            painter.fillRect(self.rect(), QColor("#090f18"))
            painter.setPen(QColor("#a5b4c7"))
            painter.drawText(
                self.rect().adjusted(18, 18, -18, -18),
                Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap,
                self._placeholder,
            )
            painter.end()
            return

        image_rect = self._image_rect()
        painter.fillRect(self.rect(), QColor("#090f18"))
        painter.drawImage(image_rect, self._frame)

        if self._has_detection:
            polygon = self._mapped_polygon()
            if len(polygon) >= 3:
                painter.setPen(QPen(
                    QColor(83, 217, 197, 75), 9,
                    Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin,
                ))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawPolygon(polygon)
                painter.setPen(QPen(
                    QColor("#53d9c5"), 3,
                    Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin,
                ))
                painter.setBrush(QColor(83, 217, 197, 24))
                painter.drawPolygon(polygon)
                bounds = polygon.boundingRect()
                tag_width, tag_height = 98, 27
                tag_x = min(
                    max(bounds.left(), image_rect.left() + 6),
                    image_rect.right() - tag_width - 6,
                )
                tag_y = bounds.top() - tag_height - 7
                if tag_y < image_rect.top() + 4:
                    tag_y = min(bounds.bottom() + 7, image_rect.bottom() - tag_height - 4)
            else:
                tag_width, tag_height = 98, 27
                tag_x, tag_y = image_rect.right() - tag_width - 10, image_rect.top() + 10
            tag = QRectF(tag_x, tag_y, tag_width, tag_height)
            painter.setPen(QPen(QColor("#53d9c5"), 1))
            painter.setBrush(QColor(7, 24, 29, 230))
            painter.drawRoundedRect(tag, 8, 8)
            painter.setPen(QColor("#baf8ee"))
            painter.drawText(tag, Qt.AlignmentFlag.AlignCenter, "✓  QR FOUND")
            painter.end()
            return

        painter.fillRect(image_rect, QColor(4, 10, 18, 17))
        band_height = max(20, int(image_rect.height() * 0.055))
        beam_y = image_rect.top() + (image_rect.height() - band_height) * self._phase / 100
        painter.fillRect(
            QRectF(image_rect.left(), beam_y, image_rect.width(), band_height),
            QColor(83, 217, 197, 24),
        )
        painter.fillRect(
            QRectF(image_rect.left(), beam_y + band_height * 0.48, image_rect.width(), 2),
            QColor(83, 217, 197, 175),
        )
        painter.setPen(QPen(QColor(83, 217, 197, 95), 1))
        painter.drawLine(
            QPointF(image_rect.left(), image_rect.top() + 1),
            QPointF(image_rect.right(), image_rect.top() + 1),
        )
        painter.drawLine(
            QPointF(image_rect.left(), image_rect.bottom() - 1),
            QPointF(image_rect.right(), image_rect.bottom() - 1),
        )
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

        # Image and QR marker share one canvas, removing independent geometry drift.
        self.scan_overlay = _ScanOverlay(self.preview_panel)
        self.scan_overlay.setObjectName("qrPreviewCanvas")
        self.scan_overlay.setMinimumSize(0, 0)
        self.scan_overlay.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        preview_layout.addWidget(self.scan_overlay)
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

        # A compact disclosure row keeps the main scan flow clean. The chevron
        # opens the exact bridge lines that were recognized in the frozen frame.
        self.results_toggle = QPushButton("Detected bridges")
        self.results_toggle.setObjectName("qrResultsToggle")
        self.results_toggle.setIcon(qta.icon("fa6s.chevron-down", color="#53d9c5"))
        self.results_toggle.setCheckable(True)
        self.results_toggle.clicked.connect(self._toggle_detected_results)
        self.results_toggle.hide()
        self.body_layout.addWidget(self.results_toggle)

        self.results_panel = QFrame(self.body_host)
        self.results_panel.setObjectName("qrResultsPanel")
        results_layout = QVBoxLayout(self.results_panel)
        results_layout.setContentsMargins(10, 8, 10, 8)
        results_layout.setSpacing(4)
        self.results_summary = QLabel("Recognized bridge lines")
        self.results_summary.setObjectName("qrResultsSummary")
        results_layout.addWidget(self.results_summary)
        self.results_text = QPlainTextEdit(self.results_panel)
        self.results_text.setObjectName("qrResultsText")
        self.results_text.setReadOnly(True)
        self.results_text.setMaximumHeight(92)
        results_layout.addWidget(self.results_text)
        self.results_panel.hide()
        self.body_layout.addWidget(self.results_panel)

        self.setStyleSheet(self.styleSheet() + f"""
            QLabel#qrIntro {{ color: {self._colors["muted"]}; background: transparent; font-size: 9pt; }}
            QLabel#qrCameraIcon {{ background: rgba(83, 217, 197, 0.11); border: 1px solid {self._colors["border"]}; border-radius: 8px; }}
            QLabel#qrEyebrow {{ color: {self._colors["muted"]}; background: transparent; font-size: 8pt; font-weight: 850; letter-spacing: 1px; }}
            QLabel#qrBadge {{ color: #53d9c5; background: rgba(83, 217, 197, 0.11); border: 1px solid rgba(83, 217, 197, 0.3); border-radius: 9px; padding: 4px 8px; font-size: 7.5pt; font-weight: 850; }}
            QFrame#qrPreviewPanel {{ background: #090f18; border: 1px solid {self._colors["border"]}; border-radius: 13px; }}
            QWidget#qrPreviewCanvas {{ background: #090f18; border: none; border-radius: 12px; }}
            QLabel#qrStatusDot {{ background: #f4b860; border-radius: 4px; }}
            QLabel#qrStatusText {{ color: {self._colors["text"]}; background: transparent; font-size: 9pt; font-weight: 650; }}
            QLabel#qrDetails {{ color: {self._colors["muted"]}; background: transparent; font-size: 8pt; }}
            QPushButton#qrResultsToggle {{ color: #53d9c5; background: transparent; border: none; text-align: left; padding: 5px 2px; font-size: 8.5pt; font-weight: 750; }}
            QPushButton#qrResultsToggle:hover {{ color: #9bf0e3; background: rgba(83, 217, 197, 0.07); border-radius: 6px; }}
            QFrame#qrResultsPanel {{ background: {self._colors["panel"]}; border: 1px solid {self._colors["border"]}; border-radius: 9px; }}
            QLabel#qrResultsSummary {{ color: {self._colors["muted"]}; background: transparent; font-size: 7.5pt; font-weight: 750; }}
            QPlainTextEdit#qrResultsText {{ color: {self._colors["text"]}; background: {self._colors["surface"]}; border: 1px solid {self._colors["border"]}; border-radius: 6px; padding: 5px; font-size: 8pt; }}
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
        self.import_button.setIcon(qta.icon("fa6s.file-import", color="#ffffff"))
        self.import_button.hide()

        self.replace_button = self.add_button(
            "Replace", primary=False, callback=self.replace_bridges
        )
        self.replace_button.setIcon(qta.icon("fa6s.arrow-rotate-left", color=self._colors["text"]))
        self.replace_button.hide()

        self.add_bridges_button = self.add_button(
            "Add", primary=True, callback=self.add_bridges
        )
        self.add_bridges_button.setIcon(qta.icon("fa6s.plus", color="#ffffff"))
        self.add_bridges_button.hide()

        self._set_status("Starting camera…", level="working")
        self._remember_preferred_size()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "scan_overlay"):
            self.scan_overlay.update()

    def _toggle_detected_results(self, expanded: bool):
        self.results_panel.setVisible(bool(expanded))
        icon = "fa6s.chevron-up" if expanded else "fa6s.chevron-down"
        self.results_toggle.setIcon(qta.icon(icon, color="#53d9c5"))
        if expanded:
            # The result drawer should not push the dialog below the monitor's
            # work area when a long bridge payload is recognized.
            self.adjustSize()
            self._remember_preferred_size()
            self.move(self.clamp_to_screen(self.pos()))

    def _configure_import_actions(self):
        settings = self.parent_
        editor = getattr(settings, "inp_bridges", None)
        existing = editor.toPlainText() if editor is not None else ""
        show_import, show_replace, show_add = bridge_import_actions(existing)
        self.import_button.setVisible(show_import)
        self.replace_button.setVisible(show_replace)
        self.add_bridges_button.setVisible(show_add)

    def _apply_detected_bridges(self, mode: str):
        if not self._detected_bridges:
            return
        settings = self.parent_
        editor = getattr(settings, "inp_bridges", None)
        if editor is None:
            self._set_status("The bridge settings field is no longer available.", level="error")
            return

        imported = list(self._detected_bridges)
        if mode == "add":
            imported = merge_bridge_lines(editor.toPlainText(), imported)

        editor.setPlainText("\n".join(imported))
        enable_checkbox = getattr(settings, "btn_bridge", None)
        if enable_checkbox is not None and not enable_checkbox.isChecked():
            enable_checkbox.setChecked(True)
        if mode == "add":
            self._set_status(f"Added bridge lines. {len(imported)} line(s) now in Settings.", level="success")
        elif mode == "replace":
            self._set_status(f"Replaced the bridge list with {len(imported)} detected line(s).", level="success")
        else:
            self._set_status(f"Imported {len(imported)} bridge line(s) into Settings.", level="success")
        self.accept()

    def import_bridges(self):
        """Import decoded bridges when the settings field is empty."""
        self._apply_detected_bridges("import")

    def replace_bridges(self):
        """Replace the current bridge list with the decoded QR result."""
        self._apply_detected_bridges("replace")

    def add_bridges(self):
        """Append decoded bridges without duplicating existing entries."""
        self._apply_detected_bridges("add")

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
        self.scan_overlay.clear_detection()
        self.results_toggle.setChecked(False)
        self.results_toggle.hide()
        self.results_panel.hide()
        self.import_button.hide()
        self.replace_button.hide()
        self.add_bridges_button.hide()
        self.retry_button.hide()
        self.details_label.setText(
            "Your QR data is checked locally. TorProxy only imports recognized bridge lines."
        )
        self.scan_overlay.clear_detection()
        self.scan_overlay.set_placeholder("Opening camera…")
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

    def _camera_failed(self, message: str):
        self.scan_overlay.stop_animation()
        logger.warning("QR camera unavailable: %s", message)
        self.scan_overlay.set_placeholder(
            "Camera unavailable\n\nCheck camera access and try again."
        )
        self._set_status(message, level="error")
        self.details_label.setText(
            "If another app is using your camera, close it and select Scan again."
        )
        self.retry_button.show()

    def _show_frame(self, image: QImage):
        self.scan_overlay.set_frame(image)

    def _qr_detected(self, payload: str, image: QImage, corners):
        bridges = parse_bridge_payload(payload)
        self.scan_overlay.set_frame(image)
        self.scan_overlay.set_detected(
            corners, (image.width(), image.height())
        )
        self._detected_bridges = bridges
        if not bridges:
            self._set_status(
                "A QR code was found, but it doesn't contain recognizable Tor bridge lines.",
                level="invalid",
            )
            self.details_label.setText(
                "Only bridge payloads are imported. Nothing has been changed in your settings."
            )
            self.results_toggle.hide()
            self.results_panel.hide()
            self.import_button.hide()
            self.replace_button.hide()
            self.add_bridges_button.hide()
            self.retry_button.show()
            return

        count = len(bridges)
        self._set_status(
            f"Found {count} Tor bridge line{'s' if count != 1 else ''}. Review the result below.",
            level="success",
        )
        self.details_label.setText(
            "The detected frame is frozen. Open the details below to review the bridge lines before importing."
        )
        self.results_text.setPlainText("\n".join(bridges))
        self.results_summary.setText(f"{count} verified bridge line(s)")
        self.results_toggle.setText(f"Detected bridges · {count}")
        self.results_toggle.setChecked(False)
        self.results_toggle.setIcon(qta.icon("fa6s.chevron-down", color="#53d9c5"))
        self.results_toggle.show()
        self.results_panel.hide()
        self._configure_import_actions()
        self.retry_button.show()

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
