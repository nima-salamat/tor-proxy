from PySide6.QtWidgets import (
    QLabel,
    QWidget,
    QVBoxLayout,
    QPushButton,
)
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtCore import Qt, QTimer
import json
import cv2
from pyzbar.pyzbar import decode
import numpy
import logging

logger = logging.getLogger(__name__)

from ui_.window.dialogs import QMessageBox
from ui_.worker.worker import Worker

class QrCodeFloatingWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.parent_ = parent
        self.cap = None
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_frame)
        
        self.data = None
        
        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)
        
        self.camera_label = QLabel() 
        self.camera_label.setAlignment(Qt.AlignCenter)
        self.camera_label.setMinimumSize(640, 480)
        self.main_layout.addWidget(self.camera_label)
        
        self.btn_close = QPushButton("close")
        self.btn_close.clicked.connect(self.close)
        self.main_layout.addWidget(self.btn_close)
        
    
    def update_frame(self):
        ret, frame = self.cap.read()
        if not ret:
            QMessageBox.warning(self, "", "Error in reading frame")
            self.close()

        frame  = numpy.flip(frame, (1))
            
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

        decoded_objects = decode(rgb_frame)
        
        for obj in decoded_objects:
            try:
                data = obj.data.decode('utf-8')
                self.process_qr_code(data, frame, obj)
            except Exception as e:
                logger.error(f"Error decoding QR: {e}")
                
        h, w, ch = rgb_frame.shape
        bytes_per_line = ch * w
        qt_image = QImage(rgb_frame.data, w, h, bytes_per_line, QImage.Format_RGB888)
        self.camera_label.setPixmap(QPixmap.fromImage(qt_image).scaled(
            self.camera_label.width(), 
            self.camera_label.height(),
            Qt.KeepAspectRatio
        ))
    
    def run(self):
        self.cap = cv2.VideoCapture(0)
    
    def process_qr_code(self, data, *args):
        self.data = data
        QMessageBox.information(self, "QR Code Detected!", "Ok")
        self.close()
      
    def close(self):
        self.cap.release()
        self.timer.stop()
        if self.data is not None:
            self.parent_.inp_bridges.setText("\n".join(json.loads(self.data)))
        super().close()
