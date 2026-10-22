from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QWidget,
    QButtonGroup,
    QRadioButton,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QCheckBox,
    QTextEdit,
    QLineEdit,
    QStackedWidget,
    QListWidget,
    QMessageBox
)
from PySide6.QtCore import Qt, QThreadPool

import qdarkstyle
from qdarkstyle.dark.palette import DarkPalette
from qdarkstyle.light.palette import LightPalette

from pyzbar.pyzbar import decode
import re
import logging
from functools import partial

logger = logging.getLogger(__name__)

from config import CONFIG
from ui_.worker.worker import Worker
from ui_.window.qrcode_widget import QrCodeFloatingWindow
from config import IS_WINDOWS
from ui_.emojis import WRONG, CORRECT, LIGHT, DARK

class SettingWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._parent = parent
        main_layout = QVBoxLayout(self)
        self.setLayout(main_layout)

        top_layout = QHBoxLayout(self)
        btn_before_page = QPushButton("⬅️")
        btn_before_page.clicked.connect(self.go_to_before_page)

        top_layout.addWidget(btn_before_page)
        self.lbl_page_number = QLabel("0")
        self.lbl_page_number.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_page_number.setFixedWidth(20)
        top_layout.addWidget(self.lbl_page_number)
        btn_next_page = QPushButton("➡️")
        btn_next_page.clicked.connect(self.go_to_next_page)
        top_layout.addWidget(btn_next_page)

        main_layout.addLayout(top_layout)

        self.page_setting = QStackedWidget()
        main_layout.addWidget(self.page_setting)

        self.first_page = QWidget()
        self.first_page_layout = QVBoxLayout()
        self.first_page.setLayout(self.first_page_layout)
        self.page_setting.addWidget(self.first_page)

        self.initialize_first_page()
        self.initialize_second_page()

    def initialize_first_page(self):
        mode_layout = QHBoxLayout(self)
        self.first_page_layout.addLayout(mode_layout)

        btn_group_mode = QButtonGroup(self)

        # use CONFIG[...] (Config implements __getitem__)
        self.btn_dark = QRadioButton("dark", self)
        self.btn_dark.setChecked(CONFIG["mode"] != "light")
        mode_layout.addWidget(self.btn_dark)
        btn_group_mode.addButton(self.btn_dark)

        self.btn_light = QRadioButton("light", self)
        self.btn_light.setChecked(CONFIG["mode"] == "light")
        mode_layout.addWidget(self.btn_light)
        btn_group_mode.addButton(self.btn_light)

        # bridge checkbox
        btn_bridge = QCheckBox("bridge", self)
        btn_bridge.setChecked(bool(CONFIG["bridge"]))
        btn_bridge.stateChanged.connect(self.bridge_state_changed)
        self.first_page_layout.addWidget(btn_bridge)

        self.inp_bridges = QTextEdit(self, placeholderText="Enter your bridges . . . (obfs4 or webtunnel)")
        self.inp_bridges.setText(CONFIG["bridges"] or "")
        self.inp_bridges.setEnabled(bool(CONFIG["bridge"]))
        self.inp_bridges.textChanged.connect(self.set_bridges)
        self.first_page_layout.addWidget(self.inp_bridges)

        btn_group_mode.buttonClicked.connect(self.change_mode)
        self.btn_qrcode = QPushButton("Qr-Code")
        self.btn_qrcode.clicked.connect(self.show_qrcode)
        self.first_page_layout.addWidget(self.btn_qrcode)

        max_circuit_dirtiness_layout = QHBoxLayout()
        max_circuit_dirtiness_layout.addWidget(QLabel("MaxCircuitDirtiness  "))
        self.first_page_layout.addLayout(max_circuit_dirtiness_layout)

        # read from parent.tor if available, else from CONFIG or fallback
        try:
            start_val = getattr(self._parent.proxyWidget.tor, "MaxCircuitDirtiness")
            if start_val is None:
                start_val = CONFIG["MaxCircuitDirtiness"] or 10
        except Exception:
            start_val = CONFIG["MaxCircuitDirtiness"] or 10

        self.inp_MaxCircuitDirtiness = QLineEdit(str(start_val))
        max_circuit_dirtiness_layout.addWidget(self.inp_MaxCircuitDirtiness)
        self.inp_MaxCircuitDirtiness.textChanged.connect(self.MaxCircuitDirtiness_changed)
        self.lbl_MaxCircuitDirtiness = QLabel(CORRECT)
        max_circuit_dirtiness_layout.addWidget(self.lbl_MaxCircuitDirtiness)

        # Automatic identity rotation is intentionally disabled by default.
        self.first_page_layout.addWidget(QLabel(
            "Identity changes are manual. Tor rate-limits NEWNYM; requesting it does not guarantee a new exit IP."
        ))
        self.qrcode_widget = QrCodeFloatingWindow(self)

        self.threadpool = QThreadPool()

    def initialize_second_page(self):
        self.second_page = QWidget()
        self.page_setting.addWidget(self.second_page)

        self.second_page_layout = QVBoxLayout()
        self.second_page.setLayout(self.second_page_layout)

        ports = ["tor_port", "proxy_port", "dns_port", "control_port"]
        for port in ports:
            lyt = QHBoxLayout()
            lbl = QLabel(port)
            inp_port = QLineEdit()

            # populate input with existing value if present (avoid "None" string)
            current_val = CONFIG[port]
            inp_port.setText(str(current_val) if current_val is not None else "")

            enabled_initial = bool(CONFIG[port + "_checked"]) if CONFIG[port + "_checked"] is not None else False
            inp_port.setEnabled(enabled_initial)

            lbl_status = QLabel(CORRECT if enabled_initial and self._is_valid_port(current_val) else WRONG)
            check_port = QCheckBox()
            check_port.setChecked(enabled_initial)

            # connect text changed -> validator (partial binds the widgets)
            inp_port.textChanged.connect(partial(self.inp_port_changed, inp_port, lbl_status, port))

            # connect checkbox state change -> enable/disable input and update CONFIG
            # stateChanged provides an int state; partial with keywords keeps signature clean
            check_port.stateChanged.connect(partial(self.check_port_changed, inp_port=inp_port, lbl_status=lbl_status, port=port))

            lyt.addWidget(lbl)
            lyt.addWidget(inp_port)
            lyt.addWidget(lbl_status)
            lyt.addWidget(check_port)

            self.second_page_layout.addLayout(lyt)
        
   
    def _enabled_port_conflict(self, port: str, value: int) -> str | None:
        for other in ("tor_port", "proxy_port", "dns_port", "control_port"):
            if other == port or not CONFIG[other + "_checked"]:
                continue
            current = CONFIG[other]
            try:
                if current is not None and int(current) == value:
                    return other
            except (TypeError, ValueError):
                continue
        return None

    def inp_port_changed(self, inp_port, lbl_status, port, text=None):
        value = inp_port.text().strip() if text is None else str(text).strip()
        if not value or not self._is_valid_port(value):
            lbl_status.setText(WRONG)
            try:
                CONFIG[port] = None
            except (ValueError, OSError) as exc:
                logger.warning("Could not clear invalid %s setting: %s", port, exc)
            return

        port_value = int(value)
        conflict = self._enabled_port_conflict(port, port_value) if CONFIG[port + "_checked"] else None
        if conflict:
            lbl_status.setText(WRONG)
            try:
                CONFIG[port] = None
            except (ValueError, OSError) as exc:
                logger.warning("Could not clear conflicting %s setting: %s", port, exc)
            logger.warning("Port %s conflicts with enabled %s.", port_value, conflict)
            return

        try:
            CONFIG[port] = port_value
        except (ValueError, OSError) as exc:
            lbl_status.setText(WRONG)
            logger.warning("Could not save %s: %s", port, exc)
            return

        lbl_status.setText(CORRECT)
        try:
            proxy = getattr(self._parent, "proxyWidget", None)
            if proxy and hasattr(proxy, "set_port"):
                proxy.set_port(port, port_value)
            elif proxy:
                setattr(proxy, port, port_value)
        except Exception:
            pass

    def check_port_changed(self, state: int, inp_port: QLineEdit = None, lbl_status: QLabel = None, port: str = ""):
        enabled = bool(state)
        val_text = inp_port.text().strip() if inp_port is not None else ""
        if enabled and self._is_valid_port(val_text):
            conflict = self._enabled_port_conflict(port, int(val_text))
            if conflict:
                if lbl_status is not None:
                    lbl_status.setText(WRONG)
                QMessageBox.warning(
                    self, "Port conflict",
                    f"Port {val_text} is already assigned to enabled setting '{conflict}'."
                )
                checkbox = self.sender()
                if checkbox is not None and hasattr(checkbox, "setChecked"):
                    checkbox.setChecked(False)
                return

        if inp_port is not None:
            inp_port.setEnabled(enabled)
        try:
            CONFIG[port + "_checked"] = enabled
        except (ValueError, OSError) as exc:
            logger.warning("Could not update %s enabled flag: %s", port, exc)
            if lbl_status is not None:
                lbl_status.setText(WRONG)
            checkbox = self.sender()
            if enabled and checkbox is not None and hasattr(checkbox, "setChecked"):
                checkbox.setChecked(False)
            return

        if lbl_status is not None:
            lbl_status.setText(CORRECT if enabled and self._is_valid_port(val_text) else WRONG)

    # ---------- other helpers ----------
    def go_to_before_page(self):
        current_index = self.page_setting.currentIndex()
        new_index = max(0, current_index - 1)
        self.page_setting.setCurrentIndex(new_index)
        self.lbl_page_number.setText(f"{self.page_setting.currentIndex()}")

    def go_to_next_page(self):
        current_index = self.page_setting.currentIndex()
        new_index = min(self.page_setting.count() - 1, current_index + 1)
        self.page_setting.setCurrentIndex(new_index)
        self.lbl_page_number.setText(f"{self.page_setting.currentIndex()}")

    def show_qrcode(self):
        worker = Worker(self.qrcode_widget.run)
        worker.signals.finished.connect(self.show_qrcode_widget)
        worker.signals.error.connect(self.show_qrcode_widget)
        self.threadpool.start(worker)
        self.btn_qrcode.setDisabled(True)

    def show_qrcode_widget(self, *args):
        self.qrcode_widget.setParent(self)
        self.qrcode_widget.move(80, 0)
        self.qrcode_widget.show()
        self.qrcode_widget.timer.start(30)
        self.btn_qrcode.setEnabled(True)
        
    def newnym_inp_changed(self):
        text = self.newnym_inp.text().strip()
        if text and text.isdigit() and 0 < int(text) < 2_147_483_647:
            try:
                interval = int(text)
                # set to parent timer if exists
                try:
                    self._parent.proxyWidget.timer.setInterval(interval)
                except Exception:
                    pass
                self.newnym_lbl_stat.setText(f"({interval//1000} sec)  " + CORRECT )
                CONFIG["newnym_interval"] = interval
            except OverflowError:
                logger.error("newnym interval overflow: %s", text)
                self.newnym_lbl_stat.setText(WRONG)
        else:
            self.newnym_lbl_stat.setText(WRONG)

    def MaxCircuitDirtiness_changed(self):
        text = self.inp_MaxCircuitDirtiness.text().strip()
        if text and text.isdigit():
            val = int(text)
            try:
                self._parent.proxyWidget.tor.MaxCircuitDirtiness = val
            except Exception:
                pass
            CONFIG["MaxCircuitDirtiness"] = val
            self.lbl_MaxCircuitDirtiness.setText(CORRECT)
        else:
            self.lbl_MaxCircuitDirtiness.setText(WRONG)

    def set_bridges(self):
        txt = self.inp_bridges.toPlainText()
        try:
            self._parent.proxyWidget.tor.bridges = txt
        except Exception:
            pass
        CONFIG["bridges"] = txt

    def bridge_state_changed(self, state):
        checked = bool(state)
        try:
            self._parent.proxyWidget.tor.bridge = checked
        except Exception:
            pass
        self.inp_bridges.setEnabled(checked)
        CONFIG["bridge"] = bool(checked)

    def change_mode(self, radiobtn):
        app = QApplication.instance()
        if radiobtn.text() == "light":
            app.setStyleSheet(qdarkstyle.load_stylesheet(palette=LightPalette()))
            CONFIG["mode"] = "light"
            try:
                self._parent.toggle_btn.setText(LIGHT)
            except Exception:
                pass
        else:
            app.setStyleSheet(qdarkstyle.load_stylesheet(palette=DarkPalette()))
            CONFIG["mode"] = "dark"
            try:
                self._parent.toggle_btn.setText(DARK)
            except Exception:
                pass

    # small utility
    @staticmethod
    def _is_valid_port(value):
        try:
            p = int(value)
            return 0 < p <= 65535
        except Exception:
            return False
