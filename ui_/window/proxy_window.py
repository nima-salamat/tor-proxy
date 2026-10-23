from PySide6.QtWidgets import (
    QLabel,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QFrame,
    QPushButton,
    QMessageBox,
    QComboBox,
    QSizePolicy,
)


from PySide6.QtCore import Qt, QTimer, QThreadPool, QPropertyAnimation, QEasingCurve
from stem import Signal as TorSignal
from stem.control import Controller
from stem import SocketClosed, OperationFailed
from stem.connection import AuthenticationFailure

from proxy import get_free_port, is_port_free
from set_proxy import has_proxy_snapshot, manage_proxy
from tor import TorRunner, Runner

from whatismyip import what_is_my_ip
from ui_.window.log_window import LogWindow
from ui_.btn.pulse_button import PulseButton
from ui_.worker.worker import Worker
from ui_.worker.utils import Data
from config import CONFIG
import json
import logging
import qtawesome as qta

logger = logging.getLogger(__name__)



class ProxyWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = Data()
        self.running = False
        self.connected = False
        self.failed = False
        self.proxy_set = has_proxy_snapshot()  # also recover safely after an unclean previous exit
        self._stopping = False
        self._identity_busy = False
        self._parent = parent
        chosen_ports = []
        while len(chosen_ports) < 4:
            candidate = get_free_port()
            if candidate not in chosen_ports:
                chosen_ports.append(candidate)
        self.tor_socks_port, self.proxy_port, self.tor_control_port, self.tor_dns_port = chosen_ports
        logger.info(f'port(proxy): {self.proxy_port} - port(socks): {self.tor_socks_port} - port(control): {self.tor_control_port}, - port(dns): {self.tor_dns_port}')
        self.tor = TorRunner(self.tor_socks_port, self.tor_control_port, self.tor_dns_port)
        self.tor.bridge = CONFIG["bridge"]
        self.tor.bridges = CONFIG["bridges"]
        self.tor.app_window = self
        self.proxy = Runner(self.proxy_port, self.tor_socks_port,self)
        # Animated left-side Event Log drawer and a clean, spacious Home canvas.
        self.main_layout = QHBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        self.logs_widget = LogWindow(self)
        self.logs_open = False
        self._logs_animation = None
        self._system_proxy_action_busy = False
        self._system_proxy_is_cleared = False
        self._system_proxy_clear_failed = False
        self.logs_widget.setMinimumWidth(0)
        self.logs_widget.setMaximumWidth(0)
        self.logs_widget.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        self.main_layout.addWidget(self.logs_widget, 0)

        self.home_content = QWidget(self)
        self.home_content.setObjectName("homeContent")
        self.home_layout = QVBoxLayout(self.home_content)
        self.home_layout.setContentsMargins(26, 18, 26, 14)
        self.home_layout.setSpacing(10)
        self.main_layout.addWidget(self.home_content, 1)

        self.btn_status = QLabel("NOT CONNECTED")
        self.btn_status.setObjectName("connectionStatus")
        self.btn_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_btn_status_style("disconnected")
        self.home_layout.addWidget(self.btn_status, 0, Qt.AlignmentFlag.AlignHCenter)

        self.connect_btn = PulseButton("Connect")
        self.connect_btn.setObjectName("connectPulseButton")
        self.connect_btn.clicked.connect(self._toggle)
        connect_row = QHBoxLayout()
        connect_row.setContentsMargins(0, 0, 0, 0)
        connect_row.addStretch(1)
        connect_row.addWidget(self.connect_btn, 0, Qt.AlignmentFlag.AlignCenter)
        connect_row.addStretch(1)
        self.home_layout.addLayout(connect_row, 1)

        metrics = QHBoxLayout()
        metrics.setContentsMargins(0, 0, 0, 0)
        metrics.setSpacing(14)
        self.lbl_percent = QLabel("0%")
        self.lbl_percent.setObjectName("bootstrapPercent")
        self.lbl_data_usage = QLabel(
            f"Proxy traffic  ·  {CONFIG['data_usage'] / 1024**2:.2f} MiB"
        )
        self.lbl_data_usage.setObjectName("trafficUsage")
        metrics.addStretch(1)
        metrics.addWidget(self.lbl_percent)
        separator = QFrame(self.home_content)
        separator.setObjectName("homeMetricSeparator")
        separator.setFrameShape(QFrame.Shape.VLine)
        metrics.addWidget(separator)
        metrics.addWidget(self.lbl_data_usage)
        metrics.addStretch(1)
        self.home_layout.addLayout(metrics)
        self.data.valueChanged.connect(self.dataValueChanged)

        proxy_row = QHBoxLayout()
        proxy_row.setContentsMargins(0, 0, 0, 0)
        proxy_row.setSpacing(12)
        proxy_title = QLabel("SYSTEM PROXY")
        proxy_title.setObjectName("systemProxyTitle")
        proxy_row.addWidget(proxy_title)
        self.system_proxy_mode = QComboBox(self.home_content)
        self.system_proxy_mode.setObjectName("systemProxyMode")
        self.system_proxy_mode.addItem("Set system proxy", "set")
        self.system_proxy_mode.addItem("Do not change system proxy", "unchanged")
        self.system_proxy_mode.addItem("Clear system proxy", "clear")
        current_mode = CONFIG["system_proxy_mode"]
        mode_index = self.system_proxy_mode.findData(current_mode)
        self.system_proxy_mode.setCurrentIndex(mode_index if mode_index >= 0 else 1)
        self.system_proxy_mode.currentIndexChanged.connect(self._on_system_proxy_mode_changed)
        proxy_row.addWidget(self.system_proxy_mode, 1)
        self.home_layout.addLayout(proxy_row)

        self.proxy_status_label = QLabel()
        self.proxy_status_label.setObjectName("proxyStatusLabel")
        self.proxy_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.proxy_status_label.setWordWrap(True)
        self.home_layout.addWidget(self.proxy_status_label)

        self.tor_ip_label = QLabel("Exit IP: not checked")
        self.tor_ip_label.setObjectName("exitIpLabel")
        self.tor_ip_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.tor_ip_label.setWordWrap(True)
        self.home_layout.addWidget(self.tor_ip_label)

        utility_row = QHBoxLayout()
        utility_row.setSpacing(8)
        self.btn_change_identity = QPushButton(qta.icon("fa6s.arrows-rotate"), "  New Identity")
        self.btn_change_identity.setObjectName("secondaryAction")
        self.btn_change_identity.clicked.connect(self.change_identity_)
        utility_row.addWidget(self.btn_change_identity)
        self.btn_log = QPushButton(qta.icon("fa6s.align-left"), "  Event Log")
        self.btn_log.setObjectName("secondaryAction")
        self.btn_log.setCheckable(True)
        self.btn_log.clicked.connect(self.show_logs)
        utility_row.addWidget(self.btn_log)
        self.btn_whatismyip = QPushButton(qta.icon("fa6s.globe"), "  Check Exit IP")
        self.btn_whatismyip.setObjectName("secondaryAction")
        self.btn_whatismyip.clicked.connect(self.whatismyip_clicked)
        utility_row.addWidget(self.btn_whatismyip)
        self.home_layout.addLayout(utility_row)

        self.thread_pool = QThreadPool(self)
        self.tor.log_message.connect(self.logs_widget.update_log)
        self.tor.service_failed.connect(self._on_tor_failed)
        self.logs_widget.apply_theme(CONFIG["mode"])
        self._apply_home_theme()
        self._update_proxy_buttons()
        self._update_proxy_mode_status()
        if CONFIG["system_proxy_mode"] == "clear":
            # Defer the operating-system change until the complete UI has been built.
            QTimer.singleShot(0, self._clear_system_proxy_mode)
        self.timer = QTimer(self)
        self.timer.setInterval(int(CONFIG["newnym_interval"] or 0))

        self.timer_data_usage = QTimer()
        self.timer_data_usage.setInterval(1000)
        self.timer_data_usage.timeout.connect(self.change_data_usage)

    def change_data_usage(self):
        self.lbl_data_usage.setText(f"Proxy traffic (both directions): {CONFIG['data_usage']/1024**2:.2f} MiB")

    def whatismyip_clicked(self):
        if not self.running or not self.connected:
            self.tor_ip_label.setText("Exit IP: unavailable — Tor proxy is not ready")
            return
        proxy_url = f"http://127.0.0.1:{self.proxy.port}"
        self.btn_whatismyip.setEnabled(False)
        self.tor_ip_label.setText("Exit IP: checking through Tor proxy…")
        self.worker = Worker(lambda: what_is_my_ip(proxy=proxy_url, timeout=10))
        self.worker.signals.finished.connect(self._on_exit_ip_checked)
        self.worker.signals.error.connect(self._on_exit_ip_failed)
        self.thread_pool.start(self.worker)

    def _on_exit_ip_checked(self, result):
        if result and result != "None":
            self.tor_ip_label.setText("Observed exit IP (proxied): " + result)
        else:
            self.tor_ip_label.setText("Exit IP: unverified")
        self.btn_whatismyip.setEnabled(True)

    def _on_exit_ip_failed(self, error):
        logger.warning("Proxied exit-IP check failed: %s", error)
        self.tor_ip_label.setText("Exit IP check failed — no direct fallback used")
        self.logs_widget.update_log(f"Exit-IP verification failed: {error}")
        self.btn_whatismyip.setEnabled(True)

    def show_logs(self):
        opening = not self.logs_open
        self.logs_open = opening
        self.btn_log.setChecked(opening)
        if self._logs_animation is not None:
            self._logs_animation.stop()
        target_width = min(400, max(292, int(self.width() * 0.36))) if opening else 0
        animation = QPropertyAnimation(self.logs_widget, b"maximumWidth", self)
        animation.setDuration(240)
        animation.setEasingCurve(
            QEasingCurve.Type.OutCubic if opening else QEasingCurve.Type.InCubic
        )
        animation.setStartValue(self.logs_widget.maximumWidth())
        animation.setEndValue(target_width)
        animation.finished.connect(lambda: self.logs_widget.setMaximumWidth(target_width))
        self._logs_animation = animation
        animation.start()

    def _apply_home_theme(self):
        dark = CONFIG["mode"] == "dark"
        border = "#3b4552" if dark else "#d7dee7"
        muted = "#aab4c1" if dark else "#667386"
        accent = "#47a3f2" if dark else "#1876bf"
        surface = "#202630" if dark else "#ffffff"
        text = "#e8edf3" if dark else "#253041"
        self.home_content.setStyleSheet(f"""
            QWidget#homeContent {{ background: transparent; }}
            QPushButton#connectPulseButton {{ background: transparent; border: none; padding: 0; margin: 0; }}
            QPushButton#connectPulseButton:hover, QPushButton#connectPulseButton:pressed, QPushButton#connectPulseButton:focus {{ background: transparent; border: none; }}
            QLabel#connectionStatus {{ color: {text}; background: transparent; border: none; padding: 4px; font-size: 12px; font-weight: 700; }}
            QLabel#connectionStatus[connectionState="connected"] {{ color: #2eae69; }}
            QLabel#connectionStatus[connectionState="connecting"] {{ color: {accent}; }}
            QLabel#connectionStatus[connectionState="disconnected"] {{ color: palette(text); }}
            QLabel#bootstrapPercent {{ color: {accent}; background: transparent; border: none; font-size: 14px; font-weight: 700; padding: 3px; }}
            QLabel#trafficUsage, QLabel#proxyStatusLabel, QLabel#exitIpLabel {{ color: {muted}; background: transparent; border: none; font-size: 11px; padding: 2px; }}
            QLabel#systemProxyTitle {{ color: {muted}; background: transparent; border: none; font-size: 10px; font-weight: 750; letter-spacing: 1px; }}
            QFrame#homeMetricSeparator {{ color: {border}; background: {border}; max-width: 1px; }}
            QComboBox#systemProxyMode {{ min-height: 34px; padding: 0 12px; border: 1px solid {border}; border-radius: 8px; background: {surface}; color: {text}; }}
            QComboBox#systemProxyMode:hover {{ border-color: {accent}; }}
            QComboBox#systemProxyMode QAbstractItemView {{ background: {surface}; color: {text}; selection-background-color: {accent}; selection-color: #ffffff; outline: none; border: 1px solid {border}; }}
            QComboBox#systemProxyMode QAbstractItemView::item {{ background: {surface}; color: {text}; padding: 8px 10px; min-height: 22px; }}
            QComboBox#systemProxyMode QAbstractItemView::item:selected {{ background: {accent}; color: #ffffff; }}
            QPushButton#secondaryAction {{ min-height: 36px; padding: 0 14px; border-radius: 8px; background: transparent; color: {text}; border: 1px solid {border}; font-weight: 600; }}
            QPushButton#secondaryAction:hover {{ background: rgba(71, 163, 242, 0.12); border-color: {accent}; }}
            QPushButton#secondaryAction:checked {{ background: rgba(71, 163, 242, 0.18); border-color: {accent}; }}
        """)
        self.logs_widget.apply_theme(CONFIG["mode"])
        icon_color = "#eff1f4" if dark else "#202832"
        self.btn_change_identity.setIcon(qta.icon("fa6s.arrows-rotate", color=icon_color))
        self.btn_log.setIcon(qta.icon("fa6s.align-left", color=icon_color))
        self.btn_whatismyip.setIcon(qta.icon("fa6s.globe", color=icon_color))

    def _on_system_proxy_mode_changed(self, index):
        mode = self.system_proxy_mode.itemData(index)
        if mode not in {"set", "unchanged", "clear"}:
            return
        try:
            CONFIG["system_proxy_mode"] = mode
        except (ValueError, OSError, KeyError) as exc:
            logger.exception("Could not save system proxy mode.")
            QMessageBox.warning(self, "System proxy setting", str(exc))
            return
        self.logs_widget.update_log("System proxy mode changed to: {}".format(mode))
        if mode == "set":
            if self.running and self.connected:
                self.set_proxy_clicked()
            else:
                self.proxy_status_label.setText("Will apply the system proxy automatically after Tor connects.")
        elif mode == "clear":
            self._clear_system_proxy_mode()
        else:
            self.proxy_status_label.setText("TorProxy will not change the system proxy automatically.")

    def _update_proxy_mode_status(self):
        mode = CONFIG["system_proxy_mode"]
        if mode == "set":
            status = (
                "System proxy is active at 127.0.0.1:{}.".format(self.proxy.port)
                if self.proxy_set else
                "Will apply the system proxy automatically after Tor connects."
            )
        elif mode == "clear":
            if self._system_proxy_action_busy:
                status = "Clearing the system proxy…"
            elif self._system_proxy_clear_failed:
                status = "Could not clear the system proxy; it may still be enabled."
            elif self._system_proxy_is_cleared:
                status = "System proxy is cleared; direct mode is active."
            else:
                status = "Clear mode selected; system proxy cleanup is pending."

        else:
            status = (
                "System proxy is currently set by TorProxy; no automatic changes will be made."
                if self.proxy_set else
                "System proxy will not be changed by TorProxy."
            )
        self.proxy_status_label.setText(status)

    def _clear_system_proxy_mode(self):
        if getattr(self, "_system_proxy_action_busy", False):
            return
        self._system_proxy_action_busy = True
        self._system_proxy_clear_failed = False
        self.proxy_status_label.setText("Clearing the system proxy…")
        self.system_proxy_mode.setEnabled(False)
        worker = Worker(lambda: manage_proxy("127.0.0.1", self.proxy.port, "disable"))
        worker.signals.finished.connect(self._on_system_proxy_cleared)
        worker.signals.error.connect(self._on_system_proxy_clear_failed)
        self.thread_pool.start(worker)

    def _on_system_proxy_cleared(self, result):
        self._system_proxy_action_busy = False
        self.system_proxy_mode.setEnabled(True)
        if str(result).strip().lower() != "true":
            self._on_system_proxy_clear_failed("The operating system did not clear the system proxy.")
            return
        self.proxy_set = False
        self._system_proxy_is_cleared = True
        self._system_proxy_clear_failed = False
        self.proxy_status_label.setText("System proxy cleared; direct mode is active.")
        self.logs_widget.update_log("System proxy cleared by the selected policy.")
        self._update_proxy_buttons()

    def _on_system_proxy_clear_failed(self, error):
        self._system_proxy_action_busy = False
        self._system_proxy_clear_failed = True
        self.system_proxy_mode.setEnabled(True)
        self.logs_widget.update_log("Could not clear system proxy: {}".format(error))
        QMessageBox.warning(self, "System proxy", "Could not clear the system proxy. Check the event log.")
        logger.warning("Explicit system proxy clear failed: %s", error)
        self._update_proxy_mode_status()

    def change_identity_(self):
        if self._identity_busy or not self.connected:
            return
        self._identity_busy = True
        self.btn_change_identity.setEnabled(False)
        worker = Worker(self.change_identity)
        worker.signals.finished.connect(self._on_identity_finished)
        worker.signals.error.connect(self._on_identity_error)
        self.thread_pool.start(worker)

    def _on_identity_finished(self, result):
        self._identity_busy = False
        self.btn_change_identity.setEnabled(True)
        if str(result).strip().lower() != "true":
            self.logs_widget.update_log("Identity request was not accepted; Tor may be rate-limiting NEWNYM.")
            logger.info("Identity request was not accepted (not ready or rate-limited).")
        else:
            self.logs_widget.update_log("Tor accepted NEWNYM. Existing connections may retain their circuits; a different IP is not guaranteed.")

    def _on_identity_error(self, error):
        self._identity_busy = False
        self.btn_change_identity.setEnabled(True)
        self.logs_widget.update_log(f"Identity request failed: {error}")
        logger.warning("Identity request failed: %s", error)

    def change_identity(self):
        if not self.connected:
            logger.warning("Identity change requested while Tor is not connected.")
            return False

        try:
            wait = float(self.controller.get_newnym_wait())
            if wait > 0:
                message = f"Tor rate-limits identity requests; try again in about {wait:.0f} seconds."
                logger.info(message)
                return False
            self.controller.signal(TorSignal.NEWNYM)
            logger.info("Tor accepted the NEWNYM request; a different exit IP is not guaranteed.")
            return True

        except SocketClosed:
            logger.error("Tor control socket is closed. Marking connection as disconnected.")
            self.connected = False
            return False

        except AuthenticationFailure:
            logger.critical("Authentication to Tor control port failed. Check password or cookie.")
            return False

        except OperationFailed:
            logger.warning("Tor NEWNYM signal was rejected. Possibly due to rate limit.")
            return False

        except Exception as e:
            logger.exception(f"Unexpected error while sending NEWNYM: {e}")
            return False

    def dataValueChanged(self, v):
        if v == "100%":
            if self._parent.isHidden():
                self._parent._notify("TorProxy", "Tor bootstrap completed")
            try:
                self.controller = Controller.from_port(address="127.0.0.1", port=self.tor_control_port)
                self.controller.authenticate()
            except Exception as e:
                logger.exception("Could not authenticate to the managed Tor ControlPort: %s", e)
                self.logs_widget.update_log(f"Tor bootstrap completed but ControlPort authentication failed: {e}")
                self.connected = False
                self.failed = True
                self.connect_btn.set_connected(False)
                if self.running:
                    self._stop_services()
                self.btn_status.setText("CONTROL AUTHENTICATION FAILED · SEE EVENT LOG")
                self.set_btn_status_style("disconnected")
                if self._parent is not None and hasattr(self._parent, "notify_user"):
                    self._parent.notify_user(
                        "Tor control authentication failed",
                        str(e),
                        level="warning",
                    )
                self._update_proxy_buttons()
                return
            self.connected = True
            self.connect_btn.set_connected(True)
            self.btn_status.setText("CONNECTED TO TOR")
            self.set_btn_status_style("connected")
            self._update_proxy_buttons()
            self._apply_system_proxy_mode()
            self.timer_data_usage.start()

        self.lbl_percent.setText(str(v)+"")

    def _on_tor_failed(self, message):
        self.failed = True
        self.logs_widget.update_log(f"Tor supervisor reported a failure: {message}")
        logger.error("Tor supervisor failed: %s", message)
        if self._parent is not None and hasattr(self._parent, "notify_user"):
            self._parent.notify_user("Tor startup failed", str(message), level="warning")
        if self.running:
            self._stop_services()
        self.connect_btn.set_connected(False)
        self.btn_status.setText("TOR STARTUP FAILED · SEE EVENT LOG")
        self.set_btn_status_style("disconnected")
        # Keep the error close to the failed action: return to Home and open
        # the Event Log drawer so the Tor-side diagnostic is immediately visible.
        if self._parent is not None and hasattr(self._parent, "_show_home"):
            self._parent._show_home()
        if not self.logs_open:
            self.show_logs()

    def set_btn_status_style(self, stmt):
        self.btn_status.setProperty("connectionState", stmt)
        self.btn_status.style().unpolish(self.btn_status)
        self.btn_status.style().polish(self.btn_status)
        self.btn_status.update()

    def _apply_system_proxy_mode(self):
        mode = CONFIG["system_proxy_mode"]
        if mode == "set":
            self.set_proxy_clicked()
        elif mode == "clear":
            if not self._system_proxy_is_cleared or self.proxy_set:
                self._clear_system_proxy_mode()
            else:
                self._update_proxy_mode_status()
        else:
            self._update_proxy_mode_status()

    def _toggle(self):
        if self.running:
            self.connect_btn.set_disconnecting()
            self._stop_services()
            return

        self.failed = False
        self.connect_btn.set_connecting()
        self.connect_btn.setEnabled(False)
        self.btn_status.setText("CHECKING PORTS…")
        self.set_btn_status_style("connecting")

        worker = Worker(self._check_ports_worker)
        worker.signals.finished.connect(self._on_ports_checked)
        self.thread_pool.start(worker)

    # ===== slot that runs on main thread with the result =====
    def _on_ports_checked(self, result):
        """
        result == (ok, ports, messages)
        This runs in the GUI thread so it's safe to touch UI and self.proxy/self.tor.
        """

        try:
            ok, ports, messages = json.loads(result)
        except Exception:
            ok = False
            ports = {}
            messages = [f"Invalid result from port checker: {result!r}"]

        # log messages to widget (safe in main thread)
        for m in messages:
            try:
                self.logs_widget.update_log(m)
            except Exception:
                logger.info("log: %s", m)

        if not ok:
            self.failed = True
            self.connect_btn.set_connected(False)
            self.set_btn_status_style("disconnected")
            self.btn_status.setText("PORT CHECK FAILED")
            self.connect_btn.setEnabled(True)
            return

        # ok==True -> attempt to set ports and start services (on main thread)
        try:
            # set ports from the ports dict (only keys that passed checks)
            if "proxy_port" in ports:
                self.proxy.port = ports["proxy_port"]
            if "tor_port" in ports:
                self.tor_socks_port = ports["tor_port"]
                self.tor.socks_port = ports["tor_port"]
                self.proxy.tor_socks_port = ports["tor_port"]
            if "control_port" in ports:
                self.tor_control_port = ports["control_port"]
                self.tor.contorl_port = ports["control_port"]
                self.tor.control_port = ports["control_port"]
            if "dns_port" in ports:
                self.tor_dns_port = ports["dns_port"]
                self.tor.dns_port = ports["dns_port"]

            # start services (wrap try/except)
            self.btn_status.setText("CONNECTING TO TOR")
            self.set_btn_status_style("connecting")

            try:
                self.proxy.start()
            except Exception as e:
                logger.exception("proxy.start() failed: %s", e)
                raise

            try:
                self.tor.update_path(CONFIG["tor_path"])
                self.tor.start()

            except Exception as e:
                logger.exception("tor.start() failed: %s", e)
                # if tor fails, try to stop proxy to avoid half-start
                try:
                    self.proxy.stop()
                except Exception:
                    logger.exception("Stopping proxy after tor.start failure also failed.")
                raise

            self.running = True
            self.failed = False
            # Don't mark connected True until your Data signals 100% (existing logic)
            self.logs_widget.update_log("Started proxy and tor successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Start failed: {e}")
            self.running = False
            self.connected = False
            self.failed = True
            self.btn_status.setText("CONNECTION FAILED")
            self.set_btn_status_style("disconnected")
            self.connect_btn.set_connected(False)
        finally:
            # always re-enable the button
            self.connect_btn.setEnabled(True)

    # ===== helper worker (runs in background) =====
    def _check_ports_worker(self):
        """
        Pure worker: no GUI ops here.
        Returns (ok: bool, ports: dict, messages: list[str])
        Clear and explicit failures list is used.
        """
        messages = []
        failures = []
        ports = {}

        checks = [
            ("proxy_port", "proxy_port_checked", "proxy port"),
            ("tor_port", "tor_port_checked", "tor socks port"),
            ("control_port", "control_port_checked", "tor control port"),
            ("dns_port", "dns_port_checked", "dns port"),
        ]

        for cfg_key, checked_key, human in checks:
            # read checked flag (use try/except because CONFIG may not have key)
            try:
                raw_checked = CONFIG[checked_key]
            except KeyError:
                # treat missing checked flag as disabled (like you asked)
                messages.append(f"{human}: missing checked flag '{checked_key}', treating as disabled.")
                continue

            checked = bool(raw_checked)
            messages.append(f"{human}: checked={checked}")

            # read raw port value
            try:
                raw = CONFIG[cfg_key]
            except KeyError:
                raw = None

            messages.append(f"{human}: value={raw!r}")

            if not checked:
                messages.append(f"{human}: disabled, skipping.")
                continue

            if raw is None or str(raw).strip() == "":
                failures.append(f"{human}: enabled but no value provided.")
                continue

            try:
                p = int(raw)
            except Exception:
                failures.append(f"{human}: value '{raw}' is not a valid integer.")
                continue

            if int(raw) in ports.values():
                failures.append(f"{human}: This port is duplicated.")
                continue

            if not (1 <= p <= 65535):
                failures.append(f"{human}: port {p} out of valid range (1-65535).")
                continue

            # Check port free (bind-based). Wrap in try/except and log result.
            try:
                free = is_port_free("127.0.0.1", p)
            except Exception as e:
                free = False
                failures.append(f"{human}: error while checking port: {e}")
                logger.exception("is_port_free error for %s:%s", human, p)
                continue

            if not free:
                failures.append(f"{human}: port {p} not free.")
            else:
                messages.append(f"{human}: port {p} is free.")
                ports[cfg_key] = p

        # finalize messages and ok
        if failures:
            messages.append("Port checks failed.")
            messages.extend(failures)
            ok = False
        else:
            messages.append("All requested ports OK.")
            ok = True

        return json.dumps([ok, ports, messages])

    def _stop_services(self):
        if self._stopping:
            return
        self._stopping = True
        self.connect_btn.set_disconnecting()
        self.btn_status.setText("DISCONNECTING…")
        self.set_btn_status_style("disconnecting")

        # Restore a policy-managed proxy when the app disconnects in Set mode.
        # Explicit app exit also cleans up TorProxy's own proxy assignment.
        should_restore_proxy = (
            CONFIG["system_proxy_mode"] == "set"
            or bool(getattr(self._parent, "_closing", False))
        )
        if self.proxy_set and should_restore_proxy:
            try:
                restored = manage_proxy("127.0.0.1", self.proxy.port, "clear")
                if restored:
                    self.proxy_set = False
                    self._system_proxy_is_cleared = False
                    self.proxy_status_label.setText("Previous system proxy settings restored.")
                else:
                    self.proxy_status_label.setText("System proxy changed externally or could not be restored; inspect settings manually")
                    self.logs_widget.update_log("System proxy was not overwritten during shutdown because safe restoration could not be confirmed.")
            except Exception as e:
                logger.exception("Error restoring system proxy during stop: %s", e)
                self.logs_widget.update_log(f"System proxy restoration failed: {e}")

        try:
            if self.proxy:
                self.proxy.stop()
                self.logs_widget.update_log("Proxy stopped.")
        except Exception as e:
            logger.exception("Error stopping the HTTP proxy: %s", e)
            self.logs_widget.update_log(f"Error while stopping the HTTP proxy: {e}")
        try:
            controller = getattr(self, "controller", None)
            if controller is not None:
                controller.close()
                self.controller = None
        except Exception as e:
            logger.warning("Closing the GUI Tor ControlPort connection failed: %s", e)
        try:
            if self.tor:
                self.tor.stop()
                self.logs_widget.update_log("Tor stopped.")
        except Exception as e:
            logger.exception("Error stopping Tor: %s", e)
            self.logs_widget.update_log(f"Error while stopping Tor: {e}")

        self.running = False
        self.connected = False
        self.lbl_percent.setText("0%")
        self.btn_status.setText("NOT CONNECTED")
        self.set_btn_status_style("disconnected")
        self.connect_btn.set_connected(False)
        self.connect_btn.setEnabled(True)
        self.timer_data_usage.stop()
        self._update_proxy_buttons()
        self._update_proxy_mode_status()
        self._stopping = False

    # ----- proxy manual control handlers (new) -----
    def set_proxy_clicked(self):
        # Used by the Set-system-proxy policy after Tor bootstrap has succeeded.
        if not self.running or not self.connected:
            self.proxy_status_label.setText(
                "Will apply the system proxy automatically after Tor connects."
            )
            return
        if getattr(self, "_system_proxy_action_busy", False):
            return
        self._system_proxy_action_busy = True
        self.system_proxy_mode.setEnabled(False)
        worker = Worker(lambda: manage_proxy("127.0.0.1", self.proxy.port, "set"))
        worker.signals.finished.connect(self._on_set_proxy_finished)
        worker.signals.error.connect(self._on_set_proxy_error)
        self.thread_pool.start(worker)

    def _on_set_proxy_finished(self, result):
        self._system_proxy_action_busy = False
        self.system_proxy_mode.setEnabled(True)
        if str(result).strip().lower() != "true":
            self._on_set_proxy_error("The operating system did not apply the proxy settings.")
            return
        self.proxy_set = True
        self._system_proxy_is_cleared = False
        self._system_proxy_clear_failed = False
        if not self.running or not self.connected or CONFIG["system_proxy_mode"] != "set":
            # The setting changed while the OS call was in flight. Restore the
            # pre-existing system state rather than leave a dead local endpoint.
            self.logs_widget.update_log(
                "Tor disconnected while the system proxy was being applied; restoring prior settings."
            )
            self.clear_proxy_clicked()
            return
        self.proxy_status_label.setText(f"System proxy active at 127.0.0.1:{self.proxy.port}")
        self.logs_widget.update_log(f"System proxy enabled at 127.0.0.1:{self.proxy.port}")
        self._update_proxy_buttons()

    def _on_set_proxy_error(self, err):
        self._system_proxy_action_busy = False
        self.system_proxy_mode.setEnabled(True)
        logger.exception("Error setting proxy: %s", err)
        self.logs_widget.update_log(f"Error setting proxy: {err}")
        QMessageBox.warning(self, "Proxy Error", f"Failed to set proxy: {err}")
        self._update_proxy_buttons()

    def clear_proxy_clicked(self):
        if not self.proxy_set:
            return
        worker = Worker(lambda: manage_proxy("127.0.0.1", self.proxy.port, "clear"))
        worker.signals.finished.connect(self._on_clear_proxy_finished)
        worker.signals.error.connect(self._on_clear_proxy_error)
        self.thread_pool.start(worker)

    def _on_clear_proxy_finished(self, result):
        if str(result).strip().lower() != "true":
            self._on_clear_proxy_error("Original proxy settings could not be safely restored; existing external changes were left untouched.")
            return
        self.proxy_set = False
        self._system_proxy_is_cleared = False
        self.proxy_status_label.setText("System proxy: original settings restored")
        self.logs_widget.update_log("The original system proxy settings were restored.")
        self._update_proxy_buttons()

    def _on_clear_proxy_error(self, err):
        logger.exception("Error clearing proxy: %s", err)
        self.logs_widget.update_log(f"Error clearing proxy: {err}")
        QMessageBox.warning(self, "Proxy Error", f"Failed to clear proxy: {err}")
        self._update_proxy_buttons()

    def _update_proxy_buttons(self):
        # Retain this handler name for existing callbacks, but update the policy status.
        self._update_proxy_mode_status()
