from PySide6.QtWidgets import (
    QLabel,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QFrame,
    QPushButton,
    QMessageBox,
)


from PySide6.QtCore import Qt, QTimer, QThreadPool
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
from ui_.emojis import CHANGE_IDENTITY, LOGS, WHAT_IS_MY_IP, TAP_TO_CONNECT
from config import CONFIG
import json
import logging

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
        # Responsive two-column home: primary connection action on the left,
        # useful proxy operations grouped in a compact card on the right.
        self.main_layout = QHBoxLayout(self)
        self.main_layout.setContentsMargins(8, 8, 8, 8)
        self.main_layout.setSpacing(18)

        hero = QWidget(self)
        hero.setObjectName("homeHero")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(8, 10, 8, 10)
        hero_layout.setSpacing(14)
        hero_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.btn_status = QLabel(TAP_TO_CONNECT)
        self.btn_status.setObjectName("connectionStatus")
        self.btn_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_btn_status_style("disconnected")
        hero_layout.addWidget(self.btn_status)
        self.connect_btn = PulseButton("Connect")
        self.connect_btn.setObjectName("connectPulseButton")
        self.connect_btn.clicked.connect(self._toggle)
        hero_layout.addWidget(self.connect_btn, 0, Qt.AlignmentFlag.AlignHCenter)

        metric_card = QFrame(hero)
        metric_card.setObjectName("homeMetricCard")
        lyt_info = QHBoxLayout(metric_card)
        lyt_info.setContentsMargins(14, 10, 14, 10)
        lyt_info.setSpacing(14)
        self.lbl_percent = QLabel("0%")
        self.lbl_percent.setObjectName("bootstrapPercent")
        lyt_info.addWidget(self.lbl_percent)
        self.lbl_data_usage = QLabel(f"Proxy traffic (both directions): {CONFIG['data_usage']/1024**2:.2f} MiB")
        self.lbl_data_usage.setWordWrap(True)
        lyt_info.addWidget(self.lbl_data_usage, 1)
        hero_layout.addWidget(metric_card)
        self.data.valueChanged.connect(self.dataValueChanged)

        utility_row = QHBoxLayout()
        self.btn_change_identity = QPushButton(CHANGE_IDENTITY)
        self.btn_change_identity.clicked.connect(self.change_identity_)
        utility_row.addWidget(self.btn_change_identity)
        self.btn_log = QPushButton(LOGS)
        self.btn_log.clicked.connect(self.show_logs)
        utility_row.addWidget(self.btn_log)
        hero_layout.addLayout(utility_row)
        hero_layout.addStretch(1)
        self.main_layout.addWidget(hero, 3)

        actions_card = QFrame(self)
        actions_card.setObjectName("homeActionCard")
        actions_layout = QVBoxLayout(actions_card)
        actions_layout.setContentsMargins(18, 18, 18, 18)
        actions_layout.setSpacing(12)
        section_title = QLabel("Proxy controls")
        section_title.setObjectName("homeSectionTitle")
        actions_layout.addWidget(section_title)
        self.logs_widget = LogWindow(self)
        self.tor.log_message.connect(self.logs_widget.update_log)
        self.tor.service_failed.connect(self._on_tor_failed)

        self.proxy_status_label = QLabel(
            "System proxy: prior-session restoration available" if self.proxy_set else "System proxy: unchanged"
        )
        self.proxy_status_label.setObjectName("proxyStatusLabel")
        self.proxy_status_label.setWordWrap(True)
        actions_layout.addWidget(self.proxy_status_label)
        layout_proxy = QHBoxLayout()
        layout_proxy.setSpacing(8)
        self.btn_set_proxy = QPushButton("Set Proxy")
        self.btn_set_proxy.clicked.connect(self.set_proxy_clicked)
        layout_proxy.addWidget(self.btn_set_proxy)
        self.btn_clear_proxy = QPushButton("Clear Proxy")
        self.btn_clear_proxy.clicked.connect(self.clear_proxy_clicked)
        layout_proxy.addWidget(self.btn_clear_proxy)
        actions_layout.addLayout(layout_proxy)
        self._update_proxy_buttons()

        separator = QFrame(actions_card)
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Plain)
        actions_layout.addWidget(separator)
        ip_title = QLabel("Exit IP")
        ip_title.setObjectName("homeSectionTitle")
        actions_layout.addWidget(ip_title)
        self.tor_ip_label = QLabel("Exit IP: not checked")
        self.tor_ip_label.setWordWrap(True)
        actions_layout.addWidget(self.tor_ip_label)
        self.btn_whatismyip = QPushButton(WHAT_IS_MY_IP)
        self.btn_whatismyip.clicked.connect(self.whatismyip_clicked)
        actions_layout.addWidget(self.btn_whatismyip)
        actions_layout.addStretch(1)
        self.main_layout.addWidget(actions_card, 2)
        self.setStyleSheet("""
            QFrame#homeActionCard, QFrame#homeMetricCard { border: 1px solid palette(mid); border-radius: 12px; background: palette(base); }
            QLabel#homeSectionTitle { font-size: 14px; font-weight: 700; }
            QLabel#bootstrapPercent { font-size: 16px; font-weight: 700; }
            QPushButton { min-height: 34px; padding: 0 12px; border-radius: 7px; }
        """)
        self.thread_pool = QThreadPool(self)
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
        if self.logs_widget.isHidden():
            self.logs_widget.setParent(self)
            self.logs_widget.move(10,10)
            self.logs_widget.show()
        else:
            self.logs_widget.hide()

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
                self.btn_status.setText("control authentication failed")
                self.set_btn_status_style("disconnected")
                self._update_proxy_buttons()
                return
            self.connected = True
            # Starting Tor never mutates system proxy settings. The user must opt in.
            self.proxy_status_label.setText(f"System proxy: unchanged (local endpoint 127.0.0.1:{self.proxy.port})")
            self._update_proxy_buttons()
            self.btn_status.setText("connected")
            self.set_btn_status_style("connected")
            self.timer_data_usage.start()

        self.lbl_percent.setText(str(v)+"")

    def _on_tor_failed(self, message):
        self.failed = True
        self.logs_widget.update_log(f"Tor supervisor reported a failure: {message}")
        logger.error("Tor supervisor failed: %s", message)
        if self.running:
            self._stop_services()

    def set_btn_status_style(self, stmt):
        if stmt == "disconnected":
            color = "#2ecc71"
        else:
            color = "#e74c3c"

        self.btn_status.setStyleSheet("""
            QLabel {
                padding: 20px;
                border-radius: 15px;
                font-size: 18px;
                font-weight: bold;
                border: 4px solid %s;
            }
            QLabel:hover {
                border: 4px solid #1B5E20;
            }
        """%(color))

    def _toggle(self):
        if self.running:
            self._stop_services()
            return

        self.failed = False
        self.connect_btn.setEnabled(False)
        self.btn_status.setText("checking ports ...")
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
            # Failed preflight must be visible and leave the controls recoverable.
            self.failed = True
            self.set_btn_status_style("disconnected")
            self.btn_status.setText("port check failed")
            self.connect_btn.setEnabled(True)
            self.connect_btn.toggle_state()
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
            self.btn_status.setText("connecting . . .")
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
            self.btn_status.setText("disconnected")
            self.set_btn_status_style("disconnected")
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
        self.btn_status.setText("disconnecting . . .")
        self.set_btn_status_style("disconnecting")

        # Restore OS settings before taking the local proxy listener down.
        if self.proxy_set:
            try:
                restored = manage_proxy("127.0.0.1", self.proxy.port, "clear")
                if restored:
                    self.proxy_set = False
                    self.proxy_status_label.setText("System proxy: original settings restored")
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
        self.btn_status.setText("disconnected")
        self.set_btn_status_style("disconnected")
        self.connect_btn.connected = False
        self.connect_btn.updateStyle()
        self.connect_btn.setEnabled(True)
        self.timer_data_usage.stop()
        self._update_proxy_buttons()
        self._stopping = False

    # ----- proxy manual control handlers (new) -----
    def set_proxy_clicked(self):
        # Explicit user action; never invoked automatically by bootstrap.
        if not self.running or not self.connected:
            QMessageBox.information(self, "TorProxy", "Start Tor and wait for successful bootstrap before enabling the system proxy.")
            return
        self.btn_set_proxy.setEnabled(False)
        self.btn_clear_proxy.setEnabled(False)
        worker = Worker(lambda: manage_proxy("127.0.0.1", self.proxy.port, "set"))
        worker.signals.finished.connect(self._on_set_proxy_finished)
        worker.signals.error.connect(self._on_set_proxy_error)
        self.thread_pool.start(worker)

    def _on_set_proxy_finished(self, result):
        if str(result).strip().lower() != "true":
            self._on_set_proxy_error("The operating system did not apply the proxy settings.")
            return
        self.proxy_set = True
        self.proxy_status_label.setText(f"System proxy: using 127.0.0.1:{self.proxy.port}")
        self.logs_widget.update_log(f"System proxy explicitly enabled at 127.0.0.1:{self.proxy.port}")
        self._update_proxy_buttons()

    def _on_set_proxy_error(self, err):
        logger.exception("Error setting proxy: %s", err)
        self.logs_widget.update_log(f"Error setting proxy: {err}")
        QMessageBox.warning(self, "Proxy Error", f"Failed to set proxy: {err}")
        self._update_proxy_buttons()

    def clear_proxy_clicked(self):
        if not self.proxy_set:
            return
        self.btn_set_proxy.setEnabled(False)
        self.btn_clear_proxy.setEnabled(False)
        worker = Worker(lambda: manage_proxy("127.0.0.1", self.proxy.port, "clear"))
        worker.signals.finished.connect(self._on_clear_proxy_finished)
        worker.signals.error.connect(self._on_clear_proxy_error)
        self.thread_pool.start(worker)

    def _on_clear_proxy_finished(self, result):
        if str(result).strip().lower() != "true":
            self._on_clear_proxy_error("Original proxy settings could not be safely restored; existing external changes were left untouched.")
            return
        self.proxy_set = False
        self.proxy_status_label.setText("System proxy: original settings restored")
        self.logs_widget.update_log("The original system proxy settings were restored.")
        self._update_proxy_buttons()

    def _on_clear_proxy_error(self, err):
        logger.exception("Error clearing proxy: %s", err)
        self.logs_widget.update_log(f"Error clearing proxy: {err}")
        QMessageBox.warning(self, "Proxy Error", f"Failed to clear proxy: {err}")
        self._update_proxy_buttons()

    def _update_proxy_buttons(self):
        # Setting the OS proxy is opt-in and only useful while the local proxy is ready.
        self.btn_set_proxy.setEnabled(bool(self.running and self.connected and not self.proxy_set))
        self.btn_clear_proxy.setEnabled(bool(self.proxy_set))