from PySide6.QtWidgets import (
    QLabel,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QFrame,
    QPushButton,
    QComboBox,
    QSizePolicy,
)


from PySide6.QtCore import Qt, QTimer, QThreadPool, QPropertyAnimation, QEasingCurve
from stem import Signal as TorSignal
from stem.control import Controller
from stem import SocketClosed, OperationFailed
from stem.connection import AuthenticationFailure

from torproxy.ports import PortAllocationError, resolve_listener_ports
from set_proxy import has_proxy_snapshot, manage_proxy
from tor import TorRunner, Runner

from whatismyip import what_is_my_ip
from ui_.window.log_window import LogWindow
from ui_.btn.pulse_button import PulseButton
from ui_.worker.worker import Worker
from ui_.worker.utils import Data
from config import CONFIG
from torproxy.killswitch import KillSwitchManager, KillSwitchError
from ui_.window.dialogs import QMessageBox
from torproxy.paths import user_directories
from torproxy.system_tunnel import SystemTunnelManager
from ui_.window.tor_log_dialog import TorLogDialog
from ui_.window.open_browser_dialog import OpenBrowserDialog
import json
import logging
import threading
from pathlib import Path
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
        self._exit_ip_check_busy = False
        self._exit_ip_worker = None
        self._parent = parent
        self._operation_lock = threading.RLock()
        self._connect_operation_busy = False
        self._killswitch_operation_active = False
        # Resolve listener ports before building the services. Automatic values
        # are saved once, reused on later launches and repaired only on conflict.
        self.listener_ports, self._port_initialization_messages = resolve_listener_ports(
            CONFIG, strict_manual=False
        )
        for message in self._port_initialization_messages:
            logger.info("%s", message)
        self.tor_socks_port = self.listener_ports["tor_port"]
        self.proxy_port = self.listener_ports["proxy_port"]
        self.tor_control_port = self.listener_ports["control_port"]
        self.tor_dns_port = self.listener_ports["dns_port"]
        self.tor = TorRunner(self.tor_socks_port, self.tor_control_port, self.tor_dns_port)
        self.system_tunnel_manager = SystemTunnelManager()
        self._system_tunnel_busy = False
        self._system_tunnel_worker = None
        try:
            self.killswitch_manager = KillSwitchManager()
            self._killswitch_unavailable = None
        except KillSwitchError as exc:
            self.killswitch_manager = None
            self._killswitch_unavailable = str(exc)
        self.tor.killswitch_manager = self.killswitch_manager
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
        self.btn_statistics = QPushButton("Statistics", self.home_content)
        self.btn_statistics.setObjectName("statisticsLink")
        self.btn_statistics.setFlat(True)
        self.btn_statistics.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_statistics.setToolTip("Open live proxy traffic statistics and charts")
        self.btn_statistics.clicked.connect(self.open_statistics_page)
        metrics.addStretch(1)
        metrics.addWidget(self.lbl_percent)
        separator = QFrame(self.home_content)
        separator.setObjectName("homeMetricSeparator")
        separator.setFrameShape(QFrame.Shape.VLine)
        metrics.addWidget(separator)
        metrics.addWidget(self.lbl_data_usage)
        metrics.addWidget(self.btn_statistics)
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

        self.system_tunnel_card = QFrame(self.home_content)
        self.system_tunnel_card.setObjectName("systemTunnelCard")
        tunnel_card_layout = QHBoxLayout(self.system_tunnel_card)
        tunnel_card_layout.setContentsMargins(14, 10, 14, 10)
        tunnel_card_layout.setSpacing(14)
        tunnel_text_layout = QVBoxLayout()
        tunnel_text_layout.setContentsMargins(0, 0, 0, 0)
        tunnel_text_layout.setSpacing(3)
        self.system_tunnel_title = QLabel("SYSTEM-WIDE TOR TUNNEL")
        self.system_tunnel_title.setObjectName("systemTunnelTitle")
        self.system_tunnel_description = QLabel(
            "Route system TCP traffic through Tor. DNS is sent over Tor; unsupported UDP is blocked."
        )
        self.system_tunnel_description.setObjectName("systemTunnelDescription")
        self.system_tunnel_description.setWordWrap(True)
        self.system_tunnel_status = QLabel("Engine not installed")
        self.system_tunnel_status.setObjectName("systemTunnelStatus")
        tunnel_text_layout.addWidget(self.system_tunnel_title)
        tunnel_text_layout.addWidget(self.system_tunnel_description)
        tunnel_text_layout.addWidget(self.system_tunnel_status)
        tunnel_card_layout.addLayout(tunnel_text_layout, 1)
        self.btn_system_tunnel = QPushButton("Install engine", self.system_tunnel_card)
        self.btn_system_tunnel.setObjectName("systemTunnelAction")
        self.btn_system_tunnel.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_system_tunnel.clicked.connect(self.toggle_system_tunnel)
        tunnel_card_layout.addWidget(self.btn_system_tunnel, 0, Qt.AlignmentFlag.AlignVCenter)
        self.home_layout.addWidget(self.system_tunnel_card)

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
        self.btn_open_browser = QPushButton(qta.icon("fa6s.globe"), "  Open Browser", self.home_content)
        self.btn_open_browser.setObjectName("secondaryAction")
        self.btn_open_browser.setToolTip(
            "Connect to Tor and wait for the verified bootstrap to finish before opening a browser."
        )
        self.btn_open_browser.setEnabled(False)
        self.btn_open_browser.clicked.connect(self.open_browser_dialog)
        utility_row.addWidget(self.btn_open_browser)
        self.home_layout.addLayout(utility_row)

        self.thread_pool = QThreadPool(self)
        self.tor.log_message.connect(self.logs_widget.update_log)
        self.tor.service_failed.connect(self._on_tor_failed)
        self.tor.bridges_updated.connect(self._sync_bridge_editor)
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

    def _sync_bridge_editor(self, bridge_text: str):
        """Reflect automatically pruned bridge records in the editor and its cards."""
        owner = self._parent
        if owner is None:
            return
        editor = owner.findChild(QWidget, "bridgeRecordsInput")
        if editor is not None and hasattr(editor, "setPlainText"):
            if editor.toPlainText() != bridge_text:
                was_blocked = editor.blockSignals(True)
                try:
                    editor.setPlainText(bridge_text)
                finally:
                    editor.blockSignals(was_blocked)

        # The editor was changed with signals blocked to avoid an intermediate
        # write of stale/partial text. Now run the Settings transaction once so
        # its saved-record snapshot, copy/remove cards and status labels match
        # the bridge list that TorRunner actually retained.
        settings_page = getattr(owner, "settingWidget", None)
        refresh = getattr(settings_page, "set_bridges", None)
        if callable(refresh):
            refresh()

    def open_tor_log_dialog(self):
        """Open a live, paginated view of the actual managed Tor log file."""
        manager = getattr(self.tor, "manager", None)
        path = getattr(manager, "log_path", None) or (user_directories().logs / "tor.log")
        dialog = TorLogDialog(self, path, manager=manager)
        dialog.exec()

    def change_data_usage(self):
        self.lbl_data_usage.setText(
            f"Proxy traffic  ·  {max(0, int(CONFIG['data_usage'] or 0)) / 1024**2:.2f} MiB"
        )

    def open_statistics_page(self):
        owner = self._parent
        show_statistics = getattr(owner, "_show_statistics", None)
        if callable(show_statistics):
            show_statistics()

    def open_browser_dialog(self):
        """Open the browser chooser only after Tor and the local HTTP listener are ready."""
        if not self.running or not self.connected or getattr(self.proxy, "server", None) is None:
            self.logs_widget.update_log(
                "Open Browser is unavailable until Tor bootstrap and the local HTTP proxy are ready."
            )
            return
        try:
            dialog = OpenBrowserDialog(self, proxy_port=int(self.proxy.port))
            dialog.exec()
        except Exception as exc:
            logger.exception("Could not open the browser chooser.")
            QMessageBox.warning(self, "Open Browser", str(exc))

    def whatismyip_clicked(self):
        if self._exit_ip_check_busy:
            return
        if not self.running or not self.connected:
            self.tor_ip_label.setText("Exit IP: unavailable — Tor proxy is not ready")
            logger.info("Exit-IP check ignored because Tor is not in the verified connected state.")
            return

        try:
            proxy_port = int(self.proxy.port)
            if not 1 <= proxy_port <= 65535:
                raise ValueError("The local HTTP proxy port is invalid.")
            proxy_url = f"http://127.0.0.1:{proxy_port}"
            self._exit_ip_check_busy = True
            self.btn_whatismyip.setEnabled(False)
            self.tor_ip_label.setText("Exit IP: checking through Tor proxy…")
            worker = Worker(self._perform_exit_ip_check, proxy_url)
            worker.signals.finished.connect(self._on_exit_ip_checked)
            worker.signals.error.connect(self._on_exit_ip_failed)
            self._exit_ip_worker = worker
            self.thread_pool.start(worker)
            logger.debug("Started exit-IP verification through the local HTTP proxy.")
        except Exception as exc:
            logger.exception("Could not start the proxied exit-IP check.")
            self._on_exit_ip_failed(f"{type(exc).__name__}: {exc}")

    @staticmethod
    def _perform_exit_ip_check(proxy_url: str) -> str:
        """Request an exit IP through the explicit local proxy, never directly."""
        return what_is_my_ip(proxy=proxy_url, timeout=10)

    def _finish_exit_ip_check(self):
        self._exit_ip_check_busy = False
        self._exit_ip_worker = None
        try:
            self.btn_whatismyip.setEnabled(True)
        except RuntimeError:
            logger.debug("Exit-IP button was destroyed before its worker completed.")

    def _on_exit_ip_checked(self, result):
        try:
            address = str(result or "").strip()
            if address and address.casefold() != "none":
                self.tor_ip_label.setText("Observed exit IP (proxied): " + address)
                logger.info("Exit-IP verification completed through the local proxy.")
            else:
                self.tor_ip_label.setText("Exit IP: unverified")
                logger.warning("Exit-IP endpoint returned an empty response.")
        except Exception:
            logger.exception("Could not display the verified exit-IP result.")
            try:
                self.tor_ip_label.setText("Exit IP result could not be displayed; see the event log")
            except RuntimeError:
                pass
        finally:
            self._finish_exit_ip_check()

    def _on_exit_ip_failed(self, error):
        message = str(error or "Unknown exit-IP verification failure.")
        logger.warning("Proxied exit-IP check failed: %s", message)
        try:
            self.tor_ip_label.setText("Exit IP check failed — no direct fallback used")
            self.logs_widget.update_log(f"Exit-IP verification failed: {message}", level="error")
        except (RuntimeError, AttributeError):
            logger.exception("Could not display the exit-IP verification failure.")
        finally:
            self._finish_exit_ip_check()

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
            QLabel#connectionStatus[connectionState="disconnected"] {{ color: {text}; }}
            QLabel#bootstrapPercent {{ color: {accent}; background: transparent; border: none; font-size: 14px; font-weight: 700; padding: 3px; }}
            QLabel#trafficUsage, QLabel#proxyStatusLabel, QLabel#exitIpLabel {{ color: {muted}; background: transparent; border: none; font-size: 11px; padding: 2px; }}
            QPushButton#statisticsLink {{ color: {accent}; background: transparent; border: none; padding: 2px 4px; font-size: 11px; font-weight: 700; }}
            QPushButton#statisticsLink:hover {{ color: {text}; border-bottom: 1px solid {accent}; }}
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
            QFrame#systemTunnelCard {{ background: {surface}; border: 1px solid {border}; border-radius: 11px; }}
            QLabel#systemTunnelTitle {{ color: {text}; background: transparent; border: none; font-size: 10px; font-weight: 800; letter-spacing: 0.8px; }}
            QLabel#systemTunnelDescription {{ color: {muted}; background: transparent; border: none; font-size: 10px; }}
            QLabel#systemTunnelStatus {{ color: {accent}; background: transparent; border: none; font-size: 10px; font-weight: 700; }}
            QPushButton#systemTunnelAction {{ min-height: 34px; padding: 0 13px; border-radius: 8px; background: {accent}; color: #ffffff; border: none; font-weight: 700; }}
            QPushButton#systemTunnelAction:hover {{ background: #2989d0; }}
            QPushButton#systemTunnelAction:disabled {{ background: {border}; color: {muted}; }}
        """)
        self.logs_widget.apply_theme(CONFIG["mode"])
        icon_color = "#eff1f4" if dark else "#202832"
        self.btn_change_identity.setIcon(qta.icon("fa6s.arrows-rotate", color=icon_color))
        self.btn_log.setIcon(qta.icon("fa6s.align-left", color=icon_color))
        self.btn_whatismyip.setIcon(qta.icon("fa6s.globe", color=icon_color))
        self.btn_open_browser.setIcon(qta.icon("fa6s.globe", color=icon_color))
        self.btn_statistics.setIcon(qta.icon("fa6s.chart-line", color=accent))

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
        if getattr(self, "_system_tunnel_busy", False):
            self.logs_widget.update_log("Tor connect/disconnect is temporarily disabled while the system tunnel changes.")
            return
        with self._operation_lock:
            if self._killswitch_operation_active:
                QMessageBox.information(
                    self, "Network protection", "Wait until the Kill Switch operation finishes before connecting."
                )
                return
            if self.running:
                self.connect_btn.set_disconnecting()
                self._stop_services()
                return
            if self._connect_operation_busy:
                return
            # Claim the connection transition synchronously on the GUI thread.
            # Settings must not arm/disarm the firewall between preflight and Tor start.
            self._connect_operation_busy = True

        self.failed = False
        self.connect_btn.set_connecting()
        self.connect_btn.setEnabled(False)
        self.btn_status.setText("CHECKING PORTS…")
        self.set_btn_status_style("connecting")

        worker = Worker(self._check_ports_worker)
        worker.signals.finished.connect(self._on_ports_checked)
        worker.signals.error.connect(self._on_port_check_error)
        self.thread_pool.start(worker)

    def _on_port_check_error(self, error):
        with self._operation_lock:
            self._connect_operation_busy = False
        self.failed = True
        self.running = False
        self.connected = False
        self.connect_btn.set_connected(False)
        self.connect_btn.setEnabled(True)
        self.btn_status.setText("CONNECTION PREFLIGHT FAILED")
        self.set_btn_status_style("disconnected")
        QMessageBox.warning(self, "Connection preflight", str(error))

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
            with self._operation_lock:
                self._connect_operation_busy = False
            self.failed = True
            self.connect_btn.set_connected(False)
            self.set_btn_status_style("disconnected")
            self.btn_status.setText("PORT CHECK FAILED")
            self.connect_btn.setEnabled(True)
            QMessageBox.warning(
                self,
                "Connection preflight",
                "\n".join(messages[-5:]) if messages else "Listener port validation failed.",
            )
            self._update_proxy_buttons()
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
            self.listener_ports = dict(ports)
            settings_page = getattr(self._parent, "settingWidget", None)
            sync_listener_ports = getattr(settings_page, "sync_listener_ports", None)
            if callable(sync_listener_ports):
                sync_listener_ports(ports)

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
            self.logs_widget.update_log("Local proxy started; Tor bootstrap is in progress. Wait for the verified CONNECTED state.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Start failed: {e}")
            self.running = False
            self.connected = False
            self.failed = True
            self.btn_status.setText("CONNECTION FAILED")
            self.set_btn_status_style("disconnected")
            self.connect_btn.set_connected(False)
        finally:
            with self._operation_lock:
                self._connect_operation_busy = False
            # always re-enable the button
            self.connect_btn.setEnabled(True)

    # ===== helper worker (runs in background) =====
    def set_kill_switch_enabled(self, enabled: bool) -> str:
        """Serialize firewall changes against Tor connection transitions."""
        if not enabled:
            tunnel_state = self.system_tunnel_manager.status()
            if tunnel_state.get("active") or not tunnel_state.get("verified", True):
                raise KillSwitchError("Stop or reconcile the system-wide tunnel before disabling Kill Switch.")
        with self._operation_lock:
            if self._connect_operation_busy or self.running or self._stopping:
                raise KillSwitchError("Finish connecting or disconnecting Tor before changing Kill Switch.")
            if self._killswitch_operation_active:
                raise KillSwitchError("Another Kill Switch operation is already running.")
            self._killswitch_operation_active = True
        try:
            return self._apply_kill_switch_enabled(bool(enabled))
        finally:
            with self._operation_lock:
                self._killswitch_operation_active = False

    def _run_kill_switch_recovery(self, *, emergency: bool = False) -> str:
        """Restore firewall connectivity without racing Tor startup or another policy change."""
        tunnel_manager = getattr(self, "system_tunnel_manager", None)
        if tunnel_manager is not None:
            tunnel_state = tunnel_manager.status()
            if tunnel_state.get("active") or not tunnel_state.get("verified", True):
                raise KillSwitchError("Stop or reconcile the system-wide tunnel before recovering the Kill Switch.")

        with self._operation_lock:
            if self._connect_operation_busy or self.running or self._stopping:
                raise KillSwitchError("Disconnect Tor before recovering the system firewall.")
            if self._killswitch_operation_active:
                raise KillSwitchError("A Kill Switch operation is still running; recovery will be queued by Settings.")
            self._killswitch_operation_active = True
        try:
            manager = getattr(self, "killswitch_manager", None)
            if manager is None:
                raise KillSwitchError(
                    getattr(self, "_killswitch_unavailable", None)
                    or "Kill Switch recovery is unavailable on this operating system."
                )
            if emergency:
                outcome = manager.emergency_recover()
                detail = str(outcome.get("detail", "")).strip() if isinstance(outcome, dict) else ""
                message = (
                    "Emergency recovery completed. Windows Firewall remains enabled; outbound traffic is allowed, "
                    "and only TorProxy-owned firewall rules were removed."
                )
            else:
                outcome = manager.recover()
                detail = str(outcome.get("detail", "")).strip() if isinstance(outcome, dict) else ""
                message = (
                    "The saved firewall configuration was restored and verified. "
                    "The Kill Switch is now disabled."
                )
            if detail:
                message += " " + detail
            try:
                CONFIG["kill_switch_enabled"] = False
            except Exception as exc:
                raise KillSwitchError(
                    f"The firewall was recovered, but TorProxy could not save the disabled preference: {exc}. "
                    "Keep the Kill Switch off in Settings before restarting the app."
                ) from exc
            return message
        finally:
            with self._operation_lock:
                self._killswitch_operation_active = False

    def recover_kill_switch(self) -> str:
        """Restore the original firewall snapshot, including a partially applied enable."""
        return self._run_kill_switch_recovery(emergency=False)

    def emergency_recover_kill_switch(self) -> str:
        """Use the explicit outbound-Allow fallback while keeping the OS firewall enabled."""
        return self._run_kill_switch_recovery(emergency=True)

    def _apply_kill_switch_enabled(self, enabled: bool) -> str:
        """Apply the OS firewall policy and keep the saved preference consistent."""
        enabled = bool(enabled)
        manager = getattr(self, "killswitch_manager", None)
        if manager is None:
            raise KillSwitchError(
                getattr(self, "_killswitch_unavailable", None)
                or "Kill Switch is unavailable on this operating system."
            )
        if enabled:
            tor_state = str(getattr(self.tor, "state", "STOPPED")).upper()
            if self.running or tor_state in {"STARTING", "BOOTSTRAPPING", "READY"}:
                raise KillSwitchError("Disconnect Tor before enabling Kill Switch so its process can be isolated safely.")
            if not self.tor.update_path(CONFIG["tor_path"]) or not self.tor.tor_path:
                raise KillSwitchError("Select a valid Tor Expert Bundle before enabling Kill Switch.")
            programs = [self.tor.tor_path]
            if self.tor.bridge and self.tor.lyrebird_path and Path(self.tor.lyrebird_path).is_file():
                programs.append(self.tor.lyrebird_path)

            # A previous failed enable/disable can leave a saved snapshot behind
            # while the persistent preference is off. Reconcile that partial state
            # before taking a fresh snapshot. Do not do this during normal connection
            # preflight when Kill Switch is already configured as active.
            if not bool(CONFIG["kill_switch_enabled"]):
                recovery_state = manager.recovery_state()
                if recovery_state.get("snapshot_exists"):
                    recovered = manager.recover()
                    recovery_detail = str(recovered.get("detail", "")).strip() if isinstance(recovered, dict) else ""
                    logger.warning(
                        "Reconciled a pending Kill Switch snapshot before activation: %s",
                        recovery_detail or "recovery completed",
                    )

            try:
                manager.activate(programs)
            except Exception as activation_error:
                # Windows writes its recovery snapshot before the first firewall
                # mutation. Only invoke rollback when that transaction marker
                # exists; an early preflight rejection must not be mistaken for
                # a failed rollback (for example, a Group Policy restriction).
                try:
                    recovery_state = manager.recovery_state()
                    if recovery_state.get("available"):
                        if recovery_state.get("snapshot_exists"):
                            manager.recover()
                            logger.info("Rolled back the partial Windows Kill Switch activation.")
                        else:
                            logger.info(
                                "Kill Switch activation stopped before a Windows snapshot was created; "
                                "no TorProxy firewall changes were committed."
                            )
                    else:
                        manager.recover()
                except Exception as recovery_error:
                    raise KillSwitchError(
                        f"Firewall activation failed: {activation_error}. "
                        f"Automatic recovery also failed: {recovery_error}. "
                        "The firewall state is not confirmed. Use Restore saved firewall or Emergency network recovery."
                    ) from activation_error
                try:
                    CONFIG["kill_switch_enabled"] = False
                except Exception as preference_error:
                    logger.exception("Could not clear the Kill Switch preference after rollback.")
                    raise KillSwitchError(
                        f"Activation failed and the firewall recovery completed, but the off preference could not be saved: {preference_error}. "
                        "Do not restart TorProxy until the Kill Switch preference is confirmed off."
                    ) from activation_error
                raise KillSwitchError(
                    f"Kill Switch was not enabled: {activation_error}. "
                    "TorProxy removed its partial rules and reconciled the saved firewall state. "
                    "Review the firewall profile settings; you can retry after they are consistent."
                ) from activation_error

            try:
                CONFIG["kill_switch_enabled"] = True
            except Exception as save_error:
                try:
                    manager.deactivate()
                except Exception as recovery_error:
                    raise KillSwitchError(
                        f"Firewall protection was applied but its preference could not be saved: {save_error}. "
                        f"Automatic firewall recovery also failed: {recovery_error}. "
                        "Inspect the firewall state before reconnecting."
                    ) from save_error
                raise KillSwitchError(
                    f"Could not save the Kill Switch preference; the firewall policy was safely restored: {save_error}"
                ) from save_error
            return "Kill Switch enabled. Outbound traffic is restricted to Tor and essential local network control."

        # Remove the firewall policy first. If restoring it fails, retain the
        # enabled preference so a subsequent connect cannot silently bypass it.
        manager.deactivate()
        try:
            CONFIG["kill_switch_enabled"] = False
        except Exception as exc:
            raise KillSwitchError(
                f"The firewall policy was restored, but the disabled preference could not be saved: {exc}. "
                "The saved preference remains enabled and will re-apply protection before the next Tor start."
            ) from exc
        return "Kill Switch disabled and the previously saved firewall policy restored."

    def _check_ports_worker(self):
        """Resolve persistent listener ports and verify the Kill Switch before start."""
        try:
            ports, messages = resolve_listener_ports(CONFIG, strict_manual=True)
        except PortAllocationError as exc:
            return json.dumps([False, {}, [str(exc)]])

        failures = []
        if CONFIG["kill_switch_enabled"]:
            try:
                if self.killswitch_manager is None:
                    raise KillSwitchError(
                        self._killswitch_unavailable or "Kill Switch backend is unavailable."
                    )
                if not self.tor.update_path(CONFIG["tor_path"]) or not self.tor.tor_path:
                    raise KillSwitchError("The configured Tor executable is unavailable.")
                programs = [self.tor.tor_path]
                if self.tor.bridge and self.tor.lyrebird_path and Path(self.tor.lyrebird_path).is_file():
                    programs.append(self.tor.lyrebird_path)
                self.killswitch_manager.activate(programs)
                messages.append("Kill Switch firewall policy was re-applied before starting Tor.")
            except Exception as exc:
                failures.append(f"Kill Switch could not be verified or activated: {exc}")

        if failures:
            messages.append("Connection preflight failed.")
            messages.extend(failures)
            return json.dumps([False, {}, messages])

        messages.append("All four persistent listener ports are available.")
        return json.dumps([True, ports, messages])

    def _stop_services(self):
        if self._stopping:
            return False
        if getattr(self, "_system_tunnel_busy", False):
            self.logs_widget.update_log("Disconnect was blocked because the system tunnel operation is still running.")
            return False
        self._stopping = True
        self.connect_btn.set_disconnecting()
        self.btn_status.setText("DISCONNECTING…")
        self.set_btn_status_style("disconnecting")

        # Release system routes before stopping Tor. If elevated cleanup fails,
        # preserve the Tor process and default-deny Kill Switch.
        tunnel_status = self.system_tunnel_manager.status()
        if tunnel_status.get("active") or not tunnel_status.get("verified", True):
            try:
                message = self.system_tunnel_manager.stop()
                self.logs_widget.update_log(message)
            except Exception as exc:
                logger.exception("Could not stop the system-wide tunnel safely.")
                self._stopping = False
                self.connect_btn.set_connected(bool(self.connected))
                self.connect_btn.setEnabled(True)
                self.btn_status.setText("TUNNEL STILL ACTIVE · TOR LEFT RUNNING")
                self.set_btn_status_style("connected" if self.connected else "disconnected")
                self.system_tunnel_status.setText("Tunnel stop failed — Kill Switch retained")
                self.logs_widget.update_log(f"System tunnel cleanup failed; Tor was not stopped: {exc}", level="error")
                QMessageBox.warning(
                    self, "System tunnel is still active",
                    "TorProxy kept Tor and the Kill Switch running because it could not confirm "
                    "that the system TUN routes were removed. Resolve the tunnel stop error before disconnecting.",
                )
                self._update_system_tunnel_controls()
                return False
        self._update_system_tunnel_controls()

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
        self._update_system_tunnel_controls()
        return True

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
        browser_button = getattr(self, "btn_open_browser", None)
        if browser_button is not None:
            ready = bool(
                self.running and self.connected and not self._connect_operation_busy and not self._stopping
            )
            browser_button.setEnabled(ready)
            browser_button.setToolTip(
                "Open an installed browser through the local TorProxy HTTP proxy."
                if ready else
                "Connect to Tor and wait for the verified bootstrap to finish first."
            )
        self._update_proxy_mode_status()
        self._update_system_tunnel_controls()


    def _update_system_tunnel_controls(self):
        """Refresh the Home tunnel card from verified local engine/process state."""
        if not hasattr(self, "btn_system_tunnel"):
            return
        if self._system_tunnel_busy:
            self.btn_system_tunnel.setEnabled(False)
            self.btn_system_tunnel.setText("Working…")
            self.system_tunnel_status.setText("Applying system tunnel changes")
            return

        status = self.system_tunnel_manager.status()
        installed = self.system_tunnel_manager.is_installed()
        self.btn_system_tunnel.setEnabled(True)
        if status.get("active"):
            self.btn_system_tunnel.setText("Stop tunnel")
            self.system_tunnel_status.setText("Active · system TCP routed through Tor")
            self.system_tunnel_description.setText(
                "System TCP uses Tor. DNS uses DoH over Tor; UDP is blocked to prevent direct leaks."
            )
            return
        if not status.get("verified", True):
            self.btn_system_tunnel.setText("Reconcile tunnel")
            self.system_tunnel_status.setText("Tunnel process state needs recovery")
            self.system_tunnel_description.setText(
                "TorProxy only stops a process whose PID, executable and start time match its saved record."
            )
            return
        if not installed:
            self.btn_system_tunnel.setText("Install engine")
            self.system_tunnel_status.setText("Engine not installed")
            self.system_tunnel_description.setText(
                "Downloads and verifies the official sing-box 1.14.4 engine."
            )
            return
        self.btn_system_tunnel.setText("Start system tunnel")
        if not self.running or not self.connected:
            self.system_tunnel_status.setText("Ready · waiting for Tor")
            self.system_tunnel_description.setText(
                "Install the engine now; connect to Tor before starting system-wide routing."
            )
        elif not bool(CONFIG["kill_switch_enabled"]):
            self.system_tunnel_status.setText("Kill Switch required")
            self.system_tunnel_description.setText(
                "Enable Kill Switch while disconnected, then reconnect Tor before starting the system tunnel."
            )
        else:
            self.system_tunnel_status.setText("Ready to start")
            self.system_tunnel_description.setText(
                "System TCP routes through Tor, DNS uses DoH over Tor, and UDP is rejected rather than sent directly."
            )

    def toggle_system_tunnel(self):
        """Install, start or stop the verified system tunnel from Home."""
        if self._system_tunnel_busy:
            return
        status = self.system_tunnel_manager.status()
        if status.get("active") or not status.get("verified", True):
            self._run_system_tunnel_action("stop", self.system_tunnel_manager.stop)
            return
        if not self.system_tunnel_manager.is_installed():
            self._run_system_tunnel_action("install", self.system_tunnel_manager.install_engine)
            return
        if not self.running or not self.connected:
            QMessageBox.information(
                self, "System-wide tunnel",
                "Connect to Tor and wait until its ControlPort and SOCKS listener are verified before starting the tunnel.",
            )
            return
        if not bool(CONFIG["kill_switch_enabled"]):
            QMessageBox.information(
                self, "Kill Switch required",
                "For leak protection, disconnect Tor, enable Kill Switch in Settings, reconnect Tor, "
                "then start the system-wide tunnel.",
            )
            return
        firewall = self.killswitch_manager.status() if self.killswitch_manager is not None else {}
        if not firewall.get("active") or not firewall.get("verified"):
            QMessageBox.warning(
                self, "Network protection",
                "TorProxy could not verify the active Kill Switch. The system tunnel was not started.",
            )
            return
        if not firewall.get("tun_interface_allowed") and firewall.get("backend") != "WFP":
            QMessageBox.information(
                self, "Update Kill Switch rules",
                "This legacy Kill Switch policy has no verified system-tunnel interface exception. "
                "While disconnected, disable and re-enable Kill Switch once, then reconnect Tor.",
            )
            return
        # The WFP backend adds the exact adapter-LUID exception from its
        # already-elevated sing-box helper after the TorProxy TUN adapter exists.
        tor_paths = [self.tor.tor_path, self.tor.lyrebird_path]
        self._run_system_tunnel_action(
            "start",
            lambda: self.system_tunnel_manager.start(
                int(self.tor.socks_port),
                tor_executables=[path for path in tor_paths if path],
            ),
        )

    def _run_system_tunnel_action(self, action: str, operation):
        self._system_tunnel_busy = True
        self._update_system_tunnel_controls()
        worker = Worker(operation)
        worker.signals.finished.connect(
            lambda message, operation_name=action:
                self._on_system_tunnel_action_finished(operation_name, message)
        )
        worker.signals.error.connect(
            lambda error, operation_name=action:
                self._on_system_tunnel_action_failed(operation_name, error)
        )
        self._system_tunnel_worker = worker
        self.thread_pool.start(worker)

    def _on_system_tunnel_action_finished(self, action: str, message: str):
        self._system_tunnel_busy = False
        self._system_tunnel_worker = None
        self.system_tunnel_status.setText(str(message))
        self.logs_widget.update_log(f"System tunnel {action}: {message}")
        self._update_system_tunnel_controls()

    def _on_system_tunnel_action_failed(self, action: str, error: str):
        self._system_tunnel_busy = False
        self._system_tunnel_worker = None
        detail = str(error or "Unknown system tunnel error.")
        self.system_tunnel_status.setText(f"{action.title()} failed — see Event Log")
        self.logs_widget.update_log(f"System tunnel {action} failed: {detail}", level="error")
        self._update_system_tunnel_controls()
        QMessageBox.warning(self, "System-wide tunnel", detail)
