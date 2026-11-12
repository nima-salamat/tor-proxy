from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QToolButton,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QFrame,
    QPushButton,
    QComboBox,
    QSizePolicy,
)


from PySide6.QtCore import QEvent, Qt, QTimer, QThreadPool, QPropertyAnimation, QEasingCurve
from pathlib import Path

from torproxy.onion_hosting import OnionHostingManager
from torproxy.bridges import parse_bridge_text
from torproxy.ports import PortAllocationError, ephemeral_loopback_port, resolve_listener_ports
from torproxy.service_pool import TorServicePool
from torproxy.service_credentials import read_upstream_credentials
from torproxy.tor_manager import TorManagerError, TorSettings
from set_proxy import has_proxy_snapshot, manage_proxy
from tor import TorRunner, Runner
from proxy import load_blocked, load_exclude

from whatismyip import what_is_my_ip
from ui_.window.log_window import LogWindow
from ui_.btn.pulse_button import PulseButton
from ui_.worker.worker import Worker
from ui_.worker.utils import Data
from config import CONFIG
from ui_.window.dialogs import QMessageBox
from torproxy.paths import user_directories
from torproxy.system_tunnel import SystemTunnelCancelled, SystemTunnelManager
from ui_.window.tor_log_dialog import TorLogDialog
from ui_.window.open_browser_dialog import OpenBrowserDialog
import ipaddress
import json
import logging
import socket
import threading
import qtawesome as qta

logger = logging.getLogger(__name__)


class SystemTunnelActionButton(QPushButton):
    """Keep the tunnel action icon in sync with normal, hover and disabled text colors."""

    def __init__(self, text: str = "Start", parent=None):
        super().__init__(text, parent)
        self._icon_name = "fa6s.play"
        self._hovered = False
        self._hover_color = "#253041"
        self._disabled_color = "#667386"
        self._icon_color = "#ffffff"
        self._sync_icon()

    def set_icon_name(self, name: str) -> None:
        self._icon_name = str(name)
        self._sync_icon()

    def set_theme_colors(self, *, text: str, muted: str) -> None:
        self._hover_color = str(text)
        self._disabled_color = str(muted)
        self._sync_icon()

    def _sync_icon(self) -> None:
        if not self.isEnabled():
            color = self._disabled_color
        elif self._hovered:
            color = self._hover_color
        else:
            color = "#ffffff"
        self._icon_color = color
        self.setIcon(qta.icon(self._icon_name, color=color))

    def _set_hovered(self, hovered: bool) -> None:
        hovered = bool(hovered)
        if hovered != self._hovered:
            self._hovered = hovered
            self._sync_icon()

    def enterEvent(self, event):
        self._set_hovered(True)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._set_hovered(False)
        super().leaveEvent(event)

    def changeEvent(self, event):
        if event.type() == QEvent.Type.EnabledChange and hasattr(self, "_icon_name"):
            self._sync_icon()
        super().changeEvent(event)


class ProxyWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = Data()
        # Load saved host policy before either proxy service can accept traffic.
        load_blocked()
        load_exclude()
        self.running = False
        self.connected = False
        self.failed = False
        self.proxy_set = has_proxy_snapshot()  # also recover safely after an unclean previous exit
        self._stopping = False
        self._disconnect_worker = None
        self._disconnect_final_status = "NOT CONNECTED"
        self._identity_busy = False
        self._exit_ip_check_busy = False
        self._exit_ip_worker = None
        self._parent = parent
        self._operation_lock = threading.RLock()
        self._connect_operation_busy = False
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
        self.tor.bridge = CONFIG["bridge"]
        self.tor.bridges = CONFIG["bridges"]
        self.tor.app_window = self
        self.proxy = Runner(self.proxy_port, self.tor_socks_port,self)
        # The pool belongs to the long-lived Home controller, not the Settings
        # widget. Closing Settings must never detach or forget isolated Tor processes.
        self.tor_service_pool: TorServicePool | None = None
        self.tor_service_profile_errors: dict[str, str] = {}
        self._tor_service_pool_lock = threading.RLock()
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
        self.home_layout.setContentsMargins(24, 18, 24, 16)
        self.home_layout.setSpacing(12)
        self.main_layout.addWidget(self.home_content, 1)

        self.btn_status = QLabel("NOT CONNECTED")
        self.btn_status.setObjectName("connectionStatus")
        self.btn_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_btn_status_style("disconnected")
        self.home_layout.addWidget(self.btn_status, 0, Qt.AlignmentFlag.AlignHCenter)

        self.connect_btn = PulseButton("Connect")
        self.connect_btn.setObjectName("connectPulseButton")
        self.connect_btn.clicked.connect(self._toggle)

        connection_hero = QWidget(self.home_content)
        connection_hero.setObjectName("connectionHero")
        connection_hero_layout = QVBoxLayout(connection_hero)
        connection_hero_layout.setContentsMargins(0, 0, 0, 0)
        connection_hero_layout.setSpacing(10)
        connection_hero_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        connection_hero_layout.addWidget(
            self.connect_btn, 0, Qt.AlignmentFlag.AlignHCenter
        )
        self.connection_hint = QLabel(
            "Start Tor to enable your configured proxy listeners.",
            connection_hero,
        )
        self.connection_hint.setObjectName("connectionHint")
        self.connection_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.connection_hint.setWordWrap(True)
        self.connection_hint.setMaximumWidth(420)
        connection_hero_layout.addWidget(
            self.connection_hint, 0, Qt.AlignmentFlag.AlignHCenter
        )

        connect_row = QHBoxLayout()
        connect_row.setContentsMargins(0, 0, 0, 0)
        connect_row.addStretch(1)
        connect_row.addWidget(connection_hero, 0, Qt.AlignmentFlag.AlignCenter)
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
        bootstrap_caption = QLabel("BOOTSTRAP", self.home_content)
        bootstrap_caption.setObjectName("homeMetricCaption")
        self.lbl_percent.setToolTip("Tor bootstrap progress")
        metrics.addWidget(bootstrap_caption)
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

        proxy_controls = QFrame(self.home_content)
        proxy_controls.setObjectName("systemProxyControls")
        proxy_controls_layout = QVBoxLayout(proxy_controls)
        proxy_controls_layout.setContentsMargins(12, 7, 12, 7)
        proxy_controls_layout.setSpacing(3)

        proxy_row = QHBoxLayout()
        proxy_row.setContentsMargins(0, 0, 0, 0)
        proxy_row.setSpacing(12)
        proxy_title = QLabel("SYSTEM PROXY")
        proxy_title.setObjectName("systemProxyTitle")
        proxy_row.addWidget(proxy_title)
        self.system_proxy_mode = QComboBox(proxy_controls)
        self.system_proxy_mode.setObjectName("systemProxyMode")
        self.system_proxy_mode.addItem("Set system proxy", "set")
        self.system_proxy_mode.addItem("Do not change system proxy", "unchanged")
        self.system_proxy_mode.addItem("Clear system proxy", "clear")
        current_mode = CONFIG["system_proxy_mode"]
        mode_index = self.system_proxy_mode.findData(current_mode)
        self.system_proxy_mode.setCurrentIndex(mode_index if mode_index >= 0 else 1)
        self.system_proxy_mode.currentIndexChanged.connect(self._on_system_proxy_mode_changed)
        proxy_row.addWidget(self.system_proxy_mode, 1)
        proxy_controls_layout.addLayout(proxy_row)

        # Keep status text available to accessibility/debugging and existing
        # state transitions, but do not consume Home space with explanatory copy.
        self.proxy_status_label = QLabel(proxy_controls)
        self.proxy_status_label.setObjectName("proxyStatusLabel")
        self.proxy_status_label.setVisible(False)

        self.system_tunnel_hint = QFrame(self.home_content)
        self.system_tunnel_hint.setObjectName("systemTunnelHint")
        self.system_tunnel_hint.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        tunnel_hint_layout = QHBoxLayout(self.system_tunnel_hint)
        tunnel_hint_layout.setContentsMargins(10, 5, 10, 5)
        tunnel_hint_layout.setSpacing(10)
        self.system_tunnel_hint_label = QLabel("System tunnel is not installed · Manage it in Updates")
        self.system_tunnel_hint_label.setObjectName("systemTunnelHintLabel")
        self.system_tunnel_hint_label.setWordWrap(False)
        tunnel_hint_layout.addWidget(self.system_tunnel_hint_label, 1)
        self.btn_system_tunnel_action = SystemTunnelActionButton("Start", self.system_tunnel_hint)
        self.btn_system_tunnel_action.setObjectName("systemTunnelAction")
        self.btn_system_tunnel_action.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_system_tunnel_action.clicked.connect(self.toggle_system_tunnel)
        tunnel_hint_layout.addWidget(self.btn_system_tunnel_action)

        self.btn_system_tunnel_manage = QPushButton("Manage", self.system_tunnel_hint)
        self.btn_system_tunnel_manage.setObjectName("systemTunnelManage")
        self.btn_system_tunnel_manage.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_system_tunnel_manage.setIcon(qta.icon("fa6s.arrow-right"))
        self.btn_system_tunnel_manage.clicked.connect(self.open_tunnel_manager)
        tunnel_hint_layout.addWidget(self.btn_system_tunnel_manage)

        # System proxy policy and the system-wide TUN are peer controls, not
        # separate Home sections. Keep both actions visible in one compact row.
        service_controls_row = QHBoxLayout()
        service_controls_row.setContentsMargins(0, 0, 0, 0)
        service_controls_row.setSpacing(12)
        service_controls_row.addWidget(proxy_controls, 1)
        service_controls_row.addWidget(self.system_tunnel_hint, 1)
        self.home_layout.addLayout(service_controls_row)

        # Compact copyable listener endpoints sit beside the observed exit IP.
        self._home_endpoint_controls = {}
        self._home_endpoint_values = {}
        endpoint_row = QHBoxLayout()
        endpoint_row.setContentsMargins(0, 0, 0, 0)
        endpoint_row.setSpacing(12)
        endpoint_panel = QWidget(self.home_content)
        endpoint_panel.setObjectName("homeEndpointPanel")
        endpoint_layout = QHBoxLayout(endpoint_panel)
        endpoint_layout.setContentsMargins(0, 0, 0, 0)
        endpoint_layout.setSpacing(8)
        endpoint_layout.addWidget(self._build_home_endpoint_card("SOCKS5", "socks"), 1)
        endpoint_layout.addWidget(self._build_home_endpoint_card("HTTP", "http"), 1)
        endpoint_row.addWidget(endpoint_panel, 2)

        self.exit_ip_card = QFrame(self.home_content)
        self.exit_ip_card.setObjectName("homeExitIpCard")
        self.exit_ip_card.setMinimumWidth(180)
        exit_ip_layout = QVBoxLayout(self.exit_ip_card)
        exit_ip_layout.setContentsMargins(12, 9, 12, 9)
        exit_ip_layout.setSpacing(5)
        exit_ip_title = QLabel("TOR EXIT IP", self.exit_ip_card)
        exit_ip_title.setObjectName("homeExitIpTitle")
        exit_ip_layout.addWidget(exit_ip_title)

        self.tor_ip_label = QLabel("Not checked yet", self.exit_ip_card)
        self.tor_ip_label.setObjectName("exitIpLabel")
        self.tor_ip_label.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        self.tor_ip_label.setWordWrap(True)
        self.tor_ip_label.setMinimumWidth(140)
        self.exit_ip_card.setToolTip(
            "Exit address observed through Tor using the local HTTP proxy."
        )
        exit_ip_layout.addWidget(self.tor_ip_label)
        endpoint_row.addWidget(self.exit_ip_card, 1)
        self.home_layout.addLayout(endpoint_row)

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
        self.tor.bridge_usage_changed.connect(self._on_tor_pool_health_changed)
        self.tor.bridges_updated.connect(self._sync_bridge_editor)
        self.logs_widget.apply_theme(CONFIG["mode"])
        self._apply_home_theme()
        self._refresh_home_endpoint_display()
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

    def _build_home_endpoint_card(self, title: str, key: str) -> QFrame:
        card = QFrame(self.home_content)
        card.setObjectName("homeEndpointCard")
        card.setMinimumWidth(210)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 9, 10, 9)
        layout.setSpacing(5)

        title_label = QLabel(title, card)
        title_label.setObjectName("homeEndpointTitle")
        layout.addWidget(title_label)

        values = QHBoxLayout()
        values.setContentsMargins(0, 0, 0, 0)
        values.setSpacing(10)

        host_column = QVBoxLayout()
        host_column.setContentsMargins(0, 0, 0, 0)
        host_column.setSpacing(2)
        host_caption = QLabel("ADDRESS", card)
        host_caption.setObjectName("homeEndpointFieldLabel")
        host_column.addWidget(host_caption)

        host_button = QToolButton(card)
        host_button.setObjectName("homeEndpointPart")
        host_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        host_button.setAutoRaise(True)
        host_button.setCursor(Qt.CursorShape.PointingHandCursor)
        host_button.setMinimumWidth(84)
        host_button.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        host_button.setToolTip("Copy IP address")
        host_button.clicked.connect(
            lambda _checked=False, endpoint=key: self._copy_home_endpoint_part(endpoint, "host")
        )
        host_column.addWidget(host_button)

        port_column = QVBoxLayout()
        port_column.setContentsMargins(0, 0, 0, 0)
        port_column.setSpacing(2)
        port_caption = QLabel("PORT", card)
        port_caption.setObjectName("homeEndpointFieldLabel")
        port_column.addWidget(port_caption)

        port_button = QToolButton(card)
        port_button.setObjectName("homeEndpointPart")
        port_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        port_button.setAutoRaise(True)
        port_button.setCursor(Qt.CursorShape.PointingHandCursor)
        port_button.setMinimumWidth(48)
        port_button.setToolTip("Copy port")
        port_button.clicked.connect(
            lambda _checked=False, endpoint=key: self._copy_home_endpoint_part(endpoint, "port")
        )
        port_column.addWidget(port_button)

        copy_button = QToolButton(card)
        copy_button.setObjectName("homeEndpointCopy")
        copy_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        copy_button.setCursor(Qt.CursorShape.PointingHandCursor)
        copy_button.setFixedSize(84, 32)
        copy_button.setText("Copy")
        copy_button.setToolTip("Copy the complete host:port endpoint")
        copy_button.setIcon(qta.icon("fa6s.copy", color="#aab4c1"))
        copy_button.clicked.connect(
            lambda _checked=False, endpoint=key: self._copy_home_endpoint_full(endpoint)
        )

        values.addLayout(host_column, 1)
        values.addLayout(port_column, 0)
        values.addWidget(copy_button, 0, Qt.AlignmentFlag.AlignBottom)
        layout.addLayout(values)

        copy_feedback_timer = QTimer(card)
        copy_feedback_timer.setSingleShot(True)
        copy_feedback_timer.timeout.connect(
            lambda endpoint=key: self._restore_home_endpoint_copy_button(endpoint)
        )
        self._home_endpoint_controls[key] = {
            "title": title_label,
            "host_caption": host_caption,
            "host": host_button,
            "port_caption": port_caption,
            "port": port_button,
            "copy": copy_button,
            "copy_timer": copy_feedback_timer,
        }
        return card

    @staticmethod
    def _resolve_lan_ipv4() -> str | None:
        """Find a usable physical LAN IPv4 address, never returning a wildcard or loopback."""
        try:
            import psutil

            interface_stats = psutil.net_if_stats()
            candidates: list[tuple[int, str, str]] = []
            virtual_markers = (
                "loopback", "torproxy", "sing-box", "wintun", "tun", "tap",
                "virtual", "vmware", "virtualbox", "vbox", "hyper-v", "docker",
                "wsl", "tailscale", "zerotier", "teredo", "bluetooth", "wireguard", "wg-",

            )
            preferred_markers = ("wi-fi", "wifi", "wlan", "wireless", "ethernet", "eth")
            lan_networks = tuple(
                ipaddress.ip_network(network)
                for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
            )
            for interface_name, addresses in psutil.net_if_addrs().items():
                name = str(interface_name).casefold()
                if any(marker in name for marker in virtual_markers):
                    continue
                stats = interface_stats.get(interface_name)
                if stats is not None and not bool(getattr(stats, "isup", False)):
                    continue
                for item in addresses:
                    if item.family != socket.AF_INET:
                        continue
                    try:
                        address = ipaddress.ip_address(str(item.address))
                    except ValueError:
                        continue
                    if not any(address in network for network in lan_networks):
                        continue
                    priority = 2 if any(marker in name for marker in preferred_markers) else 1
                    candidates.append((priority, name, str(address)))

            if not candidates:
                return None

            # UDP connect performs a local route lookup; it does not send a packet.
            route_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                route_socket.connect(("1.1.1.1", 53))
                route_address = str(route_socket.getsockname()[0])
                if any(address == route_address for _priority, _name, address in candidates):
                    return route_address
            except OSError:
                pass
            finally:
                route_socket.close()

            candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
            return candidates[0][2]
        except Exception:
            logger.debug("Could not determine a physical LAN IPv4 address for proxy endpoint display.", exc_info=True)
            return None

    def _refresh_home_endpoint_display(self) -> None:
        """Show the client-reachable host for each independent listener binding."""
        if not getattr(self, "_home_endpoint_controls", None):
            return
        socks_remote = bool(CONFIG.get("tor_socks_bind_all_interfaces", False))
        http_remote = bool(CONFIG.get("http_proxy_bind_all_interfaces", False))
        lan_ip = self._resolve_lan_ipv4() if socks_remote or http_remote else None
        endpoint_specs = (
            ("socks", socks_remote, int(self.tor_socks_port), "SOCKS5"),
            ("http", http_remote, int(self.proxy_port), "HTTP"),
        )
        for key, remote, port, label in endpoint_specs:
            host = lan_ip if remote else "127.0.0.1"
            available_host = bool(host)
            displayed_host = host or "LAN IP unavailable"
            controls = self._home_endpoint_controls[key]
            controls["title"].setText(
                label + (" · OFF" if key == "http" and not bool(CONFIG.get("http_proxy_enabled", True)) else "")
            )
            controls["host"].setText(displayed_host)
            controls["host"].setEnabled(available_host)
            controls["port"].setText(str(port))
            controls["port"].setEnabled(1 <= port <= 65535)
            controls["copy"].setEnabled(available_host and 1 <= port <= 65535)
            controls["host"].setToolTip(
                "Copy IP address" if available_host else "No physical LAN IPv4 address was detected."
            )
            self._home_endpoint_values[key] = {
                "host": host or "",
                "port": str(port),
            }

    def refresh_home_endpoint_display(self) -> None:
        """Public hook for Settings when a listener changes between local and LAN binding."""
        self._refresh_home_endpoint_display()

    def _copy_home_endpoint_part(self, key: str, part: str) -> None:
        value = str(self._home_endpoint_values.get(key, {}).get(part, "") or "")
        if value:
            QApplication.clipboard().setText(value)

    def _copy_home_endpoint_full(self, key: str) -> None:
        values = self._home_endpoint_values.get(key, {})
        host = str(values.get("host", "") or "")
        port = str(values.get("port", "") or "")
        if host and port:
            QApplication.clipboard().setText(f"{host}:{port}")
            self._show_home_endpoint_copy_feedback(key)

    def _show_home_endpoint_copy_feedback(self, key: str) -> None:
        controls = self._home_endpoint_controls.get(key, {})
        button = controls.get("copy")
        if button is None:
            return
        dark = CONFIG["mode"] == "dark"
        success = "#45c98b" if dark else "#16834f"
        button.setText("Copied")
        button.setIcon(qta.icon("fa6s.check", color=success))
        button.setToolTip("Endpoint copied to the clipboard")
        timer = controls.get("copy_timer")
        if timer is not None:
            timer.start(1100)

    def _restore_home_endpoint_copy_button(self, key: str) -> None:
        controls = self._home_endpoint_controls.get(key, {})
        button = controls.get("copy")
        if button is None:
            return
        muted = "#aab4c1" if CONFIG["mode"] == "dark" else "#667386"
        button.setText("Copy")
        button.setIcon(qta.icon("fa6s.copy", color=muted))
        button.setToolTip("Copy the complete host:port endpoint")

    def _tor_service_reserved_ports(self) -> tuple[int, ...]:
        """Return configured and dynamically allocated primary Tor listener ports."""
        values = {self.tor_socks_port, self.tor_control_port, self.tor_dns_port, self.proxy_port}
        for manager in getattr(self.tor, "_backend_managers", ()):
            settings = getattr(manager, "settings", None)
            if settings is None:
                continue
            values.update((
                getattr(settings, "socks_port", None),
                getattr(settings, "control_port", None),
                getattr(settings, "dns_port", None),
            ))
        return tuple(sorted({int(value) for value in values if value}))

    def _tor_service_reserved_paths(self) -> tuple[Path, ...]:
        """Keep independent profiles away from every primary Tor worker's state and logs."""
        directories = user_directories()
        return (
            directories.data / "tor",
            directories.data / "tor-workers",
            directories.logs / "tor.log",
            directories.logs / "tor-workers",
        )

    def _build_tor_service_settings(self, profile: dict) -> TorSettings:
        """Build an isolated manager configuration from a persisted profile."""
        selected_bundle_version = str(profile.get("tor_bundle_version") or "").strip()
        if selected_bundle_version:
            from updater import resolve_verified_bundle

            executable, bundle_root = resolve_verified_bundle(selected_bundle_version)
            geoip_path = bundle_root / "data" / "geoip"
            geoip6_path = bundle_root / "data" / "geoip6"
        else:
            if not self.tor.path_set or not self.tor.tor_path:
                self.tor.update_path(CONFIG["tor_path"])
            if not self.tor.path_set or not self.tor.tor_path:
                raise TorManagerError(
                    "A compatible Tor Expert Bundle must be installed or selected for this Custom Tor profile."
                )
            executable = Path(self.tor.tor_path)
            geoip_path = Path(self.tor.geoip_path) if self.tor.geoip_path else None
            geoip6_path = Path(self.tor.geoip6_path) if self.tor.geoip6_path else None

        use_primary_bridges = bool(profile.get("use_primary_bridges", False))
        bridges_enabled = bool(self.tor.bridge) if use_primary_bridges else bool(profile.get("bridge_enabled", False))
        bridges = str(self.tor.bridges or "") if use_primary_bridges else str(profile.get("bridges") or "")
        data_directory_value = profile.get("data_directory")
        dns_port_value = profile.get("dns_port")
        proxy_type = str(profile.get("upstream_proxy_type", "none"))
        credentials = (
            read_upstream_credentials(str(profile["id"]))
            if proxy_type != "none"
            else {"upstream_proxy_username": "", "upstream_proxy_password": ""}
        )
        return TorSettings(
            executable=Path(executable),
            socks_port=int(profile["socks_port"]),
            control_port=int(profile["control_port"]),
            dns_port=int(dns_port_value) if dns_port_value not in (None, 0, "") else None,
            data_directory=Path(data_directory_value).expanduser() if data_directory_value else None,
            geoip_path=geoip_path,
            geoip6_path=geoip6_path,
            bridges_enabled=bridges_enabled,
            bridges=bridges,
            # Legacy custom profiles inherited these two values from Main Tor.
            max_circuit_dirtiness_seconds=int(profile.get("max_circuit_dirtiness_seconds", self.tor.MaxCircuitDirtiness)),
            new_circuit_period_seconds=int(profile.get("new_circuit_period_seconds", self.tor.NewCircuitPeriod)),
            startup_timeout_seconds=float(profile.get("startup_timeout_seconds", 180)),
            shutdown_timeout_seconds=float(profile.get("shutdown_timeout_seconds", 5)),
            client_use_ipv4=bool(profile.get("client_use_ipv4", True)),
            client_use_ipv6=bool(profile.get("client_use_ipv6", True)),
            upstream_proxy_type=proxy_type,
            upstream_proxy_host=str(profile.get("upstream_proxy_host") or ""),
            upstream_proxy_port=int(profile.get("upstream_proxy_port", 1080)),
            upstream_proxy_username=credentials["upstream_proxy_username"],
            upstream_proxy_password=credentials["upstream_proxy_password"],
            webtunnel_sni_imitation=str(CONFIG["webtunnel_sni_imitation"] or ""),
            webtunnel_use_default_tls=bool(CONFIG["webtunnel_use_default_tls"]),
        )

    def _register_tor_service_profile(self, profile: dict, *, pool=None):
        """Register one persisted profile in the application-owned service pool."""
        service_pool = pool or self._ensure_tor_service_pool()
        service_id = str(profile["id"])
        manager = service_pool.register(service_id, self._build_tor_service_settings(profile))
        self.tor_service_profile_errors.pop(service_id, None)
        return manager

    def _ensure_tor_service_pool(self) -> TorServicePool:
        """Create the pool once and restore saved profiles without failing app startup."""
        with self._tor_service_pool_lock:
            configured_workers = max(1, min(8, int(CONFIG["tor_service_workers"] or 4)))
            if self.tor_service_pool is not None:
                self.tor_service_pool.set_max_workers(configured_workers)
                return self.tor_service_pool

            if not self.tor.path_set or not self.tor.tor_path:
                self.tor.update_path(CONFIG["tor_path"])
            if not self.tor.path_set or not self.tor.tor_path:
                raise TorManagerError(
                    "No compatible Tor executable is available. Install or select a Tor Expert Bundle first."
                )

            pool = TorServicePool(
                reserved_ports=self._tor_service_reserved_ports(),
                reserved_paths=self._tor_service_reserved_paths(),
                max_workers=configured_workers,
            )
            self.tor_service_pool = pool
            self.tor_service_profile_errors = {}
            for profile in CONFIG["tor_services"] or []:
                try:
                    self._register_tor_service_profile(profile, pool=pool)
                except Exception as exc:
                    service_id = str(profile.get("id", "unknown"))
                    self.tor_service_profile_errors[service_id] = f"{type(exc).__name__}: {exc}"
                    logger.warning(
                        "Could not restore isolated Tor service '%s': %s", service_id, exc
                    )
            return pool

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

    def open_custom_tor_page(self):
        owner = self._parent
        show_custom_tor = getattr(owner, "_show_custom_tor", None)
        if callable(show_custom_tor):
            show_custom_tor()

    def open_developer_tor_page(self):
        owner = self._parent
        show_page = getattr(owner, "_show_developer_tor", None)
        if callable(show_page):
            show_page()

    def _build_developer_tor_settings(self) -> TorSettings:
        """Build an isolated Developer Tor configuration from its own saved preferences."""
        if not self.tor.path_set or not self.tor.tor_path:
            self.tor.update_path(CONFIG["tor_path"])
        if not self.tor.path_set or not self.tor.tor_path:
            raise TorManagerError(
                "Install or select a compatible Tor Expert Bundle before starting Developer Tor."
            )
        preferences = dict(CONFIG["developer_tor_settings"] or {})
        bridge_mode = str(preferences.get("bridge_mode", "direct"))
        bridges = ""
        bridges_enabled = False
        if bridge_mode == "main":
            if not bool(CONFIG["bridge"]):
                raise TorManagerError(
                    "Developer Tor is set to use Main Tor bridges, but bridge mode is disabled in Settings → Bridges."
                )
            bridges = str(CONFIG["bridges"] or "")
            bridges_enabled = True
        elif bridge_mode == "custom":
            bridges = str(preferences.get("bridges") or "")
            bridges_enabled = True
        elif bridge_mode != "direct":
            raise TorManagerError("Unknown Developer Tor bridge mode.")
        if bridges_enabled:
            parsed = parse_bridge_text(bridges)
            if parsed.invalid_records or not parsed.records:
                details = " ".join(parsed.errors[:3]) or "No valid bridge records were found."
                raise TorManagerError("Developer Tor Bridge configuration is invalid: " + details)
            bridges = "\n".join(parsed.records)

        # Credentials are read from a separate, permission-restricted file;
        # they are never persisted in config.json or included in routine logs.
        proxy_type = str(preferences.get("upstream_proxy_type", "none"))
        credentials = (
            self._ensure_onion_hosting_manager().network_proxy_credentials()
            if proxy_type != "none"
            else {"upstream_proxy_username": "", "upstream_proxy_password": ""}
        )
        directories = user_directories()
        return TorSettings(
            executable=Path(self.tor.tor_path),
            socks_port=0,
            control_port=ephemeral_loopback_port(),
            dns_port=None,
            data_directory=directories.data / "developer-tor",
            geoip_path=Path(self.tor.geoip_path) if self.tor.geoip_path else None,
            geoip6_path=Path(self.tor.geoip6_path) if self.tor.geoip6_path else None,
            bridges_enabled=bridges_enabled,
            bridges=bridges,
            bridge_source=bridge_mode,
            webtunnel_sni_imitation=str(preferences.get("webtunnel_sni_imitation") or ""),
            webtunnel_use_default_tls=bool(preferences.get("webtunnel_use_default_tls", True)),
            max_circuit_dirtiness_seconds=int(preferences.get("max_circuit_dirtiness_seconds", 600)),
            new_circuit_period_seconds=int(preferences.get("new_circuit_period_seconds", 60)),
            startup_timeout_seconds=float(preferences.get("startup_timeout_seconds", 180)),
            shutdown_timeout_seconds=float(preferences.get("shutdown_timeout_seconds", 5)),
            client_use_ipv4=bool(preferences.get("client_use_ipv4", True)),
            client_use_ipv6=bool(preferences.get("client_use_ipv6", True)),
            upstream_proxy_type=proxy_type,
            upstream_proxy_host=str(preferences.get("upstream_proxy_host") or ""),
            upstream_proxy_port=int(preferences.get("upstream_proxy_port", 1080)),
            upstream_proxy_username=credentials["upstream_proxy_username"],
            upstream_proxy_password=credentials["upstream_proxy_password"],
            log_path=directories.logs / "developer-tor" / "tor.log",
        )

    def _ensure_onion_hosting_manager(self) -> OnionHostingManager:
        """Keep Developer Tor owned by Home so hiding the window never stops hosting."""
        manager = getattr(self, "onion_hosting_manager", None)
        if manager is None:
            manager = OnionHostingManager(self._build_developer_tor_settings)
            self.onion_hosting_manager = manager
        return manager

    def open_browser_dialog(self):
        """Open the browser chooser only after Tor and the local HTTP listener are ready."""
        if (
            not self.running
            or not self.connected
            or not bool(CONFIG["http_proxy_enabled"])
            or not bool(getattr(self.proxy, "is_running", False))
        ):
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
            self.tor_ip_label.setText("Unavailable · Tor is not ready")
            logger.info("Exit-IP check ignored because Tor is not in the verified connected state.")
            return
        if not bool(CONFIG["http_proxy_enabled"]) or not bool(getattr(self.proxy, "is_running", False)):
            self.tor_ip_label.setText("Unavailable · HTTP proxy is disabled")
            return

        try:
            proxy_port = int(self.proxy.port)
            if not 1 <= proxy_port <= 65535:
                raise ValueError("The local HTTP proxy port is invalid.")
            proxy_url = f"http://127.0.0.1:{proxy_port}"
            self._exit_ip_check_busy = True
            self.btn_whatismyip.setEnabled(False)
            self.tor_ip_label.setText("Checking via Tor proxy…")
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
                self.tor_ip_label.setText(address)
                logger.info("Exit-IP verification completed through the local proxy.")
            else:
                self.tor_ip_label.setText("Unverified")
                logger.warning("Exit-IP endpoint returned an empty response.")
        except Exception:
            logger.exception("Could not display the verified exit-IP result.")
            try:
                self.tor_ip_label.setText("Could not display result · See Event Log")
            except RuntimeError:
                pass
        finally:
            self._finish_exit_ip_check()

    def _on_exit_ip_failed(self, error):
        message = str(error or "Unknown exit-IP verification failure.")
        logger.warning("Proxied exit-IP check failed: %s", message)
        try:
            self.tor_ip_label.setText("Check failed · no direct fallback used")
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
        field = "transparent"
        hover = "#2b3643" if dark else "#eaf0f5"
        text = "#e8edf3" if dark else "#253041"
        self.home_content.setStyleSheet(f"""
            QWidget#homeContent {{ background: transparent; }}
            QPushButton#connectPulseButton {{ background: transparent; border: none; padding: 0; margin: 0; }}
            QPushButton#connectPulseButton:hover, QPushButton#connectPulseButton:pressed, QPushButton#connectPulseButton:focus {{ background: transparent; border: none; }}
            QLabel#connectionStatus {{
                color: {muted}; background: {surface}; border: 1px solid {border};
                border-radius: 12px; padding: 6px 14px; font-size: 11px;
                font-weight: 750; letter-spacing: 0.6px;
            }}
            QLabel#connectionStatus[connectionState="connected"] {{
                color: #45c98b; background: rgba(46, 174, 105, 0.10);
                border-color: rgba(46, 174, 105, 0.38);
            }}
            QLabel#connectionStatus[connectionState="connecting"] {{
                color: {accent}; background: rgba(71, 163, 242, 0.10);
                border-color: rgba(71, 163, 242, 0.38);
            }}
            QLabel#connectionStatus[connectionState="disconnected"] {{
                color: {muted}; background: {surface}; border-color: {border};
            }}
            QLabel#connectionHint {{
                color: {muted}; background: transparent; border: none;
                font-size: 11px; padding: 0 12px;
            }}
            QLabel#homeMetricCaption {{ color: {muted}; background: transparent; border: none; font-size: 8px; font-weight: 800; letter-spacing: 0.8px; }}
            QLabel#bootstrapPercent {{ color: {accent}; background: transparent; border: none; font-size: 16px; font-weight: 750; padding: 3px; }}
            QLabel#trafficUsage, QLabel#proxyStatusLabel {{ color: {muted}; background: transparent; border: none; font-size: 11px; padding: 2px; }}
            QWidget#homeEndpointPanel {{ background: transparent; border: none; }}
            QFrame#homeEndpointCard, QFrame#homeExitIpCard {{
                background: {surface}; border: 1px solid {border}; border-radius: 12px;
            }}
            QLabel#homeEndpointTitle, QLabel#homeExitIpTitle {{
                color: {muted}; background: transparent; border: none;
                font-size: 9px; font-weight: 800; letter-spacing: 0.8px;
            }}
            QLabel#homeEndpointFieldLabel {{
                color: {muted}; background: transparent; border: none;
                font-size: 8px; font-weight: 750; letter-spacing: 0.6px;
            }}
            QToolButton#homeEndpointPart {{
                color: {text}; background: transparent; border: none;
                padding: 0; font-size: 12px; font-weight: 700; text-align: left;
            }}
            QToolButton#homeEndpointPart:hover {{ color: {accent}; }}
            QToolButton#homeEndpointPart:disabled {{ color: {muted}; }}
            QToolButton#homeEndpointCopy {{
                min-width: 84px; min-height: 32px; color: {text}; background: {hover};
                border: 1px solid {border}; border-radius: 8px; padding: 0 7px;
                font-size: 10px; font-weight: 750;
            }}
            QToolButton#homeEndpointCopy:hover {{ background: rgba(71, 163, 242, 0.12); border-color: {accent}; }}
            QToolButton#homeEndpointCopy:disabled {{ color: {muted}; background: transparent; border-color: {border}; }}
            QLabel#exitIpLabel {{
                color: {text}; background: transparent; border: none;
                font-size: 12px; font-weight: 650; padding: 0;
            }}
            QPushButton#statisticsLink {{ color: {accent}; background: transparent; border: none; padding: 2px 4px; font-size: 11px; font-weight: 700; }}
            QPushButton#statisticsLink:hover {{ color: {text}; border-bottom: 1px solid {accent}; }}
            QLabel#systemProxyTitle {{ color: {muted}; background: transparent; border: none; font-size: 9px; font-weight: 800; letter-spacing: 0.9px; }}
            QFrame#homeMetricSeparator {{ color: {border}; background: {border}; max-width: 1px; }}
            QComboBox#systemProxyMode {{ min-height: 36px; padding: 0 12px; border: 1px solid {border}; border-radius: 9px; background: transparent; color: {text}; }}
            QComboBox#systemProxyMode:hover {{ border-color: {accent}; }}
            QComboBox#systemProxyMode QAbstractItemView {{ background: {surface}; color: {text}; selection-background-color: {accent}; selection-color: #ffffff; outline: none; border: 1px solid {border}; }}
            QComboBox#systemProxyMode QAbstractItemView::item {{ background: {surface}; color: {text}; padding: 8px 10px; min-height: 22px; }}
            QComboBox#systemProxyMode QAbstractItemView::item:selected {{ background: {accent}; color: #ffffff; }}
            QPushButton#secondaryAction {{ min-height: 40px; padding: 0 14px; border-radius: 10px; background: transparent; color: {text}; border: 1px solid {border}; font-weight: 650; }}
            QPushButton#secondaryAction:hover {{ background: rgba(71, 163, 242, 0.12); border-color: {accent}; }}
            QPushButton#secondaryAction:disabled {{ color: {muted}; }}
            QPushButton#secondaryAction:checked {{ background: rgba(71, 163, 242, 0.18); border-color: {accent}; }}
            QFrame#systemProxyControls {{ background: {surface}; border: 1px solid {border}; border-radius: 12px; }}
            QFrame#systemTunnelHint {{ background: {surface}; border: 1px solid {border}; border-radius: 12px; }}
            QLabel#systemTunnelHintLabel {{ color: {muted}; background: transparent; border: none; font-size: 10px; }}
            QPushButton#systemTunnelAction {{ min-height: 27px; padding: 0 11px; border-radius: 7px; background: {accent}; color: #ffffff; border: 1px solid {accent}; font-size: 10px; font-weight: 750; }}
            QPushButton#systemTunnelAction:hover {{ background: {hover}; color: {text}; border-color: {accent}; }}
            QPushButton#systemTunnelAction:disabled {{ background: {field}; color: {muted}; border-color: {border}; }}
            QPushButton#systemTunnelManage {{ min-height: 27px; padding: 0 9px; border-radius: 7px; background: {field}; color: {text}; border: 1px solid {border}; font-size: 10px; font-weight: 700; }}
            QPushButton#systemTunnelManage:hover {{ background: {hover}; border-color: {accent}; }}
        """)
        self.logs_widget.apply_theme(CONFIG["mode"])
        icon_color = "#eff1f4" if dark else "#202832"
        self.btn_change_identity.setIcon(qta.icon("fa6s.arrows-rotate", color=icon_color))
        self.btn_log.setIcon(qta.icon("fa6s.align-left", color=icon_color))
        self.btn_whatismyip.setIcon(qta.icon("fa6s.globe", color=icon_color))
        self.btn_open_browser.setIcon(qta.icon("fa6s.globe", color=icon_color))
        self.btn_system_tunnel_action.set_theme_colors(text=text, muted=muted)
        self.btn_statistics.setIcon(qta.icon("fa6s.chart-line", color=accent))
        for controls in getattr(self, "_home_endpoint_controls", {}).values():
            controls["copy"].setIcon(qta.icon("fa6s.copy", color=muted))

    def _on_system_proxy_mode_changed(self, index):
        mode = self.system_proxy_mode.itemData(index)
        if mode not in {"set", "unchanged", "clear"}:
            return
        if mode == "set" and not bool(CONFIG["http_proxy_enabled"]):
            previous = self.system_proxy_mode.findData(CONFIG["system_proxy_mode"])
            self.system_proxy_mode.blockSignals(True)
            if previous >= 0:
                self.system_proxy_mode.setCurrentIndex(previous)
            self.system_proxy_mode.blockSignals(False)
            self.proxy_status_label.setText(
                "Enable the local HTTP proxy in Settings → Ports before applying the system proxy."
            )
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
            if not bool(CONFIG["http_proxy_enabled"]):
                status = "System proxy unavailable · enable the local HTTP proxy in Settings → Ports."
            else:
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
            wait = float(self.tor.request_new_identity())
            if wait > 0:
                message = f"Tor rate-limits identity requests; try again in about {wait:.0f} seconds."
                logger.info(message)
                return False
            logger.info("Tor accepted the NEWNYM request; a different exit IP is not guaranteed.")
            return True
        except Exception as exc:
            logger.warning("Tor identity request failed: %s", exc)
            return False

    def _set_home_connected_feedback(self, connected: bool) -> bool:
        """Update the Home button only when aggregate Tor readiness crosses zero."""
        connected = bool(connected)
        if bool(self.connected) == connected:
            return False
        self.connected = connected
        self.connect_btn.set_connected(connected)
        return True

    def dataValueChanged(self, v):
        if v == "100%":
            manager = getattr(self.tor, "manager", None)
            manager_state = getattr(manager, "state", None) if manager is not None else None
            manager_state = str(getattr(manager_state, "value", manager_state)).lower()
            if getattr(self.tor, "state", "") != "READY" or manager_state != "ready":
                # TorManager already verifies its authenticated ControlPort and
                # SOCKS listener before emitting READY. Ignore stale/early 100%
                # updates rather than opening a second ControlPort session whose
                # transient authentication failure could tear down a healthy Tor.
                self.logs_widget.update_log(
                    "Ignored a stale 100% bootstrap update because Tor's verified READY state is not active.",
                    level="warning",
                )
                self.lbl_percent.setText(str(v))
                return

            if self._parent is not None and self._parent.isHidden():
                self._parent._notify("TorProxy", "Tor bootstrap completed")
            self._set_home_connected_feedback(True)
            self.btn_status.setText("CONNECTED TO TOR")
            self.set_btn_status_style("connected")
            self._update_proxy_buttons()
            self._update_tunnel_hint()
            tunnel_page = getattr(self._parent, "tunnel_window", None)
            refresh_tunnel_page = getattr(tunnel_page, "_refresh_state", None)
            if callable(refresh_tunnel_page):
                refresh_tunnel_page()
            self._refresh_http_proxy_settings()
            self._apply_system_proxy_mode()
            self.timer_data_usage.start()

        self.lbl_percent.setText(str(v))
    def _on_tor_pool_health_changed(self, health):
        """Reflect the number of verified primary Tor backends on the Home page."""
        if not isinstance(health, dict) or not self.running or self._stopping:
            return
        try:
            ready = max(0, int(health.get("ready_instances", 0)))
            total = max(0, int(health.get("total_instances", 0)))
        except (TypeError, ValueError):
            return

        if ready:
            # The health signal can fire for each worker and each quality update.
            # Only a 0 -> 1+ transition should replay the Connected acknowledgement;
            # losing/recovering one backend while another is healthy must not flash it.
            self._set_home_connected_feedback(True)
            self.failed = False
            if total > 0 and ready < total:
                self.btn_status.setText(f"CONNECTED · {ready}/{total} TOR INSTANCES READY")
            else:
                self.btn_status.setText("CONNECTED TO TOR")
            self.set_btn_status_style("connected")
        elif self.connected:
            # A complete backend outage may be temporary while the supervisor
            # restarts an instance. Keep the gateway alive and show reconnecting
            # instead of tearing the whole pool down immediately.
            self._set_home_connected_feedback(False)
            self.btn_status.setText("TOR INSTANCES RECONNECTING…")
            self.set_btn_status_style("connecting")

        self._update_proxy_buttons()
        self._refresh_http_proxy_settings()
        self._update_tunnel_hint()
        tunnel_page = getattr(self._parent, "tunnel_window", None)
        refresh_tunnel_page = getattr(tunnel_page, "_refresh_state", None)
        if callable(refresh_tunnel_page):
            refresh_tunnel_page()

    def _on_tor_failed(self, message):
        self.failed = True
        self.logs_widget.update_log(f"Tor supervisor reported a failure: {message}")
        logger.error("Tor supervisor failed: %s", message)
        if self._parent is not None and hasattr(self._parent, "notify_user"):
            self._parent.notify_user("Tor startup failed", str(message), level="warning")

        if self.running:
            self._request_stop_services(final_status="TOR STARTUP FAILED · SEE EVENT LOG")
        else:
            self.connect_btn.set_connected(False)
            self.btn_status.setText("TOR STARTUP FAILED · SEE EVENT LOG")
            self.set_btn_status_style("disconnected")

        self._update_proxy_buttons()
        self._update_tunnel_hint()
        tunnel_page = getattr(self._parent, "tunnel_window", None)
        refresh_tunnel_page = getattr(tunnel_page, "_refresh_state", None)
        if callable(refresh_tunnel_page):
            refresh_tunnel_page()
        if self._parent is not None and hasattr(self._parent, "_show_home"):
            self._parent._show_home()
        if not self.logs_open:
            self.show_logs()
    def _on_services_stopped(self, result: str) -> None:
        try:
            payload = json.loads(result)
            messages = payload.get("messages", []) if isinstance(payload, dict) else []
        except (TypeError, ValueError):
            messages = [str(result)]
        for message in messages:
            self.logs_widget.update_log(str(message))

        self.running = False
        self.connected = False
        self._stopping = False
        self._disconnect_worker = None
        self.lbl_percent.setText("0%")
        self.btn_status.setText(self._disconnect_final_status)
        self.set_btn_status_style("disconnected")
        self.connect_btn.set_connected(False)
        self.connect_btn.setEnabled(True)
        self.timer_data_usage.stop()
        self._update_proxy_buttons()
        self._update_proxy_mode_status()
        self._refresh_http_proxy_settings()
        self._update_tunnel_hint()

        if self._parent is not None and getattr(self._parent, "_shutdown_in_progress", False):
            self._parent._on_proxy_shutdown_complete(True, "")

    def _on_services_stop_cancelled(self, reason: str) -> None:
        """Restore the connected UI when the user declines the elevated cleanup prompt."""
        self._stopping = False
        self._disconnect_worker = None
        self.connect_btn.set_connected(bool(self.connected))
        self.connect_btn.setEnabled(True)
        self.btn_status.setText(
            "DISCONNECT CANCELLED · SERVICES STILL RUNNING"
            if self.running else "DISCONNECT CANCELLED"
        )
        self.set_btn_status_style("connected" if self.connected else "disconnected")
        self.logs_widget.update_log(
            "Disconnect cancelled; the services and system-tunnel state were left unchanged. "
            + str(reason or ""),
            level="info",
        )
        self._update_proxy_buttons()
        self._update_tunnel_hint()

        if self._parent is not None and getattr(self._parent, "_shutdown_in_progress", False):
            self._parent._on_proxy_shutdown_complete(
                False,
                "Administrator approval was cancelled. TorProxy remains open and running.",
            )

    def _on_services_stop_failed(self, error: str) -> None:
        detail = str(error or "Unknown disconnect error.")
        manager = getattr(self.tor, "manager", None)
        process = getattr(manager, "process", None) if manager is not None else None
        tor_process_active = bool(process is not None and process.poll() is None)
        tor_supervisor = getattr(self.tor, "thread", None)
        tor_supervisor_active = bool(tor_supervisor is not None and tor_supervisor.is_alive())
        tor_active = tor_process_active or tor_supervisor_active
        proxy_active = bool(getattr(self.proxy, "server", None) is not None)

        manager_state = getattr(manager, "state", None) if manager is not None else None
        manager_state = str(getattr(manager_state, "value", manager_state)).lower()
        tor_ready = tor_active and manager_state == "ready"
        self.running = tor_active or proxy_active
        self.connected = bool(tor_ready and proxy_active)
        self._stopping = False
        self._disconnect_worker = None
        if self.running:
            self.connect_btn.set_disconnect_available()
        else:
            self.connect_btn.set_connected(False)
        self.connect_btn.setEnabled(True)

        if tor_active and proxy_active:
            status = "DISCONNECT BLOCKED · SERVICES STILL RUNNING"
        elif tor_active:
            status = "PARTIAL DISCONNECT · TOR STILL RUNNING"
        elif proxy_active:
            status = "PARTIAL DISCONNECT · LOCAL PROXY STILL RUNNING"
        else:
            status = "DISCONNECTED · CLEANUP WARNING"
        self.btn_status.setText(status)
        self.set_btn_status_style("connected" if self.connected else "disconnected")
        if not self.connected:
            self.timer_data_usage.stop()
        self.logs_widget.update_log(detail, level="error")
        self._update_proxy_buttons()
        self._update_tunnel_hint()

        if self._parent is not None and getattr(self._parent, "_shutdown_in_progress", False):
            self._parent._on_proxy_shutdown_complete(False, detail)
            return
        QMessageBox.warning(self, "Disconnect", detail)

    def set_btn_status_style(self, stmt):
        self.btn_status.setProperty("connectionState", stmt)
        self.btn_status.style().unpolish(self.btn_status)
        self.btn_status.style().polish(self.btn_status)
        self.btn_status.update()
        hint = getattr(self, "connection_hint", None)
        if hint is not None:
            hints = {
                "connected": "Tor is ready · your configured proxy listeners are available.",
                "connecting": "Connecting to Tor · proxy traffic is not ready yet.",
                "disconnected": "Start Tor to enable your configured proxy listeners.",
            }
            hint.setText(hints.get(stmt, hints["disconnected"]))

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
            self.logs_widget.update_log(
                "Tor connect/disconnect is temporarily disabled while the system tunnel changes."
            )
            return
        with self._operation_lock:
            if self.running:
                self._request_stop_services()
                return
            if self._connect_operation_busy or self._stopping:
                return
            self._connect_operation_busy = True

        self.failed = False
        self.connect_btn.set_connecting()
        self.connect_btn.setEnabled(False)
        self.btn_status.setText("CHECKING PORTS…")
        self.set_btn_status_style("connecting")

        worker = Worker(self._check_ports_worker)
        worker.signals.finished.connect(self._on_ports_checked)
        worker.signals.cancelled.connect(self._on_port_check_cancelled)
        worker.signals.error.connect(self._on_port_check_error)
        self.thread_pool.start(worker)
    def _on_port_check_cancelled(self, reason: str) -> None:
        """Return Home to its idle state when stale-tunnel recovery is declined."""
        with self._operation_lock:
            self._connect_operation_busy = False
        self.failed = False
        self.running = False
        self.connected = False
        self.connect_btn.set_connected(False)
        self.connect_btn.setEnabled(True)
        self.btn_status.setText("CONNECTION CANCELLED")
        self.set_btn_status_style("disconnected")
        self.logs_widget.update_log(
            "Connection cancelled; the previous system tunnel was not changed. "
            + str(reason or ""),
            level="info",
        )
        self._update_proxy_buttons()
        self._update_tunnel_hint()

    def _on_port_check_error(self, error):
        if self._stopping or bool(getattr(self._parent, "_closing", False)):
            with self._operation_lock:
                self._connect_operation_busy = False
            return
        with self._operation_lock:
            self._connect_operation_busy = False
        self.failed = True
        self.running = False
        self.connected = False
        self.connect_btn.set_connected(False)
        self.connect_btn.setEnabled(True)
        self.btn_status.setText("CONNECTION PREFLIGHT FAILED")
        self.set_btn_status_style("disconnected")
        self._update_proxy_buttons()
        QMessageBox.warning(self, "Connection preflight", str(error))

    # ===== slot that runs on main thread with the result =====
    def _on_ports_checked(self, result):
        """
        result == (ok, ports, messages)
        This runs in the GUI thread so it's safe to touch UI and self.proxy/self.tor.
        """

        # An explicit Exit may start async cleanup while the preflight worker is
        # still resolving ports. Never start Tor after shutdown has been requested.
        if self._stopping or bool(getattr(self._parent, "_closing", False)):
            with self._operation_lock:
                self._connect_operation_busy = False
            return

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
            # The Home action must switch to its waiting state while Tor bootstraps.
            self._update_proxy_buttons()
            self._update_tunnel_hint()
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
            # Recompute Home and Tunnel actions now that preflight has ended.
            self._update_proxy_buttons()
            # always re-enable the button
            self.connect_btn.setEnabled(True)

    # ===== helper worker (runs in background) =====
    def _check_ports_worker(self):
        """Reconcile any previous TorProxy TUN session before starting Tor."""
        messages = []
        try:
            recovery = self.system_tunnel_manager.cleanup_previous_session()
            if recovery and "No previous TorProxy tunnel state needs cleanup" not in recovery:
                messages.append(recovery)
        except SystemTunnelCancelled:
            raise
        except Exception as exc:
            return json.dumps([
                False,
                {},
                [
                    "The previous sing-box tunnel could not be safely reconciled. "
                    "Tor was not started to avoid connecting while stale system routes may remain.",
                    str(exc),
                ],
            ])

        try:
            ports, port_messages = resolve_listener_ports(CONFIG, strict_manual=True)
        except PortAllocationError as exc:
            return json.dumps([False, {}, [*messages, str(exc)]])

        messages.extend(port_messages)
        messages.append("All four persistent listener ports are available.")
        return json.dumps([True, ports, messages])

    def _request_stop_services(self, *, final_status: str = "NOT CONNECTED") -> bool:
        """Queue disconnect work; never wait for OS helpers or child processes on the GUI thread."""
        if self._stopping:
            return bool(self._parent is not None and getattr(self._parent, "_shutdown_in_progress", False))
        if getattr(self, "_system_tunnel_busy", False):
            message = "Disconnect was blocked because the system tunnel operation is still running."
            self.logs_widget.update_log(message)
            return False

        self._stopping = True
        self._disconnect_final_status = final_status
        self.connect_btn.set_disconnecting()
        self.connect_btn.setEnabled(False)
        self.btn_status.setText("DISCONNECTING…")
        self.set_btn_status_style("disconnecting")
        self._update_proxy_buttons()
        self._update_tunnel_hint()

        worker = Worker(self._stop_services_worker)
        worker.signals.finished.connect(self._on_services_stopped)
        worker.signals.cancelled.connect(self._on_services_stop_cancelled)
        worker.signals.error.connect(self._on_services_stop_failed)
        self._disconnect_worker = worker
        self.thread_pool.start(worker)
        return True

    def _stop_services_worker(self) -> str:
        """Perform blocking OS cleanup away from Qt's GUI thread; never touch widgets."""
        messages: list[str] = []
        tunnel_status = self.system_tunnel_manager.status()
        tunnel_record_exists = self.system_tunnel_manager.process_state_path.exists()
        if tunnel_record_exists or tunnel_status.get("active") or not tunnel_status.get("verified", True):
            try:
                messages.append(self.system_tunnel_manager.cleanup_previous_session())
            except SystemTunnelCancelled:
                raise
            except Exception as exc:
                raise RuntimeError(
                    "System tunnel cleanup failed; Tor and its SOCKS listener were kept running: "
                    + str(exc)
                ) from exc

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
                    messages.append("Previous system proxy settings restored.")
                else:
                    messages.append(
                        "System proxy changed externally or could not be restored; inspect settings manually."
                    )
            except Exception as exc:
                logger.exception("Error restoring system proxy during stop.")
                messages.append(f"System proxy restoration failed: {exc}")

        stop_errors: list[str] = []
        http_proxy_blocks_tor_shutdown = False
        if self.proxy:
            try:
                self.proxy.stop()
                messages.append("Local HTTP proxy stopped.")
            except Exception as exc:
                logger.exception("Error stopping the local HTTP proxy.")
                stop_errors.append(f"HTTP proxy shutdown failed: {exc}")
                # Never tear down the Tor SOCKS backends while an HTTP handler
                # still owns an upstream tunnel. Keep both service references
                # alive so a retry can finish cleanup without stranding clients.
                listener = getattr(self.proxy, "server", None)
                listener_thread = getattr(self.proxy, "thread", None)
                http_proxy_blocks_tor_shutdown = (
                    listener is not None
                    or bool(listener_thread is not None and listener_thread.is_alive())
                )
                if http_proxy_blocks_tor_shutdown:
                    stop_errors.append(
                        "Tor was deliberately kept running because the local HTTP proxy "
                        "still owns active client handlers."
                    )

        if self.tor and not http_proxy_blocks_tor_shutdown:
            try:
                self.tor.stop()
                messages.append("Tor stopped.")
            except Exception as exc:
                logger.exception("Error stopping Tor.")
                stop_errors.append(f"Tor shutdown failed: {exc}")

        # Developer Tor is independent while the window is hidden or Main Tor disconnects.
        # Only an explicit application exit owns and stops this separate hosting runtime.
        if getattr(self._parent, "_closing", False):
            onion_manager = getattr(self, "onion_hosting_manager", None)
            if onion_manager is not None:
                try:
                    onion_manager.shutdown_runtime()
                    messages.append("Developer Tor and its Onion Services stopped.")
                except Exception as exc:
                    logger.exception("Error stopping Developer Tor during application exit.")
                    stop_errors.append(f"Developer Tor shutdown failed: {exc}")

        # Additional Tor profiles are independent while the UI remains open.
        # An explicit application exit, however, owns and must stop every child.
        if getattr(self._parent, "_closing", False) and self.tor_service_pool is not None:
            service_ids = self.tor_service_pool.service_ids
            if service_ids:
                try:
                    service_results = self.tor_service_pool.stop_all()
                    service_failures = {
                        service_id: error for service_id, error in service_results.items() if error
                    }
                    if service_failures:
                        stop_errors.append(
                            "Isolated Tor service shutdown failed: "
                            + "; ".join(f"{key}: {value}" for key, value in service_failures.items())
                        )
                    else:
                        messages.append(f"Stopped {len(service_ids)} isolated Tor service(s).")
                        try:
                            self.tor_service_pool.close()
                        except Exception as monitor_error:
                            stop_errors.append(
                                f"Isolated Tor health monitor shutdown failed: {monitor_error}"
                            )
                except Exception as exc:
                    logger.exception("Error stopping isolated Tor services during application exit.")
                    stop_errors.append(f"Isolated Tor service shutdown failed: {exc}")

        if stop_errors:
            raise RuntimeError(
                "Disconnect was incomplete; TorProxy will keep the remaining service state visible. "
                + " | ".join(stop_errors)
            )

        return json.dumps({"messages": messages})
    def set_proxy_clicked(self):
        # Used by the Set-system-proxy policy after Tor bootstrap has succeeded.
        if not self.running or not self.connected:
            self.proxy_status_label.setText(
                "Will apply the system proxy automatically after Tor connects."
            )
            return
        if not bool(CONFIG["http_proxy_enabled"]) or not bool(getattr(self.proxy, "is_running", False)):
            self.proxy_status_label.setText(
                "System proxy was not applied because the local HTTP proxy listener is disabled or unavailable."
            )
            self.logs_widget.update_log(
                "System proxy was not applied: the local HTTP proxy listener is disabled or unavailable.",
                level="warning",
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

    def _refresh_http_proxy_settings(self):
        settings_page = getattr(self._parent, "settingWidget", None)
        refresh = getattr(settings_page, "_refresh_http_proxy_status", None)
        if callable(refresh):
            refresh()

    def _update_proxy_buttons(self):
        browser_button = getattr(self, "btn_open_browser", None)
        if browser_button is not None:
            http_ready = bool(
                CONFIG["http_proxy_enabled"] and getattr(self.proxy, "is_running", False)
            )
            ready = bool(
                self.running
                and self.connected
                and http_ready
                and not self._connect_operation_busy
                and not self._stopping
            )
            browser_button.setEnabled(ready)
            browser_button.setToolTip(
                "Open an installed browser through the local TorProxy HTTP proxy."
                if ready else
                (
                    "Enable the local HTTP proxy in Settings → Ports."
                    if not http_ready else
                    "Connect to Tor and wait for the verified bootstrap to finish first."
                )
            )
        self._update_proxy_mode_status()
        self._update_tunnel_hint()
        tunnel_page = getattr(self._parent, "tunnel_window", None)
        refresh_tunnel_page = getattr(tunnel_page, "_refresh_state", None)
        if callable(refresh_tunnel_page):
            refresh_tunnel_page()


    def _update_tunnel_hint(self):
        """Refresh the compact Home status and expose the correct tunnel action."""
        label = getattr(self, "system_tunnel_hint_label", None)
        if label is None:
            return

        action_button = getattr(self, "btn_system_tunnel_action", None)
        manage_button = getattr(self, "btn_system_tunnel_manage", None)
        manager = getattr(self, "system_tunnel_manager", None)
        show_action = False
        show_manage = False
        action_text = "Start"
        action_icon = "fa6s.play"
        action_enabled = False
        action_tooltip = "Connect to Tor before starting the system tunnel."
        self._home_tunnel_action = "toggle"

        if manager is None:
            message = "System tunnel is unavailable · Open Updates → Tunnel"
            show_manage = True
        else:
            installed_version = None
            try:
                installed_version = manager.installed_version
                state = manager.status()
                tunnel_page = getattr(self._parent, "tunnel_window", None)
                page_busy = bool(getattr(tunnel_page, "_busy", False))
                busy = bool(
                    getattr(self, "_system_tunnel_busy", False)
                    or page_busy
                    or self._stopping
                    or self._connect_operation_busy
                )
                tor_ready = bool(self.running and self.connected and not self._stopping)

                if state.get("active"):
                    message = (
                        f"System tunnel active · sing-box v{installed_version or 'verified'}"
                    )
                    action_text = "Stop"
                    action_icon = "fa6s.stop"
                    action_enabled = not busy
                    action_tooltip = "Stop the system tunnel and remove its routes safely."
                    show_action = True
                elif not state.get("verified", True):
                    message = "System tunnel needs route reconciliation"
                    action_text = "Reconcile"
                    action_icon = "fa6s.arrows-rotate"
                    action_enabled = not busy
                    action_tooltip = "Stop the stale tunnel process and reconcile system routes."
                    show_action = True
                elif installed_version:
                    if self._connect_operation_busy:
                        message = f"sing-box v{installed_version} installed · preparing Tor connection"
                        action_text = "Preparing…"
                        action_tooltip = "TorProxy is checking for leftover sing-box routes before connecting."
                    elif self._stopping:
                        message = f"sing-box v{installed_version} installed · disconnecting Tor"
                        action_text = "Stopping…"
                        action_tooltip = "The system tunnel is stopped before Tor disconnects."
                    elif self.running and not self.connected:
                        message = f"sing-box v{installed_version} installed · Tor is connecting"
                        action_text = "Waiting for Tor"
                        action_tooltip = "The Start action becomes available after Tor bootstrap and ControlPort verification."
                    elif tor_ready:
                        message = f"System tunnel ready to start · sing-box v{installed_version}"
                        action_text = "Start"
                        action_tooltip = "Start system-wide Tor routing."
                    else:
                        message = f"sing-box v{installed_version} installed · connect Tor to enable Start"
                        action_text = "Waiting for Tor"
                        action_tooltip = "Connect to Tor and wait for verified READY status before starting the tunnel."
                    action_icon = "fa6s.play"
                    action_enabled = tor_ready and not busy
                    show_action = True
                else:
                    message = "System tunnel is not installed · Install it from Updates → Tunnel"
                    show_manage = True
            except Exception as exc:
                logger.debug("Could not refresh system tunnel summary: %s", exc)
                if installed_version:
                    message = "System tunnel status is unavailable · Open its manager to inspect it"
                    action_text = "Open"
                    action_icon = "fa6s.arrow-up-right-from-square"
                    action_enabled = True
                    action_tooltip = "Open the Tunnel page to inspect the current system state."
                    self._home_tunnel_action = "open"
                    show_action = True
                else:
                    message = "System tunnel is not installed or unavailable · Open Updates → Tunnel"
                    show_manage = True

        label.setText(message)
        if action_button is not None:
            action_button.setText(action_text)
            action_button.set_icon_name(action_icon)
            action_button.setToolTip(action_tooltip)
            action_button.setEnabled(action_enabled)
            action_button.setVisible(show_action)
        if manage_button is not None:
            manage_button.setVisible(show_manage)

    def toggle_system_tunnel(self):
        """Use the Tunnel page's existing guarded worker for Home Start/Stop actions."""
        if getattr(self, "_home_tunnel_action", "toggle") == "open":
            self.open_tunnel_manager()
            return
        tunnel_page = getattr(self._parent, "tunnel_window", None)
        callback = getattr(tunnel_page, "toggle_tunnel_from_home", None)
        if callable(callback):
            callback()
            self._update_tunnel_hint()
            return
        self.open_tunnel_manager()

    def open_tunnel_manager(self):
        """Navigate to the dedicated engine and tunnel management page."""
        callback = getattr(self._parent, "_show_tunnel_page", None)
        if callable(callback):
            callback()
