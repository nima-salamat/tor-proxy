"""Persistent, collision-aware allocation for TorProxy listener ports."""
from __future__ import annotations

import json
import socket
from collections.abc import Callable, Mapping
from typing import Any

PORT_SPECS = (
    ("proxy_port", "proxy_port_checked", "HTTP proxy"),
    ("tor_port", "tor_port_checked", "Tor SOCKS"),
    ("control_port", "control_port_checked", "Tor ControlPort"),
    ("dns_port", "dns_port_checked", "Tor DNS"),
)


class PortAllocationError(RuntimeError):
    """A configured listener port cannot be used safely."""


def can_bind_loopback(host: str | int, port: int | None = None) -> bool:
    """Return whether a TCP listener can bind a loopback port.

    Accept both can_bind_loopback(port) for public callers and
    can_bind_loopback(host, port) for allocator probes.
    """
    if port is None:
        host, port = "127.0.0.1", int(host)
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((str(host), int(port)))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def can_bind_loopback_udp(host: str | int, port: int | None = None) -> bool:
    """Return whether a UDP listener can bind a loopback port.

    Accept both can_bind_loopback_udp(port) and can_bind_loopback_udp(host, port).
    """
    if port is None:
        host, port = "127.0.0.1", int(host)
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind((str(host), int(port)))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def ephemeral_loopback_port() -> int:
    """Ask the OS for an available ephemeral loopback port, then release the probe socket."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])
    finally:
        probe.close()


def _valid_port(value: Any) -> bool:
    return type(value) is int and 1 <= value <= 65535


def _save_auto_values(config: Any, values: Mapping[str, int]) -> None:
    """Persist all automatically selected ports in one atomic config write when supported."""
    if not values:
        return
    update_many = getattr(config, "update_many", None)
    if callable(update_many):
        try:
            update_many(dict(values))
        except Exception as exc:
            raise PortAllocationError(f"Could not save the selected listener ports: {exc}") from exc
        return
    get_config = getattr(config, "get_config", None)
    save_config = getattr(config, "save_config", None)
    if callable(get_config) and callable(save_config):
        try:
            payload = json.loads(get_config())
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PortAllocationError(f"Could not read settings before saving listener ports: {exc}") from exc
        if not isinstance(payload, dict):
            raise PortAllocationError("The application settings are not a JSON object.")
        payload.update(values)
        try:
            save_config(json.dumps(payload))
        except Exception as exc:
            raise PortAllocationError(f"Could not save the selected listener ports: {exc}") from exc
        return
    try:
        for key, value in values.items():
            config[key] = value
    except Exception as exc:
        raise PortAllocationError(f"Could not save the selected listener ports: {exc}") from exc


def resolve_listener_ports(
    config: Any,
    *,
    available: Callable[[str, int], bool] | None = None,
    candidate_provider: Callable[[], int] | None = None,
    udp_available: Callable[[str, int], bool] | None = None,
    strict_manual: bool = True,
) -> tuple[dict[str, int], list[str]]:
    """Reuse saved ports; allocate unique automatic ports and never silently change pinned values.

    Existing saved values are checked before any new port is allocated. New TCP listener
    candidates are reserved with live sockets while the complete set is selected. This
    prevents the OS from handing the same ephemeral port repeatedly when a port is
    allocated and immediately released (notably observed on Windows). The reservations
    are released immediately before returning so Tor and the HTTP proxy can bind them.

    A custom candidate_provider is primarily for deterministic tests and retains the
    explicit availability-probe behavior. Production allocation uses bind(port=0)
    directly, without an unnecessary second bind to the just-released candidate.
    """
    # The injectable probe contract is (host, port), while the low-level
    # socket helpers intentionally expose (port, host). Adapt explicitly;
    # passing these directly used to send "127.0.0.1" to int(port), silently
    # marking every candidate as unavailable.
    probe = available or (lambda host, port: can_bind_loopback(port, host))
    udp_probe = udp_available or (lambda host, port: can_bind_loopback_udp(port, host))
    assigned: dict[str, int] = {}
    automatic_updates: dict[str, int] = {}
    messages: list[str] = []
    used: set[int] = set()
    reservations: list[socket.socket] = []

    def port_is_available(key: str, port: int) -> bool:
        try:
            if not bool(probe("127.0.0.1", port)):
                return False
            # Tor's DNSPort can require the same numeric port for TCP and UDP.
            if key == "dns_port" and not bool(udp_probe("127.0.0.1", port)):
                return False
            return True
        except Exception:
            return False

    def new_bound_candidate(key: str, label: str) -> int:
        last_error: OSError | None = None
        for _attempt in range(128):
            tcp_socket: socket.socket | None = None
            udp_socket: socket.socket | None = None
            try:
                tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp_socket.bind(("127.0.0.1", 0))
                port = int(tcp_socket.getsockname()[1])
                if not _valid_port(port) or port in used:
                    tcp_socket.close()
                    continue

                if key == "dns_port":
                    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udp_socket.bind(("127.0.0.1", port))

                # Keep the reservation until every listener port has been selected.
                reservations.append(tcp_socket)
                tcp_socket = None
                if udp_socket is not None:
                    reservations.append(udp_socket)
                    udp_socket = None
                return port
            except OSError as exc:
                last_error = exc
                if tcp_socket is not None:
                    tcp_socket.close()
                if udp_socket is not None:
                    udp_socket.close()

        detail = f" Last socket error: {last_error}" if last_error else ""
        raise PortAllocationError(
            f"Could not reserve an available loopback port for {label} after 128 attempts.{detail}"
        )

    def pick_ephemeral(key: str, label: str) -> int:
        if candidate_provider is None:
            return new_bound_candidate(key, label)

        for _attempt in range(128):
            try:
                port = candidate_provider()
            except Exception as exc:
                raise PortAllocationError(f"Could not allocate a port for {label}: {exc}") from exc
            if not _valid_port(port) or port in used:
                continue
            if port_is_available(key, port):
                return port
        raise PortAllocationError(
            f"Could not find an available loopback port for {label} after 128 attempts."
        )

    # Validate pinned entries first, then preserve every other valid saved value.
    # Missing/invalid values are allocated only after these preferred ports are assigned.
    def priority(spec: tuple[str, str, str]) -> int:
        key, checked_key, _label = spec
        if _valid_port(config[key]) and bool(config[checked_key]):
            return 0
        if _valid_port(config[key]):
            return 1
        if bool(config[checked_key]):
            return 2
        return 3

    ordered_specs = sorted(PORT_SPECS, key=priority)
    try:
        for key, checked_key, label in ordered_specs:
            pinned = bool(config[checked_key])
            saved = config[key]

            if pinned:
                if not _valid_port(saved):
                    reason = (
                        f"{label}: a manual port is enabled, but its value is not an integer between 1 and 65535."
                    )
                    if strict_manual:
                        raise PortAllocationError(reason)
                    selected = pick_ephemeral(key, label)
                    assigned[key] = selected
                    used.add(selected)
                    messages.append(reason + f" A temporary port {selected} is used only to keep the UI available.")
                    continue
                if saved in used:
                    reason = f"{label}: port {saved} duplicates another listener port."
                    if strict_manual:
                        raise PortAllocationError(reason)
                    selected = pick_ephemeral(key, label)
                    assigned[key] = selected
                    used.add(selected)
                    messages.append(reason + f" A temporary port {selected} is used only to keep the UI available.")
                    continue
                if not port_is_available(key, saved):
                    reason = f"{label}: manually selected port {saved} is already in use."
                    if strict_manual:
                        raise PortAllocationError(reason + " Free it or choose another port in Settings → Ports.")
                    selected = pick_ephemeral(key, label)
                    assigned[key] = selected
                    used.add(selected)
                    messages.append(reason + f" A temporary port {selected} is used only to keep the UI available.")
                    continue
                assigned[key] = saved
                used.add(saved)
                messages.append(f"{label}: keeping manually selected port {saved}.")
                continue

            if _valid_port(saved) and saved not in used:
                if port_is_available(key, saved):
                    assigned[key] = saved
                    used.add(saved)
                    messages.append(f"{label}: reusing saved port {saved}.")
                    continue

            previous = saved if _valid_port(saved) else None
            selected = pick_ephemeral(key, label)
            assigned[key] = selected
            used.add(selected)
            automatic_updates[key] = selected
            if previous is None:
                messages.append(f"{label}: initialized and saved port {selected}.")
            else:
                messages.append(
                    f"{label}: saved port {previous} is unavailable; switched to and saved port {selected}."
                )

        _save_auto_values(config, automatic_updates)
        return assigned, messages
    finally:
        # Never keep a socket open after handing ports to Tor/Runner.
        for reserved_socket in reservations:
            try:
                reserved_socket.close()
            except OSError:
                pass
