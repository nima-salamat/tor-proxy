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


def can_bind_loopback(port: int, host: str = "127.0.0.1") -> bool:
    """Return whether a TCP listener can currently bind the requested loopback port."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((host, int(port)))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def can_bind_loopback_udp(port: int, host: str = "127.0.0.1") -> bool:
    """Return whether a UDP listener can currently bind the requested loopback port."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind((host, int(port)))
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
    """Reuse persisted ports, repair automatic collisions, and never override pinned values.

    The sockets are probed and released before their owners start. This deliberately
    avoids holding a socket that Tor or the HTTP server must bind itself; the actual
    bind remains authoritative and a subsequent preflight repairs an automatic
    collision if another process wins the small probe-to-bind race.
    """
    probe = available or can_bind_loopback
    udp_probe = udp_available or can_bind_loopback_udp
    candidate = candidate_provider or ephemeral_loopback_port

    def port_is_available(key: str, port: int) -> bool:
        try:
            if not bool(probe("127.0.0.1", port)):
                return False
            # Tor's DNSPort may own both TCP and UDP on the same numeric port.
            if key == "dns_port" and not bool(udp_probe("127.0.0.1", port)):
                return False
            return True
        except Exception:
            return False
    assigned: dict[str, int] = {}
    automatic_updates: dict[str, int] = {}
    messages: list[str] = []
    used: set[int] = set()

    # Resolve user-pinned ports first so automatic selections cannot collide with them.
    ordered_specs = sorted(PORT_SPECS, key=lambda item: not bool(config[item[1]]))

    def pick_ephemeral(key: str, label: str) -> int:
        for _attempt in range(128):
            try:
                port = candidate()
            except Exception as exc:
                raise PortAllocationError(f"Could not allocate a port for {label}: {exc}") from exc
            if not _valid_port(port) or port in used:
                continue
            if port_is_available(key, port):
                return port
        raise PortAllocationError(
            f"Could not find an available loopback port for {label} after 128 attempts."
        )

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
            is_available = port_is_available(key, saved)
            if not is_available:
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
            is_available = port_is_available(key, saved)
            if is_available:
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
