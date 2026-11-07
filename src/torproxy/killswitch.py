"""Cross-platform, persistent system-wide firewall kill switch."""
from __future__ import annotations

import logging
import os
import sys
from collections.abc import Iterable
from pathlib import Path

LOGGER = logging.getLogger(__name__)


class KillSwitchError(RuntimeError):
    """A kill-switch operation could not be completed or verified."""


class KillSwitchManager:
    """Coordinate platform firewall backends without owning Tor's process lifecycle."""

    def __init__(self, backend=None, *, platform_name: str | None = None):
        self.platform_name = platform_name or os.name
        if backend is not None:
            self.backend = backend
        elif self.platform_name == "nt":
            from .firewall.windows import WindowsFirewallBackend
            self.backend = WindowsFirewallBackend()
        elif self.platform_name == "posix" and sys.platform.startswith("linux"):
            from .firewall.linux import LinuxFirewallBackend
            self.backend = LinuxFirewallBackend()
        else:
            raise KillSwitchError("Kill Switch is supported only on Windows and Linux.")

    @staticmethod
    def _program_paths(programs: Iterable[str | os.PathLike[str]]) -> tuple[str, ...]:
        normalized: list[str] = []
        for item in programs:
            path = Path(item).expanduser()
            try:
                resolved = path.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise KillSwitchError(f"Allowed Tor executable does not exist: {path}") from exc
            if not resolved.is_file():
                raise KillSwitchError(f"Allowed Tor executable is not a file: {resolved}")
            value = str(resolved)
            if value not in normalized:
                normalized.append(value)
        if not normalized:
            raise KillSwitchError("At least the managed Tor executable must be allowlisted.")
        return tuple(normalized)

    def activate(self, programs: Iterable[str | os.PathLike[str]]) -> None:
        paths = self._program_paths(programs)
        try:
            self.backend.activate(paths)
        except KillSwitchError:
            raise
        except Exception as exc:
            raise KillSwitchError(f"Could not activate the system firewall kill switch: {exc}") from exc

    def deactivate(self) -> dict[str, object]:
        try:
            result = self.backend.deactivate()
            return dict(result) if isinstance(result, dict) else {}
        except KillSwitchError:
            raise
        except Exception as exc:
            raise KillSwitchError(f"Could not safely deactivate the kill switch: {exc}") from exc

    def recover(self) -> dict[str, object]:
        """Restore the pre-Kill-Switch firewall snapshot when one is available."""
        callback = getattr(self.backend, "recover", None)
        if callback is None:
            callback = self.backend.deactivate
        try:
            result = callback()
            return dict(result) if isinstance(result, dict) else {}
        except KillSwitchError:
            raise
        except Exception as exc:
            raise KillSwitchError(f"Could not restore the saved firewall policy: {exc}") from exc

    def emergency_recover(self) -> dict[str, object]:
        """Explicitly restore ordinary outbound access if normal recovery is insufficient."""
        callback = getattr(self.backend, "emergency_recover", None)
        if callback is None:
            callback = getattr(self.backend, "recover", None) or self.backend.deactivate
        try:
            result = callback()
            return dict(result) if isinstance(result, dict) else {}
        except KillSwitchError:
            raise
        except Exception as exc:
            raise KillSwitchError(f"Emergency firewall recovery failed: {exc}") from exc

    def set_tor_cgroup(self, cgroup_id: int | None, cgroup_level: int | None = None) -> None:
        callback = getattr(self.backend, "set_tor_cgroup", None)
        if callback is None:
            if cgroup_id is not None:
                raise KillSwitchError("This firewall backend does not support cgroup isolation.")
            return
        try:
            callback(cgroup_id, cgroup_level)
        except KillSwitchError:
            raise
        except Exception as exc:
            raise KillSwitchError(f"Could not update the Tor cgroup firewall exception: {exc}") from exc

    def recovery_state(self) -> dict[str, object]:
        """Return local, non-privileged hints about pending recovery state."""
        callback = getattr(self.backend, "recovery_state", None)
        if callback is None:
            return {"available": False, "verified": False}
        try:
            return dict(callback())
        except Exception as exc:
            LOGGER.warning("Could not inspect local Kill Switch recovery state: %s", exc)
            return {"available": False, "verified": False, "detail": str(exc)}

    def status(self) -> dict[str, object]:
        try:
            return dict(self.backend.status())
        except Exception as exc:
            LOGGER.warning("Could not verify the current firewall kill-switch state: %s", exc)
            return {"active": False, "verified": False, "detail": str(exc)}
