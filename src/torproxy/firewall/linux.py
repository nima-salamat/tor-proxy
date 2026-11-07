"""Linux nftables backend using a dedicated systemd scope for the Tor process."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from ..killswitch import KillSwitchError


class LinuxFirewallBackend:
    """Own one nftables table and never exempt the desktop user's general UID."""

    def __init__(self, *, runner=subprocess.run):
        self._runner = runner

    def _helper_command(self, action: str, argument: str | None = None) -> list[str]:
        pkexec = shutil.which("pkexec")
        if not pkexec:
            raise KillSwitchError("PolicyKit pkexec is required to manage nftables with administrator privileges.")
        if not shutil.which("systemd-run") or not shutil.which("systemctl"):
            raise KillSwitchError("A systemd user manager is required to isolate Tor in a dedicated cgroup.")
        if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
            raise KillSwitchError("A unified cgroup v2 hierarchy is required; UID-wide exceptions are unsafe.")
        if getattr(sys, "frozen", False):
            command = [sys.executable, "--killswitch-helper", action]
        else:
            helper_script = Path(__file__).resolve().with_name("linux_helper.py")
            command = [sys.executable, str(helper_script), action]
        if argument is not None:
            command.append(argument)
        return [pkexec, *command]

    def _run_helper(self, action: str, argument: str | None = None) -> dict[str, object]:
        try:
            result = self._runner(self._helper_command(action, argument), stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, timeout=60, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise KillSwitchError(f"Could not run the privileged nftables helper: {exc}") from exc
        if result.returncode != 0:
            details = (result.stderr or result.stdout or "No diagnostic was returned.").strip()
            raise KillSwitchError(details[:1200])
        output = (result.stdout or "").strip()
        if not output:
            return {"ok": True}
        try:
            import json
            payload = json.loads(output.splitlines()[-1])
        except (ValueError, TypeError) as exc:
            raise KillSwitchError("The privileged firewall helper returned an invalid response.") from exc
        if not payload.get("ok"):
            raise KillSwitchError(str(payload.get("error") or "The Linux firewall operation failed."))
        return payload

    def activate(self, programs: tuple[str, ...]) -> None:
        self._run_helper("install")

    def set_tor_cgroup(self, cgroup_id: int | None, cgroup_level: int | None = None) -> None:
        if cgroup_id is None:
            self._run_helper("clear-cgroup")
            return
        if type(cgroup_id) is not int or cgroup_id <= 0 or type(cgroup_level) is not int or cgroup_level < 1:
            raise KillSwitchError("The Tor cgroup identifier or hierarchy level is invalid.")
        self._run_helper("set-cgroup", f"{cgroup_id}:{cgroup_level}")

    def deactivate(self) -> None:
        self._run_helper("remove")

    def status(self) -> dict[str, object]:
        try:
            return self._run_helper("status")
        except KillSwitchError as exc:
            return {"active": False, "verified": False, "detail": str(exc)}
