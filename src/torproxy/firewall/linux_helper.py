"""Root-only helper for TorProxy's persistent nftables kill-switch service."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TABLE = "torproxy_killswitch"
SET_NAME = "tor_cgroups"
TUN_INTERFACE = "torproxy-tun"
TUN_RULE = f'oifname "{TUN_INTERFACE}" accept'
UNIT = "torproxy-killswitch.service"
CONFIG_PATH = Path("/etc/torproxy-killswitch.nft")
UNIT_PATH = Path("/etc/systemd/system") / UNIT
MARKER = "# Managed by TorProxy Kill Switch. Do not edit."
CGROUP_ROOT = Path("/sys/fs/cgroup")


class HelperError(RuntimeError):
    pass


def _run(args: list[str], *, input_text: str | None = None, timeout: int = 20) -> str:
    try:
        result = subprocess.run(args, input=input_text, capture_output=True, text=True,
                                timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise HelperError(f"{Path(args[0]).name} could not be executed: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "command failed").strip()
        raise HelperError(f"{Path(args[0]).name}: {detail[:900]}")
    return result.stdout.strip()


def _require_root() -> None:
    if os.name != "posix" or os.geteuid() != 0:
        raise HelperError("The Linux firewall helper must run with administrator privileges.")
    if not (CGROUP_ROOT / "cgroup.controllers").is_file():
        raise HelperError("Unified cgroup v2 is unavailable.")
    for binary in ("nft", "systemctl"):
        if not shutil.which(binary):
            raise HelperError(f"Required system utility is missing: {binary}")


def _table_exists() -> bool:
    result = subprocess.run(["nft", "list", "table", "inet", TABLE], stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=10, check=False)
    return result.returncode == 0


def _chain_is_safe(chain: str) -> bool:
    """Reject every unrecognized output-chain rule, especially extra accepts."""
    expected = {
        'oifname "lo" accept',
        "udp sport 68 udp dport 67 accept",
        "udp sport 546 udp dport 547 accept",
        "ip6 daddr { fe80::/10, ff02::/16 } icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept",
    }
    allowed_optional = {TUN_RULE}
    observed: set[str] = set()
    cgroup_rules: list[str] = []
    policy_seen = False
    for raw_line in chain.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("chain ") or line in {"{", "}"}:
            continue
        if line == f"table inet {TABLE} {{":
            continue
        if line.startswith("type filter hook output"):
            if "policy drop" not in line:
                return False
            policy_seen = True
            continue
        if line in expected or line in allowed_optional:
            observed.add(line)
            continue
        if line.startswith("socket cgroupv2 level ") and line.endswith(f" @{SET_NAME} accept"):
            cgroup_rules.append(line)
            continue
        # No jump, return, queue, accept or opaque rule can be allowed here.
        return False
    return policy_seen and expected <= observed and observed <= expected | allowed_optional and len(cgroup_rules) <= 1


def _owned_installation() -> bool:
    if not UNIT_PATH.is_file() or not CONFIG_PATH.is_file():
        return False
    try:
        return MARKER in UNIT_PATH.read_text(encoding="utf-8") and MARKER in CONFIG_PATH.read_text(encoding="utf-8")
    except OSError:
        return False


def _rules(cgroup_level: int | None = None, *, table: bool = False) -> str:
    lines = []
    if table:
        lines.extend((f"table inet {TABLE} {{", f" set {SET_NAME} {{ type cgroupsv2; }}",
                      " chain output {", "  type filter hook output priority 0; policy drop;"))
        if cgroup_level is None:
            cgroup_level = 1
    else:
        lines.append(f"flush chain inet {TABLE} output")
    lines.extend((
        '  oifname "lo" accept',
        f"  {TUN_RULE}",
        "  udp sport 68 udp dport 67 accept",
        "  udp sport 546 udp dport 547 accept",
        "  ip6 daddr { fe80::/10, ff02::/16 } icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept",
    ))
    if cgroup_level is not None:
        if type(cgroup_level) is not int or cgroup_level < 1:
            raise HelperError("Invalid cgroup hierarchy level.")
        lines.append(f"  socket cgroupv2 level {cgroup_level} @{SET_NAME} accept")
    if table:
        lines.extend((" }", "}"))
    return "\n".join(lines) + "\n"


def _write_atomic(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except OSError:
            pass


def install() -> dict[str, object]:
    _require_root()
    if _table_exists() and not _owned_installation():
        raise HelperError(f"nftables table inet {TABLE} already exists but is not owned by TorProxy; refusing to modify it.")
    if UNIT_PATH.exists() and not _owned_installation():
        raise HelperError(f"{UNIT_PATH} already exists and is not a TorProxy-managed unit.")
    nft_path = shutil.which("nft")
    if not nft_path:
        raise HelperError("nftables is not installed.")

    table_exists = _table_exists()
    if table_exists:
        if not _owned_installation():
            raise HelperError(f"nftables table inet {TABLE} exists without TorProxy ownership markers.")
        current_chain = _run(["nft", "list", "chain", "inet", TABLE, "output"])
        if not _chain_is_safe(current_chain):
            raise HelperError("The existing TorProxy nftables chain contains an unknown or permissive rule; refusing to overwrite it.")
        # Validate the cgroupv2 expression against the already-created set without
        # deleting or replacing the live drop-policy chain.
        _run(["nft", "--check", "-f", "-"], input_text=_rules(cgroup_level=1))
    else:
        nft_config = MARKER + "\n" + _rules(table=True, cgroup_level=1)
        # This syntax check rejects old nft/kernel combinations before installation.
        _run(["nft", "--check", "-f", "-"], input_text=nft_config)

    unit_text = "\n".join((
        "[Unit]", "Description=TorProxy persistent network kill switch",
        "DefaultDependencies=no", "After=local-fs.target systemd-modules-load.service nftables.service",
        "Before=network-pre.target", "Wants=network-pre.target", "",
        "[Service]", "Type=oneshot", "RemainAfterExit=yes",
        f"ExecStart={nft_path} -f {CONFIG_PATH}", "",
        "[Install]", "WantedBy=multi-user.target", "", MARKER, "",
    ))
    _write_atomic(CONFIG_PATH, MARKER + "\n" + _rules(table=True, cgroup_level=1), 0o600)
    _write_atomic(UNIT_PATH, unit_text, 0o644)
    _run(["systemctl", "daemon-reload"])
    if table_exists:
        # Enable persistence without restarting an active unit: ExecStart loads a
        # new table and must not be replayed against the already-live table.
        _run(["systemctl", "enable", UNIT], timeout=30)
    else:
        _run(["systemctl", "enable", "--now", UNIT], timeout=30)
        if not _table_exists():
            # The service may have remained active while its table was removed.
            _run(["systemctl", "restart", UNIT], timeout=30)
    if not _table_exists():
        raise HelperError("The persistent nftables unit started but the kill-switch table is missing.")
    unit_state = subprocess.run(
        ["systemctl", "is-active", UNIT],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10, check=False,
    )
    if unit_state.returncode != 0 or (unit_state.stdout or "").strip() != "active":
        raise HelperError(
            "The nftables table exists, but the TorProxy system service is not active. "
            "Persistent protection across restart could not be verified."
        )
    _run(["nft", "flush", "set", "inet", TABLE, SET_NAME])
    _run(["nft", "-f", "-"], input_text=_rules())
    verified_chain = _run(["nft", "list", "chain", "inet", TABLE, "output"])
    if not _chain_is_safe(verified_chain):
        raise HelperError("The installed nftables output chain failed strict verification.")
    return {"ok": True, "active": True, "tun_interface_allowed": True, "detail": "nftables drop policy installed; only the Tor cgroup and TorProxy TUN interface are allowed."}


def set_cgroup(cgroup_id: int | None, cgroup_level: int | None = None) -> dict[str, object]:
    _require_root()
    if not _owned_installation() or not _table_exists():
        raise HelperError("TorProxy's persistent kill-switch service is not installed.")
    if cgroup_id is None:
        _run(["nft", "flush", "set", "inet", TABLE, SET_NAME])
        _run(["nft", "-f", "-"], input_text=_rules())
        return {"ok": True, "active": True, "cgroup_id": None}
    if type(cgroup_id) is not int or cgroup_id <= 0 or type(cgroup_level) is not int or cgroup_level < 1:
        raise HelperError("Invalid Tor cgroup identifier or hierarchy level.")
    _run(["nft", "flush", "set", "inet", TABLE, SET_NAME])
    _run(["nft", "add", "element", "inet", TABLE, SET_NAME, "{", str(cgroup_id), "}"])
    _run(["nft", "-f", "-"], input_text=_rules(cgroup_level))
    current = _run(["nft", "list", "chain", "inet", TABLE, "output"])
    if not _chain_is_safe(current) or f"socket cgroupv2 level {cgroup_level} @{SET_NAME} accept" not in current:
        raise HelperError("nftables did not retain the verified Tor cgroupv2 exception.")
    return {"ok": True, "active": True, "cgroup_id": cgroup_id, "cgroup_level": cgroup_level}


def remove() -> dict[str, object]:
    _require_root()
    if not _owned_installation():
        if _table_exists():
            raise HelperError("The nftables table exists but its ownership cannot be verified; refusing to delete it.")
        return {"ok": True, "active": False, "detail": "No TorProxy-owned firewall policy exists."}
    _run(["systemctl", "disable", "--now", UNIT], timeout=30)
    if _table_exists():
        _run(["nft", "delete", "table", "inet", TABLE])
    if _table_exists():
        raise HelperError("The TorProxy nftables table still exists after removal.")
    UNIT_PATH.unlink(missing_ok=True)
    CONFIG_PATH.unlink(missing_ok=True)
    _run(["systemctl", "daemon-reload"])
    return {"ok": True, "active": False}


def status() -> dict[str, object]:
    _require_root()
    if not _owned_installation() or not _table_exists():
        return {"ok": True, "active": False, "verified": False, "detail": "No active TorProxy nftables policy."}
    active = _run(["systemctl", "is-active", UNIT]) == "active"
    chain = _run(["nft", "list", "chain", "inet", TABLE, "output"])
    verified = active and _chain_is_safe(chain)
    return {"ok": True, "active": verified, "verified": verified,
            "tun_interface_allowed": verified and TUN_RULE in chain,
            "detail": "Persistent nftables kill switch." if verified else "Unknown or permissive nftables output rules were detected."}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(json.dumps({"ok": False, "error": "Missing helper action."}))
        return 2
    action = args[0]
    try:
        if action == "install" and len(args) == 1:
            result = install()
        elif action == "set-cgroup" and len(args) == 2 and args[1].count(":") == 1:
            raw_id, raw_level = args[1].split(":", 1)
            if not raw_id.isdecimal() or not raw_level.isdecimal():
                raise HelperError("Invalid cgroup argument.")
            result = set_cgroup(int(raw_id), int(raw_level))
        elif action == "clear-cgroup" and len(args) == 1:
            result = set_cgroup(None)
        elif action == "remove" and len(args) == 1:
            result = remove()
        elif action == "status" and len(args) == 1:
            result = status()
        else:
            raise HelperError("Unsupported firewall helper action or arguments.")
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
