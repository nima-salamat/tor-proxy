from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from torproxy.killswitch import KillSwitchError, KillSwitchManager
from torproxy.firewall.linux_helper import HelperError, _chain_is_safe, _rules
from torproxy.firewall.windows import WindowsFirewallBackend, _POWERSHELL


class FakeBackend:
    def __init__(self):
        self.programs = None
        self.active = False
        self.cgroup = None
        self.calls = []

    def activate(self, programs):
        self.programs = programs
        self.active = True
        self.calls.append("activate")

    def deactivate(self):
        self.active = False
        self.calls.append("deactivate")

    def set_tor_cgroup(self, cgroup_id, cgroup_level):
        self.cgroup = (cgroup_id, cgroup_level)

    def status(self):
        return {"active": self.active, "verified": True}


def test_manager_validates_programs_and_delegates_to_backend(tmp_path):
    executable = tmp_path / "tor"
    executable.write_text("fake tor", encoding="utf-8")
    backend = FakeBackend()
    manager = KillSwitchManager(backend=backend)

    manager.activate([executable, executable])
    assert backend.programs == (str(executable.resolve()),)
    assert manager.status() == {"active": True, "verified": True}

    manager.set_tor_cgroup(1234, 5)
    assert backend.cgroup == (1234, 5)

    manager.deactivate()
    assert manager.status()["active"] is False
    assert backend.calls == ["activate", "deactivate"]


def test_manager_recovery_prefers_backend_recovery_hooks():
    class RecoveryBackend(FakeBackend):
        def recover(self):
            self.calls.append("recover")
            return {"ok": True, "detail": "preserved Domain"}

        def emergency_recover(self):
            self.calls.append("emergency-recover")
            return {"ok": True, "detail": "outbound Allow restored"}

    backend = RecoveryBackend()
    manager = KillSwitchManager(backend=backend)

    recovered = manager.recover()
    emergency = manager.emergency_recover()

    assert backend.calls == ["recover", "emergency-recover"]
    assert recovered["detail"] == "preserved Domain"
    assert emergency["detail"] == "outbound Allow restored"


def test_windows_backend_forwards_recovery_actions(tmp_path):
    calls = []

    def fake_runner(_script, action, _snapshot, _request, result_path):
        calls.append(action)
        result_path.write_text(
            json.dumps({"ok": True, "active": False, "mode": action}),
            encoding="utf-8",
        )
        return 0

    backend = WindowsFirewallBackend(state_dir=tmp_path / "state", runner=fake_runner)
    backend.recover()
    backend.emergency_recover()

    assert calls == ["recover", "emergency"]


def test_windows_disable_uses_drift_tolerant_recovery():
    def fake_runner(_script, action, _snapshot, _request, result_path):
        assert action == "recover"
        result_path.write_text(
            json.dumps({"ok": True, "active": False, "detail": "preserved Domain"}),
            encoding="utf-8",
        )
        return 0

    backend = WindowsFirewallBackend(state_dir=Path("state"), runner=fake_runner)
    backend.deactivate()


def test_windows_recovery_preserves_external_profile_changes():
    assert "Externally changed profile settings were preserved" in _POWERSHELL
    assert "$preservedProfiles[$name]" in _POWERSHELL
    assert "Externally changed firewall profile $name was modified during recovery." in _POWERSHELL
    recover_start = _POWERSHELL.index("elseif ($Action -eq 'recover')")
    recover_end = _POWERSHELL.index("elseif ($Action -eq 'emergency')", recover_start)
    recovery_script = _POWERSHELL[recover_start:recover_end]
    assert "Assert-ManagedState $snapshot $false" not in recovery_script


def test_windows_helper_scopes_system_tunnel_allow_rule_to_the_exact_tun_interface():
    assert "TorProxy_KS_TUN" in _POWERSHELL
    assert "-InterfaceAlias 'TorProxy'" in _POWERSHELL
    assert "Test-TunInterfaceAllowRule" in _POWERSHELL
    assert "tun_interface_allowed" in _POWERSHELL


def test_windows_helper_exposes_saved_and_emergency_recovery_paths():
    assert "elseif ($Action -eq 'recover')" in _POWERSHELL
    assert "elseif ($Action -eq 'emergency')" in _POWERSHELL
    assert "The saved TorProxy firewall snapshot is invalid" in _POWERSHELL
    assert "already-restored" in _POWERSHELL
    assert "-DefaultOutboundAction Allow" in _POWERSHELL
    assert "kept Windows Firewall enabled" in _POWERSHELL


def test_windows_elevated_runner_has_a_bounded_wait_and_terminates_timeouts():
    import inspect
    from torproxy.firewall.windows import ELEVATED_HELPER_TIMEOUT_MS, _run_elevated

    source = inspect.getsource(_run_elevated)
    assert ELEVATED_HELPER_TIMEOUT_MS == 30_000
    assert "WaitForSingleObject(info.hProcess, ELEVATED_HELPER_TIMEOUT_MS)" in source
    assert "TerminateProcess" in source
    assert "ctypes.POINTER(wintypes.DWORD)" in source
    assert "WAIT_TIMEOUT" in source
    assert "Last reported step" in source


def test_manager_recovery_state_is_local_and_does_not_require_admin():
    class RecoveryStateBackend(FakeBackend):
        def recovery_state(self):
            return {"available": True, "snapshot_exists": True, "verified": False}

    manager = KillSwitchManager(backend=RecoveryStateBackend())
    assert manager.recovery_state() == {
        "available": True,
        "snapshot_exists": True,
        "verified": False,
    }


def test_manager_rejects_missing_or_empty_tor_allowlist(tmp_path):
    manager = KillSwitchManager(backend=FakeBackend())
    with pytest.raises(KillSwitchError, match="does not exist"):
        manager.activate([tmp_path / "missing-tor"])
    with pytest.raises(KillSwitchError, match="At least"):
        manager.activate([])


def test_manager_rejects_unsupported_platform():
    with pytest.raises(KillSwitchError, match="Windows and Linux"):
        KillSwitchManager(platform_name="unsupported")


def test_linux_rules_default_to_drop_and_never_allow_the_desktop_uid():
    rules = _rules(cgroup_level=5, table=True)
    assert "type filter hook output priority 0; policy drop;" in rules
    assert 'oifname "lo" accept' in rules
    assert 'oifname "torproxy-tun" accept' in rules
    assert "socket cgroupv2 level 5 @tor_cgroups accept" in rules
    assert "meta skuid" not in rules
    assert "meta cgroup" not in rules


def test_linux_rules_without_tor_cgroup_keep_tor_blocked():
    rules = _rules()
    assert "policy drop" not in rules  # The chain is flushed and the base policy remains drop.
    assert "socket cgroupv2" not in rules
    assert "flush chain inet torproxy_killswitch output" in rules


@pytest.mark.parametrize("level", [0, -1, True, "5"])
def test_linux_rules_reject_invalid_cgroup_hierarchy_level(level):
    with pytest.raises(HelperError, match="cgroup hierarchy"):
        _rules(cgroup_level=level)


def test_linux_helper_dispatch_rejects_malformed_cgroup_arguments(capsys):
    from torproxy.firewall.linux_helper import main

    result = main(["set-cgroup", "1234"])
    captured = capsys.readouterr()
    assert result == 1
    assert "Unsupported firewall helper action" in captured.out


def test_linux_backend_reports_a_bounded_helper_timeout():
    from torproxy.firewall.linux import HELPER_TIMEOUT_SECONDS, LinuxFirewallBackend

    calls = []

    def timeout_runner(command, **kwargs):
        calls.append((command, kwargs))
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    backend = LinuxFirewallBackend(runner=timeout_runner)
    backend._helper_command = lambda action, argument=None: ["pkexec", action]
    with pytest.raises(KillSwitchError, match="180 seconds.*install"):
        backend._run_helper("install")

    assert calls[0][1]["timeout"] == HELPER_TIMEOUT_SECONDS == 180


@pytest.mark.skipif(os.name == "nt", reason="The Linux firewall backend requires Linux cgroup v2.")
def test_linux_backend_passes_numeric_cgroup_id_and_level_without_shell(monkeypatch):
    from torproxy.firewall import linux

    calls = []

    def fake_which(name):
        return f"/usr/bin/{name}"

    def fake_is_file(path):
        return str(path) == "/sys/fs/cgroup/cgroup.controllers"

    def fake_runner(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout='{"ok": true}', stderr="")

    monkeypatch.setattr(linux.shutil, "which", fake_which)
    monkeypatch.setattr(Path, "is_file", fake_is_file)
    backend = linux.LinuxFirewallBackend(runner=fake_runner)
    backend.set_tor_cgroup(1234, 5)

    command, kwargs = calls[0]
    assert command[-2:] == ["set-cgroup", "1234:5"]
    assert command[0] == "/usr/bin/pkexec"
    assert Path(command[-3]).name == "linux_helper.py"
    assert kwargs["timeout"] == linux.HELPER_TIMEOUT_SECONDS == 180
    assert "shell" not in kwargs


def test_windows_backend_uses_elevated_helper_and_verifies_result(tmp_path):
    executable = tmp_path / "tor.exe"
    executable.write_text("fake tor", encoding="utf-8")
    calls = []

    def fake_runner(script_path, action, snapshot_path, request_path, result_path):
        calls.append(action)
        request = json.loads(request_path.read_text(encoding="utf-8"))
        if action == "activate":
            assert request["programs"] == [str(executable.resolve())]
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_text('{"version":1}', encoding="utf-8")
        result_path.write_text(json.dumps({"ok": True, "active": True}), encoding="utf-8")
        return 0

    backend = WindowsFirewallBackend(state_dir=tmp_path / "state", runner=fake_runner)
    backend.activate((str(executable.resolve()),))
    assert backend.status()["active"] is True
    backend.deactivate()
    assert calls == ["activate", "status", "recover"]


def test_windows_backend_refuses_unverified_helper_result(tmp_path):
    executable = tmp_path / "tor.exe"
    executable.write_text("fake tor", encoding="utf-8")

    def fake_runner(_script, _action, _snapshot, _request, result_path):
        result_path.write_text(json.dumps({"ok": False, "error": "policy conflict"}), encoding="utf-8")
        return 1

    backend = WindowsFirewallBackend(state_dir=tmp_path / "state", runner=fake_runner)
    with pytest.raises(KillSwitchError, match="policy conflict"):
        backend.activate((str(executable.resolve()),))


def test_windows_firewall_helper_is_strict_about_outbound_exceptions():
    assert "DefaultOutboundAction Block" in _POWERSHELL
    assert "GroupPolicy" in _POWERSHELL
    assert "-PolicyStore ActiveStore -TracePolicyStore -Direction Outbound" in _POWERSHELL
    assert "PolicyStoreSourceType" in _POWERSHELL
    assert "([string]$_.PolicyStoreSourceType -ne 'Local' -or" in _POWERSHELL
    assert "Enabled outbound Allow rules are enforced by Group Policy" in _POWERSHELL
    assert "PolicyStoreSource" in _POWERSHELL
    assert "Enabled outbound Allow rules outside the local firewall store" in _POWERSHELL
    assert "Get-NetFirewallApplicationFilter" in _POWERSHELL
    assert "Get-NetFirewallServiceFilter" in _POWERSHELL
    assert "Get-NetFirewallPortFilter" in _POWERSHELL
    assert "Get-NetFirewallAddressFilter" in _POWERSHELL
    assert "Get-NetFirewallSecurityFilter" in _POWERSHELL
    assert "$null -eq $security -or [string]$security.OverrideBlockRules -ne 'False'" in _POWERSHELL
    assert "authenticated block bypass is disabled" in _POWERSHELL
    assert "Program=$program" in _POWERSHELL
    assert "RemotePort=$remotePort" in _POWERSHELL
    assert "RemoteAddress=$remoteAddress" in _POWERSHELL
    assert "Rule filters are included to identify their owner and scope" in _POWERSHELL
    assert "function Get-SnapshotValue($snapshot, [string]$name)" in _POWERSHELL
    assert "function Set-SnapshotValue($snapshot, [string]$name, $value)" in _POWERSHELL
    assert "function Test-SharedAccessDynamicAllowRule($rule)" in _POWERSHELL
    assert "[string]$rule.PolicyStoreSourceType -ne 'Dynamic'" in _POWERSHELL
    assert "$serviceNames -contains 'SharedAccess'" in _POWERSHELL
    assert "TorProxy_KS_Block_SharedAccess" in _POWERSHELL
    assert "-Action Block -Program $sharedAccessProgram -Service SharedAccess -OverrideBlockRules $false" in _POWERSHELL
    assert "Assert-SharedAccessBlockRule" in _POWERSHELL
    assert "Get-SnapshotValue $snapshot 'blockSharedAccess' -and" not in _POWERSHELL
    assert "Get-SnapshotValue $snapshot 'blockSharedAccess') -and $sharedAccessRuleNames.ContainsKey([string]$_.Name)" in _POWERSHELL
    assert "Set-Phase 'Reading the effective outbound firewall rules...'" in _POWERSHELL
    assert "$ProgressPath = $ResultPath + '.progress'" in _POWERSHELL
    assert "Set-NetFirewallRule" not in _POWERSHELL
    assert "TorProxy Kill Switch" in _POWERSHELL
    assert "original snapshot is missing" in _POWERSHELL
    assert "could not be restored to its saved state" in _POWERSHELL





def test_windows_activation_reuses_a_single_traced_active_store_scan():
    activation_start = _POWERSHELL.index("if ($Action -eq 'activate')")
    activation_end = _POWERSHELL.index("elseif ($Action -eq 'deactivate')", activation_start)
    activation_script = _POWERSHELL[activation_start:activation_end]

    traced_query = (
        "Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore "
        "-Direction Outbound -Action Allow -Enabled True"
    )
    assert activation_script.count(traced_query) == 1
    assert "$sharedAccessRuleNames[[string]$rule.Name] = $true" in activation_script
    assert "$sharedAccessRuleNames.ContainsKey([string]$_.Name)" in activation_script
    assert "$finalActiveAllow = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound" in activation_script
    assert "-ErrorAction Stop" in activation_script


def test_windows_first_activation_treats_missing_owned_group_as_empty():
    assert "function Get-GroupRulesOrEmpty([string]$policyStore)" in _POWERSHELL
    assert "-ErrorAction SilentlyContinue -ErrorVariable queryErrors" in _POWERSHELL
    assert "CmdletizationQuery_NotFound_RuleGroup*" in _POWERSHELL
    assert "throw $unexpectedErrors[0]" in _POWERSHELL
    assert "$orphanedGroup = @(Get-GroupRulesOrEmpty 'ActiveStore')" in _POWERSHELL
    assert "Get-NetFirewallRule -PolicyStore ActiveStore -Group $Group -ErrorAction Stop" not in _POWERSHELL


def test_optional_firewall_group_query_only_suppresses_expected_not_found():
    assert "CmdletizationQuery_NotFound_RuleGroup*" in _POWERSHELL
    assert "-ErrorAction SilentlyContinue -ErrorVariable queryErrors" in _POWERSHELL
    assert "Where-Object {" in _POWERSHELL
    assert "[string]$_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound_RuleGroup*'" in _POWERSHELL
    assert "throw $unexpectedErrors[0]" in _POWERSHELL


def test_windows_saved_local_allow_rules_are_processed_in_one_com_collection_pass():
    start = _POWERSHELL.index("function Set-SnapshotLocalRulesEnabled")
    end = _POWERSHELL.index("function Set-SnapshotProfile", start)
    helper = _POWERSHELL[start:end]
    assert "New-Object -ComObject HNetCfg.FwPolicy2" in helper
    assert "$rules = $policy.Rules" in helper
    assert "foreach ($rule in $rules)" in helper
    assert "$wanted.Contains($ruleName)" in helper
    assert "$rule.Enabled = [bool]$enabled" in helper
    assert "Set-NetFirewallRule" not in helper
    assert "Get-NetFirewallRule" not in helper

    activation_start = _POWERSHELL.index("if ($Action -eq 'activate')")
    activation_end = _POWERSHELL.index("elseif ($Action -eq 'deactivate')", activation_start)
    activation_script = _POWERSHELL[activation_start:activation_end]
    assert "Set-SnapshotLocalRulesEnabled $snapshot $false" in activation_script
    assert "Disabling saved local outbound Allow rules through COM" in activation_script

    recovery_start = _POWERSHELL.index("elseif ($Action -eq 'recover')")
    recovery_end = _POWERSHELL.index("elseif ($Action -eq 'emergency')", recovery_start)
    recovery_script = _POWERSHELL[recovery_start:recovery_end]
    assert "Set-SnapshotLocalRulesEnabled $snapshot $true" in recovery_script
    assert "Restoring saved local outbound Allow rules through COM" in recovery_script


def test_windows_profile_updates_use_netsecurity_enum_strings():
    assert "function Set-SnapshotProfile($saved)" in _POWERSHELL
    assert "$enabledValue = if ([bool]$saved.Enabled) { 'True' } else { 'False' }" in _POWERSHELL
    assert "Set-NetFirewallProfile -PolicyStore PersistentStore -Profile ([string]$saved.Name) -Enabled $enabledValue" in _POWERSHELL
    assert "Set-NetFirewallProfile -PolicyStore PersistentStore -Profile ([string]$saved.Name) -Enabled ([bool]$saved.Enabled)" not in _POWERSHELL
    assert _POWERSHELL.count("Set-SnapshotProfile $saved") == 2


def test_windows_saved_rule_updates_use_native_firewall_com_not_netsecurity_cim():
    start = _POWERSHELL.index("function Set-SnapshotLocalRulesEnabled")
    end = _POWERSHELL.index("function Set-SnapshotProfile", start)
    helper = _POWERSHELL[start:end]

    assert "New-Object -ComObject HNetCfg.FwPolicy2" in helper
    assert "$rules = $policy.Rules" in helper
    assert "foreach ($rule in $rules)" in helper
    assert "$rule.Enabled = [bool]$enabled" in helper
    assert "[int]$rule.Direction -ne 2" in helper
    assert "[int]$rule.Action -ne 1" in helper
    assert "FinalReleaseComObject" in helper
    assert "Set-NetFirewallRule" not in helper
    assert "Get-NetFirewallRule" not in helper
    assert "None of the {0} saved firewall rules were found" in helper
    assert "Windows Firewall COM updated" in helper


def test_windows_helper_reports_the_current_phase_without_affecting_firewall_work():
    assert "function Set-Phase([string]$phase)" in _POWERSHELL
    assert "Progress reporting must never prevent a firewall operation." in _POWERSHELL
    assert "Verifying effective firewall profiles and TorProxy-owned rules" in _POWERSHELL


def test_linux_install_is_idempotent_without_restarting_the_live_drop_chain(tmp_path, monkeypatch):
    from torproxy.firewall import linux_helper

    calls = []

    monkeypatch.setattr(linux_helper, "_require_root", lambda: None)
    monkeypatch.setattr(linux_helper, "_table_exists", lambda: True)
    monkeypatch.setattr(linux_helper, "_owned_installation", lambda: True)
    monkeypatch.setattr(linux_helper, "CONFIG_PATH", tmp_path / "torproxy-killswitch.nft")
    monkeypatch.setattr(linux_helper, "UNIT_PATH", tmp_path / "torproxy-killswitch.service")
    monkeypatch.setattr(
        linux_helper.subprocess, "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, stdout="active", stderr=""),
    )
    monkeypatch.setattr(linux_helper.shutil, "which", lambda _name: "/usr/sbin/nft")

    def fake_run(args, *, input_text=None, timeout=20):
        calls.append((args, input_text))
        if args[:3] == ["nft", "list", "chain"]:
            return """table inet torproxy_killswitch {
                chain output {
                type filter hook output priority filter; policy drop;
                oifname "lo" accept
                udp sport 68 udp dport 67 accept
                udp sport 546 udp dport 547 accept
                ip6 daddr { fe80::/10, ff02::/16 } icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
                }
            }"""
        return ""

    monkeypatch.setattr(linux_helper, "_run", fake_run)
    result = linux_helper.install()

    assert result["active"] is True
    commands = [args for args, _input in calls]
    assert ["systemctl", "enable", linux_helper.UNIT] in commands
    assert ["systemctl", "enable", "--now", linux_helper.UNIT] not in commands
    assert ["systemctl", "restart", linux_helper.UNIT] not in commands
    assert "ExecStop=" not in linux_helper.UNIT_PATH.read_text(encoding="utf-8")
    checks = [payload for args, payload in calls if args[:3] == ["nft", "--check", "-f"]]
    assert any("socket cgroupv2 level 1 @tor_cgroups accept" in (payload or "") for payload in checks)
    assert ["nft", "flush", "set", "inet", linux_helper.TABLE, linux_helper.SET_NAME] in commands


def test_windows_helper_can_restore_a_partially_applied_policy():
    assert "Assert-ManagedState $snapshot $false" in _POWERSHELL
    assert "$currentProfiles = Get-PersistentProfiles" in _POWERSHELL
    assert "DefaultOutboundAction" in _POWERSHELL


def test_windows_kill_switch_checks_effective_policy_but_snapshots_local_settings():
    # The local persistent store is reversible configuration; ActiveStore is
    # the merged policy that Windows Firewall actually enforces.
    assert "Get-NetFirewallProfile -PolicyStore ActiveStore" in _POWERSHELL
    assert "Get-NetFirewallProfile -PolicyStore PersistentStore" in _POWERSHELL
    assert "$profiles = Get-PersistentProfiles" in _POWERSHELL
    assert "function Assert-EffectiveOutboundAction" in _POWERSHELL
    assert "foreach ($serviceName in @('BFE', 'MpsSvc'))" in _POWERSHELL
    assert "Required Windows filtering service $serviceName is not running." in _POWERSHELL
    assert "DisabledInterfaceAliases" in _POWERSHELL
    assert """if ($expectedAction -eq 'Block') {
            $disabledInterfaces = @($profile.DisabledInterfaceAliases""" in _POWERSHELL
    assert "excludes interface filtering for: $names" in _POWERSHELL
    assert "Assert-EffectiveOutboundAction 'Block'" in _POWERSHELL
    assert "Assert-EffectiveOutboundAction 'Allow'" in _POWERSHELL
    assert "Assert-EffectiveOutboundAction 'Allow'" in _POWERSHELL
    assert "The effective Windows Firewall $name profile could not be read from ActiveStore." in _POWERSHELL
    assert "Effective Windows Firewall profile $name does not enforce outbound $expectedAction." in _POWERSHELL
    assert "Set-NetFirewallProfile -PolicyStore PersistentStore" in _POWERSHELL



def test_linux_chain_verification_rejects_missing_rules_and_unexpected_allow_rules():
    safe_chain = """table inet torproxy_killswitch {
    chain output {
        type filter hook output priority filter; policy drop;
        oifname "lo" accept
        udp sport 68 udp dport 67 accept
        udp sport 546 udp dport 547 accept
        ip6 daddr { fe80::/10, ff02::/16 } icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
        socket cgroupv2 level 5 @tor_cgroups accept
    }
}"""
    assert _chain_is_safe(safe_chain)
    assert not _chain_is_safe(safe_chain.replace('oifname "lo" accept', "oifname eth0 accept"))
    assert not _chain_is_safe(safe_chain.replace("socket cgroupv2 level 5 @tor_cgroups accept", "ip daddr 0.0.0.0/0 accept"))
    assert not _chain_is_safe(safe_chain + "\n ip daddr 198.51.100.1 accept")
    assert _chain_is_safe(safe_chain.replace(
        'oifname "lo" accept', 'oifname "lo" accept\n        oifname "torproxy-tun" accept'
    ))
    assert not _chain_is_safe(safe_chain.replace(
        'oifname "lo" accept', 'oifname "lo" accept\n        oifname "eth0" accept'
    ))
    assert not _chain_is_safe(safe_chain.replace("policy drop", "policy accept"))


@pytest.mark.skipif(os.name != "nt", reason="PowerShell parser is available on the Windows CI runner.")
def test_windows_firewall_script_parses_as_valid_powershell(tmp_path):
    import shutil

    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        pytest.skip("Windows PowerShell is unavailable.")
    script_path = tmp_path / "torproxy-firewall.ps1"
    script_path.write_text(_POWERSHELL, encoding="utf-8")
    escaped_path = str(script_path).replace("'", "''")
    command = (
        "$tokens=$null; $parseErrors=$null; "
        f"[System.Management.Automation.Language.Parser]::ParseFile('{escaped_path}', "
        "[ref]$tokens, [ref]$parseErrors) | Out-Null; "
        "if ($parseErrors.Count -gt 0) { "
        "$parseErrors | ForEach-Object { Write-Error $_.Message }; exit 1 }"
    )
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20, check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout



def test_windows_backend_does_not_silently_ignore_orphaned_firewall_rules(tmp_path):
    def fake_runner(_script, action, _snapshot, _request, result_path):
        assert action == "recover"
        result_path.write_text(
            json.dumps({"ok": False, "error": "original snapshot is missing"}),
            encoding="utf-8",
        )
        return 1

    backend = WindowsFirewallBackend(state_dir=tmp_path / "state", runner=fake_runner)
    with pytest.raises(KillSwitchError, match="original snapshot is missing"):
        backend.deactivate()



def test_linux_chain_verification_rejects_a_foreign_table_header():
    safe_chain = """table inet torproxy_killswitch {
        chain output {
            type filter hook output priority filter; policy drop;
            oifname "lo" accept
            udp sport 68 udp dport 67 accept
            udp sport 546 udp dport 547 accept
            ip6 daddr { fe80::/10, ff02::/16 } icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
        }
    }"""
    assert _chain_is_safe(safe_chain)
    assert not _chain_is_safe(safe_chain.replace(
        "table inet torproxy_killswitch", "table inet other_table"
    ))
