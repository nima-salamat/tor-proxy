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


def test_windows_wfp_helper_scopes_system_tunnel_allow_to_the_exact_tun_interface():
    source = (
        Path(__file__).resolve().parents[1]
        / "launcher"
        / "src"
        / "wfp_helper.cpp"
    ).read_text(encoding="utf-8")
    assert 'ConvertInterfaceNameToLuidW(L"TorProxy"' in source
    assert "FWPM_CONDITION_IP_LOCAL_INTERFACE" in source
    assert "TorProxy WFP permit TorProxy tunnel interface" in source


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


def test_windows_wfp_source_uses_persistent_filters_and_one_transaction():
    source = (
        Path(__file__).resolve().parents[1]
        / "launcher"
        / "src"
        / "wfp_helper.cpp"
    ).read_text(encoding="utf-8")

    assert "FwpmTransactionBegin0" in source
    assert "FwpmTransactionCommit0" in source
    assert "FwpmTransactionAbort0" in source
    assert "FWPM_PROVIDER_FLAG_PERSISTENT" in source
    assert "FWPM_SUBLAYER_FLAG_PERSISTENT" in source
    assert "FWPM_FILTER_FLAG_PERSISTENT" in source
    assert "FWPM_LAYER_ALE_AUTH_CONNECT_V4" in source
    assert "FWPM_LAYER_ALE_AUTH_CONNECT_V6" in source
    assert "FWPM_CONDITION_ALE_APP_ID" in source
    assert "FWPM_CONDITION_IP_LOCAL_INTERFACE" in source
    assert "FWPM_CONDITION_FLAGS" in source
    assert "FWPM_CONDITION_ORIGINAL_ICMP_TYPE" in source
    assert "FWPM_CONDITION_ICMP_TYPE" not in source
    assert "FWPM_SESSION_FLAG_DYNAMIC" not in source
    assert "FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT" not in source
    assert "void allowTunnelInterface()" in source
    assert 'action == L"allow-tun"' in source
    assert 'ConvertInterfaceNameToLuidW(L"TorProxy"' in source
    assert "removeTunnelPermitFilters(engine.get())" in source
    assert "matchesTunnelLuid" in source
    assert "tun_interface_allowed=" in source
    assert "installed < 11" in source
    assert "existing < 11" in source
    assert "count >= 11" in source


def test_windows_wfp_cmake_target_is_installed_with_the_desktop_package():
    cmake = (
        Path(__file__).resolve().parents[1] / "launcher" / "CMakeLists.txt"
    ).read_text(encoding="utf-8")
    assert "add_executable(TorProxyWfpHelper src/wfp_helper.cpp)" in cmake
    assert "target_link_libraries(TorProxyWfpHelper PRIVATE Fwpuclnt Iphlpapi Ole32)" in cmake
    assert "install(TARGETS TorProxyWfpHelper RUNTIME DESTINATION .)" in cmake


def test_windows_backend_includes_the_native_wfp_helper_path_in_request(tmp_path):
    executable = tmp_path / "tor.exe"
    executable.write_text("fake tor", encoding="utf-8")
    helper = tmp_path / "TorProxyWfpHelper.exe"
    helper.write_bytes(b"test stub")
    calls = []

    def fake_runner(_script, action, _snapshot, request_path, result_path):
        payload = json.loads(request_path.read_text(encoding="utf-8"))
        calls.append((action, payload))
        result_path.write_text(json.dumps({"ok": True, "active": True}), encoding="utf-8")
        return 0

    backend = WindowsFirewallBackend(
        state_dir=tmp_path / "state",
        runner=fake_runner,
        wfp_helper_path=helper,
    )
    backend.activate((str(executable.resolve()),))

    persisted_helper = tmp_path / "state" / "native" / "TorProxyWfpHelper.exe"
    assert calls[0][0] == "activate"
    assert calls[0][1]["wfp_helper_path"] == str(persisted_helper)
    assert persisted_helper.read_bytes() == b"test stub"
    assert calls[0][1]["programs"] == [str(executable.resolve())]


def test_windows_backend_refuses_to_run_without_packaged_wfp_helper(tmp_path, monkeypatch):
    from torproxy.firewall import windows

    monkeypatch.setattr(windows, "_find_wfp_helper", lambda: None)
    backend = WindowsFirewallBackend(state_dir=tmp_path / "state")
    with pytest.raises(KillSwitchError, match="TorProxyWfpHelper.exe is missing"):
        backend._invoke("activate", ("C:\\\\Tor\\\\tor.exe",))


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


def test_windows_firewall_activation_has_no_legacy_per_rule_fallback():
    activation_start = _POWERSHELL.index("if ($Action -eq 'activate')")
    activation_end = _POWERSHELL.index("if ($Action -eq 'recover' -or", activation_start)
    activation_script = _POWERSHELL[activation_start:activation_end]

    assert "Invoke-WfpHelper 'activate' $programs" in activation_script
    assert "Set-NetFirewallProfile" not in activation_script
    assert "Set-SnapshotLocalRulesEnabled" not in activation_script
    assert "Set-NetFirewallRule" not in activation_script
    assert "Get-NetFirewallRule" not in activation_script
    assert "TorProxyWfpHelper.exe is missing" in _POWERSHELL

    fallback_start = _POWERSHELL.index("function Set-SnapshotRulesByInternalIds")
    fallback_end = _POWERSHELL.index("function Set-SnapshotLocalRulesEnabled", fallback_start)
    assert "Set-NetFirewallRule" in _POWERSHELL[fallback_start:fallback_end]
    assert "Get-SnapshotValue $snapshot 'blockSharedAccess'" in _POWERSHELL
    assert "original snapshot is missing" in _POWERSHELL


def test_windows_activation_uses_transactional_wfp_without_per_rule_updates():
    activation_start = _POWERSHELL.index("if ($Action -eq 'activate')")
    activation_end = _POWERSHELL.index("if ($Action -eq 'recover' -or", activation_start)
    activation_script = _POWERSHELL[activation_start:activation_end]

    assert "Invoke-WfpHelper 'activate' $programs" in activation_script
    assert "Persistent WFP filter set committed and verified" in activation_script
    assert "Set-NetFirewallProfile" not in activation_script
    assert "Set-SnapshotLocalRulesEnabled" not in activation_script
    assert "Save-Snapshot" not in activation_script
    assert "Set-NetFirewallProfile" not in activation_script
    assert "Get-NetFirewallRule" not in activation_script
    assert "Invoke-WfpHelper 'activate' $programs" in activation_script


def test_windows_legacy_recovery_only_suppresses_missing_owned_rule_groups():
    assert "function Get-GroupRulesOrEmpty([string]$policyStore)" in _POWERSHELL
    assert "-ErrorAction SilentlyContinue -ErrorVariable queryErrors" in _POWERSHELL
    assert "CmdletizationQuery_NotFound_RuleGroup*" in _POWERSHELL
    assert "throw $unexpectedErrors[0]" in _POWERSHELL
    assert "Get-NetFirewallRule -PolicyStore ActiveStore -Group $Group -ErrorAction Stop" not in _POWERSHELL
    assert "Set-SnapshotLocalRulesEnabled $snapshot $false" not in _POWERSHELL


def test_optional_firewall_group_query_only_suppresses_expected_not_found():
    assert "CmdletizationQuery_NotFound_RuleGroup*" in _POWERSHELL
    assert "-ErrorAction SilentlyContinue -ErrorVariable queryErrors" in _POWERSHELL
    assert "Where-Object {" in _POWERSHELL
    assert "[string]$_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound_RuleGroup*'" in _POWERSHELL
    assert "throw $unexpectedErrors[0]" in _POWERSHELL


def test_windows_saved_local_allow_rules_map_internal_ids_to_com_friendly_names():
    start = _POWERSHELL.index("function Set-SnapshotLocalRulesEnabled")
    end = _POWERSHELL.index("function Set-SnapshotProfile", start)
    helper = _POWERSHELL[start:end]
    fallback_start = _POWERSHELL.index("function Set-SnapshotRulesByInternalIds")
    fallback_end = _POWERSHELL.index("function Set-SnapshotLocalRulesEnabled", fallback_start)
    fallback = _POWERSHELL[fallback_start:fallback_end]

    assert "Get-NetFirewallRule -PolicyStore PersistentStore -Name $names" in helper
    assert "$netRule.DisplayName" in helper
    assert "$rules.Item([string]$friendlyName)" in helper
    assert "$rule.Name -ine [string]$friendlyName" in helper
    assert "$rule.Enabled = [bool]$enabled" in helper
    assert "$comNameCounts[$candidateName]++" in helper
    assert "$duplicateRuleIds.Add([string]$entry.InternalName)" in helper
    assert "$fallbackRuleIds.Add([string]$expected.InternalName)" in helper
    assert "$comCount -ne 1" in helper
    assert "Set-SnapshotRulesByInternalIds ($fallbackRuleIds.ToArray())" in helper
    assert "Set-NetFirewallRule" not in helper
    assert "Set-NetFirewallRule -PolicyStore PersistentStore -Name ($changeIds.ToArray()) -Enabled $enabledValue" in fallback
    assert "Get-NetFirewallRule -PolicyStore PersistentStore -Name $ruleIds" in fallback
    assert "FinalReleaseComObject" in helper

    recovery_start = _POWERSHELL.index("elseif ($Action -eq 'recover')")
    recovery_end = _POWERSHELL.index("elseif ($Action -eq 'emergency')", recovery_start)
    recovery_script = _POWERSHELL[recovery_start:recovery_end]
    assert "Set-SnapshotLocalRulesEnabled $snapshot $true" in recovery_script

def test_windows_profile_updates_use_netsecurity_enum_strings():
    assert "function Set-SnapshotProfile($saved)" in _POWERSHELL
    assert "$enabledValue = if ([bool]$saved.Enabled) { 'True' } else { 'False' }" in _POWERSHELL
    assert "Set-NetFirewallProfile -PolicyStore PersistentStore -Profile ([string]$saved.Name) -Enabled $enabledValue" in _POWERSHELL
    assert "Set-NetFirewallProfile -PolicyStore PersistentStore -Profile ([string]$saved.Name) -Enabled ([bool]$saved.Enabled)" not in _POWERSHELL
    assert _POWERSHELL.count("Set-SnapshotProfile $saved") == 2


def test_windows_saved_rule_updates_handle_duplicate_and_com_missing_names_by_guid():
    fallback_start = _POWERSHELL.index("function Set-SnapshotRulesByInternalIds")
    fallback_end = _POWERSHELL.index("function Set-SnapshotLocalRulesEnabled", fallback_start)
    fallback = _POWERSHELL[fallback_start:fallback_end]
    assert "Get-NetFirewallRule -PolicyStore PersistentStore -Name $ruleIds" in fallback
    assert "Set-NetFirewallRule -PolicyStore PersistentStore -Name ($changeIds.ToArray()) -Enabled $enabledValue" in fallback
    assert "Get-NetFirewallRule -PolicyStore PersistentStore -Name $ruleIds -ErrorAction Stop" in fallback
    assert "did not reach the requested Enabled state during $reason fallback" in fallback

    start = _POWERSHELL.index("function Set-SnapshotLocalRulesEnabled")
    end = _POWERSHELL.index("function Set-SnapshotProfile", start)
    helper = _POWERSHELL[start:end]
    assert "$expectedByFriendlyName[$friendlyName]" in helper
    assert "$comNameCounts" in helper
    assert "$comCount -ne 1" in helper
    assert "$duplicateRuleIds.Add([string]$entry.InternalName)" in helper
    assert "$fallbackRuleIds.Add([string]$expected.InternalName)" in helper
    assert "[int]$exception.HResult -eq -2147024894" in helper
    assert "if (-not $isMissing) { throw }" in helper
    assert "Set-SnapshotRulesByInternalIds ($fallbackRuleIds.ToArray())" in helper
    assert "$rules.Item([string]$friendlyName)" in helper
    assert "[int]$rule.Direction -ne 2" in helper
    assert "[int]$rule.Action -ne 1" in helper
    assert "Windows Firewall updated" in helper

def test_windows_helper_reports_wfp_phases_without_affecting_firewall_work():
    assert "function Set-Phase([string]$phase)" in _POWERSHELL
    assert "Progress reporting must never prevent a firewall operation." in _POWERSHELL
    assert "Installing persistent IPv4/IPv6 WFP filters in one transaction" in _POWERSHELL
    assert "Removing TorProxy-owned persistent WFP filters in one transaction" in _POWERSHELL
    assert "$tunAllowed = $detail -match 'tun_interface_allowed=true'" in _POWERSHELL


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
