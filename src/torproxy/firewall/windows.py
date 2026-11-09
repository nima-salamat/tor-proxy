"""Windows Defender Firewall backend with reversible outbound-policy changes."""
from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ..killswitch import KillSwitchError
from ..paths import user_directories

GROUP = "TorProxy Kill Switch"
SNAPSHOT_NAME = "windows-firewall-snapshot.json"
ELEVATED_HELPER_TIMEOUT_MS = 30_000
WFP_HELPER_NAME = "TorProxyWfpHelper.exe"


def _find_wfp_helper() -> Path | None:
    """Locate the packaged native WFP helper or a local CMake build."""
    candidates: list[Path] = []
    configured = os.environ.get("TORPROXY_WFP_HELPER")
    if configured:
        candidates.append(Path(configured).expanduser())

    try:
        candidates.append(Path(sys.executable).resolve().parent / WFP_HELPER_NAME)
    except (OSError, RuntimeError):
        pass

    try:
        repository_root = Path(__file__).resolve().parents[3]
        candidates.extend(
            [
                repository_root / WFP_HELPER_NAME,
                repository_root / "build" / "launcher" / "Release" / WFP_HELPER_NAME,
                repository_root / "build" / "launcher" / WFP_HELPER_NAME,
                repository_root / "build" / "launcher" / "Debug" / WFP_HELPER_NAME,
            ]
        )
    except (IndexError, OSError, RuntimeError):
        pass

    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved.is_file():
            return resolved
    return None


_POWERSHELL = r"""
param(
    [Parameter(Mandatory=$true)][string]$Action,
    [Parameter(Mandatory=$true)][string]$SnapshotPath,
    [Parameter(Mandatory=$true)][string]$RequestPath,
    [Parameter(Mandatory=$true)][string]$ResultPath
)
$ErrorActionPreference = 'Stop'
$Group = 'TorProxy Kill Switch'
$ProgressPath = $ResultPath + '.progress'
function Set-Phase([string]$phase) {
    try {
        [System.IO.File]::WriteAllText(
            $ProgressPath, $phase, [System.Text.UTF8Encoding]::new($false)
        )
    } catch {
        # Progress reporting must never prevent a firewall operation.
    }
}
Set-Phase "Starting elevated Windows Firewall helper ($Action)..."
function Write-Result($value) {
    $json = ConvertTo-Json -InputObject $value -Depth 8 -Compress
    [System.IO.File]::WriteAllText($ResultPath, $json, [System.Text.UTF8Encoding]::new($false))
}
function Save-Snapshot($snapshot) {
    $temp = $SnapshotPath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    $json = ConvertTo-Json -InputObject $snapshot -Depth 10
    [System.IO.File]::WriteAllText($temp, $json, [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temp -Destination $SnapshotPath -Force
}
function Get-ActiveProfiles {
    # ActiveStore is the merged policy Windows Firewall currently enforces.
    return @(Get-NetFirewallProfile -PolicyStore ActiveStore -Profile Domain,Private,Public | Select-Object Name,Enabled,DefaultOutboundAction,DisabledInterfaceAliases)
}
function Get-GroupRulesOrEmpty([string]$policyStore) {
    # NetSecurity reports an empty -Group query as a CIM NotFound error instead
    # of returning an empty collection. Treat only that precise condition as
    # the expected first-run state; provider/permission failures must still stop.
    $queryErrors = @()
    $rules = @(Get-NetFirewallRule -PolicyStore $policyStore -Group $Group -ErrorAction SilentlyContinue -ErrorVariable queryErrors)
    $unexpectedErrors = @($queryErrors | Where-Object {
        [string]$_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound_RuleGroup*'
    })
    if ($unexpectedErrors.Count -gt 0) {
        throw $unexpectedErrors[0]
    }
    return $rules
}
function Get-PersistentProfiles {
    # PersistentStore is the local configuration TorProxy snapshots and restores.
    return @(Get-NetFirewallProfile -PolicyStore PersistentStore -Profile Domain,Private,Public | Select-Object Name,Enabled,DefaultOutboundAction)
}
function Assert-EffectiveOutboundAction([string]$expectedAction) {
    if ($expectedAction -eq 'Block') {
        # Firewall profile settings are ineffective if the filtering services are stopped.
        foreach ($serviceName in @('BFE', 'MpsSvc')) {
            $service = Get-Service -Name $serviceName -ErrorAction Stop
            if ([string]$service.Status -ne 'Running') {
                throw "Required Windows filtering service $serviceName is not running."
            }
        }
    }
    $profiles = @(Get-ActiveProfiles)
    foreach ($name in @('Domain', 'Private', 'Public')) {
        $profile = $profiles | Where-Object { [string]$_.Name -eq $name } | Select-Object -First 1
        if ($null -eq $profile) {
            throw "The effective Windows Firewall $name profile could not be read from ActiveStore."
        }
        if (-not [bool]$profile.Enabled -or [string]$profile.DefaultOutboundAction -ne $expectedAction) {
            throw "Effective Windows Firewall profile $name does not enforce outbound $expectedAction."
        }
        if ($expectedAction -eq 'Block') {
            $disabledInterfaces = @($profile.DisabledInterfaceAliases | Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_)
            })
            if ($disabledInterfaces.Count -gt 0) {
                $names = ($disabledInterfaces | ForEach-Object { [string]$_ }) -join ', '
                throw "Effective Windows Firewall profile $name excludes interface filtering for: $names."
            }
        }
    }
}
function Get-SnapshotValue($snapshot, [string]$name) {
    if ($snapshot -is [System.Collections.IDictionary]) {
        return $snapshot[$name]
    }
    $property = $snapshot.PSObject.Properties[$name]
    if ($null -eq $property) { return $null }
    return $property.Value
}
function Set-SnapshotValue($snapshot, [string]$name, $value) {
    if ($snapshot -is [System.Collections.IDictionary]) {
        $snapshot[$name] = $value
        return
    }
    $property = $snapshot.PSObject.Properties[$name]
    if ($null -eq $property) {
        $snapshot | Add-Member -NotePropertyName $name -NotePropertyValue $value
    } else {
        $property.Value = $value
    }
}
function Set-SnapshotRulesByInternalIds($ids, $expectedById, [bool]$enabled, [string]$reason) {
    $ruleIds = @($ids | ForEach-Object { [string]$_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    if ($ruleIds.Count -eq 0) {
        return [pscustomobject]@{ Matched = 0; Changed = 0 }
    }

    $before = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $ruleIds -ErrorAction Stop)
    if ($before.Count -ne $ruleIds.Count) {
        throw "Only $($before.Count) of $($ruleIds.Count) firewall rules could be re-read for the $reason fallback."
    }

    $changeIds = [System.Collections.Generic.List[string]]::new()
    foreach ($current in $before) {
        $id = [string]$current.Name
        if (-not $expectedById.ContainsKey($id)) {
            throw "Firewall rule ID $id was not part of the saved snapshot; refusing the $reason fallback."
        }
        $expected = $expectedById[$id]
        $currentEnabled = ([string]$current.Enabled -eq 'True')
        if ([string]$current.Direction -ne 'Outbound' -or
            [string]$current.Action -ne 'Allow' -or
            ($currentEnabled -ne [bool]$expected.Enabled -and $currentEnabled -ne $enabled)) {
            throw "Firewall rule $id changed outside TorProxy before the $reason fallback; refusing to overwrite it."
        }
        if ($currentEnabled -ne $enabled) {
            $changeIds.Add($id)
        }
    }

    if ($changeIds.Count -gt 0) {
        $enabledValue = if ($enabled) { 'True' } else { 'False' }
        Set-NetFirewallRule -PolicyStore PersistentStore -Name ($changeIds.ToArray()) -Enabled $enabledValue -ErrorAction Stop | Out-Null
    }

    $verified = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $ruleIds -ErrorAction Stop)
    if ($verified.Count -ne $ruleIds.Count) {
        throw "Only $($verified.Count) of $($ruleIds.Count) firewall rules were returned during $reason fallback verification."
    }
    foreach ($current in $verified) {
        $id = [string]$current.Name
        if ([string]$current.Direction -ne 'Outbound' -or
            [string]$current.Action -ne 'Allow' -or
            ([string]$current.Enabled -eq 'True') -ne $enabled) {
            throw "Firewall rule $id did not reach the requested Enabled state during $reason fallback."
        }
    }

    return [pscustomobject]@{ Matched = $ruleIds.Count; Changed = $changeIds.Count }
}

function Set-SnapshotLocalRulesEnabled($snapshot, [bool]$enabled) {
    # NetSecurity's Name is the stable policy-store ID (often a GUID), while
    # INetFwRule.Name is only a friendly display name and is not unique.
    # Resolve IDs first; use COM only where the friendly name is unique in the
    # entire effective COM collection. Duplicate names are changed by GUID.
    $names = @($snapshot.disabledRules | ForEach-Object { [string]$_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    if ($names.Count -eq 0) { return }

    $wanted = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $names) { [void]$wanted.Add([string]$name) }

    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $policy = $null
    $rules = $null
    $matched = 0
    $changed = 0
    $missingIds = @()
    try {
        Set-Phase ("Resolving {0} saved firewall IDs in PersistentStore..." -f $names.Count)
        $netRules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $names -ErrorAction Stop)

        $expectedByFriendlyName = @{}
        $expectedById = @{}
        $resolvedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($netRule in $netRules) {
            $ruleId = [string]$netRule.Name
            if (-not $wanted.Contains($ruleId)) { continue }

            if ([string]$netRule.Direction -ne 'Outbound' -or [string]$netRule.Action -ne 'Allow') {
                throw "Saved firewall rule $ruleId no longer matches an outbound Allow rule; refusing to modify it."
            }

            $friendlyName = [string]$netRule.DisplayName
            if ([string]::IsNullOrWhiteSpace($friendlyName)) {
                throw "Saved firewall rule $ruleId has no friendly DisplayName; refusing to guess its COM identity."
            }

            $expected = @{
                InternalName = $ruleId
                FriendlyName = $friendlyName
                Enabled = ([string]$netRule.Enabled -eq 'True')
            }
            if (-not $expectedByFriendlyName.ContainsKey($friendlyName)) {
                $expectedByFriendlyName[$friendlyName] = @()
            }
            $expectedByFriendlyName[$friendlyName] = @($expectedByFriendlyName[$friendlyName]) + @($expected)
            $expectedById[$ruleId] = $expected
            [void]$resolvedIds.Add($ruleId)
        }

        $missingIds = @($names | Where-Object { -not $resolvedIds.Contains([string]$_) })
        if ($expectedById.Count -eq 0) {
            $psExamples = @($netRules | Select-Object -First 6 | ForEach-Object {
                "$([string]$_.Name) => $([string]$_.DisplayName)"
            }) -join ', '
            if (-not $psExamples) { $psExamples = '<no saved IDs resolved in PersistentStore>' }
            throw ("None of the {0} saved internal rule IDs resolved in PersistentStore. PowerShell examples: {1}." -f $names.Count, $psExamples)
        }

        $policy = New-Object -ComObject HNetCfg.FwPolicy2
        $rules = $policy.Rules
        $totalRules = [int]$rules.Count

        # INetFwRules.Item accepts the friendly name. Count those names in the
        # actual COM collection so a same-name rule from another policy source
        # also routes through the unambiguous NetSecurity ID path.
        $comNameCounts = @{}
        $enumerated = 0
        foreach ($candidate in $rules) {
            $candidateName = [string]$candidate.Name
            if (-not [string]::IsNullOrWhiteSpace($candidateName)) {
                if (-not $comNameCounts.ContainsKey($candidateName)) {
                    $comNameCounts[$candidateName] = 0
                }
                $comNameCounts[$candidateName]++
            }
            $enumerated++
            if ([System.Runtime.InteropServices.Marshal]::IsComObject($candidate)) {
                [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($candidate)
            }
        }
        if ($enumerated -ne $totalRules) {
            throw "Windows Firewall COM enumeration returned $enumerated rules but reported $totalRules; refusing an incomplete update."
        }

        $duplicateRuleIds = [System.Collections.Generic.List[string]]::new()
        $uniqueFriendlyNames = [System.Collections.Generic.List[string]]::new()
        foreach ($friendlyName in @($expectedByFriendlyName.Keys)) {
            $entries = @($expectedByFriendlyName[$friendlyName])
            $comCount = if ($comNameCounts.ContainsKey([string]$friendlyName)) { [int]$comNameCounts[[string]$friendlyName] } else { 0 }

            # COM lookup is safe only when the exact friendly name was
            # observed exactly once in the COM collection. Zero matches means
            # the rule is NetSecurity-only (for example, a package/AppContainer
            # rule); more than one means the friendly name is ambiguous.
            if ($entries.Count -gt 1 -or $comCount -ne 1) {
                foreach ($entry in $entries) {
                    $duplicateRuleIds.Add([string]$entry.InternalName)
                }
            } else {
                $uniqueFriendlyNames.Add([string]$friendlyName)
            }
        }

        # Hold collisions for a single exact-GUID NetSecurity batch. Also add
        # any unique friendly name whose COM Item lookup reports FILE_NOT_FOUND.
        $fallbackRuleIds = [System.Collections.Generic.List[string]]::new()
        foreach ($id in $duplicateRuleIds) { $fallbackRuleIds.Add([string]$id) }

        Set-Phase ("Updating {0} uniquely named firewall rules through COM; {1} rules require exact-GUID lookup..." -f $uniqueFriendlyNames.Count, $fallbackRuleIds.Count)
        foreach ($friendlyName in $uniqueFriendlyNames) {
            $expected = @($expectedByFriendlyName[$friendlyName])[0]
            $rule = $null
            try {
                $rule = $rules.Item([string]$friendlyName)
            } catch {
                # Some Windows-owned/package rules are visible through
                # NetSecurity but INetFwRules::Item cannot resolve their name.
                # Fall back only for the documented file-not-found COM result;
                # the subsequent update is scoped to the saved internal GUID.
                $exception = $_.Exception
                $isMissing = $false
                while ($null -ne $exception) {
                    if ([int]$exception.HResult -eq -2147024894) {
                        $isMissing = $true
                        break
                    }
                    $exception = $exception.InnerException
                }
                if (-not $isMissing) { throw }
                $fallbackRuleIds.Add([string]$expected.InternalName)
                continue
            }
            if ($null -eq $rule) {
                $fallbackRuleIds.Add([string]$expected.InternalName)
                continue
            }

            try {
                if ([string]$rule.Name -ine [string]$friendlyName -or
                    [int]$rule.Direction -ne 2 -or [int]$rule.Action -ne 1) {
                    throw "COM rule '$friendlyName' no longer matches saved outbound Allow rule ID $($expected.InternalName)."
                }
                if ([bool]$rule.Enabled -ne [bool]$expected.Enabled) {
                    throw "Saved firewall rule ID $($expected.InternalName) has different Enabled state in NetSecurity and COM; refusing to modify it."
                }

                $matched++
                if ([bool]$rule.Enabled -ne $enabled) {
                    $rule.Enabled = [bool]$enabled
                    if ([bool]$rule.Enabled -ne $enabled) {
                        throw "Outbound firewall rule ID $($expected.InternalName) could not be changed through the Windows Firewall COM API."
                    }
                    $changed++
                }
            } finally {
                if ([System.Runtime.InteropServices.Marshal]::IsComObject($rule)) {
                    [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($rule)
                }
            }
        }

        if ($fallbackRuleIds.Count -gt 0) {
            Set-Phase ("Updating {0} COM-unavailable/ambiguous firewall rules by exact saved GUID..." -f $fallbackRuleIds.Count)
            $fallbackResult = Set-SnapshotRulesByInternalIds ($fallbackRuleIds.ToArray()) $expectedById $enabled 'COM lookup'
            $matched += [int]$fallbackResult.Matched
            $changed += [int]$fallbackResult.Changed
        }

        $timer.Stop()
        Set-Phase ("Windows Firewall updated {0} rules ({1} verified; {2} saved IDs no longer exist) in {3:N1}s." -f $changed, $matched, $missingIds.Count, $timer.Elapsed.TotalSeconds)
    }
    finally {
        if ($null -ne $rules -and [System.Runtime.InteropServices.Marshal]::IsComObject($rules)) {
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($rules)
        }
        if ($null -ne $policy -and [System.Runtime.InteropServices.Marshal]::IsComObject($policy)) {
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($policy)
        }
    }
}function Set-SnapshotProfile($saved) {
    # Set-NetFirewallProfile uses the GpoBoolean enum, not System.Boolean.
    $enabledValue = if ([bool]$saved.Enabled) { 'True' } else { 'False' }
    Set-NetFirewallProfile -PolicyStore PersistentStore -Profile ([string]$saved.Name) -Enabled $enabledValue -DefaultOutboundAction ([string]$saved.DefaultOutboundAction)
}
function Format-FilterValue($value) {
    if ($null -eq $value) { return 'Any' }
    $items = @($value | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($items.Count -eq 0) { return 'Any' }
    $text = $items -join ','
    if ($text.Length -gt 96) { return $text.Substring(0, 93) + '...' }
    return $text
}
function Get-RuleFilter($rule, [string]$cmdletName) {
    try {
        return ($rule | & $cmdletName -ErrorAction Stop | Select-Object -First 1)
    } catch {
        return $null
    }
}
function Test-SharedAccessDynamicAllowRule($rule) {
    if ([string]$rule.PolicyStoreSourceType -ne 'Dynamic' -or
        [string]$rule.Direction -ne 'Outbound' -or
        [string]$rule.Action -ne 'Allow' -or
        [string]$rule.Enabled -ne 'True') {
        return $false
    }
    $application = Get-RuleFilter $rule 'Get-NetFirewallApplicationFilter'
    $service = Get-RuleFilter $rule 'Get-NetFirewallServiceFilter'
    $security = Get-RuleFilter $rule 'Get-NetFirewallSecurityFilter'
    if ($null -eq $application -or $null -eq $service) { return $false }
    # Only treat the dynamic ICS allow as contained when Windows confirms
    # it does not carry the authenticated allow-bypass flag.
    if ($null -eq $security -or [string]$security.OverrideBlockRules -ne 'False') { return $false }
    $programPath = [Environment]::ExpandEnvironmentVariables([string]$application.Program)
    $expectedPath = Join-Path $env:SystemRoot 'System32\svchost.exe'
    try {
        $programPath = [System.IO.Path]::GetFullPath($programPath)
        $expectedPath = [System.IO.Path]::GetFullPath($expectedPath)
    } catch {
        return $false
    }
    $serviceNames = @($service.Service | ForEach-Object { [string]$_ })
    return ($programPath -ieq $expectedPath) -and ($serviceNames -contains 'SharedAccess')
}
function Assert-SharedAccessBlockRule {
    $rule = Get-NetFirewallRule -PolicyStore ActiveStore -Name 'TorProxy_KS_Block_SharedAccess' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $rule -or [string]$rule.Group -ne $Group -or
        [string]$rule.Enabled -ne 'True' -or [string]$rule.Direction -ne 'Outbound' -or
        [string]$rule.Action -ne 'Block') {
        throw 'The TorProxy Internet Connection Sharing block rule is missing or was modified.'
    }
    $application = Get-RuleFilter $rule 'Get-NetFirewallApplicationFilter'
    $service = Get-RuleFilter $rule 'Get-NetFirewallServiceFilter'
    $security = Get-RuleFilter $rule 'Get-NetFirewallSecurityFilter'
    if ($null -eq $application -or $null -eq $service) {
        throw 'The TorProxy Internet Connection Sharing block rule filters cannot be verified.'
    }
    if ($null -eq $security -or [string]$security.OverrideBlockRules -ne 'False') {
        throw 'The TorProxy Internet Connection Sharing block rule cannot verify that authenticated block bypass is disabled.'
    }
    $programPath = [Environment]::ExpandEnvironmentVariables([string]$application.Program)
    $expectedPath = [System.IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'System32\svchost.exe'))
    try { $programPath = [System.IO.Path]::GetFullPath($programPath) } catch {
        throw 'The TorProxy Internet Connection Sharing block rule program path is invalid.'
    }
    $serviceNames = @($service.Service | ForEach-Object { [string]$_ })
    if ($programPath -ine $expectedPath -or $serviceNames -notcontains 'SharedAccess') {
        throw 'The TorProxy Internet Connection Sharing block rule no longer matches only the SharedAccess service.'
    }
}
function Get-UnmanagedRuleDiagnostic($rule) {
    $application = Get-RuleFilter $rule 'Get-NetFirewallApplicationFilter'
    $service = Get-RuleFilter $rule 'Get-NetFirewallServiceFilter'
    $port = Get-RuleFilter $rule 'Get-NetFirewallPortFilter'
    $address = Get-RuleFilter $rule 'Get-NetFirewallAddressFilter'
    $security = Get-RuleFilter $rule 'Get-NetFirewallSecurityFilter'
    $overrideBlockRules = if ($null -ne $security) { [string]$security.OverrideBlockRules } else { 'unavailable' }
    $sourceType = if ([string]$rule.PolicyStoreSourceType) { [string]$rule.PolicyStoreSourceType } else { 'unknown' }
    $source = if ([string]$rule.PolicyStoreSource) { [string]$rule.PolicyStoreSource } else { 'unavailable' }
    $description = if ([string]$rule.Description) { [string]$rule.Description } else { 'none' }
    $program = if ($null -ne $application) { Format-FilterValue $application.Program } else { 'unavailable' }
    $package = if ($null -ne $application) { Format-FilterValue $application.Package } else { 'unavailable' }
    $serviceName = if ($null -ne $service) { Format-FilterValue $service.Service } else { 'unavailable' }
    $protocol = if ($null -ne $port) { Format-FilterValue $port.Protocol } else { 'unavailable' }
    $localPort = if ($null -ne $port) { Format-FilterValue $port.LocalPort } else { 'unavailable' }
    $remotePort = if ($null -ne $port) { Format-FilterValue $port.RemotePort } else { 'unavailable' }
    $localAddress = if ($null -ne $address) { Format-FilterValue $address.LocalAddress } else { 'unavailable' }
    $remoteAddress = if ($null -ne $address) { Format-FilterValue $address.RemoteAddress } else { 'unavailable' }
    $displayName = if ([string]$rule.DisplayName) { [string]$rule.DisplayName } else { 'none' }
    $group = if ([string]$rule.Group) { [string]$rule.Group } else { 'none' }
    $details = "Name=$([string]$rule.Name); DisplayName=$displayName; Group=$group; Description=$description; SourceType=$sourceType; Source=$source; Program=$program; Package=$package; Service=$serviceName; Protocol=$protocol; LocalPort=$localPort; RemotePort=$remotePort; LocalAddress=$localAddress; RemoteAddress=$remoteAddress; OverrideBlockRules=$overrideBlockRules"
    if ($details.Length -gt 620) { return $details.Substring(0, 617) + '...' }
    return $details
}
function Test-TunInterfaceAllowRule {
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name 'TorProxy_KS_TUN' -ErrorAction SilentlyContinue)
    if ($rules.Count -ne 1) { return $false }
    $rule = $rules[0]
    if ([string]$rule.Enabled -ne 'True' -or
        [string]$rule.Direction -ne 'Outbound' -or
        [string]$rule.Action -ne 'Allow') { return $false }
    $filters = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue)
    if ($filters.Count -ne 1) { return $false }
    $aliases = @($filters[0].InterfaceAlias | Where-Object { $_ })
    return ($aliases.Count -eq 1 -and [string]$aliases[0] -eq 'TorProxy')
}
function Assert-ManagedState($snapshot, $requireRules = $true) {
    $profiles = Get-PersistentProfiles
    foreach ($saved in $snapshot.profiles) {
        $current = $profiles | Where-Object { $_.Name -eq $saved.Name } | Select-Object -First 1
        if ($null -eq $current) {
            throw "Firewall profile $($saved.Name) is unavailable."
        }
        $original = ([bool]$current.Enabled -eq [bool]$saved.Enabled) -and
                    ([string]$current.DefaultOutboundAction -eq [string]$saved.DefaultOutboundAction)
        $applied = [bool]$current.Enabled -and [string]$current.DefaultOutboundAction -eq 'Block'
        if (-not $original -and -not $applied) {
            throw "Firewall profile $($saved.Name) changed outside TorProxy. Refusing to overwrite the external change."
        }
        if ($requireRules -and -not $applied) {
            throw "Firewall profile $($saved.Name) is not enabled with outbound Block; protection is not active."
        }
    }
    if ($requireRules) {
        Assert-EffectiveOutboundAction 'Block'
        $groupRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group $Group -ErrorAction SilentlyContinue)
        if ($groupRules.Count -lt 1) {
            throw 'TorProxy firewall rules are missing. The saved snapshot was retained for manual recovery.'
        }
        if ([bool](Get-SnapshotValue $snapshot 'blockSharedAccess')) {
            Assert-SharedAccessBlockRule
        }
    }
}
try {
    Set-Phase 'Loading the firewall action request...'
    $request = Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
    # The new WFP activation/status path does not depend on NetSecurity.
    # Load the legacy module only for existing snapshot restoration or
    # emergency reconciliation of a previous TorProxy version.
    if (($Action -eq 'recover' -or $Action -eq 'deactivate' -or $Action -eq 'emergency') -or
        (Test-Path -LiteralPath $SnapshotPath)) {
        Set-Phase 'Loading legacy Windows Firewall recovery module...'
        Import-Module NetSecurity -ErrorAction Stop
        if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
            throw 'The Windows NetSecurity PowerShell module is unavailable for legacy snapshot recovery.'
        }
    }
    function Invoke-WfpHelper([string]$nativeAction, [string[]]$nativeArguments = @()) {
        $helperPath = [string]$request.wfp_helper_path
        if ([string]::IsNullOrWhiteSpace($helperPath) -or
            -not [System.IO.File]::Exists($helperPath)) {
            throw 'The native TorProxyWfpHelper.exe is missing. Reinstall the current Windows package; the legacy per-rule firewall updater is intentionally disabled.'
        }
        $arguments = @($nativeAction) + @($nativeArguments)
        $output = @(& $helperPath @arguments 2>&1)
        $exitCode = $LASTEXITCODE
        $detail = ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
        if ($exitCode -ne 0) {
            throw "Native Windows Filtering Platform helper failed (exit code $exitCode): $detail"
        }
        return $detail.Trim()
    }

    # New activations use one persistent WFP transaction. They do not change
    # existing Windows Firewall rules or profile defaults.
    if ($Action -eq 'activate') {
        if (Test-Path -LiteralPath $SnapshotPath) {
            throw 'A legacy Windows Firewall snapshot still exists. Run Restore saved firewall once before enabling the WFP kill switch.'
        }
        $programs = @($request.programs)
        if ($programs.Count -lt 1) { throw 'At least one Tor executable must be allowlisted.' }
        foreach ($program in $programs) {
            if (-not [System.IO.File]::Exists([string]$program)) { throw "Allowed executable does not exist: $program" }
        }
        Set-Phase 'Installing persistent IPv4/IPv6 WFP filters in one transaction...'
        $detail = Invoke-WfpHelper 'activate' $programs
        Set-Phase 'Persistent WFP filter set committed and verified.'
        Write-Result @{ ok = $true; active = $true; verified = $true; backend = 'WFP'; detail = $detail }
        return
    }

    if ($Action -eq 'recover' -or $Action -eq 'deactivate' -or $Action -eq 'emergency') {
        Set-Phase 'Removing TorProxy-owned persistent WFP filters in one transaction...'
        $wfpRecovery = Invoke-WfpHelper 'recover'
    }

    # A WFP-only activation never edits the Windows Firewall profiles or
    # creates a legacy snapshot. Do not "restore" unrelated pre-existing
    # Block defaults just because the WFP snapshot file is absent.
    if (($Action -eq 'recover' -or $Action -eq 'deactivate') -and
        -not (Test-Path -LiteralPath $SnapshotPath)) {
        $legacyRules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Group $Group -ErrorAction SilentlyContinue)
        if ($legacyRules.Count -eq 0) {
            Write-Result @{ ok = $true; active = $false; verified = $true; backend = 'WFP'; detail = $wfpRecovery }
            return
        }
    }

    if ($Action -eq 'status' -and -not (Test-Path -LiteralPath $SnapshotPath)) {
        $detail = Invoke-WfpHelper 'status'
        $active = $detail.StartsWith('ACTIVE', [System.StringComparison]::OrdinalIgnoreCase)
        $verified = $active -or $detail.StartsWith('INACTIVE', [System.StringComparison]::OrdinalIgnoreCase)
        Write-Result @{ ok = $true; active = $active; verified = $verified; backend = 'WFP'; detail = $detail }
        return
    }

    if ($Action -eq 'deactivate') {
        Set-Phase 'Restoring the saved Windows Firewall configuration...'
        if (-not (Test-Path -LiteralPath $SnapshotPath)) {
            $orphanedGroup = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group $Group -ErrorAction SilentlyContinue)
            if ($orphanedGroup.Count -gt 0) {
                throw 'TorProxy firewall rules exist but the original snapshot is missing. Refusing to guess the original firewall policy; manual recovery is required.'
            }
            Write-Result @{ ok = $true; active = $false; detail = 'No TorProxy firewall snapshot or managed rules exist.' }
        } else {
            $snapshot = Get-Content -LiteralPath $SnapshotPath -Raw | ConvertFrom-Json
            Assert-ManagedState $snapshot $false
            Get-NetFirewallRule -PolicyStore PersistentStore -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule

            $currentProfiles = Get-PersistentProfiles
            foreach ($saved in $snapshot.profiles) {
                $current = $currentProfiles | Where-Object { $_.Name -eq $saved.Name } | Select-Object -First 1
                if ($null -ne $current -and [bool]$current.Enabled -and [string]$current.DefaultOutboundAction -eq 'Block') {
                    Set-SnapshotProfile $saved
                }
            }
            Set-Phase 'Restoring saved local outbound Allow rules through COM...'
            Set-SnapshotLocalRulesEnabled $snapshot $true
            $restoredProfiles = Get-PersistentProfiles
            foreach ($saved in $snapshot.profiles) {
                $current = $restoredProfiles | Where-Object { $_.Name -eq $saved.Name } | Select-Object -First 1
                if ($null -eq $current -or [bool]$current.Enabled -ne [bool]$saved.Enabled -or
                    [string]$current.DefaultOutboundAction -ne [string]$saved.DefaultOutboundAction) {
                    throw "Windows Firewall profile $($saved.Name) could not be restored to its saved state."
                }
            }

            Remove-Item -LiteralPath $SnapshotPath -Force
            Write-Result @{ ok = $true; active = $false; detail = 'TorProxy rules removed and the saved firewall policy restored and verified.' }
        }
    }
    elseif ($Action -eq 'recover') {
        Set-Phase 'Reconciling the saved Windows Firewall snapshot...'
        if (-not (Test-Path -LiteralPath $SnapshotPath)) {
            $orphanedRules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Group $Group -ErrorAction SilentlyContinue)
            if ($orphanedRules.Count -gt 0) {
                throw 'TorProxy firewall rules exist but the saved snapshot is missing. Use emergency recovery to restore outbound access.'
            }
            $currentProfiles = Get-PersistentProfiles
            $stillBlocked = @($currentProfiles | Where-Object { [string]$_.DefaultOutboundAction -eq 'Block' })
            if ($stillBlocked.Count -gt 0) {
                throw 'No saved snapshot exists and outbound traffic is still blocked. Use emergency recovery to restore normal outbound access.'
            }
            Write-Result @{ ok = $true; active = $false; mode = 'already-restored'; detail = 'No TorProxy rules or restrictive outbound profile settings remain; recovery is already complete.' }
        } else {
            $snapshot = Get-Content -LiteralPath $SnapshotPath -Raw | ConvertFrom-Json
            if (@($snapshot.profiles).Count -lt 1 -or [string]$snapshot.group -ne $Group) {
                throw 'The saved TorProxy firewall snapshot is invalid; no firewall changes were made.'
            }

            # Preserve externally changed profile settings while restoring only
            # profiles which still match the exact restrictive state TorProxy applied.
            $currentProfiles = Get-PersistentProfiles
            $preservedProfiles = @{}
            $preservedNames = @()
            foreach ($saved in $snapshot.profiles) {
                $current = $currentProfiles | Where-Object { $_.Name -eq $saved.Name } | Select-Object -First 1
                if ($null -eq $current) {
                    throw "Firewall profile $($saved.Name) is unavailable; recovery cannot be verified."
                }
                $original = ([bool]$current.Enabled -eq [bool]$saved.Enabled) -and ([string]$current.DefaultOutboundAction -eq [string]$saved.DefaultOutboundAction)
                $applied = [bool]$current.Enabled -and [string]$current.DefaultOutboundAction -eq 'Block'
                if ($original) { continue }
                if ($applied) {
                    Set-SnapshotProfile $saved
                } else {
                    $name = [string]$saved.Name
                    $preservedProfiles[$name] = @{
                        Enabled = [bool]$current.Enabled
                        DefaultOutboundAction = [string]$current.DefaultOutboundAction
                    }
                    $preservedNames += $name
                }
            }

            # Delete only TorProxy-owned persistent rules and re-enable only
            # the local rules recorded as enabled in the original snapshot.
            Get-NetFirewallRule -PolicyStore PersistentStore -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
            Set-Phase 'Restoring saved local outbound Allow rules in one batch...'
            Set-SnapshotLocalRulesEnabled $snapshot $true

            $restoredProfiles = Get-PersistentProfiles
            foreach ($saved in $snapshot.profiles) {
                $name = [string]$saved.Name
                $current = $restoredProfiles | Where-Object { $_.Name -eq $name } | Select-Object -First 1
                if ($null -eq $current) {
                    throw "Firewall profile $name disappeared during recovery."
                }
                if ($preservedProfiles.ContainsKey($name)) {
                    $expected = $preservedProfiles[$name]
                    if ([bool]$current.Enabled -ne [bool]$expected.Enabled -or [string]$current.DefaultOutboundAction -ne [string]$expected.DefaultOutboundAction) {
                        throw "Externally changed firewall profile $name was modified during recovery."
                    }
                } elseif ([bool]$current.Enabled -ne [bool]$saved.Enabled -or [string]$current.DefaultOutboundAction -ne [string]$saved.DefaultOutboundAction) {
                    throw "Firewall profile $name could not be restored to its saved state."
                }
            }


            $archivePath = $SnapshotPath + '.recovered'
            if (Test-Path -LiteralPath $archivePath) {
                $archivePath = $SnapshotPath + '.recovered.' + [guid]::NewGuid().ToString('N')
            }
            Move-Item -LiteralPath $SnapshotPath -Destination $archivePath -Force
            $detail = 'TorProxy rules were removed; managed profile changes and saved local rules were restored and verified.'
            if ($preservedNames.Count -gt 0) {
                $detail += ' Externally changed profile settings were preserved: ' + ($preservedNames -join ', ') + '.'
            }
            Write-Result @{ ok = $true; active = $false; mode = 'snapshot'; detail = $detail }
        }
    }
    elseif ($Action -eq 'emergency') {
        Set-Phase 'Restoring normal outbound access while keeping Windows Firewall enabled...'
        # Explicit user-requested fallback. Keep Windows Firewall enabled and
        # restore ordinary outbound access without resetting unrelated rules.
        Set-NetFirewallProfile -PolicyStore PersistentStore -Profile Domain,Private,Public -Enabled True -DefaultOutboundAction Allow
        Assert-EffectiveOutboundAction 'Allow'
        Get-NetFirewallRule -PolicyStore PersistentStore -Group $Group -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction Stop

        if (Test-Path -LiteralPath $SnapshotPath) {
            $archivePath = $SnapshotPath + '.emergency-recovered'
            if (Test-Path -LiteralPath $archivePath) {
                $archivePath = $SnapshotPath + '.emergency-recovered.' + [guid]::NewGuid().ToString('N')
            }
            Move-Item -LiteralPath $SnapshotPath -Destination $archivePath -Force
        }
        Write-Result @{ ok = $true; active = $false; mode = 'emergency'; detail = 'Emergency recovery restored outbound Allow on all profiles, kept Windows Firewall enabled, and removed only TorProxy-owned rules. The previous snapshot was preserved when present.' }
    }
    elseif ($Action -eq 'status') {
        Set-Phase 'Verifying current Windows Firewall protection status...'
        if (-not (Test-Path -LiteralPath $SnapshotPath)) {
            $orphanedGroup = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group $Group -ErrorAction SilentlyContinue)
            $orphaned = $orphanedGroup.Count -gt 0
            Write-Result @{ ok = $true; active = $false; verified = (-not $orphaned); tun_interface_allowed = $false; detail = $(if ($orphaned) { 'TorProxy rules exist without the original snapshot; manual recovery is required.' } else { 'No saved Kill Switch policy.' }) }
        } else {
            $snapshot = Get-Content -LiteralPath $SnapshotPath -Raw | ConvertFrom-Json
            Assert-ManagedState $snapshot
            $remaining = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -Direction Outbound -Action Allow -Enabled True -ErrorAction Stop | Where-Object {
                if ([string]$_.Group -eq $Group) { return $false }
                if ([bool](Get-SnapshotValue $snapshot 'blockSharedAccess') -and (Test-SharedAccessDynamicAllowRule $_)) { return $false }
                return $true
            })
            $verified = $remaining.Count -eq 0
            $tunAllowed = Test-TunInterfaceAllowRule
            Write-Result @{ ok = $true; active = $verified; verified = $verified; tun_interface_allowed = $tunAllowed; detail = 'Windows Firewall policy inspected.' }
        }
    }
    else {
        throw 'Unsupported firewall action.'
    }
}
catch {
    Write-Result @{ ok = $false; error = [string]$_.Exception.Message }
    exit 1
}
"""


def _run_elevated(script_path: Path, action: str, snapshot_path: Path,
                  request_path: Path, result_path: Path) -> int:
    """Run a fixed, locally written PowerShell script through the standard UAC prompt."""
    if os.name != "nt":
        raise KillSwitchError("The Windows firewall backend is available only on Windows.")
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR),
            ("hkeyClass", wintypes.HANDLE), ("dwHotKey", wintypes.DWORD),
            ("hIcon", wintypes.HANDLE), ("hProcess", wintypes.HANDLE),
        ]

    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        raise KillSwitchError("Windows PowerShell is required for Defender Firewall integration.")
    args = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(script_path), "-Action", action,
            "-SnapshotPath", str(snapshot_path), "-RequestPath", str(request_path),
            "-ResultPath", str(result_path)]
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = powershell
    info.lpParameters = subprocess.list2cmdline(args)
    info.nShow = 0
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):
        error = ctypes.get_last_error()
        if error == 1223:
            raise KillSwitchError("Administrator approval was cancelled; no firewall change was confirmed.")
        raise KillSwitchError(f"Windows could not request administrator privileges (error {error}).")
    # Declare native signatures explicitly: HANDLE is pointer-sized on 64-bit Windows.
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    try:
        wait_result = kernel32.WaitForSingleObject(info.hProcess, ELEVATED_HELPER_TIMEOUT_MS)
        if wait_result == 0x00000102:  # WAIT_TIMEOUT
            progress_path = Path(str(result_path) + ".progress")
            try:
                last_phase = progress_path.read_text(encoding="utf-8").strip()
            except OSError:
                last_phase = "The helper did not report its current stage."
            phase_detail = f" Last reported step: {last_phase}" if last_phase else ""
            if not kernel32.TerminateProcess(info.hProcess, 1):
                error = ctypes.get_last_error()
                raise KillSwitchError(
                    f"The elevated firewall operation exceeded {ELEVATED_HELPER_TIMEOUT_MS // 1000} seconds."
                    f"{phase_detail} Windows could not stop the helper process (error {error}). "
                    "Use Emergency network recovery."
                )
            kernel32.WaitForSingleObject(info.hProcess, 5000)
            raise KillSwitchError(
                f"The elevated firewall operation exceeded {ELEVATED_HELPER_TIMEOUT_MS // 1000} seconds."
                f"{phase_detail} The helper was terminated; use Restore saved firewall or "
                "Emergency network recovery to reconcile any partial changes."
            )
        if wait_result == 0xFFFFFFFF:  # WAIT_FAILED
            error = ctypes.get_last_error()
            raise KillSwitchError(f"Waiting for the elevated firewall helper failed (Windows error {error}).")
        if wait_result != 0:  # WAIT_OBJECT_0
            raise KillSwitchError(f"Unexpected Windows wait result: {wait_result}.")
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(exit_code)):
            error = ctypes.get_last_error()
            raise KillSwitchError(f"Windows could not read the elevated helper exit code (error {error}).")
        return int(exit_code.value)
    finally:
        kernel32.CloseHandle(info.hProcess)


class WindowsFirewallBackend:
    """Use persistent WFP filters without editing user-owned firewall rules."""

    def __init__(
        self,
        *,
        state_dir: Path | None = None,
        runner=_run_elevated,
        wfp_helper_path: Path | None = None,
    ):
        self.state_dir = Path(state_dir or (user_directories().state / "killswitch"))
        self.snapshot_path = self.state_dir / SNAPSHOT_NAME
        self._runner = runner
        self.wfp_helper_path = Path(wfp_helper_path) if wfp_helper_path else _find_wfp_helper()

    def _invoke(self, action: str, programs: tuple[str, ...] = ()) -> dict[str, object]:
        if self._runner is _run_elevated and self.wfp_helper_path is None:
            raise KillSwitchError(
                "TorProxyWfpHelper.exe is missing. Install the current Windows package "
                "or build launcher/src/wfp_helper.cpp with CMake; the slow per-rule "
                "firewall updater is no longer used."
            )
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="torproxy-killswitch-") as temporary:
            root = Path(temporary)
            script = root / "firewall.ps1"
            request = root / "request.json"
            result = root / "result.json"
            script.write_text(_POWERSHELL, encoding="utf-8")
            request.write_text(
                json.dumps(
                    {
                        "programs": list(programs),
                        "wfp_helper_path": str(self.wfp_helper_path) if self.wfp_helper_path else "",
                    }
                ),
                encoding="utf-8",
            )
            exit_code = self._runner(script, action, self.snapshot_path, request, result)
            if not result.is_file():
                raise KillSwitchError("The elevated firewall helper did not write a result; its state is unknown.")
            try:
                payload = json.loads(result.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise KillSwitchError("The elevated firewall helper returned malformed status data.") from exc
            if exit_code != 0 or not payload.get("ok"):
                raise KillSwitchError(str(payload.get("error") or f"Windows firewall operation failed ({exit_code})."))
            return payload

    def activate(self, programs: tuple[str, ...]) -> None:
        self._invoke("activate", programs)

    def deactivate(self) -> dict[str, object]:
        # Normal disable and explicit recovery share the tolerant restore path.
        # Externally changed firewall profiles are preserved rather than making
        # the user unable to disable protection after a Windows policy update.
        return self._invoke("recover")

    def recover(self) -> dict[str, object]:
        """Restore the saved pre-Kill-Switch firewall state, including partial installs."""
        return self._invoke("recover")

    def emergency_recover(self) -> dict[str, object]:
        """Restore ordinary outbound access while keeping Defender Firewall enabled."""
        return self._invoke("emergency")

    def recovery_state(self) -> dict[str, object]:
        """Inspect the local snapshot without requiring UAC or querying firewall policy."""
        return {
            "available": True,
            "snapshot_exists": self.snapshot_path.is_file(),
            "verified": False,
        }

    def status(self) -> dict[str, object]:
        try:
            return self._invoke("status")
        except KillSwitchError as exc:
            return {"active": False, "verified": False, "detail": str(exc)}
