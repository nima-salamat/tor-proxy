"""Windows Defender Firewall backend with reversible outbound-policy changes."""
from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..killswitch import KillSwitchError
from ..paths import user_directories

GROUP = "TorProxy Kill Switch"
SNAPSHOT_NAME = "windows-firewall-snapshot.json"

_POWERSHELL = r"""
param(
    [Parameter(Mandatory=$true)][string]$Action,
    [Parameter(Mandatory=$true)][string]$SnapshotPath,
    [Parameter(Mandatory=$true)][string]$RequestPath,
    [Parameter(Mandatory=$true)][string]$ResultPath
)
$ErrorActionPreference = 'Stop'
$Group = 'TorProxy Kill Switch'
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
    if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        throw 'The Windows NetSecurity PowerShell module is unavailable.'
    }
    $request = Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
    if ($Action -eq 'activate') {
        $programs = @($request.programs)
        if ($programs.Count -lt 1) { throw 'At least one Tor executable must be allowlisted.' }
        foreach ($program in $programs) {
            if (-not [System.IO.File]::Exists([string]$program)) { throw "Allowed executable does not exist: $program" }
        }

        if (Test-Path -LiteralPath $SnapshotPath) {
            $snapshot = Get-Content -LiteralPath $SnapshotPath -Raw | ConvertFrom-Json
            Assert-ManagedState $snapshot $false
        } else {
            $orphanedGroup = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group $Group -ErrorAction SilentlyContinue)
            if ($orphanedGroup.Count -gt 0) {
                throw 'TorProxy firewall rules exist but the original snapshot is missing. Refusing to guess the original firewall policy; manual recovery is required.'
            }
            $profiles = Get-PersistentProfiles
            $activeAllow = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue)
            $gpoRules = @($activeAllow | Where-Object { [string]$_.PolicyStoreSourceType -eq 'GroupPolicy' })
            if ($gpoRules.Count -gt 0) {
                $gpoDetails = @($gpoRules | Select-Object -First 8 | ForEach-Object {
                    "$([string]$_.Name) [$([string]$_.PolicyStoreSource)]"
                }) -join '; '
                throw "Enabled outbound Allow rules are enforced by Group Policy and cannot be safely disabled: $gpoDetails"
            }
            $sharedAccessRules = @($activeAllow | Where-Object { Test-SharedAccessDynamicAllowRule $_ })
            $localAllow = @(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue)
            $localNames = @($localAllow | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
            $localSet = @{}
            foreach ($name in $localNames) { $localSet[$name] = $true }
            $unmanaged = @($activeAllow | Where-Object {
                ([string]$_.PolicyStoreSourceType -ne 'Local' -or
                 -not $localSet.ContainsKey([string]$_.Name)) -and
                [string]$_.Group -ne $Group -and
                -not (Test-SharedAccessDynamicAllowRule $_)
            })
            if ($unmanaged.Count -gt 0) {
                $details = @($unmanaged | Select-Object -First 4 | ForEach-Object {
                    Get-UnmanagedRuleDiagnostic $_
                }) -join ' || '
                throw "Enabled outbound Allow rules outside the local firewall store cannot be safely disabled. Rule filters are included to identify their owner and scope: $details"
            }
            $snapshot = [ordered]@{
                version = 1
                profiles = @($profiles | ForEach-Object {
                    [ordered]@{
                        Name = [string]$_.Name
                        Enabled = [bool]$_.Enabled
                        DefaultOutboundAction = [string]$_.DefaultOutboundAction
                    }
                })
                disabledRules = @($localNames)
                blockSharedAccess = ($sharedAccessRules.Count -gt 0)
                sharedAccessProgram = (Join-Path $env:SystemRoot 'System32\svchost.exe')
                applied = [ordered]@{ Enabled = $true; DefaultOutboundAction = 'Block' }
                group = $Group
            }
            Save-Snapshot $snapshot
        }

        # A dynamic ICS allow rule is tied to svchost.exe/SharedAccess. Keep
        # that source rule intact, but override it with a TorProxy-owned
        # explicit Block rule while the Kill Switch is active.
        $latestActiveAllow = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue)
        $latestSharedAccessRules = @($latestActiveAllow | Where-Object { Test-SharedAccessDynamicAllowRule $_ })
        if ($latestSharedAccessRules.Count -gt 0) {
            Set-SnapshotValue $snapshot 'blockSharedAccess' $true
            Set-SnapshotValue $snapshot 'sharedAccessProgram' (Join-Path $env:SystemRoot 'System32\svchost.exe')
            Save-Snapshot $snapshot
        } elseif ($null -eq (Get-SnapshotValue $snapshot 'blockSharedAccess')) {
            Set-SnapshotValue $snapshot 'blockSharedAccess' $false
            Set-SnapshotValue $snapshot 'sharedAccessProgram' (Join-Path $env:SystemRoot 'System32\svchost.exe')
            Save-Snapshot $snapshot
        }

        # Apply the restrictive default before removing old exceptions.
        Set-NetFirewallProfile -PolicyStore PersistentStore -Profile Domain,Private,Public -Enabled True -DefaultOutboundAction Block
        foreach ($name in @($snapshot.disabledRules)) {
            Set-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name) -Enabled False
        }
        Get-NetFirewallRule -PolicyStore PersistentStore -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule

        $i = 0
        foreach ($program in $programs) {
            $i++
            New-NetFirewallRule -PolicyStore PersistentStore -Name ("TorProxy_KS_Tor_" + $i) -DisplayName ("TorProxy Kill Switch Tor " + $i) -Group $Group -Direction Outbound -Action Allow -Program ([string]$program) -Profile Any -Enabled True | Out-Null
        }
        New-NetFirewallRule -PolicyStore PersistentStore -Name 'TorProxy_KS_DHCPv4' -DisplayName 'TorProxy Kill Switch DHCPv4' -Group $Group -Direction Outbound -Action Allow -Protocol UDP -LocalPort 68 -RemotePort 67 -RemoteAddress Any -Profile Any | Out-Null
        New-NetFirewallRule -PolicyStore PersistentStore -Name 'TorProxy_KS_DHCPv6' -DisplayName 'TorProxy Kill Switch DHCPv6' -Group $Group -Direction Outbound -Action Allow -Protocol UDP -LocalPort 546 -RemotePort 547 -RemoteAddress Any -Profile Any | Out-Null
        New-NetFirewallRule -PolicyStore PersistentStore -Name 'TorProxy_KS_NDP' -DisplayName 'TorProxy Kill Switch IPv6 Neighbor Discovery' -Group $Group -Direction Outbound -Action Allow -Protocol ICMPv6 -IcmpType 133,135,136 -RemoteAddress Any -Profile Any | Out-Null
        # Only system traffic already routed to the exact TorProxy TUN adapter
        # may leave that virtual interface. Physical NICs remain default-deny.
        New-NetFirewallRule -PolicyStore PersistentStore -Name 'TorProxy_KS_TUN' -DisplayName 'TorProxy Kill Switch System Tunnel' -Group $Group -Direction Outbound -Action Allow -InterfaceAlias 'TorProxy' -Profile Any -Enabled True | Out-Null
        if (-not (Test-TunInterfaceAllowRule)) { throw 'The dedicated TorProxy TUN firewall exception could not be verified.' }
        if ([bool](Get-SnapshotValue $snapshot 'blockSharedAccess')) {
            $sharedAccessProgram = [string](Get-SnapshotValue $snapshot 'sharedAccessProgram')
            if (-not $sharedAccessProgram) {
                $sharedAccessProgram = Join-Path $env:SystemRoot 'System32\svchost.exe'
            }
            New-NetFirewallRule -PolicyStore PersistentStore -Name 'TorProxy_KS_Block_SharedAccess' -DisplayName 'TorProxy Kill Switch Block Internet Connection Sharing' -Group $Group -Direction Outbound -Action Block -Program $sharedAccessProgram -Service SharedAccess -OverrideBlockRules $false -Profile Any -Enabled True | Out-Null
            Assert-SharedAccessBlockRule
        }

        Assert-EffectiveOutboundAction 'Block'
        $remaining = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -Direction Outbound -Action Allow -Enabled True | Where-Object {
            if ([string]$_.Group -eq $Group) { return $false }
            if ([bool](Get-SnapshotValue $snapshot 'blockSharedAccess') -and (Test-SharedAccessDynamicAllowRule $_)) { return $false }
            return $true
        })
        if ($remaining.Count -gt 0) {
            $details = @($remaining | Select-Object -First 4 | ForEach-Object { Get-UnmanagedRuleDiagnostic $_ }) -join ' || '
            throw "Unmanaged outbound Allow rules remain active; strict Kill Switch verification failed: $details"
        }
        if ([bool](Get-SnapshotValue $snapshot 'blockSharedAccess')) {
            Assert-SharedAccessBlockRule
        }
        Write-Result @{ ok = $true; active = $true; tun_interface_allowed = (Test-TunInterfaceAllowRule); detail = 'Outbound default block verified; TorProxy exceptions, the dedicated TUN interface, and the SharedAccess deny override are active.' }
    }
    elseif ($Action -eq 'deactivate') {
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
                    Set-NetFirewallProfile -PolicyStore PersistentStore -Profile ([string]$saved.Name) -Enabled ([bool]$saved.Enabled) -DefaultOutboundAction ([string]$saved.DefaultOutboundAction)
                }
            }
            foreach ($name in @($snapshot.disabledRules)) {
                $rule = Get-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name) -ErrorAction SilentlyContinue
                if ($null -ne $rule -and [string]$rule.Enabled -eq 'False') {
                    Set-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name) -Enabled True
                }
            }
            $restoredProfiles = Get-PersistentProfiles
            foreach ($saved in $snapshot.profiles) {
                $current = $restoredProfiles | Where-Object { $_.Name -eq $saved.Name } | Select-Object -First 1
                if ($null -eq $current -or [bool]$current.Enabled -ne [bool]$saved.Enabled -or
                    [string]$current.DefaultOutboundAction -ne [string]$saved.DefaultOutboundAction) {
                    throw "Windows Firewall profile $($saved.Name) could not be restored to its saved state."
                }
            }
            foreach ($name in @($snapshot.disabledRules)) {
                $rule = Get-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name) -ErrorAction SilentlyContinue
                if ($null -ne $rule -and [string]$rule.Enabled -ne 'True') {
                    throw "Outbound firewall rule $name could not be restored to its saved enabled state."
                }
            }
            Remove-Item -LiteralPath $SnapshotPath -Force
            Write-Result @{ ok = $true; active = $false; detail = 'TorProxy rules removed and the saved firewall policy restored and verified.' }
        }
    }
    elseif ($Action -eq 'recover') {
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
                    Set-NetFirewallProfile -PolicyStore PersistentStore -Profile ([string]$saved.Name) -Enabled ([bool]$saved.Enabled) -DefaultOutboundAction ([string]$saved.DefaultOutboundAction)
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
            foreach ($name in @($snapshot.disabledRules)) {
                $rule = Get-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name) -ErrorAction SilentlyContinue
                if ($null -ne $rule -and [string]$rule.Enabled -ne 'True') {
                    Set-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name) -Enabled True
                }
            }

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
            foreach ($name in @($snapshot.disabledRules)) {
                $rule = Get-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name) -ErrorAction SilentlyContinue
                if ($null -ne $rule -and [string]$rule.Enabled -ne 'True') {
                    throw "Firewall rule $name could not be restored to its saved enabled state."
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
        if (-not (Test-Path -LiteralPath $SnapshotPath)) {
            $orphanedGroup = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group $Group -ErrorAction SilentlyContinue)
            $orphaned = $orphanedGroup.Count -gt 0
            Write-Result @{ ok = $true; active = $false; verified = (-not $orphaned); tun_interface_allowed = $false; detail = $(if ($orphaned) { 'TorProxy rules exist without the original snapshot; manual recovery is required.' } else { 'No saved Kill Switch policy.' }) }
        } else {
            $snapshot = Get-Content -LiteralPath $SnapshotPath -Raw | ConvertFrom-Json
            Assert-ManagedState $snapshot
            $remaining = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -Direction Outbound -Action Allow -Enabled True | Where-Object {
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
        wait_result = kernel32.WaitForSingleObject(info.hProcess, 60000)
        if wait_result == 0x00000102:  # WAIT_TIMEOUT
            if not kernel32.TerminateProcess(info.hProcess, 1):
                error = ctypes.get_last_error()
                raise KillSwitchError(
                    "The elevated firewall operation exceeded 60 seconds and Windows could not stop "
                    f"the helper process (error {error}). Use Emergency network recovery."
                )
            kernel32.WaitForSingleObject(info.hProcess, 5000)
            raise KillSwitchError(
                "The elevated firewall operation exceeded 60 seconds. The helper was terminated; "
                "use Restore saved firewall or Emergency network recovery to reconcile any partial changes."
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
    """Use Defender Firewall's default-block policy with exact Tor exceptions."""

    def __init__(self, *, state_dir: Path | None = None, runner=_run_elevated):
        self.state_dir = Path(state_dir or (user_directories().state / "killswitch"))
        self.snapshot_path = self.state_dir / SNAPSHOT_NAME
        self._runner = runner

    def _invoke(self, action: str, programs: tuple[str, ...] = ()) -> dict[str, object]:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="torproxy-killswitch-") as temporary:
            root = Path(temporary)
            script = root / "firewall.ps1"
            request = root / "request.json"
            result = root / "result.json"
            script.write_text(_POWERSHELL, encoding="utf-8")
            request.write_text(json.dumps({"programs": list(programs)}), encoding="utf-8")
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
