# Troubleshooting

## Tor does not start

1. Confirm the selected Tor executable exists and is executable.
2. If using the updater, ensure archive download and safe extraction completed. If OpenPGP is enabled in Settings → Advanced, confirm the signature verification stage also succeeded. The installed list distinguishes `SIGNED` from `HTTPS ONLY · UNSIGNED`.
3. Inspect `torproxy.log` and `tor.log` under the user's application state directory. Logs may contain local host names; handle them as private user data.
4. The app validates torrc before launch. Invalid directives, duplicate ports, missing bridge transport binaries, or invalid bridge records should fail early.
5. Check that another application is not occupying configured listener ports. TorProxy does not kill unrelated Tor processes.

## Check Exit IP closes the application or returns an error

Exit-IP verification is sent through TorProxy's explicit local HTTP proxy; it never falls back to a direct internet request. Check the Event Log and the per-user log directory for `torproxy.log`. If the process exits without a Python traceback, inspect `torproxy-crash.log`, which captures Python's native-fault traceback when available. The IP checker needs a verified Tor connection and a working exit circuit; a failed endpoint or blocked API should be shown as a check failure, not interpreted as a disconnected bridge.

## Custom WebTunnel SNI imitation

By default, SNI imitation is disabled and Lyrebird uses the original hostname from the bridge's `url=`. To try an override, go to **Settings → Bridges**, select a suggested hostname or enter a DNS hostname, then reconnect. TorProxy adds `sni-imitation=<hostname>` only to WebTunnel records. The bridge URL, including its original path, remains unchanged. Support depends on the selected Lyrebird build and bridge configuration; not all bridges support it. To undo it, select **Use the hostname in url= (default; no override)** and reconnect.

## Lyrebird reports `CurvePreferences includes unsupported curve`

This message is a local pluggable-transport/runtime compatibility error, not proof that the remote bridge is dead. TorProxy preserves bridge records when isolated checks hit this error and does not use it as a reason to delete nodes. If a direct (non-pluggable-transport) bridge is configured, TorProxy allows it to continue bootstrapping instead of aborting on one Lyrebird TLS warning. If every configured bridge uses Lyrebird, startup reports the incompatibility rather than wasting time deleting the list.

Check which Tor Expert Bundle is selected in Bundles. The `16.0a14` line is an alpha prerelease; try a verified stable Tor Expert Bundle in the updater and repeat the connection test. The updater should select the exact Windows architecture and keep its normal integrity/signature checks. Do not copy `lyrebird.exe` from an unknown source or treat this error as evidence that the bridge endpoints themselves are all offline.

## Tor rejects a bridge fingerprint or says its key digest has the wrong length

Tor bridge lines may contain a 40-character hexadecimal identity fingerprint. For WebTunnel and obfs4, the fingerprint is a bare token after the endpoint; some Snowflake lines also include a `fingerprint=...` transport option. Do not use a nickname, partial fingerprint, or the hashed fingerprint shown in Tor Relay Search in place of the bridge fingerprint. Copy the full bridge line from the Tor Project bridge source. TorProxy now rejects malformed fingerprints before launching Tor, can normalize fingerprints that are split into whitespace-separated hex groups, and reports item-specific reasons in Settings. If Tor still rejects the list, the error includes a secret-safe summary of token lengths and option names; it never prints bridge addresses, fingerprints, or WebTunnel secret paths in that summary.

## Bootstrap stays at 0% or appears frozen

Open **Event Log → Live Tor log** to see the actual `tor.log` file while Tor is running. This view follows new file writes, colors Tor notice/warning/error lines, caps the visible buffer, and can load older entries in pages. The progress indicator now also reads Tor's `Bootstrapped N%` log notices if the ControlPort status is not yet available. A reported 100% is not treated as connected until the authenticated ControlPort and SOCKS listener are verified.

At 0%, inspect the live file for the last `Bootstrapped N%` line and nearby `[warn]`/`[err]` messages. If the log never advances beyond `Bootstrapped 0% (starting)`, check whether the selected Tor bundle starts, whether its pluggable transport binary exists, and whether the network can reach the configured bridge. If the log reports progress but the UI is stuck, confirm the latest line in the live viewer rather than relying only on the percentage label. The popup's **Clear log history** action asks for confirmation before truncating the current Tor log; new entries continue to stream afterwards.

Check the system clock, connectivity, and whether Tor is blocked on the current network. If bridges are required, enable bridge mode and provide complete supported bridge records. A transport executable must exist in the selected bundle. Do not include bridge secrets or private network details in a public bug report.

Automatic bridge cleanup is an opt-in preflight in Settings → Bridges. It checks records independently before the normal connection starts, so it may delay startup. It never removes a bridge when the result is inconclusive, and keeps the full original list if no bridge is confirmed working. If several bridges are removed, recheck the network and transport executable before concluding the bridges themselves are invalid.

## HTTP proxy reports WinError 10053 or a client disconnect

A traceback at `BaseHTTPRequestHandler` while reading the first request line means the local client connection was interrupted before a complete HTTP request was received. This can happen when an application cancels a request, closes a connection abruptly, or otherwise abandons a proxy socket. It does not, by itself, indicate a failed Tor circuit.

The HTTP proxy now handles expected client connection resets/aborts/broken pipes at the request boundary and closes the affected connection. Idle reads are bounded by a 30-second socket timeout so clients that connect but do not send a request cannot occupy worker threads indefinitely. These are per-read timeouts, not an absolute deadline for an entire upload.

If the message coincides with failed page loads, compare the timestamp with **Event Log → Live Tor log** and `tor.log`. Verify the application is configured for the local HTTP proxy and that Tor's SOCKS listener is ready. Do not treat this exception alone as proof of a bridge, exit relay, or Tor bootstrap failure.


Bootstrap completion does not guarantee every destination is reachable. Confirm the local HTTP proxy endpoint is correct, the app uses HTTP proxy for HTTP and HTTPS proxy/CONNECT for TLS destinations, the host is not blocked, and the configured SOCKS listener matches the managed Tor instance. A failed Tor route must not fall back to a direct route.

## Exit-IP check fails

The action requires TorProxy to be connected and sends HTTPS through the local HTTP proxy. It will not retry without a proxy. Verify the proxy listener is ready and that the selected Tor exit can reach the IP-check service. A failure is reported as unverified rather than a Tor IP.

## Bundle verification fails

Release discovery recognizes stable and supported alpha names separately. A visible release directory does not imply a compatible artifact is available; TorProxy checks for the exact platform/architecture Expert Bundle and its matching signature before enabling download. If the release is unavailable for this CPU/OS, use a release that publishes a matching Expert Bundle rather than trying a browser installer or `.mar` update archive.


Open Settings → Advanced and enable “Verify Tor bundle signatures with OpenPGP (GnuPG)” if you want publisher-signature verification. In that mode, TorProxy looks for GnuPG using `PATH`, common platform installation locations, then `TORPROXY_GPG_EXECUTABLE`. On Windows, install GnuPG from its official download page (https://gnupg.org/download/) and either add its `bin` directory to `PATH` or set `TORPROXY_GPG_EXECUTABLE` to the full `gpg.exe` path before restarting TorProxy. The chosen executable is smoke-tested with `--version`; verification subprocesses have timeouts and do not use a shell. The exact archive and detached `.asc` sidecar are required, and the signing key must match the independently pinned full fingerprint. Missing runtime, missing sidecar, wrong signer, invalid signature and timeout stop signed installation. When OpenPGP is disabled, the updater labels bundles `HTTPS ONLY · UNSIGNED`; HTTPS does not authenticate the publisher's signature.

## System proxy will not restore

The app restores Windows/GNOME settings only when current values still match those it applied. If you changed proxy settings in another app or OS settings panel while TorProxy was active, restoration is refused to avoid overwriting your changes. Review the operating system's proxy settings and select the desired values manually. The stored snapshot remains available for investigation.

On unsupported platforms, the system-proxy action fails closed. It does not claim success or run a shell command as a fallback.

## Missing Python/native dependency

Install dependencies with `python -m pip install -e ".[dev]"`. On Debian/Ubuntu, QR decoding requires `libzbar0`. GnuPG is optional and needed only if OpenPGP signature verification is enabled in Settings → Advanced. On Windows, install GnuPG from its official distribution and ensure it can be invoked or set `TORPROXY_GPG_EXECUTABLE` when signed verification is enabled.

## Reporting an issue

Include OS/Python versions, sanitized logs, the action that failed, and whether the issue reproduces with a verified Tor Expert Bundle. Remove IPs, bridge lines, usernames, cookies, credentials, full URLs, and query strings first.


## Kill Switch blocks all network access or will not activate

This is expected when Tor is stopped: the firewall intentionally remains in outbound default-deny mode. Start TorProxy, connect Tor, and configure applications to use the displayed loopback HTTP proxy. Direct connections from applications that ignore the proxy are blocked, not redirected.

On Windows, activation asks for Administrator approval. It fails closed if Group Policy or another policy store contributes outbound Allow rules that cannot safely be disabled and verified. If another administrator or firewall product changes the managed profiles/rules, TorProxy may refuse automatic restoration and preserve its snapshot. Inspect Windows Defender Firewall before making manual changes.

On Linux, check that \`nft\`, \`pkexec\`, \`systemctl\`, a systemd user manager and unified cgroup v2 are available. The kernel and nftables build must support \`socket cgroupv2\` matching. A systemd service installs the \`torproxy_killswitch\` nftables table before network startup. If the desktop session lacks a working PolicyKit agent or \`systemd-run --user --scope\` cannot create a scope, TorProxy refuses to start Tor under the Kill Switch rather than allowing the desktop user's UID.

To restore access, use **Settings → Advanced → Network protection → System-wide Kill Switch → Disable** while TorProxy can request administrator approval. If the UI cannot start, Windows administrators can inspect the saved state under the TorProxy per-user state directory and the rules named \`TorProxy Kill Switch\`. On Linux, the owned service is \`torproxy-killswitch.service\` and the owned table is \`inet torproxy_killswitch\`; do not delete unrelated nftables tables. Manual recovery should remove only those TorProxy-owned resources after inspecting their ownership markers.

When Kill Switch is enabled, direct Exclude Host entries are blocked. Tor bundle downloads or updater operations that use a direct connection may also fail until protection is deliberately disabled.

### Windows activation takes too long

The Windows Kill Switch now uses a small native `TorProxyWfpHelper.exe` and Windows Filtering Platform (WFP), rather than changing every saved outbound Allow rule through COM or NetSecurity. The helper installs TorProxy-owned persistent IPv4 and IPv6 ALE connect filters in one explicit WFP transaction. Higher-weight permits are limited to the configured Tor/bridge executable paths, loopback, DHCPv4/v6, IPv6 neighbor discovery, and the `TorProxy` tunnel interface when present; a lower-weight catch-all block in the same sublayer stops other outbound connection attempts. Permit filters do not clear WFP's action right, so another firewall/security provider can still veto Tor traffic. Existing Windows Firewall rules and Domain/Private/Public profile defaults are not modified by a new WFP activation. WFP policy changes trigger reauthorization of existing ALE flows, so previously authorized connections are checked against the new policy on their next packet. The provider, sublayer, and filters are persistent across BFE stop/start; disabling/recovery deletes only filters owned by TorProxy in one transaction. The helper is bundled next to `TorProxy.exe` and copied to `%LOCALAPPDATA%\\TorProxy\\State\\killswitch\\native` on first use so the recovery executable remains available if the portable application folder is removed. If the UI is unavailable, run an elevated PowerShell window and execute `& "$env:LOCALAPPDATA\\TorProxy\\State\\killswitch\\native\\TorProxyWfpHelper.exe" recover` to remove only TorProxy-owned WFP filters. A legacy snapshot from an older release must be restored once before a new WFP activation; the program refuses to mix old profile/rule state with the new backend. The 30-second bound remains as a fail-safe for a hung native helper, not as a per-rule update budget. The Linux nftables helper retains its separate 180-second bound. A timeout may occur after some firewall changes have been applied, so use **Restore saved firewall** first and **Emergency network recovery** only if the saved-state restore cannot restore connectivity. Do not repeatedly retry activation while a previous operation is still being reconciled.

### Windows firewall source detection

Before changing existing outbound Allow rules, TorProxy queries the merged ActiveStore with PowerShell's `-TracePolicyStore` switch. Windows only populates `PolicyStoreSourceType` and `PolicyStoreSource` for ActiveStore results when source tracing is requested. This distinguishes Local rules from Group Policy, Dynamic, Generated and Hardcoded entries; unsupported sources remain a fail-closed error and are reported by rule name/source rather than silently ignored.

The built-in Internet Connection Sharing outbound rule is a narrowly-recognized exception only when all of these match: Dynamic source, outbound Allow, enabled, the exact system `svchost.exe` path, and service `SharedAccess`. TorProxy does not edit or delete that Windows-owned dynamic rule. Instead it adds an owned, exact-program/service outbound Block rule for `SharedAccess` while the Kill Switch is active. Windows Firewall gives explicit Block rules precedence over conflicting Allow rules; TorProxy verifies the Block rule's action, state, program and service before treating the dynamic ICS allow as contained. This intentionally disables Internet Connection Sharing traffic while protected; the owned Block rule is removed when the saved firewall policy is restored. Every other Dynamic or non-local Allow rule continues to fail closed.

For a non-local rule, the activation error also includes its display name, description, policy source, application/package, service, protocol, ports, and address filters where Windows exposes them. These fields are read-only diagnostics: TorProxy does not remove a Dynamic/Generated/Hardcoded rule or assume that a rule is harmless merely because it belongs to Windows. For manual inspection, run the following in an elevated PowerShell window, substituting the rule name from the error:

```powershell
$ruleName = Read-Host 'Paste the rule Name from the TorProxy error, including braces'
$rule = Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -Name $ruleName
$rule | Format-List Name, DisplayName, Description, Group, Enabled, Profile, Direction, Action, PolicyStoreSourceType, PolicyStoreSource
$rule | Get-NetFirewallApplicationFilter | Format-List Program, Package
$rule | Get-NetFirewallServiceFilter | Format-List Service
$rule | Get-NetFirewallPortFilter | Format-List Protocol, LocalPort, RemotePort, IcmpType
$rule | Get-NetFirewallAddressFilter | Format-List LocalAddress, RemoteAddress
```

Share the output after removing usernames or other private paths. Do not manually delete or disable a Dynamic rule as a workaround; first identify the component that owns it and whether its policy can be changed through that component.
