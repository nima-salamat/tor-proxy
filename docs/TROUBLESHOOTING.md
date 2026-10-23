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

## Tor says ready but a website does not load

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
