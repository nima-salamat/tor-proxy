# Troubleshooting

## Tor does not start

1. Confirm the selected Tor executable exists and is executable.
2. If using the updater, verify that download and signature verification completed and the extracted bundle appears in the verified bundle list.
3. Inspect `torproxy.log` and `tor.log` under the user's application state directory. Logs may contain local host names; handle them as private user data.
4. The app validates torrc before launch. Invalid directives, duplicate ports, missing bridge transport binaries, or invalid bridge records should fail early.
5. Check that another application is not occupying configured listener ports. TorProxy does not kill unrelated Tor processes.

## Bootstrap stays below 100%

Check the system clock, connectivity, and whether Tor is blocked on the current network. If bridges are required, enable bridge mode and provide a current bridge record for a supported transport. A transport executable must exist in the selected bundle. Do not include bridge secrets or private network details in a public bug report.

## Tor says ready but a website does not load

Bootstrap completion does not guarantee every destination is reachable. Confirm the local HTTP proxy endpoint is correct, the app uses HTTP proxy for HTTP and HTTPS proxy/CONNECT for TLS destinations, the host is not blocked, and the configured SOCKS listener matches the managed Tor instance. A failed Tor route must not fall back to a direct route.

## Exit-IP check fails

The action requires TorProxy to be connected and sends HTTPS through the local HTTP proxy. It will not retry without a proxy. Verify the proxy listener is ready and that the selected Tor exit can reach the IP-check service. A failure is reported as unverified rather than a Tor IP.

## Bundle verification fails

Release discovery recognizes stable and supported alpha names separately. A visible release directory does not imply a compatible artifact is available; TorProxy checks for the exact platform/architecture Expert Bundle and its matching signature before enabling download. If the release is unavailable for this CPU/OS, use a release that publishes a matching Expert Bundle rather than trying a browser installer or `.mar` update archive.


TorProxy looks for GnuPG using `PATH`, common platform installation locations, then `TORPROXY_GPG_EXECUTABLE`. On Windows, install GnuPG from its official download page (https://gnupg.org/download/) and either add its `bin` directory to `PATH` or set `TORPROXY_GPG_EXECUTABLE` to the full `gpg.exe` path before restarting TorProxy. The chosen executable is smoke-tested with `--version`; verification subprocesses have timeouts and do not use a shell. The exact archive and its detached `.asc` sidecar are required, and the signing key must match the independently pinned full fingerprint. Missing runtime, missing sidecar, wrong signer, invalid signature and timeout all stop installation. Do not remove the verification requirement or retry by accepting an unsigned checksum.

## System proxy will not restore

The app restores Windows/GNOME settings only when current values still match those it applied. If you changed proxy settings in another app or OS settings panel while TorProxy was active, restoration is refused to avoid overwriting your changes. Review the operating system's proxy settings and select the desired values manually. The stored snapshot remains available for investigation.

On unsupported platforms, the system-proxy action fails closed. It does not claim success or run a shell command as a fallback.

## Missing Python/native dependency

Install dependencies with `python -m pip install -e ".[dev]"`. On Debian/Ubuntu, QR decoding requires `libzbar0` and bundle verification requires `gnupg`. On Windows, install GnuPG from its official distribution and ensure it can be invoked or set `TORPROXY_GPG_EXECUTABLE`; TorProxy intentionally refuses to install an archive until the detached signature has been verified.

## Reporting an issue

Include OS/Python versions, sanitized logs, the action that failed, and whether the issue reproduces with a verified Tor Expert Bundle. Remove IPs, bridge lines, usernames, cookies, credentials, full URLs, and query strings first.
