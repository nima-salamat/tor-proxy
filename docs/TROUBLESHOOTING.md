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

Ensure GnuPG is available as `gpg`, the `.asc` sidecar belongs to the exact archive, and the download came from the official Tor distribution. A missing or invalid signature is not bypassed. If the official format changes, the validator needs a reviewed update before it should accept the new format.

## System proxy will not restore

The app restores Windows/GNOME settings only when current values still match those it applied. If you changed proxy settings in another app or OS settings panel while TorProxy was active, restoration is refused to avoid overwriting your changes. Review the operating system's proxy settings and select the desired values manually. The stored snapshot remains available for investigation.

On unsupported platforms, the system-proxy action fails closed. It does not claim success or run a shell command as a fallback.

## Missing Python/native dependency

Install dependencies with `python -m pip install -e ".[dev]"`. On Debian/Ubuntu, QR decoding requires `libzbar0` and bundle verification requires `gnupg`. ZBar installation on other platforms differs.

## Reporting an issue

Include OS/Python versions, sanitized logs, the action that failed, and whether the issue reproduces with a verified Tor Expert Bundle. Remove IPs, bridge lines, usernames, cookies, credentials, full URLs, and query strings first.
