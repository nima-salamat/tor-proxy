# TorProxy

TorProxy is a PySide6 desktop front-end for running a locally managed Tor process and exposing a loopback-only HTTP proxy to applications that support manual proxy configuration.

The project is being modernized from a flat desktop utility into a testable Python core with safer Tor lifecycle management, validated host policy, configurable bundle signature verification, and reversible system-proxy integration.

> **Privacy and security note:** TorProxy is not a guarantee of anonymity. It protects only traffic that is actually routed through its Tor-backed proxy. Applications can make direct connections, leak information at the application layer, or retain identifying state. Read [the security model](docs/SECURITY.md) before relying on it.

## Features

- Start/stop supervision for an application-owned Tor process, with bounded startup and shutdown.
- Loopback-only SOCKS, ControlPort, DNSPort (when configured), and HTTP proxy listeners.
- Stem-based Tor control with cookie authentication, bootstrap status, process-identity checks, and rate-limited `NEWNYM` requests.
- HTTP forwarding and HTTPS `CONNECT` tunnels through Tor's SOCKS endpoint, with remote DNS for Tor-routed destinations.
- Immutable block/bypass host-rule snapshots shared by HTTP and CONNECT.
- An IP-check action that uses the configured local HTTP proxy and **does not retry directly**.
- Explicit opt-in for system proxy changes, snapshot-based restoration, and protection against overwriting later external changes.
- Tor Expert Bundle downloads are restricted to official Tor HTTPS hosts and safely extracted; optional OpenPGP signature verification checks the pinned Tor signing-key fingerprint when enabled in Settings → Advanced.
- Versioned configuration, per-user writable data paths, atomic settings writes, tests, and CI.

## Architecture

```mermaid
flowchart TD
    UI[PySide6 UI] --> Supervisor[TorRunner compatibility adapter]
    Supervisor --> Manager[TorManager / Stem controller]
    Manager --> Tor[Tor process]
    UI --> LocalProxy[Loopback HTTP proxy]
    LocalProxy --> Policy[Block and bypass host rules]
    Policy -->|Default route| Socks[Loopback Tor SOCKS]
    Socks --> Tor
    Policy -->|Explicit exclusion only| Direct[Direct connection outside Tor]
    UI --> Bundle[Signed bundle manager]
    UI --> Config[Per-user configuration and state]
```

The new, independently testable code lives in `src/torproxy/`. Existing UI modules continue to use a small compatibility layer while migration progresses. See [Architecture](docs/ARCHITECTURE.md) for lifecycle and thread boundaries.

## Requirements and support status

| Area | Current policy |
|---|---|
| Python | `>=3.10`, as declared in `pyproject.toml` |
| Desktop UI | PySide6 |
| Bundle downloader | Windows/Linux, x86_64 or 32-bit x86 Expert Bundles |
| System proxy integration | Windows user Internet Settings; GNOME `gsettings` on Linux |
| macOS | Not currently supported by the bundle downloader or system-proxy adapter |
| CPU/OS validation | GitHub Actions is configured for Windows and Ubuntu on Python 3.10–3.13; check the [Actions page](https://github.com/nima-salamat/tor-proxy/actions) for actual results |

The matrix describes intended CI coverage, not a claim that every platform has been manually tested. Arbitrary user-supplied Tor executables may work, but are not part of the bundle downloader's supported matrix.

## Install and run

### Prerequisites

Install Python 3.10 or newer. GnuPG (`gpg`) is needed only when optional OpenPGP signature verification is enabled in Settings → Advanced. On Debian/Ubuntu, the optional QR-code feature needs native ZBar:

```bash
sudo apt-get update
sudo apt-get install -y gnupg libzbar0
```

On Windows, install GnuPG from a trusted distribution and ensure `gpg.exe` is on `PATH`, or configure `TORPROXY_GPG_EXECUTABLE` with its full path, only if you enable OpenPGP verification. Some platforms require additional native setup for QR decoding; see [Troubleshooting](docs/TROUBLESHOOTING.md).

### Development installation

```bash
git clone https://github.com/nima-salamat/tor-proxy.git
cd tor-proxy
python -m venv .venv
```

Activate the virtual environment, then run:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python main.py
```

A legacy-compatible runtime dependency file is also provided:

```bash
python -m pip install -r requirements.txt
```

The first launch migrates an existing root-level `config.json` into the per-user configuration directory when possible. Invalid configuration is reported rather than silently treated as a successful load.

## Get a Tor bundle

1. Open the application's Tor bundle/update view.
2. Retrieve the official release list.
3. Select a release for the current supported OS/CPU.
4. Confirm download and watch the status until safe extraction finishes; when OpenPGP is enabled, the pinned-key signature check must also pass.
5. Review the bundle's `SIGNED` or `HTTPS ONLY · UNSIGNED` label, then select it as the default Tor executable.

Downloads are stored in the current user's application-data directory, not inside the installed source tree. Unsafe archive entries and path traversal are always rejected. OpenPGP verification is optional and off by default for convenience; when enabled, invalid/missing signatures or an unavailable GnuPG runtime stop installation. With it off, publisher identity is not cryptographically authenticated, even though downloads are restricted to official HTTPS hosts.

Older repository versions included large archives in `bundles/`. These are no longer required in source control. Existing local archives that lack a verifiable `.asc` signature are not automatically trusted by the updater; download a verified bundle again, or explicitly select a local Tor executable whose origin you trust.

## Release channels and bundle verification

The updater recognizes numeric stable releases (for example, `15.0.26`) and the supported alpha naming convention (for example, `16.0a14`). Stable releases are prioritized; alpha releases are labelled as prereleases and can be hidden with the prerelease filter. A release directory is downloadable only when the exact current-platform Expert Bundle is listed; its matching detached `.asc` signature must also be listed when OpenPGP verification is enabled. Tor Browser installers, `.mar` updates, debug archives and checksum files are not substitutes for an Expert Bundle.

The bundle page displays transfer bytes and, when the server advertises a usable `Content-Length`, percentage, speed and an approximate remaining-time estimate. Unknown transfer lengths use an indeterminate progress bar. When enabled, signature verification appears as a distinct stage; safe archive extraction and installation are always shown separately. A completed transfer alone never counts as an installed bundle. Cancellation is available during network transfer and is disabled during stages that cannot be safely interrupted.

OpenPGP verification is optional and can be enabled in Settings → Advanced. When enabled, the detached signature is checked against the independently pinned Tor signing-key fingerprint and GnuPG is discovered from `PATH`, common installation paths, or `TORPROXY_GPG_EXECUTABLE`. If no verifier can be started, the signed installation stops. When OpenPGP is disabled, TorProxy labels the installation `HTTPS ONLY · UNSIGNED` and does not claim publisher authentication; choose that mode only if you accept the reduced security guarantee.

## Start Tor and configure an application

1. Start TorProxy and select **Connect**.
2. Wait for bootstrap to reach 100%. The application checks the managed Tor ControlPort and SOCKS listener separately from the local HTTP proxy.
3. Use the HTTP proxy endpoint displayed by TorProxy. It listens on `127.0.0.1`; configure both HTTP and HTTPS proxy fields in your application to `127.0.0.1:<shown-proxy-port>`.

To diagnose a stalled connection, open **Event Log → Live Tor log**. It streams the active `tor.log` from disk, uses severity colors, limits the number of rendered lines, and loads earlier entries in pages. The percentage can be populated from Tor's own bootstrap notices before the ControlPort status becomes available; TorProxy does not mark the connection as ready until the ControlPort identity and SOCKS listener checks pass.
4. Test with **What is my IP?**. It sends an HTTPS request through the local proxy and reports the observed exit IP only if the proxied request succeeds.

Do not expose the local HTTP proxy, SOCKS port, or ControlPort to a LAN. The application deliberately rejects non-loopback HTTP proxy binds.

## Identity requests

Choose **Change Identity** to request Tor's `NEWNYM` signal. The application consults Stem's cooldown information and does not start a repeating timer by default.

A successful `NEWNYM` command means Tor accepted an identity/circuit request; it does **not** guarantee a different public IP. Existing TCP connections can continue using their existing circuits. See [Stem's controller API](https://tpo.pages.torproject.net/network-health/stem/api/control.html) for details.

## Bridges and advanced settings

Bridge mode accepts complete Tor bridge records with an IPv4 or bracketed IPv6 endpoint. Records may include a supported transport (**obfs4**, **Snowflake**, **WebTunnel**, or **meek_lite**) or be plain endpoint/fingerprint entries where no pluggable transport is used. TorProxy normalizes copied text to one canonical record per line, separates adjacent records pasted on a single line (including plain `Bridge [IPv6]:port` records), removes the optional torrc `Bridge` prefix, and strips accidental quotes around IPv6 authorities. The Settings page shows saved entries as individual cards with copy and remove actions. Manual input, QR imports, and startup configuration use the same parser. Unrecognized or incomplete records do not overwrite the previous valid list.

In **Settings → Bridges**, each bridge card also shows live usage from Tor's authenticated ControlPort. It is marked connected only when a currently built circuit's first hop matches that bridge's identity fingerprint. A bridge can remain configured yet not be observed in a current circuit; this is not by itself proof that the bridge is dead.

The **WebTunnel SNI imitation** option is off by default, which leaves the hostname from each bridge's `url=` parameter unchanged. You can select one of the suggestions or type a custom DNS hostname; TorProxy then adds `sni-imitation=<hostname>` to WebTunnel records only. This setting applies on the next Tor start, does not replace `url=`, and is dependent on a Lyrebird build and bridge that support SNI imitation. Not every bridge supports this option, so restore the default if it prevents bootstrap.

In **Settings → Bridges**, you can optionally enable automatic bridge cleanup. Before connecting, TorProxy tests each configured bridge in an isolated Tor process (up to four checks in parallel). A failed record is removed from the saved list only when at least one other bridge is confirmed to complete bootstrap. Explicit dial failures can be removed; ambiguous results and local Lyrebird/TLS/runtime errors are retained. If no bridge succeeds, the entire original list is preserved and the normal Tor startup path still gets a chance to try the configured alternatives. If the real Tor bootstrap later times out, TorProxy performs one fresh check and retries once only when a working alternative is confirmed and cleanup actually reduces the list. Generic `general SOCKS server failure` messages, SOCKS DNS-leak warnings, and missing-hop/directory notices are not treated as proof that a configured bridge is dead. This preflight can add up to about 30 seconds per bridge-check wave; bridge addresses are not written to the event log.

The supervised Tor configuration currently supports circuit dirtiness, new-circuit period, IPv4/IPv6 client behavior, bridge records, and local listener endpoints. Country-specific `ExitNodes`/`StrictNodes` controls are not presented as supported UI features in this redesign. Avoid unreviewed Tor directives.

## Blocked hosts and exclusions

Host rules match a root domain and its subdomains by default. Prefix `=` for an exact hostname only, and `*.` for subdomains only. Rules are normalized with IDNA and IP-literal handling. Blocking is applied consistently to HTTP and HTTPS CONNECT requests.

Excluded hosts are a deliberate bypass: TorProxy connects to them directly. That can reveal the destination and DNS lookup to the local network/ISP and expose your direct IP. Leave exclusions empty unless you intentionally want this behavior. Block rules take precedence over exclusions.

## System proxy settings

System proxy changes are **manual and disabled by default**. Tor startup never changes global settings automatically.

The system-proxy control currently supports Windows Internet Settings and GNOME `gsettings`. Before changing settings, TorProxy saves the previous values. On clear/shutdown, it restores them only when it can confirm the settings still match the values it applied. If another application changed them in the meantime, TorProxy leaves those external changes untouched and reports that manual inspection may be required. macOS integration is not implemented.

Applications configured manually to use `127.0.0.1:<shown-proxy-port>` do not require system-wide proxy changes.

## Configuration and data paths

Settings, application state, logs, and downloaded bundles live in per-user locations rather than the source checkout. Defaults and supported legacy keys are described in [Configuration](docs/CONFIGURATION.md).

Traffic usage counts bytes observed in both directions for proxied HTTP requests and CONNECT tunnels. It is an application-level counter, not a total network-usage meter; under extreme bursts, the bounded counter queue can drop updates and log a warning.

## Security and limitations

- The default HTTP proxy, SOCKS, ControlPort, and DNS listeners bind to loopback.
- The ControlPort is cookie-authenticated; the controller must identify the Tor process launched by this application.
- The IP checker has no direct-network fallback.
- With OpenPGP verification enabled, downloads fail closed when a signature or pinned-key check fails; safe extraction checks always apply.
- Logs avoid recording request URLs and query strings, but local logs and host-rule lists should still be treated as user data.
- Direct exclusions intentionally bypass Tor.
- System-proxy restoration can fail safely if another program changes settings.
- This is not a firewall or system-wide traffic-enforcement mechanism. An application can ignore the proxy.
- CI tests use fakes/local servers; they do not prove real-world anonymity or verify every OS integration.

Read [Security](docs/SECURITY.md) and [Troubleshooting](docs/TROUBLESHOOTING.md) before reporting an issue.

## Development and testing

```bash
python -m pip install -e ".[dev]"
ruff check src/torproxy tests --select E,F,UP --ignore E501
pytest --cov=torproxy.host_rules --cov=torproxy.ip_check --cov-report=term-missing --cov-fail-under=75
```

The offline suite also exercises stable/alpha release parsing, exact artifact/signature selection, transfer progress/cancellation, GnuPG failure modes, optional HTTPS-only installation, trust-method markers, and atomic installation publication. Normal CI does not download a real Tor archive.

An opt-in integration test contacts the official Tor Project distribution, downloads a compatible Expert Bundle, and verifies its real detached signature. It requires GnuPG, internet access, and a supported OS/architecture. Do not enable it in an untrusted test environment because it downloads a large archive.

On Linux/macOS shells with a supported runtime:

```bash
TORPROXY_ONLINE_SIGNATURE_TEST=1 pytest -m integration tests/test_updater_pipeline.py::test_live_official_expert_bundle_download_and_signature
```

In Windows PowerShell:

```powershell
$env:TORPROXY_ONLINE_SIGNATURE_TEST = "1"
pytest -m integration tests/test_updater_pipeline.py::test_live_official_expert_bundle_download_and_signature
```

A skipped opt-in test is not evidence of a verified download. Record the actual test result and platform when reporting integration validation.

See [Contributing](CONTRIBUTING.md), [Changelog](CHANGELOG.md), and the [project report](docs/PROJECT_REPORT.md).

## License

MIT. See [LICENSE](LICENSE).
