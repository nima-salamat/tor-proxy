# TorProxy — Project Report

## Executive summary

The repository began as a small, flat PySide6 application with network/proxy logic, process management, system settings, and update behavior coupled through module-level functions and shared state. The redesign introduces a separately testable `src/torproxy` core while retaining compatibility interfaces for the legacy UI.

The most security-sensitive changes target unsafe network exposure, false-positive IP verification, process supervision, system-proxy restoration, unverified bundles, mutable host rules, and writes into the source checkout.

## Baseline audit findings

| Severity | Finding in the baseline | Redesign response |
|---|---|---|
| Critical | The HTTP proxy listener could bind to a non-loopback/all-interface address. | The server constructor now rejects non-loopback binds; the GUI creates it on `127.0.0.1`. |
| Critical | The old updater could accept a missing checksum in some paths. | Download/install uses a detached OpenPGP signature and pinned signing-key fingerprint; missing/invalid signatures fail closed. |
| High | IP checking could make a direct request while labelling the result as Tor's IP. | Explicit HTTP/HTTPS proxy settings, no redirects, timeouts, IP validation, and no direct retry. |
| High | System proxy changes used shell commands and clearing did not preserve prior settings. | Windows registry/GNOME adapters, saved snapshots, argv-based subprocess calls, explicit opt-in, conditional restoration. |
| High | Tor status was inferred from log text; subprocess pipes could remain undrained. | Supervised process, file-backed subprocess output, configuration validation, authenticated Stem control, bootstrap-phase parsing. |
| High | Tor could be treated as connected based on one signal rather than distinguishing process, control, SOCKS, HTTP proxy, and actual request state. | Separate lifecycle/bootstrap/listener status and a separately proxied exit-IP request. |
| Medium | Host rules and traffic counters used mutable module state without clear ownership/shutdown. | Immutable rule snapshots, locking, bounded byte-event queue and explicit tracker stop event. |
| Medium | Runtime files and bundles were kept relative to the checkout, and large archives were committed. | Per-user config/data/cache/state paths and removal of the large checked-in archives. |
| Medium | A broad pytest suite and CI were absent from the root structure. | Focused core tests and a Windows/Ubuntu Python CI matrix were added. |

## Architecture changes

- `paths.py` resolves OS-specific per-user directories.
- `configuration.py` defines typed, validated settings and atomic JSON persistence; root `config.py` remains a compatibility facade for legacy UI keys.
- `host_rules.py` handles normalization, IDNA/IP literals, exact/root/subdomain semantics, deduplication, and immutable updates.
- `tor_manager.py` owns the Tor child process, torrc, bounded start/stop, bootstrap state, authenticated ControlPort, managed process identity, and `NEWNYM` cooldown.
- `bundle.py` validates official distribution URLs, detached signatures, download size, and archive member paths/types before extraction.
- `ip_check.py` requires an explicit proxy and refuses direct fallback.
- `proxy.py` enforces loopback binding and consistent policy for absolute-form HTTP and HTTPS CONNECT.
- `set_proxy.py` abstracts Windows Internet Settings and GNOME settings with reversible snapshots.
- The existing `TorRunner` and GUI are transitional adapters; a full migration of every legacy UI module into the package remains future work.

## Security behavior changes

- Automatic system-proxy changes on bootstrap were removed.
- Automatic periodic `NEWNYM` requests are disabled; manual requests honor Tor's rate-limit information.
- The ControlPort and SOCKS listener bind to `127.0.0.1`; cookie authentication is enabled and the reported Tor PID is compared with the managed child PID.
- Normal proxy traffic uses SOCKS remote DNS. Excluded hosts take an explicit direct route and can expose traffic outside Tor.
- The exit-IP checker reports an observed IP only when its proxied HTTPS response returns a valid address.
- Archive extraction refuses traversal, links, special members, oversized expansion, and overwriting an existing destination.
- System proxy cleanup restores prior values only when current settings still match the values TorProxy applied; external changes are left alone.

## Tests and CI

Test modules cover host rules, configuration and migration, user paths, proxy-required IP checks, Tor configuration and bridge validation, tar extraction, loopback-only proxy binding, HTTP forwarding through a local fake SOCKS5 relay, and mocked Windows proxy restoration.

GitHub Actions is configured for Windows/Ubuntu and Python 3.10–3.13. A green result must be confirmed from the actual workflow after the branch is pushed. CI fakes do not prove successful connection to the live Tor network or validate every GUI/platform-specific behavior.

## UI/updater follow-up in progress

The follow-up branch `feature/modern-ui-and-updater-repair` adds a modern sidebar shell and a substantially revised bundle-manager page. Release names and release channels are parsed explicitly; compatible artifact discovery requires both the exact archive and detached signature. Transfer events use a typed progress object, and the GUI displays download, verification, extraction, and completion stages. Common GnuPG paths and `TORPROXY_GPG_EXECUTABLE` are supported as recovery mechanisms; absence of GnuPG still prevents installation because signature verification remains mandatory.

Managed bundle auto-discovery now consults the existing verified-bundle inventory instead of trusting every matching folder name. Qt layout construction was corrected in the main shell, settings, overview, blocked-host and bypass-host views. Regression tests were added for version parsing, listing/artifact filtering, progress semantics, and managed executable selection. These changes remain subject to the branch's actual CI results and manual platform checks; they are not evidence of a completed live Windows signature-verification session.

## Known limitations and remaining work

- Legacy UI code remains in root/`ui_/`. Service integration is improved, but the complete desktop UI has not been migrated to a package-oriented view-model architecture.
- macOS system-proxy integration and bundle downloads are not implemented.
- Automated bundle downloads target Windows/Linux x86 and x86_64; ARM download support is not enabled.
- Real Tor-network integration tests are not run by default.
- Tests do not fully cover every Tor process race, every Windows/GNOME failure mode, or a live bridge connection.
- Browser fingerprinting, application bypasses, WebRTC, and arbitrary system DNS are outside this application's enforcement boundary.
- Byte accounting is best-effort under extreme queue saturation.
- Country-based exit-node controls are not exposed as implemented UI features in this redesign.
- The package/layout migration is incremental rather than a completed rewrite of every module.

## Validation evidence

The CI configuration defines the commands to be executed. Before release, inspect the real Actions results, manually smoke-test start/stop and proxy restoration on each declared OS, test a valid signed Expert Bundle, and run an opt-in integration test against a verified Tor binary.
