# Changelog

All notable changes are recorded here. Dates and release numbers are added only when a release is actually published.

## Unreleased

- Added continuous Tor Check health monitoring for isolated Tor profiles, with per-profile RTT, degraded/unhealthy hysteresis, automatic health recovery, dead-process reconciliation, stale ControlPort cleanup and live Start/Stop state updates. Independent profiles remain isolated and are not load-balanced with one another.
- Bounded the primary SOCKS gateway to 256 concurrent sessions and the local HTTP proxy to 128 concurrent clients by default; added active/rejected session and per-backend connection metrics, pruned stale backend metrics, and made shutdown close active sockets and wait for client handlers.
- Fixed Windows HTTP proxy shutdown: active relays now receive an explicit cancellation event, outbound sockets are registered before Tor/DNS connect begins, and Tor is kept alive if an HTTP client handler has not yet released its upstream tunnel.
- Made the HTTP shutdown path cancellation-aware for blocked network setup: outbound Tor SOCKS connects and direct-route DNS resolution now run in daemon workers polled by the shutdown event; client acceptance is synchronized with the shutdown transition so no late request can escape the final socket sweep.
- Hardened Tor health probes by disabling environment-proxy inheritance, rejecting redirects, streaming a bounded response body, and never retaining exit IP values. Throttled expensive bridge fingerprint ControlPort queries to once every five seconds and use shorter follow-up/recovery intervals after a failed health check.
- Added an enabled-by-default local HTTP proxy preference in Settings → Ports, live listener toggling, and an end-to-end HTTPS/HTTP CONNECT diagnostic. Hardened CONNECT relay handling against buffered read-ahead so initial TCP tunnel bytes are not lost.
- Added deterministic primary bridge distribution after optional concurrent preflight: records sharing an explicit bridge fingerprint stay together, identity groups are weighted by their actual record count, verified bridge groups are seeded into every worker when available, and remaining groups are balanced without overlap where possible. Small pools or fewer verified groups than workers trigger deliberate, visible sharing. Settings reports each instance's assigned bridge count and sharing status.
- Clarified and surfaced that automatic bridge preflight already runs concurrently through a bounded 1–8 worker thread pool, with each unique bridge record tested in an isolated temporary Tor process; confirmed failures alone may be pruned and inconclusive records remain.
- Added per-instance end-to-end Tor health probes through each worker's own SOCKS5 listener using the Tor Project Check API; only workers confirmed with `IsTor: true` are eligible for traffic, and two consecutive probe failures withdraw a worker until it recovers. Settings → Tor Services now displays each primary instance's verified state and probe latency.
- Replaced primary SOCKS round-robin routing with least-active-connection and latency-aware backend selection, plus per-backend cooldown/fallback when a SOCKS connection fails; a sole healthy worker carries all new connections.
- Replaced the single-backend primary Tor SOCKS path with a stable loopback SOCKS5 failover gateway backed by 1–4 isolated Tor workers; the HTTP proxy and sing-box System Tunnel continue to use the configured endpoint, and new connections retry healthy workers when one backend fails. Unexpectedly exited workers receive up to three supervised restart attempts with backoff.
- Added Settings → Tor Services → Primary connection redundancy to configure how many Tor workers back the main connection (default 2). Documented that failover affects new connections only; existing TCP streams cannot migrate and each worker has separate Tor state/circuits.
- Prevented duplicate GUI ControlPort authentication from turning an already verified Tor READY state into a false disconnect; NEWNYM now uses TorManager's authenticated controller.
- Treat Tor and local HTTP proxy shutdown as incomplete while a process or worker thread remains alive, retaining service ownership and retryable Disconnect state.
- Increased the bounded concurrent bridge-health worker limit to eight and clarified completion-order progress reporting.
- Added the TorServicePool core API for multiple isolated Tor processes with unique data directories, log files and listener ports.
- Added Settings → Tor Services with persistent profile creation/editing/removal, independent SOCKS/Control/DNS listeners, per-profile bridge selection and DataDirectory controls, asynchronous Start/Stop and concurrent bulk operations; explicit app exit now stops all registered isolated services.
- Added configurable 1–8 worker limits for parallel bridge health checks and concurrent isolated-service operations.
- Improved Windows elevated tunnel-helper diagnostics for STATUS_CONTROL_C_EXIT and made ShellExecuteEx activation synchronous from background workers.

## v1.2.0 — 2026-11-10
- Added native Windows window-management support for top-edge snapping, Snap Layouts, and resizing from all four edges and corners while preserving the custom title bar.
- Made automatic listener-port values read-only until the corresponding Fixed option is enabled; added regression coverage for the state transition.
- Updated the native launcher splash to follow the selected application/system theme.

- Matched the sing-box manager page to the Bundle updater visual language and added live tunnel status refresh while the page is open.
- Added pre-connect reconciliation of recorded sing-box state and an Advanced emergency cleanup action. Cleanup remains identity-checked and refuses to delete untracked TUN adapters or terminate unrelated processes.

### UI, updater, and security redesign
- Browser discovery now starts after the shared popup is shown and runs in a Qt background worker; the dialog immediately renders its last SQLite-cached snapshot and refreshes it atomically when the scan finishes.
- Added stale-install handling for cached browser cards: an executable that was deleted or moved is removed from the database/UI immediately and produces a clear launch error, even while discovery is still running.
- Reworked the Open Browser chooser to use the shared frameless popup shell and existing dialog theme; browser cards now display installed Windows executable/shortcut icons or Linux desktop-theme icons instead of a generic globe.
- Expanded Windows browser discovery to StartMenuInternet registrations, Start Menu shortcuts, App Paths, uninstall metadata and user/machine install folders; Linux discovery now retains desktop-file icon metadata alongside XDG launch information.

- Added a Home-page Open Browser dialog with Windows/Linux detection for common Chromium and Firefox-family browsers, persistent custom-browser entries, isolated per-browser profiles, and a dedicated safe launcher that uses the existing TorProxy HTTP proxy without adding an explicit direct route to Chromium's proxy argument and with Firefox's system-request proxy failover disabled. Chromium's non-proxied WebRTC UDP policy and Firefox's proxy-aware ICE restrictions are applied in those isolated profiles. Repeated Firefox launches reuse the active TorProxy profile without forcing a second Firefox instance.
- Added persistent listener-port allocation. Automatic ports are initialized and saved once, reused on later launches, and replaced only when a port conflict is detected; DNSPort checks both TCP and UDP; manually pinned ports remain user-controlled and fail preflight rather than being silently changed.
- Added browser discovery, profile, launch and listener-port regression tests; included the browser package in PyInstaller builds.


- Hardened the HTTP proxy request boundary against expected client abort/reset/broken-pipe errors, added a bounded idle-read timeout for incomplete requests, and introduced regression tests for disconnect handling and stalled request lines.
- Hardened Check Exit IP: overlapping checks are prevented, the UI always clears the busy state on success/failure, background worker failures record tracebacks, and the request remains explicitly proxied with no direct-network fallback. Added a dedicated `torproxy-crash.log` native-fault trace and main-thread exception logging for diagnosis of previously silent exits.
- Added an optional WebTunnel SNI imitation setting with no-override as the default, a small list of hostname suggestions, custom DNS-hostname validation, and `sni-imitation=` injection for WebTunnel records only. Explicit per-bridge SNI values take precedence, and changes apply on the next Tor start.

- Bridge cards now show live usage only when the authenticated Tor ControlPort reports a currently built circuit whose first-hop identity matches that card's configured bridge fingerprint. Configured, unobserved, or identity-unmatchable bridges are labelled accordingly instead of being shown as connected merely because Bridge mode is enabled.
- Automatic preflight and failed-bootstrap recovery now distinguish bridge endpoint failures (refused connections and unresolvable bridge hostnames) from transient timeouts/resets/EOFs, TLS/SNI handshake issues, Lyrebird setup errors, generic SOCKS warnings, DNS-leak notices, and missing directory-node descriptors. One refused connection or permanent DNS lookup failure is endpoint-specific; timeouts, resets, and EOFs require repeated independent dial failures before a bridge is marked unusable. When the real Tor bootstrap times out, the app performs one fresh isolated check and retries once only if a working alternative is verified and failed records can be safely removed. If the checks are inconclusive or the issue is global to the transport runtime, it preserves the entire list.
- Automatic bridge preflight now treats Lyrebird TLS curve/runtime errors as local transport issues: it preserves the full list and continues into normal Tor startup rather than aborting from the preflight helper. If one bridge completes bootstrap, only explicit dial failures of other records can be pruned; inconclusive transport results remain saved. A direct-bridge alternative is allowed to continue when Lyrebird reports an unsupported TLS curve.

- Bridge parsing now validates both bare 40-hex identity fingerprints and `fingerprint=` parameters before writing `torrc`; grouped hex chunks are normalized, and invalid items show indexed reasons instead of reaching Tor's config parser. If Tor still rejects a digest, diagnostics summarize token lengths/options without exposing bridge addresses, identity fingerprints, or WebTunnel secret URLs.

- Fixed Windows pluggable-transport launch configuration: Lyrebird's native executable path is now passed as a literal path token instead of the Torrc-escaped, quoted path that caused `CreateProcessA()` to fail. Transport launch errors are now distinguished from unreachable bridges, so the auto-check never prunes bridge records for a local executable/configuration failure.
- Stabilized the live log viewer by appending streamed rows in place, capping the visible document without redrawing it on every poll, preserving the user's vertical/horizontal scroll position, and keeping the horizontal scrollbar on a left-to-right layout.

- Added a live on-disk Tor log viewer launched from Event Log, with colored severities, configurable visible-line limits, paginated older history, live tailing, and confirmation before clearing the active log.
- Fixed the bootstrap display path to parse Tor's own `Bootstrapped N%` notices when ControlPort status is delayed; `100%` from a log alone no longer marks Tor connected before ControlPort and SOCKS verification.

- Added an opt-in bridge health check that tests multiple bridge records independently in parallel and removes confirmed failures only when at least one alternative completes Tor bootstrap; inconclusive checks and all-failed lists are preserved.
- Updated shortcut capture to show the live modifier/key combination while keys are held and finalize the binding on key release.

- Reworked the desktop shell with the existing top navigation, clearer page hierarchy, a live Tor state summary in the page header, and coordinated light/dark styling while retaining the existing feature views.
- Added stable-versus-alpha Tor release recognition, numeric ordering, and exact Expert Bundle plus detached-signature eligibility checks; unsupported release folders are not treated as downloadable artifacts.
- Added typed streamed-download progress, size/speed/ETA reporting where available, cancellation during safe transfer stages, and distinct signature/extraction/install status.
- Improved GnuPG executable discovery and remediation using PATH, common install paths, and `TORPROXY_GPG_EXECUTABLE`; pinned-fingerprint verification remains fail-closed when enabled in Settings → Advanced.
- Restricted managed-bundle auto-selection to bundles that pass the existing verification-marker, archive-digest, platform, and executable checks.
- Corrected duplicate Qt layout ownership patterns and added regression coverage for release parsing, bundle eligibility, download progress, executable selection, and layout construction.

### Security and architecture redesign

- Added a `src/torproxy` core for validated configuration, host rules, platform paths, IP checks, Tor process management, and configurable bundle signature verification.
- Restricted the local HTTP proxy to loopback and unified host policy across HTTP and CONNECT.
- Replaced request-target logging with privacy-conscious activity logging and bounded bidirectional byte accounting.
- Routed the exit-IP checker through the configured proxy with no direct fallback.
- Added supervised Tor lifecycle states, torrc validation, cookie authentication, bootstrap reporting, managed-process identity checks, and NEWNYM cooldown handling.
- Disabled automatic system-proxy changes and repeating identity requests by default.
- Added snapshot-based Windows/GNOME proxy restoration and protection against clobbering external changes.
- Added OpenPGP-signature verification, download limits, and safe tar extraction; bundle archives are no longer required in source control.
- Added versioned user configuration, per-user writable data paths, focused tests, CI, and security/architecture documentation.
- Preserved compatibility adapters for the desktop UI pending a further migration of all legacy UI modules.
