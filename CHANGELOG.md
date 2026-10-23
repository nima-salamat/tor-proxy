# Changelog

All notable changes are recorded here. Dates and release numbers are added only when a release is actually published.

## Unreleased — UI, updater, and security redesign

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

## Unreleased — security and architecture redesign

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
