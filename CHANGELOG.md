# Changelog

All notable changes are recorded here. Dates and release numbers are added only when a release is actually published.

## Unreleased — UI, updater, and security redesign

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
