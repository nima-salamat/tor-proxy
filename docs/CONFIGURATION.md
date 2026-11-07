# Configuration Reference

## Storage

The legacy-facing facade stores `config.json` in the user's configuration directory:

- Windows: `%APPDATA%\TorProxy`
- macOS: `~/Library/Application Support/TorProxy/Config`
- Linux: `$XDG_CONFIG_HOME/torproxy` (defaults to `~/.config/torproxy`)

Runtime state and downloaded Tor bundles use per-user data/state directories. Logs are stored under the per-user state directory. These paths respect standard environment overrides. On first launch, an existing root-level `config.json` is imported when available.

Writes use a unique temporary file, restrictive permissions where supported, and atomic replacement. Malformed JSON or invalid values produce a diagnostic instead of being silently treated as valid configuration.

## Legacy keys retained

| Key | Meaning | Default |
|---|---|---|
| `schema_version` | Legacy configuration schema version | `1` |
| `mode` | UI theme, `dark` or `light` | `dark` |
| `bridge` | Enable bridge mode | `false` |
| `auto_prune_bridges` | Independently test bridges before connecting and remove confirmed failures only when another bridge works | `false` |
| `bridges` | User-provided bridge records | empty |
| `tor_port` | Optional SOCKS listener override | automatically chosen when unset/disabled |
| `control_port` | Optional ControlPort override | automatically chosen when unset/disabled |
| `dns_port` | Optional DNS listener override | automatically chosen when unset/disabled |
| `proxy_port` | Optional local HTTP proxy override | automatically chosen when unset/disabled |
| `*_checked` | Whether a manual port override is enabled | `false` |
| `tor_path` | Explicit local Tor executable or bundle directory | unset; discover managed bundles |
| `MaxCircuitDirtiness` | Tor circuit dirtiness in seconds | `600` |
| `newnym_interval` | Legacy preference in milliseconds | `0`; automatic rotation disabled |
| `system_proxy_auto` | Reserved compatibility preference | `false`; never automatically changes OS settings |
| `kill_switch_enabled` | Persistent system-wide outbound firewall protection | `false`; Windows Defender Firewall or Linux nftables/cgroup v2 |
| `data_usage` | Aggregate proxy byte count | `0` |
| `log_level` | Logging verbosity | `INFO` |

Unknown keys are ignored by the compatibility facade during loading. The newer typed settings model in `src/torproxy/configuration.py` is intended to become the canonical schema as more UI modules migrate.

## Listener defaults and safety

Tor's SOCKS, ControlPort, DNSPort, and TorProxy's HTTP proxy are configured for `127.0.0.1`. Listener ports must be valid and distinct. Do not configure a non-loopback proxy interface.

Automatic listener ports are initialized once and stored in the existing `proxy_port`, `tor_port`, `control_port` and `dns_port` fields. They are reused across application launches while available. If another process occupies an automatic port, TorProxy allocates and atomically saves a replacement before connection. When the corresponding `*_checked` flag is enabled, the port is user-pinned: TorProxy reports a conflict rather than silently changing the requested value. The DNSPort is probed against both TCP and UDP binds. These stored values do not reserve sockets while TorProxy is stopped; the connection preflight probes them again immediately before starting the listeners.

Browser-only profiles are stored under the per-user data directory in `browser_profiles/`. Manually added browser executables are recorded in `custom_browsers.json` in the per-user configuration directory. Neither feature modifies the user's normal browser profile or operating-system proxy settings.


## Host-rule files

Blocked hosts and direct exclusions are maintained separately in per-user configuration storage. Both lists use the same host-rule parser and matcher.

- `example.org` — the hostname and all subdomains.
- `=example.org` — exactly that hostname, not its subdomains.
- `*.example.org` — all subdomains at any depth, but not the root hostname. For example, `*.ir` matches `example.ir` and `api.example.ir`.
- `*-api.something.com` — a wildcard inside one DNS label; matches `v2-api.something.com`.
- `api-*.something.com` — matches labels such as `api-v2.something.com`.
- `api.*.example.com` — matches one label in that position, such as `api.eu.example.com`.
- `*example.org` — retained as a legacy shorthand for `*.example.org`.

The `*` character matches zero or more characters within one DNS label; it does not match a dot. Label-glob patterns must match the same number of labels. The special `*.domain` suffix form matches subdomains across any depth. These are glob-style hostname rules, **not regular expressions**; regex syntax such as `?`, `[]`, `+`, or grouping is not supported. Wildcards inside an internationalized label must use its ASCII/IDNA form, although whole IDN labels and IDN suffixes are supported.

Rules accept hostnames/IP literals, not URLs, user-info, paths, or `host:port` authorities. Unicode hostname labels are normalized using IDNA. Block rules take precedence over exclusions. Excluded hosts use a direct connection outside Tor, so only add exclusions when that privacy trade-off is intentional.

## Bridge records

Bridge mode accepts complete records for obfs4, Snowflake, WebTunnel, or meek_lite with an IPv4:port or bracketed IPv6:port authority. The shared parser normalizes spacing, removes an optional `Bridge` prefix, splits recognizable adjacent records into separate lines, and deduplicates exact repeated records. Manual paste, QR import, the individual bridge-card list, and Tor configuration validation use the same rules. Unrecognized or incomplete text is reported without overwriting the last valid saved bridge list. Transport executable lookup is relative to the selected bundle; missing executables remain startup errors.

The optional `auto_prune_bridges` preference performs individual, isolated bridge checks before startup, with up to four checks in parallel. Confirmed failures are saved as removed only if another bridge is confirmed working; inconclusive checks and a list with no confirmed success are preserved. This is off by default and can add startup delay.

## System proxy settings

System proxy changes happen only when the user explicitly selects the system-proxy action. The app stores a snapshot and restores it only if it still owns the active values. If another process changes the setting, restoration is refused and requires manual inspection.


## Kill Switch

`kill_switch_enabled` is an opt-in, persistent firewall preference. Enabling it requires administrator approval and a valid selected Tor executable. Disconnect Tor before enabling it so the firewall can be installed before the managed Tor process starts.

- Windows: administrator/UAC approval, Windows Defender Firewall, and no unmanaged/Group Policy outbound Allow rules that prevent strict verification.
- Linux: PolicyKit (`pkexec`), nftables, systemd user scopes, unified cgroup v2, and support for nftables `socket cgroupv2` matching. UID-wide exceptions are deliberately not used.
- Applications must be configured to use TorProxy's local HTTP proxy. Other applications' direct outbound connections are blocked, not transparently redirected.
- Direct Exclude Host rules are blocked while Kill Switch is enabled.
- The firewall policy intentionally remains active after Tor stops, TorProxy exits, and system restart. Turn the setting off explicitly to restore the saved state. If another administrator or security product changes the firewall policy, restoration may be refused to avoid overwriting external changes.


## Bundle downloads and local imports

When Tor reaches READY, TorProxy's own release-list, artifact, archive, detached-signature, and pinned-key requests use its live local SOCKS5H listener, including remote DNS. Direct bootstrap is a separate, explicitly confirmed operation and is unavailable while the Kill Switch is active. Network failures never trigger an automatic direct fallback.

OpenPGP signature verification is enabled by default. To import a local Tor Expert Bundle, open Bundles → Import .tar.gz and select the exact archive matching this device's OS and architecture. A matching `.asc` file beside it is checked against the pinned Tor key when signature verification is enabled. An import without verified publisher signature is marked `LOCAL · UNSIGNED`, is never mislabeled as an HTTPS download, and requires an explicit trust confirmation before setting it as the default.
