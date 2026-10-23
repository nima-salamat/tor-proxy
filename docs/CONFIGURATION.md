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
| `data_usage` | Aggregate proxy byte count | `0` |
| `log_level` | Logging verbosity | `INFO` |

Unknown keys are ignored by the compatibility facade during loading. The newer typed settings model in `src/torproxy/configuration.py` is intended to become the canonical schema as more UI modules migrate.

## Listener defaults and safety

Tor's SOCKS, ControlPort, DNSPort, and TorProxy's HTTP proxy are configured for `127.0.0.1`. Listener ports must be valid and distinct. Do not configure a non-loopback proxy interface.

## Host-rule files

Blocked hosts and direct exclusions are maintained separately in per-user configuration storage. Accepted syntax:

- `example.org` — root domain and subdomains.
- `=example.org` — exactly that hostname.
- `*.example.org` — subdomains only, not the root.

Rules accept hostnames/IP literals, not URLs, user-info, paths, or `host:port` authorities. Unicode hostnames are normalized using IDNA. Block rules take precedence over exclusions.

## Bridge records

Bridge mode accepts complete records for obfs4, Snowflake, or WebTunnel with an IPv4:port or bracketed IPv6:port authority. The shared parser normalizes spacing, removes an optional `Bridge` prefix, splits recognizable adjacent records into separate lines, and deduplicates exact repeated records. Manual paste, QR import, the individual bridge-card list, and Tor configuration validation use the same rules. Unrecognized or incomplete text is reported without overwriting the last valid saved bridge list. Transport executable lookup is relative to the selected bundle; missing executables remain startup errors.

The optional `auto_prune_bridges` preference performs individual, isolated bridge checks before startup, with up to four checks in parallel. Confirmed failures are saved as removed only if another bridge is confirmed working; inconclusive checks and a list with no confirmed success are preserved. This is off by default and can add startup delay.

## System proxy settings

System proxy changes happen only when the user explicitly selects the system-proxy action. The app stores a snapshot and restores it only if it still owns the active values. If another process changes the setting, restoration is refused and requires manual inspection.
