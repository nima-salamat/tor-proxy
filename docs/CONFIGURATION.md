# Configuration Reference

## Storage

The legacy-facing facade stores `config.json` in the user's configuration directory:

- Windows: `%APPDATA%\TorProxy`
- macOS: `~/Library/Application Support/TorProxy/Config`
- Linux: `$XDG_CONFIG_HOME/torproxy` (defaults to `~/.config/torproxy`)

Runtime state and downloaded Tor bundles use per-user data/state directories. Logs are stored under the per-user state directory. These paths respect standard environment overrides. On first launch, an existing root-level `config.json` is imported when available.

Writes use a unique temporary file, restrictive permissions where supported, and atomic replacement. Malformed JSON or invalid values produce a diagnostic instead of being silently treated as valid configuration.

## WebTunnel TLS compatibility

`webtunnel_use_default_tls` defaults to `true` and adds the documented `utls=none` option to WebTunnel Bridge records, selecting Go's native TLS fingerprint instead of uTLS impersonation. Main Tor and Developer Tor have independent settings. It can be disabled when a specific uTLS fingerprint is intentionally required.

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
| `http_proxy_enabled` | Start the HTTP proxy with the primary Tor session | `true` |\n| `http_proxy_bind_all_interfaces` | Bind HTTP proxy to `0.0.0.0` for LAN clients instead of loopback | `false` |
| `*_checked` | Whether a manual port override is enabled | `false` |
| `tor_path` | Explicit local Tor executable or bundle directory | unset; discover managed bundles |
| `MaxCircuitDirtiness` | Tor circuit dirtiness in seconds | `600` |
| `newnym_interval` | Legacy preference in milliseconds | `0`; automatic rotation disabled |
| `system_proxy_auto` | Reserved compatibility preference | `false`; never automatically changes OS settings |
| `kill_switch_enabled` | Legacy preference accepted only when parsing older configuration files; ignored by the current application | `false` |
| `data_usage` | Aggregate proxy byte count | `0` |
| `log_level` | Logging verbosity | `INFO` |

Unknown keys are ignored by the compatibility facade during loading. The newer typed settings model in `src/torproxy/configuration.py` is intended to become the canonical schema as more UI modules migrate.

## Listener defaults and safety

Tor's SOCKS, ControlPort, DNSPort, and TorProxy's HTTP proxy are configured for `127.0.0.1`. Listener ports must be valid and distinct. Do not configure a non-loopback proxy interface.

The HTTP proxy is enabled by default and starts with the primary Tor session; it can be turned off in Settings → Ports without disabling the Tor SOCKS listener or System Tunnel. By default the listener is restricted to `127.0.0.1:<proxy_port>`. Settings → Ports → Allow HTTP proxy connections from the local network opts into binding `0.0.0.0:<proxy_port>` so other devices on the LAN can connect using this computer’s LAN IP (not `0.0.0.0` as the client address). This proxy has no authentication: enabling the option allows every device that can reach the port to relay traffic through Tor. Use only on a trusted private network and configure the OS firewall to restrict source devices; never expose the port to the public Internet. Disabling the option restores loopback-only binding immediately. It supports HTTP requests and HTTPS/raw TCP tunneling through HTTP `CONNECT`. A listening port or successful TCP ping is not proof that Tor is ready: use Settings → Ports → Test HTTP CONNECT to verify an actual HTTPS request through Tor.

For Telegram Android, select HTTP Proxy and enable “Transparent TCP connection” so Telegram uses HTTP `CONNECT` for TCP streams. Telegram client support for HTTP proxy varies by app; Telegram generally lists SOCKS5 and MTProto as its common proxy types, with HTTP available in certain clients.

Automatic listener ports are initialized once and stored in the existing `proxy_port`, `tor_port`, `control_port` and `dns_port` fields. They are reused across application launches while available. If another process occupies an automatic port, TorProxy allocates and atomically saves a replacement before connection. When the corresponding `*_checked` flag is enabled, the port is user-pinned: TorProxy reports a conflict rather than silently changing the requested value. The DNSPort is probed against both TCP and UDP binds. These stored values do not reserve sockets while TorProxy is stopped; the connection preflight probes them again immediately before starting the listeners.

Browser-only profiles are stored under the per-user data directory in `browser_profiles/`. Manually added browser executables are recorded in `custom_browsers.json` in the per-user configuration directory. Neither feature modifies the user's normal browser profile or operating-system proxy settings.


## Host-rule files

Blocked hosts and direct exclusions are maintained separately in per-user configuration storage. Both lists use the same host-rule parser and matcher in the HTTP proxy, the primary Tor SOCKS5 failover gateway, and System Tunnel. New HTTP proxy and SOCKS5 connections use saved changes immediately. The SOCKS5 gateway rejects blocked destinations, connects excluded destinations directly outside Tor, and forwards only ordinary destinations to a Tor worker. System Tunnel reads the files when it starts, so stop and start the tunnel after editing a rule. TUN host rules apply to supported TCP connections only; domain rules rely on FakeIP reverse mapping or HTTP/TLS hostname sniffing, while IP-literal rules match destination IPs. TUN DNS continues to use its configured FakeIP and Tor-routed DoH resolver.

- `example.org` — the hostname and all subdomains.
- `=example.org` — exactly that hostname, not its subdomains.
- `*.example.org` — all subdomains at any depth, but not the root hostname. For example, `*.ir` matches `example.ir` and `api.example.ir`.
- `*-api.something.com` — a wildcard inside one DNS label; matches `v2-api.something.com`.
- `api-*.something.com` — matches labels such as `api-v2.something.com`.
- `api.*.example.com` — matches one label in that position, such as `api.eu.example.com`.
- `*example.org` — retained as a legacy shorthand for `*.example.org`.

The `*` character matches zero or more characters within one DNS label; it does not match a dot. Label-glob patterns must match the same number of labels. The special `*.domain` suffix form matches subdomains across any depth. These are glob-style hostname rules, **not regular expressions**; regex syntax such as `?`, `[]`, `+`, or grouping is not supported. Wildcards inside an internationalized label must use its ASCII/IDNA form, although whole IDN labels and IDN suffixes are supported.

Rules accept hostnames/IP literals, not URLs, user-info, paths, or `host:port` authorities. Unicode hostname labels are normalized using IDNA. Block rules take precedence over exclusions. Excluded hosts use a direct connection outside Tor, so only add exclusions when that privacy trade-off is intentional. In System Tunnel, exclusions affect TCP destination routing; DNS remains on the tunnel's configured resolver.

## Bridge records

Bridge mode accepts complete records for obfs4, Snowflake, WebTunnel, or meek_lite with an IPv4:port or bracketed IPv6:port authority. The shared parser normalizes spacing, removes an optional `Bridge` prefix, splits recognizable adjacent records into separate lines, and deduplicates exact repeated records. Manual paste, QR import, the individual bridge-card list, and Tor configuration validation use the same rules. Unrecognized or incomplete text is reported without overwriting the last valid saved bridge list. Transport executable lookup is relative to the selected bundle; missing executables remain startup errors.

The optional `auto_prune_bridges` preference performs individual, isolated bridge checks before startup, with up to four checks in parallel. Confirmed failures are saved as removed only if another bridge is confirmed working; inconclusive checks and a list with no confirmed success are preserved. This is off by default and can add startup delay.

## System proxy settings

System proxy changes happen only when the user explicitly selects the system-proxy action. The app stores a snapshot and restores it only if it still owns the active values. If another process changes the setting, restoration is refused and requires manual inspection.


## Legacy Kill Switch preference

The `kill_switch_enabled` key remains in the supported-key list so older `config.json` files can be read without losing unrelated settings. The current application does not display this preference, activate an operating-system firewall policy, or use it to gate Tor, direct-exclusion, bundle, or system-tunnel operations.

Persistent firewall rules created by an older release are separate OS state and are not removed by deleting this configuration key. Restore those rules with the recovery controls in the older release that created them; do not delete unrelated firewall state manually.

## Bundle downloads and local imports

When Tor reaches READY, TorProxy's own release-list, artifact, archive, detached-signature, and pinned-key requests use its live local SOCKS5H listener, including remote DNS. Direct bootstrap is a separate, explicitly confirmed operation. Network failures never trigger an automatic direct fallback.

OpenPGP signature verification is optional and disabled by default. Tor Expert Bundles download from the approved official HTTPS endpoints and are safely extracted without requiring GnuPG or a detached signature. To opt into publisher authentication, enable Verify Tor bundle signatures with OpenPGP (GnuPG) in Settings → Advanced. To import a local Tor Expert Bundle, open Bundles → Import .tar.gz and select the exact archive matching this device's OS and architecture. A matching `.asc` file beside it is checked against the pinned Tor key when signature verification is enabled. An import without verified publisher signature is marked `LOCAL · UNSIGNED`, is never mislabeled as an HTTPS download, and requires an explicit trust confirmation before setting it as the default.
