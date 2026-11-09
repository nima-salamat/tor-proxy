# Security Design

## Local listeners

The HTTP proxy constructor rejects non-loopback IPs. The GUI binds it to `127.0.0.1`. Tor SOCKS, ControlPort, and optional DNSPort are also configured explicitly on `127.0.0.1`. Never expose these services to a LAN or public interface.

The ControlPort is cookie-authenticated, with the cookie stored under Tor's user-data directory. Stem negotiates the supported cookie-authentication method. After authentication, TorProxy checks that the ControlPort's reported process PID matches the child it launched; a port held by a different Tor process is not accepted as the managed process.

## Proxy routes and DNS

HTTP requests and CONNECT tunnels share block/exclusion evaluation. Normal destinations go to the local SOCKS5 listener with remote DNS; TorProxy does not resolve those destination names itself. Blocked destinations are rejected. Exclusions intentionally call the direct socket API and can disclose destination DNS and traffic outside Tor. The direct route is opt-in by rule, never a fallback after Tor proxy failure.

A loopback HTTP proxy is not a firewall. Applications can ignore it, use another network API, or send identifying application-layer metadata. The project cannot prevent all traffic from leaving the machine outside Tor.

## Browser launch

The Home launcher starts detected browsers with a dedicated TorProxy-owned profile and a single local HTTP proxy endpoint. Chromium receives only the `--proxy-server` endpoint; TorProxy does not add an explicit `direct://` route to Chromium's proxy argument. Firefox's dedicated profile is configured for manual HTTP and HTTPS proxying with no added proxy-bypass list and `network.proxy.failover_direct=false` (which disables Firefox's direct failover for system requests); its ICE preferences restrict non-proxied WebRTC candidates. Chromium is launched with `--webrtc-ip-handling-policy=disable_non_proxied_udp`. Browser start is blocked until Tor is verified READY and the loopback HTTP proxy accepts a connection.

This is not a complete browser traffic firewall. A normal browser may still use protocol paths or application features that do not honor its HTTP proxy, including extension traffic, QUIC or other native networking paths. Chromium's proxy subsystem also has its own failure/bad-proxy handling; the absence of a `direct://` entry in the launch argument is not a guarantee that every browser subsystem fails closed. TorProxy applies browser-level WebRTC restrictions by default, but these are best-effort browser controls, not an OS firewall. Browser fingerprinting and identifying account state are not neutralized. TorProxy therefore does not claim that this feature offers Tor Browser's protections or guarantees anonymity.


## IP verification

The IP-check path requires a configured proxy, disables environment proxy inheritance, applies explicit HTTP/HTTPS proxy settings, uses connection/read timeouts, rejects redirects, and validates the response as an IP address. The same explicit-route rule applies to TorProxy-owned release discovery, artifact listings, archive/signature transfers, and pinned-key retrieval: when Tor is READY they use the live SOCKS5H endpoint and remote DNS. A direct bootstrap connection requires a separate user confirmation for that operation and never occurs as a failure fallback. A proxy error or malformed IP-check response is a failed/unverified result, never a direct request. The check service observes the request; the result says only which address that request used.

## System proxy changes

Changing global settings is a manual user action. The app stores relevant original Windows Internet Settings values (including binary settings values) or available GNOME proxy keys before applying its local endpoint. Clearing/restoring checks that current settings still match the app-applied settings. If another actor changed them, restoration is refused to avoid clobbering those changes. Windows/GNOME behavior is covered with mocks; actual OS smoke tests remain necessary. macOS support is not implemented.

## Bundle trust and extraction

The downloader always restricts archive transfers to approved Tor distribution hosts over HTTPS and safely extracts regular files only. OpenPGP signature verification is optional and disabled by default in Settings → Advanced. By default, the downloader uses approved Tor Project HTTPS distribution hosts and performs the archive safety checks below without requiring GnuPG or a detached `.asc` file. In this mode the publisher's OpenPGP identity is not authenticated; the bundle is marked `https_only` and the UI labels it `HTTPS ONLY · UNSIGNED`. Users can opt in to OpenPGP verification; when enabled, the downloader requires the matching detached `.asc`, imports the key into a temporary GnuPG home, validates the full pinned primary fingerprint, and fails closed on missing GnuPG or a missing/invalid signature. HTTPS does not provide the same publisher-authentication guarantee as the Tor signing key.

Tar extraction uses a temporary sibling directory in both modes, rejects absolute/traversal paths, links, special file types, duplicate extracted files, and expansion above a configured size limit. It refuses to overwrite an existing destination. The local marker records the archive SHA-256 digest and whether OpenPGP verification actually succeeded. Manual imports without a matching verified signature use a distinct `local_unverified` marker; they are not mislabeled as HTTPS downloads or signed installs.

When OpenPGP verification is enabled, the pinned key is Tor Browser Developers' primary signing key, fingerprint `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`. Consult the [official Tor signature guide](https://support.torproject.org/tor-browser/getting-started/verifying-tor-browser/) for current guidance on keys and subkeys.

## Configuration, files, and logs

Configuration and host-rule writes use atomic replacement and restrictive file modes where supported. Runtime paths are per-user. Logs avoid full request targets and query strings but should not be treated as a secret vault. User-supplied Tor executables are an explicit trust decision and should come from a source the user trusts.

## Anonymity limitations

TorProxy does not guarantee anonymity, a different IP after `NEWNYM`, or protection for directly excluded hosts. The loopback HTTP proxy does not transparently capture and redirect every application, and this release does not provide an operating-system Kill Switch or default-deny firewall. Browsers and other applications can still use direct routes or leak identity by design or configuration. Use a correctly configured application and verify the route actually used.


## Legacy firewall configuration

The current desktop application no longer exposes or activates the optional system-wide Kill Switch. The `kill_switch_enabled` key is retained only for backwards-compatible parsing of old configuration files and is not consulted by current proxy, Tor, bundle, or tunnel flows. The absence of a firewall feature is deliberate: the system tunnel must not depend on Kill Switch rules, WFP interface exceptions, or nftables output exceptions.

A firewall policy that was created by an older TorProxy release may remain on the operating system after upgrading, because persistent Windows Firewall/WFP and Linux nftables resources outlive the application process. This release does not manage or automatically remove those legacy resources. Before relying on normal connectivity after upgrading from a release where Kill Switch was enabled, restore that old policy using the recovery controls in the older TorProxy release. Do not delete unrelated firewall rules or nftables tables manually.

## System-wide tunnel boundaries

The optional TUN feature is TCP-only because TorProxy uses Tor's local SOCKS5 listener and Tor SOCKS does not provide an arbitrary UDP transport. sing-box rejects user UDP traffic in the route table; DNS is the explicit exception because TUN DNS packets are hijacked into the DNS module and its HTTPS resolver is dialed over the Tor SOCKS outbound. This is intentionally fail-closed rather than allowing QUIC, game, VoIP, or other UDP traffic to escape directly.

The sing-box process and the managed Tor/bridge executables bypass TUN routing so Tor can establish its own relay connections without being fed back into itself. This means Tor itself needs its own direct network route to reach relays. The TUN is a routing mechanism, not a default-deny firewall; it does not create Windows Firewall/WFP rules, Linux nftables output exceptions, or a system-wide egress block.

Tunnel release checks and engine downloads use the local Tor SOCKS5H listener whenever Tor is READY. When Tor is not ready, each such operation requires separate explicit consent for a direct bootstrap request. TorProxy never retries a failed Tor-routed request directly. The downloaded archive is accepted only after its SHA-256 matches the platform/version digest pinned in the application; an upstream version without a pinned digest is visible but cannot be installed.

The sing-box helper accepts only a pinned release archive for the current supported platform and verifies that the executable it will launch is byte-for-byte the executable in that archive. It validates the generated configuration before starting the privileged process, records PID/image/start-time identity, and refuses to terminate a process whose identity does not match. A dead stale PID record may be removed; a live mismatched PID is never killed or adopted. The GUI must not disconnect Tor or exit while a tunnel process remains active or unverified.
