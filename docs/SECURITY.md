# Security Design

## Local listeners

The HTTP proxy constructor rejects non-loopback IPs. The GUI binds it to `127.0.0.1`. Tor SOCKS, ControlPort, and optional DNSPort are also configured explicitly on `127.0.0.1`. Never expose these services to a LAN or public interface.

The ControlPort is cookie-authenticated, with the cookie stored under Tor's user-data directory. Stem negotiates the supported cookie-authentication method. After authentication, TorProxy checks that the ControlPort's reported process PID matches the child it launched; a port held by a different Tor process is not accepted as the managed process.

## Proxy routes and DNS

HTTP requests and CONNECT tunnels share block/exclusion evaluation. Normal destinations go to the local SOCKS5 listener with remote DNS; TorProxy does not resolve those destination names itself. Blocked destinations are rejected. Exclusions intentionally call the direct socket API and can disclose destination DNS and traffic outside Tor. The direct route is opt-in by rule, never a fallback after Tor proxy failure.

A loopback HTTP proxy is not a firewall. Applications can ignore it, use another network API, or send identifying application-layer metadata. The project cannot prevent all traffic from leaving the machine outside Tor.

## IP verification

The IP-check path requires a configured proxy, disables environment proxy inheritance, applies explicit HTTP/HTTPS proxy settings, uses connection/read timeouts, rejects redirects, and validates the response as an IP address. A proxy error or malformed response is a failed/unverified result, never a direct request. The check service observes the request; the result says only which address that request used.

## System proxy changes

Changing global settings is a manual user action. The app stores relevant original Windows Internet Settings values (including binary settings values) or available GNOME proxy keys before applying its local endpoint. Clearing/restoring checks that current settings still match the app-applied settings. If another actor changed them, restoration is refused to avoid clobbering those changes. Windows/GNOME behavior is covered with mocks; actual OS smoke tests remain necessary. macOS support is not implemented.

## Bundle trust and extraction

The downloader always restricts archive transfers to approved Tor distribution hosts over HTTPS and safely extracts regular files only. OpenPGP signature verification is optional and is off by default in Settings → Advanced. When enabled, the downloader requires the matching detached `.asc`, imports the key into a temporary GnuPG home, validates the full pinned primary fingerprint, and fails closed on missing GnuPG, missing/invalid signature, unexpected redirects, failed downloads, unsupported platforms, or malformed versions. When disabled, the publisher is not cryptographically authenticated; the bundle is explicitly marked `https_only` and the UI labels it `HTTPS ONLY · UNSIGNED`. HTTPS does not provide the same integrity/authenticity guarantee as the Tor signing key.

Tar extraction uses a temporary sibling directory in both modes, rejects absolute/traversal paths, links, special file types, duplicate extracted files, and expansion above a configured size limit. It refuses to overwrite an existing destination. The local marker records the archive SHA-256 digest and whether OpenPGP verification actually succeeded; HTTPS-only installs are not represented as signed.

When OpenPGP verification is enabled, the pinned key is Tor Browser Developers' primary signing key, fingerprint `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`. Consult the [official Tor signature guide](https://support.torproject.org/tor-browser/getting-started/verifying-tor-browser/) for current guidance on keys and subkeys.

## Configuration, files, and logs

Configuration and host-rule writes use atomic replacement and restrictive file modes where supported. Runtime paths are per-user. Logs avoid full request targets and query strings but should not be treated as a secret vault. User-supplied Tor executables are an explicit trust decision and should come from a source the user trusts.

## Anonymity limitations

TorProxy does not guarantee anonymity, a different IP after `NEWNYM`, or no DNS leaks for directly excluded hosts while the Kill Switch is disabled. The loopback HTTP proxy does not transparently capture and redirect every application; the optional Kill Switch instead blocks direct outbound traffic. Browsers and other applications can still leak identity by design or configuration. Use a correctly configured application and verify the route actually used.


## System-wide Kill Switch

The optional Kill Switch is an operating-system firewall policy, not a system-proxy preference. When enabled, TorProxy applies an outbound default-deny policy and permits only the managed Tor process (plus narrowly scoped local network control traffic). Applications must still be configured to use TorProxy's loopback HTTP proxy; the Kill Switch does not transparently proxy arbitrary applications. Applications that bypass the proxy are blocked rather than silently routed directly.

On Windows, TorProxy uses Windows Defender Firewall. It snapshots the Domain, Private and Public profile enabled/default-outbound settings and the enabled local outbound Allow rule names before applying outbound Block. It disables the saved local outbound Allow rules and adds exact-program exceptions for the selected Tor executable and, when applicable, Lyrebird. DHCP and IPv6 Neighbor Discovery exceptions are narrow protocol/port rules. If Group Policy or another policy store contributes enabled outbound Allow rules that TorProxy cannot safely own, activation fails closed. Existing profile state and saved local rules are restored only when the managed profile policy can still be identified. External policy changes may require manual recovery; the original snapshot is intentionally retained rather than overwritten.

On Linux, TorProxy requires nftables, PolicyKit (\`pkexec\`), systemd user scopes, unified cgroup v2, and nftables/kernel support for \`socket cgroupv2\`. A persistent system service installs an \`inet\` output chain with policy \`drop\` before normal network startup. Tor is launched in a dedicated transient systemd scope; only sockets associated with that scope's cgroup are exempted. TorProxy deliberately does not exempt the desktop user's UID, because that would also exempt browsers and unrelated applications running as the same user. If cgroup isolation or nftables syntax validation is unavailable, activation is rejected.

The Kill Switch remains active after Tor stops, TorProxy exits, or the machine restarts. It is removed only by explicitly disabling the setting and successfully restoring the saved policy. This is intentional: a stopped Tor process must not cause the machine to resume unprotected outbound access. On Linux the persistent service owns only the \`torproxy_killswitch\` table and its own unit/files. On Windows it owns only the named TorProxy rule group plus the firewall profile values and local outbound rules recorded in its snapshot.

Direct Exclude Host rules are treated as blocked while the Kill Switch preference is enabled. Bundle downloads and other TorProxy features that attempt direct network access may also be unavailable while protection is active; disable the Kill Switch deliberately before performing such operations outside Tor.

The Kill Switch does not promise anonymity, protect against application-layer identification, block every non-IP link-layer protocol, or make a manually configured application safe if it ignores the HTTP proxy. Firewall policies may also be constrained by enterprise management or other firewall software. Verify the actual firewall state on the target machine before relying on it.
