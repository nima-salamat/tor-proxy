# Developer Tor · Onion Hosting

Developer Tor is a separate Tor client owned by TorProxy's Home controller. It is designed only to publish local TCP applications as v3 Onion Services. It does not reuse the main proxy Tor process or the Custom Tor profile pool.

## Runtime boundary

The dedicated runtime has its own:

- Tor process and `DataDirectory` at the per-user `developer-tor` data directory;
- torrc, ControlPort, authentication cookie and `tor.log`;
- ControlPort bound only to `127.0.0.1`, with cookie authentication;
- lifecycle, bootstrap status and process cleanup.

Its torrc explicitly uses `SocksPort 0` and no DNSPort. Developer Tor has its own saved network preferences and uses a direct connection by default. Main Tor bridges are never inherited automatically: the user may explicitly select the saved Main bridge list, or configure a separate Developer Tor bridge list. Only the bridge records are reused; the Main Tor process, DataDirectory, listeners, bridge-health decisions and control state are not shared. Custom Tor profiles and circuit controls also remain separate. This is a separate Tor client process, not a relay or exit node. Process separation does not make a full operating-system sandbox.

The Home controller owns the `OnionHostingManager`. Navigating away from the page or closing the window with X only hides TorProxy to the system tray; the runtime remains active. Explicit Exit first cancels any in-flight Developer Tor bootstrap, waits for the start operation to release its lifecycle lock, and then verifies that the owned Tor process and DataDirectory lock are gone. If another shutdown step fails and the application stays open, the Developer Tor lifecycle can be resumed.

## Developer Tor network settings

Open **Home → Developer Tor → Settings** to configure this runtime independently.

- **Direct** is the default and does not configure bridges.
- **Custom bridges** accepts separately stored obfs4, Snowflake, WebTunnel, meek_lite or vanilla Bridge records. The shared Bridge parser validates and normalizes each record before Tor starts.
- **Main bridges** explicitly reads the saved Main Tor bridge-enabled flag and bridge list when Developer Tor starts. Main bridge mode must be enabled. This is a one-way settings reuse: it does not share the Main Tor process, DataDirectory, ControlPort, SOCKS listener, health state or bridge pruning. Changes to either list apply to Developer Tor only after its next restart.
- WebTunnel SNI imitation, MaxCircuitDirtiness, NewCircuitPeriod, startup/shutdown timeouts and IPv4/IPv6 preferences are saved separately. At least one IP family must remain enabled.
- An optional upstream SOCKS5 or HTTP CONNECT proxy can be configured for Tor's own network connections. This is not a local proxy listener for applications. When authentication is used, the username/password pair is stored in `developer-tor/keys/network-proxy.json`, outside `config.json`; on Unix the file is mode `0600` in a mode `0700` directory. The generated torrc is also written with restrictive permissions. On Windows the files inherit the per-user application-data ACL. A proxy hostname is resolved by the local system before Tor connects to it.

The runtime card reports the selected connection mode, configured bridge transports, first-hop identities observed on built circuits, enabled address families and upstream proxy type. First-hop verification is based on authenticated ControlPort circuit data; configured bridge records alone are not presented as proof of an active bridge.

Changing network preferences while Developer Tor is running does not mutate the live process. Restart the Developer Tor runtime to apply them. The current version does not automatically prune Developer Tor bridges; bridge failures remain visible in its own Tor log and the saved list is preserved.

When a configured bridge list includes WebTunnel, TorProxy adds the Go-documented `tlssecpmlkem=0` compatibility setting to the Tor child-process environment. This disables only the two SecP/ML-KEM groups enabled by Go 1.26 by default, restoring the pre-Go-1.26 default key-exchange set for Lyrebird. Other `GODEBUG` entries are preserved, the application environment is not modified, and the setting is not added for direct/obfs4-only runtimes. TorProxy does not disable the older X25519/ML-KEM group or classical TLS curves.

WebTunnel peer-side TLS alerts such as `remote error: tls: illegal parameter` or an unrecognized handshake reply are treated as inconclusive connection attempts. Tor is allowed to try the configured bridges for the full startup window; a timeout does not classify all bridges as dead or delete records. The separate Go/TLS error `CurvePreferences includes unsupported curve` is a local Lyrebird runtime incompatibility: when every configured bridge uses WebTunnel, TorProxy reports it immediately rather than retrying the same failing transport. If another transport such as obfs4 or Snowflake is configured, bootstrap continues so Tor can try that alternative. Bridge-health probes preserve records for both categories of error.

## Diagnosing HTTP 502 responses

The Onion Service forwarder is a TCP mapping: it passes the visitor's connection to the configured local host and port. It does not generate an HTTP 502 page, choose an application upstream, or route visitor requests through Developer Tor's SOCKS listener. Developer Tor intentionally has `SocksPort 0`; it publishes the service through Tor's ControlPort instead of acting as a browser proxy.

TorProxy's separate local HTTP proxy can return the exact response `502 Upstream connection failed` when its own outbound connection fails. Requests sent through that proxy use the **Main Tor** SOCKS endpoint for normal Tor routes, or a direct socket for a host explicitly matched by the Exclude rules. Developer Tor being READY does not mean Main Tor is READY, and starting Developer Tor does not make the Main Tor SOCKS endpoint available.

The proxy event log records the destination host and port, chosen route, upstream endpoint, exception class and a bounded exception summary for these failures. It intentionally omits the HTTP path and query string. Interpret it as follows:

- `route=tor` with `Tor SOCKS endpoint 127.0.0.1:<port>` and a connection-refused error means the Main Tor SOCKS/gateway listener is unavailable or not accepting connections. Start Main Tor and wait for its verified READY state.
- A SOCKS protocol error such as host/network unreachable means the Main Tor SOCKS listener answered but could not establish that destination. Inspect the Main Tor log, bridge/circuit state and destination availability.
- `route=direct` means the destination matched an Exclude rule and bypassed Tor by design; test ordinary direct connectivity and review the Exclude entry.

For an Onion Service page, test the configured local target directly on the same computer first (for example, `curl.exe -i http://127.0.0.1:<local-port>/`). If that returns the same 502, the error is coming from the local web application or its own reverse proxy, not from the Onion Service transport. If the local request works, repeat it with the onion hostname as the Host header; virtual-host or reverse-proxy rules may behave differently for that host. When opening the onion address through TorProxy's local HTTP proxy, the visitor-side request travels through Main Tor; use Tor Browser or another independently configured Tor client to test the published service without that additional Main Tor proxy hop.

## Onion Service model

One Developer Tor process can own multiple v3 Onion Services. Each service has a unique local profile ID, a name, a local loopback target, a virtual Onion port, a persistent/temporary lifetime, public/private access and an Auto Start preference.

Only literal loopback IP addresses (`127.0.0.1` addresses or `::1`) are accepted. Hostnames, wildcard addresses, LAN addresses and arbitrary remote targets are rejected. Before adding the service, TorProxy checks that the selected local TCP port accepts a connection. Start the local web server first.

Services are created and removed through the authenticated ControlPort using `ADD_ONION` and `DEL_ONION`. `Flags=Detach` keeps a service independent from the lifetime of the individual controller connection. A Tor process exit still removes every service published by that process.

## Address and key persistence

Persistent Onion Services reuse their Tor-generated `ED25519-V3` private key after stopping or restarting Developer Tor, preserving the v3 address. Private keys are stored outside `config.json` under `developer-tor/keys`; on Unix the key directory is restricted to mode `0700` and each key file to `0600`. Windows inherits the access-control policy of the per-user application data directory.

The normal configuration stores only non-secret service metadata, the v3 address identifier and (for private services) the X25519 public key. Temporary service profiles and their key material exist only in memory and are discarded when Developer Tor is stopped or TorProxy exits.

A persistent key file that is missing or damaged is treated as an error. TorProxy does not silently generate a replacement key, because that would change the Onion address.

## Public and private access

Public services can be visited by anyone who knows the address. Private services use v3 client authorization: Tor receives a Base32 X25519 public key through `ADD_ONION ClientAuthV3=...`, while TorProxy retains the matching Base32 private key in the protected key file.

The **Copy client key** action copies the Tor client authorization line:

`<56-character-onion-id>:descriptor:x25519:<base32-private-key>`

This is a secret credential. Share it only with the intended visitor, and never paste it into issue reports, logs or public chat. The address alone is not enough to visit a private service. Tor Browser users can import the matching `.auth_private` credential according to Tor Project's client authorization instructions.

The first version manages one client authorization key per private Onion Service. Multiple named clients, key revocation UI and key rotation are future work.

## Operations and lifecycle

1. Start Developer Tor and wait until its bootstrap reaches 100%.
2. Start the local website/API on `127.0.0.1` or `::1`.
3. Create the Onion Service and choose its virtual port and access mode.
4. Start the service. TorProxy checks the local listener, then sends `ADD_ONION`.
5. Stop or delete an individual service without restarting other Onion Services.
6. Restarting Developer Tor restores persistent services with their saved identities when Auto Start is enabled. Temporary services are discarded when the runtime stops.

The runtime log is separate from Main Tor and Custom Tor logs. The page's service-level Logs shortcut opens this Developer Tor runtime log; application/web-server logs remain owned by the hosted application.

## Privacy and deployment warnings

An Onion address does not guarantee that a hosted application is anonymous. The application can expose identifying information through content, headers, analytics, uploaded files, error pages, server logs or external resources. TorProxy forwards to a local process; it does not audit or sandbox that application.

The local destination must be trusted. Do not bind a development server to a public interface for convenience; TorProxy deliberately accepts loopback-only destinations. Running a second Tor process uses additional memory and network resources, and it performs its own bootstrap.
