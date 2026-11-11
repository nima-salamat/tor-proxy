# Developer Tor · Onion Hosting

Developer Tor is a separate Tor client owned by TorProxy's Home controller. It is designed only to publish local TCP applications as v3 Onion Services. It does not reuse the main proxy Tor process or the Custom Tor profile pool.

## Runtime boundary

The dedicated runtime has its own:

- Tor process and `DataDirectory` at the per-user `developer-tor` data directory;
- torrc, ControlPort, authentication cookie and `tor.log`;
- ControlPort bound only to `127.0.0.1`, with cookie authentication;
- lifecycle, bootstrap status and process cleanup.

Its torrc explicitly uses `SocksPort 0` and no DNSPort. Main Tor bridges, bridge health decisions, SOCKS/HTTP ports, Custom Tor profiles and circuit controls are not copied into Developer Tor. This is a separate Tor client process, not a relay or exit node. Process separation does not make a full operating-system sandbox.

The Home controller owns the `OnionHostingManager`. Navigating away from the page or closing the window with X only hides TorProxy to the system tray; the runtime remains active. Explicit Exit stops Developer Tor together with the other application-owned child processes.

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
