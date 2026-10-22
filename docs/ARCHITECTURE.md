# Architecture

## Components

```mermaid
flowchart TD
  View[PySide6 views] --> Adapter[TorRunner / Runner]
  Adapter --> Manager[TorManager]
  Manager -->|subprocess| Tor[Tor process]
  Manager -->|Stem / authenticated ControlPort| Tor
  View --> Http[HTTP proxy server]
  Http --> Rules[Immutable host-policy snapshot]
  Rules --> Socks[SOCKS5 with remote DNS]
  Socks --> Tor
  Rules -->|explicit exclude only| Direct[Direct socket connection]
  View --> Bundle[Bundle download and signature verification]
  View --> Config[Per-user state / config]
```

## Process lifecycle

`TorManager` owns only the subprocess it creates. It validates the executable and generated torrc, uses Tor's configuration verification mode before launch, redirects child output to a file rather than leaving pipes undrained, and polls the process while waiting for the authenticated ControlPort and bootstrap status. Startup has a deadline. Shutdown requests termination of the managed child, waits a bounded interval, then force-terminates if required.

States are `STOPPED`, `STARTING`, `BOOTSTRAPPING`, `READY`, `STOPPING`, and `FAILED`. `READY` means Tor reported a completed bootstrap, the ControlPort responded after authentication, the control endpoint identified the managed PID, and the SOCKS TCP listener accepted a connection. It does not mean every destination is reachable; the proxied IP check tests a real request separately.

The HTTP proxy is an independent local service. It is loopback-only. HTTP absolute-form requests and HTTPS CONNECT share one hostname policy. Normal traffic goes through the configured SOCKS endpoint with remote DNS; excluded hosts take an explicit direct route. Blocked hosts are rejected before upstream connection attempts.

## Thread boundaries

- Qt widgets are created and updated on the GUI thread.
- `TorRunner` runs blocking supervisor work on a dedicated Python thread and emits Qt signals for logs and failures.
- HTTP requests run in handler threads.
- The traffic tracker drains a bounded byte-event queue and persists aggregate counters periodically.
- Network requests and bundle installation run in UI worker tasks; results/errors return through worker signals.

Avoid calling widgets directly from a worker. Status and log updates should be delivered to Qt slots through signals. Some old UI helpers remain transitional and need the same review as the rest of the UI migration.

## Persistence and resources

- App configuration is stored in per-user configuration directories.
- Runtime state, logs, and downloaded bundles are stored in per-user writable paths.
- Packaged UI assets remain read-only resources.
- JSON settings and host-rule files use temporary files and atomic replacement.
- A downloaded Tor bundle is considered a managed/verified installation only when its detached signature is valid and a verification marker has been written after safe extraction.

## Identity workflow

A manual identity request checks Stem's `get_newnym_wait()`. When Tor reports a cooldown, the UI declines the request and logs the wait; otherwise it sends `NEWNYM`. Neither signal acceptance nor a completed request guarantees an exit-IP change. Existing connections may remain on their current circuits.
