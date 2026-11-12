## Custom Tor dashboard and lifecycle

The **Home → Custom Tor** shortcut opens the dedicated profile-management page. It has its own **Back to Home** action and contains profile creation/editing, service cards, Start/Stop controls, bulk actions and per-profile live Logs. The **Settings → Custom Tor** section is reserved for persistent resource preferences: primary Tor instance count, parallel bridge-probe workers and concurrent custom-service operations. Profile details (ID, display name, SOCKS/Control/DNS ports, bridge inheritance or custom bridges, and DataDirectory) are edited in the same custom-framed dialog from the management page.

Profile-list changes are validated and written together through the configuration store's atomic update_many operation. The app restores the saved profiles from its normal per-user configuration on the next launch; each profile retains its own automatically assigned log path under tor-services/<service-id>/tor.log unless a custom path is configured. The Logs action opens that file even before the first Tor process has created it and follows new output while the process starts and runs.

A normal **Stop** request is available while a service is starting. It marks startup for cancellation, signals the current Tor process and reconciles under the service start lock so a late launch cannot leave a child running. **Force stop** escalates independently of an in-progress graceful stop and immediately kills the managed Tor process (and its dedicated systemd scope when one is active). A graceful Stop already attempts a forced kill after its configured shutdown timeout; the explicit Force stop action skips that wait.

Closing the main window with **X** hides TorProxy to the system tray, so custom services intentionally continue running in the background with the application. Choosing **Exit TorProxy** performs application cleanup and stops all registered isolated Tor profiles before the process exits. If one of those services was already being stopped, the shutdown path joins/escalates that stop rather than reporting a spurious “already stopping” error.

# Primary Tor connection failover

The primary Home connection now runs as a pool of isolated Tor workers behind one stable loopback SOCKS5 gateway. The configured Tor SOCKS port remains the gateway endpoint, so the main HTTP proxy, operating-system proxy setting and sing-box System Tunnel continue to use the same address. Each Tor worker has its own SOCKS/Control/DNS listeners, DataDirectory, control cookie and log file. A worker that had reached READY and later exits unexpectedly is retried up to three times with an increasing delay; initial failures are not blindly retried unless another worker is already healthy, avoiding endless loops for a shared bundle or transport problem.

A Tor process is not considered usable merely because it bootstrapped or has an open SOCKS port. Every primary worker is probed independently through its own SOCKS5H listener. The Tor Project Check API (`https://check.torproject.org/api/ip`) is the authoritative positive verification: `IsTor: true` marks the result as Tor-verified and the exit IP is discarded. If that API is unavailable or returns an unrecognized response, TorProxy checks two independent HTTPS reachability targets through the same managed SOCKS endpoint. At least one fallback target must succeed before the worker is considered reachable-but-unverified; an explicit `IsTor: false` is always a failure. No probe uses environment proxy variables or falls back to a direct route. Each result records the probe class and timing only, never the exit IP or destination response content. Probes run in parallel every 20 seconds while the pool is healthy. After a first failed cycle, the affected pool is rechecked after 5 seconds; while any worker is unhealthy, recovery checks run every 10 seconds. Two consecutive failed multi-target cycles withdraw a previously usable worker; a successful cycle restores it.

The gateway receives usable workers, preferring Tor-verified results and retaining the explicitly marked reachable-but-unverified state when the Check API is unavailable. If just one worker is usable, all new connections use that worker. When multiple workers are usable, each new SOCKS CONNECT is assigned using a least-active-connection score with latency weighting and round-robin tie handling in **Balanced** mode. **Low latency** mode prioritizes the rolling backend quality cost (P50, P95 spread, jitter and recent probe-failure ratio), with a small concurrency penalty to avoid overloading one worker. The setting is available under Settings → Custom Tor configuration and applies immediately to new connections. A backend that fails its local SOCKS handshake is temporarily deprioritized, and the same CONNECT is attempted against the next available worker. A destination-level refusal is not treated as a Tor worker failure. The gateway holds a backend reservation for the full lifetime of the TCP stream and releases it on close. The loopback SOCKS listener is capped at 256 concurrent sessions and the local HTTP proxy is capped at 128 concurrent clients by default. Excess sessions are rejected instead of creating unbounded daemon threads. HTTP shutdown first signals cancellation to active handlers, closes tracked client and upstream sockets (including an upstream SOCKS CONNECT still being established), and makes the bidirectional relay check the stop event every 250 ms instead of sleeping through its full idle timeout. The proxy runner retains its listener references if any handler still cannot be reaped, and the application does not stop Tor beneath that live handler. Settings exposes active connections per backend, cooldown/failure counts, and SOCKS gateway capacity/rejections.

The application shutdown path treats the HTTP listener as a dependency of the primary Tor workers. If a handler cannot be reaped, the primary Tor pool is deliberately kept running and both object references remain available for another cleanup attempt; it is preferable to report an incomplete disconnect rather than silently kill the upstream for a still-running client handler.

## Primary bridge distribution

When bridge mode is enabled, TorProxy checks the configured bridge pool once before starting the primary workers when **Auto prune unusable bridges** is enabled. The preflight uses a bounded thread pool; the **Concurrent bridge probes** setting controls the maximum from 1 to 8, and each unique bridge record is tested in its own short-lived Tor process. Only confirmed failures are removed, and only after at least one bridge has completed bootstrap. Inconclusive results are retained. This is a one-time preflight, not a continuous background scan: repeatedly starting temporary Tor processes for every bridge would add avoidable CPU, memory and network load.

After that filtering step, the retained bridge records are split across primary Tor instances. Records with the same explicit bridge fingerprint are kept in the same group, including alternate transport/configuration lines for that identity. Groups are distributed deterministically using their record count as the load weight, so a fingerprint with several alternate transport lines does not count as lightly as a single-record identity. Group boundaries are never split, preserving one-worker ownership of a known fingerprint. If preflight verifies one or more bridge identities, at least one verified group is assigned to each worker; when there are fewer verified groups than workers, those known-working groups are deliberately shared. Remaining groups are spread without overlap where possible. Exact duplicate records are parsed once. If preflight is disabled or yields no verified records, the whole pool is balanced without overlap when enough distinct groups exist, and groups are reused only when the pool is smaller than the worker count. The full master list remains in the user's configuration; only each worker's generated torrc receives its assigned subset. Settings shows the number of bridge records assigned to each instance and whether verified bridge groups needed to be shared. A restarted worker retains its original bridge shard.

Distribution still applies when automatic pruning is disabled, but no preflight filtering is performed in that case. Tor itself remains responsible for selecting and using bridges within each worker; TorProxy partitions the configured bridge pool between independent Tor processes, it does not try to assign individual circuits to bridge lines.

The Home status and instance summary use the multi-target connectivity result and distinguish Tor-verified from reachable-but-unverified workers; a live Tor process alone is not enough to count as usable. For independent profiles, the pool also checks the child process itself: a process that exits while its manager still says READY is immediately shown as failed/unhealthy, excluded from further probes, then reconciled under the per-service lifecycle lock. Reconciliation closes the stale controller and releases the DataDirectory lock before the UI offers a clean stopped state. The monitor never races a service's start operation. If all workers lose reachability after the pool has worked, TorProxy keeps the gateway and periodically probes for recovery rather than immediately tearing down the whole connection. At initial startup, the app allows a 90-second connectivity-verification window after Tor bootstrap before reporting a failed connection.

Health probes ignore system `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` environment variables so they cannot silently bypass the worker being measured. Responses are streamed with bounded body sizes, redirects are rejected, TLS verification stays enabled, and exit IP values are not retained. The Tor Check API remains the only probe that positively verifies Tor; two independent HTTPS fallbacks can establish reachability when that API has an outage, but the UI labels that state separately. A bounded rolling quality window records P50/P95 end-to-end request latency, inter-sample jitter and probe-failure ratio. These are HTTPS-over-Tor request metrics, not ICMP ping or per-hop packet-loss measurements.

Each primary Tor worker also has a dedicated authenticated ControlPort event monitor. It validates the ControlPort process PID and collects aggregate `CIRC`, `STREAM`, `ORCONN` and `BW` events through a bounded queue. Circuit build durations, circuit failures, stream detach/failure counts, OR-connection failures and byte counters are available in diagnostics. The collector does not retain stream destinations, relay fingerprints, circuit paths or raw event text. Event data is observational; it does not force circuit rotation or alter Tor's internal path-selection and guard algorithms.

Failover is per new TCP connection, not live migration. An already-established TCP/HTTPS stream remains tied to the Tor worker that accepted it and can fail if that worker exits; the application must reconnect. Tor workers also have separate Tor state, circuits and guards, so a failover can use a different circuit/exit. A shared bridge transport or bundle failure can still affect every worker.

Configure **Settings → Tor Services → Primary connection redundancy → Main Tor instances** to choose 1–4 primary Tor workers (default: 2). The setting applies on the next connection. The same page shows each worker's reachability/verification state, rolling latency and circuit diagnostics. More workers consume additional memory, CPU, sockets and network capacity. Setting it to 1 disables redundancy.

## Independent Tor profiles

The optional profiles described below are separate from the primary connection pool. They are manually configured endpoints for applications or identities and do not participate in main-connection failover. They are intentionally **not load-balanced with one another**: combining their traffic would defeat the separate identity and application boundaries. Each profile gets its own multi-target SOCKS probe after startup and every 20 seconds while running. Tor Check `IsTor: true` is marked verified; if Tor Check is unavailable, at least one of two independent HTTPS fallback targets must succeed for a reachable-but-unverified state. One transient failed probe is shown as degraded, two consecutive failed cycles mark it unhealthy, and a subsequent successful cycle restores it. Settings displays the measured request latency or a privacy-safe error summary and refreshes the cards while the page is visible. The monitor also detects a Tor child that exited while its manager still reported READY, closes the stale ControlPort controller, releases that profile's DataDirectory lock, and presents the profile as stopped so it can be started again. Isolated profiles are not silently restarted or moved into the primary load balancer.


TorProxy's core now exposes `TorServicePool` from `torproxy.service_pool`. It manages multiple independent Tor processes; it does not share a Tor data directory or ControlPort between profiles.

## Isolation guarantees

Each registered service gets its own:

- Tor process and generated `torrc`.
- `DataDirectory` and control-authentication cookie.
- SOCKS, ControlPort, and optional DNSPort listener set.
- Tor log file.

The pool rejects duplicate service IDs, overlapping/nested data directories, overlapping log paths, repeated listener ports, and conflicts with application ports supplied through `reserved_ports`. Registration reserves resources even while a service is stopped, so two registered profiles cannot later start on the same listener.

`start_all()` and `stop_all()` run each service operation concurrently with a bounded worker count. A failure is returned against that service ID and does not cancel unrelated services. A service cannot be unregistered while its process or startup operation is active.

## Example

```python
from pathlib import Path

from torproxy.service_pool import TorServicePool
from torproxy.tor_manager import TorSettings

pool = TorServicePool(
    # Reserve the primary Tor listeners and the HTTP proxy listener already
    # owned by the main TorProxy window.
    reserved_ports=(9155, 50152, 59619, 10818),
    max_workers=4,
)

pool.register(
    "personal",
    TorSettings(
        executable=Path(r"C:\TorBundle\tor\tor.exe"),
        socks_port=19155,
        control_port=19156,
        dns_port=19157,
    ),
)
pool.register(
    "work",
    TorSettings(
        executable=Path(r"C:\TorBundle\tor\tor.exe"),
        socks_port=19255,
        control_port=19256,
        dns_port=19257,
    ),
)

start_results = pool.start_all()
# { "personal": None, "work": None } when both started successfully.
print(pool.status())

# Stop only one profile, or stop all independent services concurrently.
pool.stop_service("personal")
stop_results = pool.stop_all()
```

When no paths are supplied in `TorSettings`, the pool assigns separate per-user paths under `data/tor-services/<service-id>` and `logs/tor-services/<service-id>/tor.log`. Pass the main application's listener ports in `reserved_ports` when creating the pool; those are not inferred automatically.

## Manage profiles in the desktop app

Open **Settings → Tor Services** to create and manage profiles without writing Python code.

- **Add Tor service** creates a profile ID and display name, then assigns its SOCKS and ControlPort values. DNSPort is optional; set it to zero to disable it.
- **Bridge source** can inherit the primary Tor service's current bridge settings, or use a profile-specific bridge list. Custom bridge lines are parsed and validated before they are saved.
- **Data directory** can be selected explicitly. Leave it blank to use the isolated default under the per-user `tor-services/<profile-id>` directory. Each profile also receives its own log file automatically.
- **Start / Stop** controls one profile. **Start all / Stop all** starts or stops registered profiles concurrently using the configured service-worker limit. Operations run outside the GUI thread, and one service's failure is reported without cancelling the others.
- **Concurrent bridge probes** controls the number of independent bridge checks used by the primary service's automatic bridge health check. Choose 1–8 workers; the default is 8.
- **Concurrent service operations** controls the number of Tor profiles that Start all / Stop all can operate on at once. Choose 1–8 workers; the default is 4.

The profiles and worker limits are persisted in the normal per-user TorProxy configuration. Profiles are restored into the manager when Settings opens and a compatible Tor Expert Bundle is available. A profile exposes its loopback SOCKS endpoint at `127.0.0.1:<SOCKS port>`; configure the application you want to isolate to use that endpoint. The primary Home connection and system-proxy controls continue to manage the primary Tor service; stopping the primary connection does not stop additional profiles. An explicit **Exit TorProxy** stops all registered isolated services before the app exits.

Editing or removing a profile requires it to be stopped. Removing a profile preserves its DataDirectory and log files so that Tor state is not silently deleted.


## Load-balancer implementation choice

The primary gateway stays protocol-aware and in-process. HAProxy and Envoy are mature general-purpose TCP/HTTP load balancers, but a plain TCP check only proves that a listener accepts connections; it does not verify that a particular SOCKS endpoint exits through Tor. Reproducing TorProxy's per-worker SOCKS probe, privacy-preserving result handling, and lifecycle coordination would require a separate health-check agent and another packaged process. The bounded gateway is therefore retained instead of adding an external load balancer that would not replace the Tor-specific supervision logic.


## Local HTTP proxy shutdown

The HTTP server closes both the client socket and every registered upstream socket before Tor is stopped. New client registration is synchronized with the shutdown flag, preventing a just-accepted connection from slipping past the final socket sweep. Blocking SOCKS connects and direct-route DNS resolution run in daemon workers while the HTTP handler polls the shutdown event; the handler can therefore exit promptly even when Windows does not interrupt a blocking Winsock operation immediately. The handler's socket is closed by the server, and any resolver/connect worker left behind is daemonized and holds no live proxy socket. The application retains service references if an actual handler still fails to leave within the bounded shutdown window.
