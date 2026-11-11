# Primary Tor connection failover

The primary Home connection now runs as a pool of isolated Tor workers behind one stable loopback SOCKS5 gateway. The configured Tor SOCKS port remains the gateway endpoint, so the main HTTP proxy, operating-system proxy setting and sing-box System Tunnel continue to use the same address. Each Tor worker has its own SOCKS/Control/DNS listeners, DataDirectory, control cookie and log file. A worker that had reached READY and later exits unexpectedly is retried up to three times with an increasing delay; initial failures are not blindly retried unless another worker is already healthy, avoiding endless loops for a shared bundle or transport problem.

A Tor process is not considered usable merely because it bootstrapped or has an open SOCKS port. Every primary worker is probed independently through its own SOCKS listener using SOCKS5 remote DNS and the Tor Project Check API (`https://check.torproject.org/api/ip`). The response must confirm `IsTor: true`; the exit IP is discarded. A worker becomes eligible only after a successful probe. Probes run in parallel every 20 seconds while the pool is healthy. After a first failed check, the affected pool is rechecked after 5 seconds so a second failure can withdraw a worker promptly. While any worker is unhealthy, recovery checks run every 10 seconds. Two consecutive failed probes withdraw a previously healthy worker; one successful probe brings it back.

The gateway receives only the verified healthy workers. If just one worker is healthy, all new connections use that worker. When multiple workers are healthy, each new SOCKS CONNECT is assigned using a least-active-connection score with latency weighting and round-robin tie handling. A backend that fails its local SOCKS handshake is temporarily deprioritized, and the same CONNECT is attempted against the next available worker. A destination-level refusal is not treated as a Tor worker failure. The gateway holds a backend reservation for the full lifetime of the TCP stream and releases it on close. The loopback SOCKS listener is capped at 256 concurrent sessions and the local HTTP proxy is capped at 128 concurrent clients by default. Excess sessions are rejected instead of creating unbounded daemon threads. Shutdown closes active client sockets and waits for their handlers to leave. Settings exposes active connections per backend, cooldown/failure counts, and SOCKS gateway capacity/rejections.

## Primary bridge distribution

When bridge mode is enabled, TorProxy checks the configured bridge pool once before starting the primary workers when **Auto prune unusable bridges** is enabled. The preflight uses a bounded thread pool; the **Concurrent bridge probes** setting controls the maximum from 1 to 8, and each unique bridge record is tested in its own short-lived Tor process. Only confirmed failures are removed, and only after at least one bridge has completed bootstrap. Inconclusive results are retained. This is a one-time preflight, not a continuous background scan: repeatedly starting temporary Tor processes for every bridge would add avoidable CPU, memory and network load.

After that filtering step, the retained bridge records are split across primary Tor instances. Records with the same explicit bridge fingerprint are kept in the same group, including alternate transport/configuration lines for that identity. Groups are distributed deterministically using their record count as the load weight, so a fingerprint with several alternate transport lines does not count as lightly as a single-record identity. Group boundaries are never split, preserving one-worker ownership of a known fingerprint. If preflight verifies one or more bridge identities, at least one verified group is assigned to each worker; when there are fewer verified groups than workers, those known-working groups are deliberately shared. Remaining groups are spread without overlap where possible. Exact duplicate records are parsed once. If preflight is disabled or yields no verified records, the whole pool is balanced without overlap when enough distinct groups exist, and groups are reused only when the pool is smaller than the worker count. The full master list remains in the user's configuration; only each worker's generated torrc receives its assigned subset. Settings shows the number of bridge records assigned to each instance and whether verified bridge groups needed to be shared. A restarted worker retains its original bridge shard.

Distribution still applies when automatic pruning is disabled, but no preflight filtering is performed in that case. Tor itself remains responsible for selecting and using bridges within each worker; TorProxy partitions the configured bridge pool between independent Tor processes, it does not try to assign individual circuits to bridge lines.

The Home status and instance summary use the network-verified healthy count, not merely Tor process state. For independent profiles, the pool also checks the child process itself: a process that exits while its manager still says READY is immediately shown as failed/unhealthy, excluded from further probes, then reconciled under the per-service lifecycle lock. Reconciliation closes the stale controller and releases the DataDirectory lock before the UI offers a clean stopped state. The monitor never races a service's start operation. If all workers lose Tor Check connectivity after the pool has worked, TorProxy keeps the gateway and periodically probes for recovery rather than immediately tearing down the whole connection. At initial startup, the app allows a 90-second network-verification window after Tor bootstrap before reporting a failed connection.

Health probes ignore system `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` environment variables so they cannot silently bypass the worker being measured. Responses are streamed with a 16 KiB size limit, redirects are rejected, TLS verification stays enabled, and exit IP values are not retained. The health check depends on the Tor Project Check service. If that single verification service is unreachable, workers may be temporarily considered unhealthy even when another destination would work; consecutive-failure hysteresis and periodic recovery probes reduce flapping but cannot remove this common dependency. A worker that exits is excluded from new connections while remaining verified workers keep serving traffic.

Failover is per new TCP connection, not live migration. An already-established TCP/HTTPS stream remains tied to the Tor worker that accepted it and can fail if that worker exits; the application must reconnect. Tor workers also have separate Tor state, circuits and guards, so a failover can use a different circuit/exit. A shared bridge transport or bundle failure can still affect every worker.

Configure **Settings → Tor Services → Primary connection redundancy → Main Tor instances** to choose 1–4 primary Tor workers (default: 2). The setting applies on the next connection. The same page shows each worker's current state and verified Tor Check latency. More workers consume additional memory, CPU, sockets and network capacity. Setting it to 1 disables redundancy.

## Independent Tor profiles

The optional profiles described below are separate from the primary connection pool. They are manually configured endpoints for applications or identities and do not participate in main-connection failover. They are intentionally **not load-balanced with one another**: combining their traffic would defeat the separate identity and application boundaries. Each profile gets its own end-to-end Tor Check probe after startup and every 20 seconds while running. It is marked network-healthy only when its own SOCKS port reaches Tor Check and receives `IsTor: true`; one transient failure is shown as degraded, two consecutive failures mark it unhealthy, and a subsequent successful probe restores healthy status. Settings displays the verified RTT or a privacy-safe error summary and refreshes the cards while the page is visible. The monitor also detects a Tor child that exited while its manager still reported READY, closes the stale ControlPort controller, releases that profile's DataDirectory lock, and presents the profile as stopped so it can be started again. Isolated profiles are not silently restarted or moved into the primary load balancer.


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
