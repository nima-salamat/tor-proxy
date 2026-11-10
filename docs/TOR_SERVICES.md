# Multiple isolated Tor services

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
