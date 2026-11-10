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

## UI integration status

The existing Home connection button still controls the primary Tor service. The pool is a tested core API for additional isolated services; a profile-management UI and routing individual applications to each profile are not part of this change yet. Until those screens are added, additional services must be registered and managed by code using the API above.
