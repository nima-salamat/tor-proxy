# TorProxy documentation

This folder contains the technical guides for TorProxy. The root [README](../README.md) is the short project introduction; use this page to find the right guide without having to read every document.

## Choose a guide

| I want to... | Read |
|---|---|
| Understand the Tor runtimes, worker pool, failover, and bridge distribution | [Tor services](TOR_SERVICES.md) |
| Create an Onion Service or configure Developer Tor | [Developer Tor & Onion Hosting](ONION_HOSTING.md) |
| Understand what traffic is and is not protected, and review the trust boundaries | [Security design](SECURITY.md) and the root [security policy](../SECURITY.md) |
| Change ports, host rules, bridges, storage paths, or bundle verification settings | [Configuration reference](CONFIGURATION.md) |
| Understand how the application components, workers, and lifecycle fit together | [Architecture](ARCHITECTURE.md) |
| Fix a connection, bridge, browser, bundle, or system-tunnel problem | [Troubleshooting](TROUBLESHOOTING.md) |
| Review the redesign, audit findings, tests, and known limitations | [Project report](PROJECT_REPORT.md) |
| Contribute code or documentation | [Contributing guide](../CONTRIBUTING.md) |

## How the Tor runtimes differ

TorProxy has three distinct runtime concepts. They are intentionally kept separate:

- **Main Tor** is the primary connection used by the Home dashboard, stable SOCKS5 gateway, local HTTP proxy, and optional system tunnel. It can supervise multiple worker processes behind one endpoint.
- **Custom Tor** adds independent Tor profiles for applications that need separate Tor state, listeners, bridge choices, or identity boundaries. These profiles are not mixed into the Main Tor load balancer.
- **Developer Tor** is a separate Tor process dedicated to publishing local TCP services as v3 Onion Services. It is not an application-facing SOCKS proxy and does not reuse Main Tor or Custom Tor process state.

See [Tor services](TOR_SERVICES.md) and [Onion Hosting](ONION_HOSTING.md) for the operational details.

## Documentation conventions

- UI paths such as **Home → Developer Tor → Settings** refer to the current desktop navigation.
- A setting that applies only after a restart is called out in its guide; do not assume that editing a saved preference mutates a running Tor process.
- Security-sensitive behavior is described as implemented behavior, not as a promise of anonymity or complete traffic containment.
- Update the relevant guide whenever a feature changes its behavior, supported platforms, defaults, migration, or security boundary.

## Current support summary

The current portable desktop packages target Windows x64 and glibc-based Linux x86_64. The optional system tunnel is supported on those same desktop targets and carries supported TCP traffic only. macOS, Android, ARM, and musl-based Linux are not part of the current packaged support matrix.

For build and test evidence, consult the [project report](PROJECT_REPORT.md) and the live [GitHub Actions workflows](https://github.com/nima-salamat/tor-proxy/actions).
