# Security Policy

## Reporting a vulnerability

Please do not disclose exploitable vulnerabilities in public issues.

Use GitHub's private vulnerability reporting feature for this repository, if available. Otherwise, contact the repository maintainer through a verified GitHub account and request a private disclosure channel. Do not include real IP addresses, authentication cookies, private bridge lines, or personal/network identifiers in a public report.

## Scope and threat model

TorProxy runs a local Tor process and optional local HTTP proxy. The intended trust boundary is the current user's machine. HTTP proxy, SOCKS, ControlPort, and DNS listeners are intended to bind to loopback only. The app does not enforce that all system traffic uses Tor.

Important limitations:

- A direct-connection exclusion deliberately bypasses Tor and may expose destination DNS and traffic outside Tor.
- An application's own telemetry, cookies, browser fingerprint, DNS behavior, or alternate network stack may identify the user independently.
- `NEWNYM` does not guarantee a new exit IP and does not move existing connections to another circuit.
- The IP-check endpoint sees the request; one successful check is not proof of anonymity or absence of leaks.
- A system-wide proxy setting is not a firewall. Applications can bypass it.
- Local configuration, host rules, and logs are user data. Logs are designed to omit full request targets and query strings, but users should still protect local access.
- Bundle downloads require a detached OpenPGP signature that verifies against a pinned Tor Browser Developers primary-key fingerprint. Missing or invalid signatures must fail closed.
- User-supplied Tor executables are an explicit trust decision. Prefer a verified official Tor Expert Bundle.

## Security-sensitive changes

Please include tests for listener binding, block/bypass policy, proxy routing, failed network operations, process ownership, configuration persistence, and signature/extraction failures. Never disable verification to work around an offline environment; report the limitation instead.
