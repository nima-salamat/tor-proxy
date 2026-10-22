# Contributing

Thank you for considering a contribution to TorProxy.

## Development setup

Use Python 3.10 or newer. On Debian/Ubuntu, install the native prerequisites for QR decoding and signature verification:

```bash
sudo apt-get install -y gnupg libzbar0
python -m venv .venv
python -m pip install -e ".[dev]"
```

Run the app from a checkout with `python main.py`.

## Before opening a pull request

- Start with a feature branch based on the latest `main`.
- Preserve unrelated work and never commit user-specific config, downloaded bundles, logs, tokens, or private host rules.
- Keep side effects out of module import time. Avoid opening sockets, changing system settings, or launching the GUI on import.
- Keep UI updates on the Qt thread; communicate with workers through signals.
- Keep local network services loopback-only by default.
- Never convert failed signature, checksum, or route verification into success.
- Use explicit timeouts for subprocesses and network calls.
- Add regression tests. Prefer fakes/local servers over dependence on the public Tor network.
- Update docs whenever behavior, migration, supported options, or limitations change.

## Checks

```bash
ruff check src/torproxy tests --select E,F,UP
pytest --cov=torproxy.host_rules --cov=torproxy.ip_check --cov-report=term-missing --cov-fail-under=75
```

CI targets Windows and Ubuntu with Python 3.10–3.13. Check actual workflow results before claiming a platform or Python version is verified.

## Pull requests

Describe the problem, security implications, behavior changes, checks run, and platform limitations. Do not claim measured performance, coverage, anonymity, or test completion without evidence. Avoid mixing unrelated refactors with a security fix when they can be reviewed separately.
