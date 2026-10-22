"""IP verification helpers; a configured proxy is mandatory for exit-IP claims."""
from __future__ import annotations

import requests

from torproxy.ip_check import ProxyCheckError, fetch_exit_ip


def check_connectivity(proxy: str | None = None, timeout: float = 5.0) -> bool:
    """Check HTTPS connectivity only through an explicitly configured proxy."""
    if not proxy:
        return False
    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.head(
                "https://www.google.com",
                proxies={"http": proxy, "https": proxy},
                timeout=(timeout, timeout),
                allow_redirects=False,
            )
            return 200 <= response.status_code < 500
    except requests.RequestException:
        return False


def what_is_my_ip(proxy=None, timeout=10):
    """Return an observed exit IP through proxy; never silently connect directly."""
    if not proxy:
        raise ProxyCheckError("An explicit proxy URL is required; direct IP checks are disabled.")
    return fetch_exit_ip(proxy, timeout=(min(5.0, float(timeout)), float(timeout)))
