from __future__ import annotations

import set_proxy


def _windows_values(*, enabled: int, server: str = "", auto_url: str = "", auto_detect: int = 0):
    return {
        "ProxyEnable": {"exists": True, "value": enabled},
        "ProxyServer": {"exists": bool(server), "value": server},
        "AutoConfigURL": {"exists": bool(auto_url), "value": auto_url},
        "AutoDetect": {"exists": True, "value": auto_detect},
    }


def test_windows_status_identifies_torproxy_endpoint(monkeypatch):
    monkeypatch.setattr(set_proxy, "get_os_name", lambda: set_proxy.Os.Windows)
    monkeypatch.setattr(
        set_proxy.Handler,
        "_windows_values",
        lambda _self: _windows_values(
            enabled=1,
            server="http=127.0.0.1:8118;https=127.0.0.1:8118",
        ),
    )

    status = set_proxy.get_system_proxy_status("127.0.0.1", 8118)

    assert status["state"] == "enabled"
    assert status["owner"] == "torproxy"
    assert "TorProxy" in status["detail"]


def test_windows_status_reports_external_proxy_and_automatic_configuration(monkeypatch):
    monkeypatch.setattr(set_proxy, "get_os_name", lambda: set_proxy.Os.Windows)
    monkeypatch.setattr(
        set_proxy.Handler,
        "_windows_values",
        lambda _self: _windows_values(
            enabled=1,
            server="127.0.0.1:9050",
            auto_url="",
            auto_detect=0,
        ),
    )

    status = set_proxy.get_system_proxy_status("127.0.0.1", 8118)
    assert status["state"] == "enabled"
    assert status["owner"] == "other"

    monkeypatch.setattr(
        set_proxy.Handler,
        "_windows_values",
        lambda _self: _windows_values(
            enabled=0,
            auto_url="https://proxy.example/proxy.pac",
        ),
    )
    automatic = set_proxy.get_system_proxy_status("127.0.0.1", 8118)
    assert automatic["state"] == "enabled"
    assert automatic["owner"] == "other"


def test_windows_status_reports_disabled_without_proxy_or_auto_detection(monkeypatch):
    monkeypatch.setattr(set_proxy, "get_os_name", lambda: set_proxy.Os.Windows)
    monkeypatch.setattr(
        set_proxy.Handler,
        "_windows_values",
        lambda _self: _windows_values(enabled=0),
    )

    status = set_proxy.get_system_proxy_status("127.0.0.1", 8118)

    assert status["state"] == "disabled"
    assert status["owner"] == "none"


def test_gnome_status_identifies_torproxy_manual_configuration(monkeypatch):
    monkeypatch.setattr(set_proxy, "get_os_name", lambda: set_proxy.Os.Linux)
    monkeypatch.setattr(
        set_proxy.Handler,
        "_gsettings_available_values",
        lambda _self: {
            "mode": "'manual'",
            "use-same-proxy": "true",
            "http.host": "'127.0.0.1'",
            "http.port": "8118",
            "https.host": "'127.0.0.1'",
            "https.port": "8118",
            "ftp.host": "''",
            "ftp.port": "0",
            "socks.host": "''",
            "socks.port": "0",
        },
    )

    status = set_proxy.get_system_proxy_status("127.0.0.1", 8118)

    assert status["state"] == "enabled"
    assert status["owner"] == "torproxy"


def test_gnome_status_distinguishes_direct_and_external_manual_modes(monkeypatch):
    monkeypatch.setattr(set_proxy, "get_os_name", lambda: set_proxy.Os.Linux)
    monkeypatch.setattr(
        set_proxy.Handler,
        "_gsettings_available_values",
        lambda _self: {"mode": "'none'"},
    )

    direct = set_proxy.get_system_proxy_status("127.0.0.1", 8118)
    assert direct["state"] == "disabled"

    monkeypatch.setattr(
        set_proxy.Handler,
        "_gsettings_available_values",
        lambda _self: {
            "mode": "'manual'",
            "use-same-proxy": "false",
            "http.host": "'proxy.example'",
            "http.port": "8080",
            "https.host": "''",
            "https.port": "0",
            "ftp.host": "''",
            "ftp.port": "0",
            "socks.host": "''",
            "socks.port": "0",
        },
    )
    external = set_proxy.get_system_proxy_status("127.0.0.1", 8118)
    assert external["state"] == "enabled"
    assert external["owner"] == "other"


def test_system_proxy_status_is_unknown_when_platform_read_fails(monkeypatch):
    monkeypatch.setattr(set_proxy, "get_os_name", lambda: set_proxy.Os.Linux)

    def unavailable(_self):
        raise RuntimeError("desktop settings service is unavailable")

    monkeypatch.setattr(set_proxy.Handler, "_gsettings_available_values", unavailable)
    status = set_proxy.get_system_proxy_status("127.0.0.1", 8118)

    assert status["state"] == "unknown"
    assert status["owner"] == "unknown"
    assert "unavailable" in status["detail"]


def test_unsupported_platform_is_reported_as_unknown(monkeypatch):
    monkeypatch.setattr(set_proxy, "get_os_name", lambda: set_proxy.Os.Mac)

    status = set_proxy.get_system_proxy_status("127.0.0.1", 8118)

    assert status["state"] == "unknown"
    assert status["owner"] == "unknown"
