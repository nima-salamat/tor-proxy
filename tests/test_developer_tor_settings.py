from __future__ import annotations

import json
import os
from copy import deepcopy
from types import SimpleNamespace

import pytest

from config import Config, ConfigError, DEFAULT_DATA
from torproxy.onion_hosting import OnionHostingManager
from torproxy.tor_manager import TorManager, TorManagerError, TorSettings


class MemoryConfig:
    def __init__(self):
        self.values = {
            "onion_hosting_services": [],
            "developer_tor_settings": deepcopy(DEFAULT_DATA["developer_tor_settings"]),
        }

    def __getitem__(self, key):
        return self.values[key]

    def update_many(self, values):
        self.values.update(values)


def _valid_custom_bridge_settings():
    data = deepcopy(DEFAULT_DATA)
    data["developer_tor_settings"].update({
        "bridge_mode": "custom",
        "bridges": "[2001:db8::4]:443 0123456789ABCDEF0123456789ABCDEF01234567",
    })
    return data


def test_developer_tor_defaults_are_isolated_and_direct():
    settings = DEFAULT_DATA["developer_tor_settings"]
    assert settings["bridge_mode"] == "direct"
    assert settings["bridges"] == ""
    assert settings["client_use_ipv4"] is True
    assert settings["client_use_ipv6"] is True
    assert settings["upstream_proxy_type"] == "none"
    assert settings["webtunnel_use_default_tls"] is True


@pytest.mark.parametrize(
    ("scope", "invalid_value"),
    [("main", "yes"), ("developer", 1)],
)
def test_config_rejects_non_boolean_webtunnel_tls_mode(scope, invalid_value):
    data = deepcopy(DEFAULT_DATA)
    if scope == "main":
        data["webtunnel_use_default_tls"] = invalid_value
    else:
        data["developer_tor_settings"]["webtunnel_use_default_tls"] = invalid_value
    with pytest.raises(ConfigError, match="webtunnel_use_default_tls"):
        Config._validate(data)


def test_config_accepts_valid_custom_developer_bridges():
    Config._validate(_valid_custom_bridge_settings())


def test_config_rejects_custom_mode_without_a_valid_bridge():
    data = deepcopy(DEFAULT_DATA)
    data["developer_tor_settings"]["bridge_mode"] = "custom"
    with pytest.raises(ConfigError, match="Custom Bridge mode"):
        Config._validate(data)


def test_config_rejects_private_proxy_credentials_in_json_config():
    data = deepcopy(DEFAULT_DATA)
    data["developer_tor_settings"]["upstream_proxy_password"] = "do-not-store"
    with pytest.raises(ConfigError, match="stored outside config.json"):
        Config._validate(data)


def test_config_rejects_disabling_both_ip_families():
    data = deepcopy(DEFAULT_DATA)
    data["developer_tor_settings"]["client_use_ipv4"] = False
    data["developer_tor_settings"]["client_use_ipv6"] = False
    with pytest.raises(ConfigError, match="at least one"):
        Config._validate(data)


def test_proxy_credentials_are_saved_outside_config_with_restrictive_permissions(tmp_path):
    config = MemoryConfig()
    directories = SimpleNamespace(data=tmp_path / "data", logs=tmp_path / "logs")
    manager = OnionHostingManager(lambda: None, config=config, directories=directories)
    values = {
        **deepcopy(DEFAULT_DATA["developer_tor_settings"]),
        "upstream_proxy_type": "socks5",
        "upstream_proxy_host": "127.0.0.1",
        "upstream_proxy_port": 1080,
        "upstream_proxy_username": "proxy-user",
        "upstream_proxy_password": "proxy-password",
    }

    manager.save_settings(values)

    saved_config = config["developer_tor_settings"]
    assert "upstream_proxy_username" not in saved_config
    assert "upstream_proxy_password" not in saved_config
    assert "proxy-password" not in json.dumps(saved_config)
    assert manager.settings_snapshot()["upstream_proxy_username"] == "proxy-user"
    assert manager.settings_snapshot()["upstream_proxy_password"] == "proxy-password"
    assert manager.network_credentials_path.is_file()
    if os.name != "nt":
        assert manager.network_credentials_path.stat().st_mode & 0o777 == 0o600
        assert manager.network_credentials_path.parent.stat().st_mode & 0o777 == 0o700


def test_torrc_renders_isolated_bridge_ip_family_and_upstream_proxy_options(tmp_path):
    settings = TorSettings(
        executable=tmp_path / "tor",
        socks_port=0,
        control_port=19051,
        data_directory=tmp_path / "developer-tor",
        bridges_enabled=True,
        bridges="[2001:db8::4]:443 0123456789ABCDEF0123456789ABCDEF01234567",
        bridge_source="custom",
        client_use_ipv4=False,
        client_use_ipv6=True,
        upstream_proxy_type="socks5",
        upstream_proxy_host="127.0.0.1",
        upstream_proxy_port=1080,
        upstream_proxy_username="proxy-user",
        upstream_proxy_password="proxy-password",
    )
    torrc = TorManager(settings).render_torrc()

    assert "SocksPort 0" in torrc
    assert "UseBridges 1" in torrc
    assert "Bridge [2001:db8::4]:443 0123456789ABCDEF0123456789ABCDEF01234567" in torrc
    assert "ClientUseIPv4 0" in torrc
    assert "ClientUseIPv6 1" in torrc
    assert 'Socks5Proxy "127.0.0.1:1080"' in torrc
    assert 'Socks5ProxyUsername "proxy-user"' in torrc
    assert 'Socks5ProxyPassword "proxy-password"' in torrc


def test_developer_tor_webtunnel_adds_utls_none_by_default(tmp_path):
    executable = tmp_path / "tor" / "tor.exe"
    executable.parent.mkdir(parents=True)
    executable.write_text("fake tor", encoding="utf-8")
    transport_dir = executable.parent / "pluggable_transports"
    transport_dir.mkdir()
    (transport_dir / "lyrebird.exe").write_text("fake transport", encoding="utf-8")
    fingerprint = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"

    torrc = TorManager(TorSettings(
        executable=executable,
        socks_port=0,
        control_port=19053,
        bridges_enabled=True,
        bridges=(
            f"webtunnel 192.0.2.10:443 {fingerprint} "
            "url=https://bridge.example/path ver=0.0.1"
        ),
        data_directory=tmp_path / "developer-tor",
        webtunnel_use_default_tls=True,
    )).render_torrc()

    bridge_line = next(line for line in torrc.splitlines() if line.startswith("Bridge "))
    assert "utls=none" in bridge_line
    assert "url=https://bridge.example/path" in bridge_line


def test_tor_settings_require_complete_proxy_authentication(tmp_path):
    with pytest.raises(TorManagerError, match="supplied together"):
        TorSettings(
            executable=tmp_path / "tor",
            socks_port=0,
            control_port=19052,
            upstream_proxy_type="socks5",
            upstream_proxy_host="127.0.0.1",
            upstream_proxy_port=1080,
            upstream_proxy_username="only-user",
        )
