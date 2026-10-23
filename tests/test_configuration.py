import json

import pytest

from config import Config as AppConfig, ConfigError as AppConfigError, DEFAULT_DATA
from torproxy.configuration import ConfigStore, ConfigurationError, TorProxyConfig, migrate_legacy_config


def test_missing_configuration_creates_defaults_atomically(tmp_path):
    path = tmp_path / "config" / "config.json"
    store = ConfigStore(path)
    config = store.load()
    assert config.proxy_host == "127.0.0.1"
    assert config.system_proxy_auto is False
    assert store.load() == config
    assert json.loads(path.read_text())["schema_version"] == 1


def test_legacy_settings_are_migrated(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"mode": "light", "bridge": True, "bridges": "obfs4 abc:1", "tor_port": 9052}))
    config = ConfigStore(path).load()
    assert config.mode == "light"
    assert config.bridge_enabled is True
    assert config.bridges == "obfs4 abc:1"
    assert config.socks_port == 9052


def test_corrupt_configuration_fails_with_actionable_error(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{broken")
    with pytest.raises(ConfigurationError, match="Cannot read configuration"):
        ConfigStore(path).load()


def test_non_loopback_proxy_is_rejected():
    with pytest.raises(ConfigurationError, match="loopback"):
        TorProxyConfig(proxy_host="0.0.0.0")


def test_duplicate_ports_are_rejected():
    with pytest.raises(ConfigurationError, match="distinct"):
        TorProxyConfig(proxy_port=9050, socks_port=9050)


def test_legacy_migration_preserves_supported_values():
    migrated = migrate_legacy_config({"mode": "light", "newnym_interval": 30000, "data_usage": 123})
    assert migrated["mode"] == "light"
    assert migrated["newnym_interval_seconds"] == 30
    assert migrated["data_usage_bytes"] == 123

def test_app_configuration_defaults_to_no_sni_override_and_normalizes_custom_host():
    data = dict(DEFAULT_DATA)
    assert data["webtunnel_sni_imitation"] == ""
    data["webtunnel_sni_imitation"] = "WWW.Example.COM."
    AppConfig._validate(data)
    assert data["webtunnel_sni_imitation"] == "www.example.com"


def test_app_configuration_rejects_invalid_sni_override():
    data = dict(DEFAULT_DATA)
    data["webtunnel_sni_imitation"] = "https://example.com/path"
    with pytest.raises(AppConfigError, match="webtunnel_sni_imitation is invalid"):
        AppConfig._validate(data)
