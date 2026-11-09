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

def test_app_configuration_defaults_openpgp_signature_verification_to_off():
    assert DEFAULT_DATA["verify_tor_signatures"] is False


def test_previous_default_on_openpgp_preference_is_migrated_to_off(tmp_path):
    from config import Config as AppConfig

    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "verify_tor_signatures": True,
        "mode": "dark",
    }), encoding="utf-8")
    store = AppConfig()
    store.path = path

    loaded = store.load()

    assert loaded["verify_tor_signatures"] is False
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["schema_version"] == 2
    assert saved["verify_tor_signatures"] is False


def test_schema_two_preserves_an_explicit_openpgp_opt_in(tmp_path):
    from config import Config as AppConfig

    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "schema_version": 2,
        "verify_tor_signatures": True,
        "mode": "dark",
    }), encoding="utf-8")
    store = AppConfig()
    store.path = path

    assert store.load()["verify_tor_signatures"] is True


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



def test_kill_switch_setting_defaults_to_off_and_requires_boolean_values():
    from torproxy.configuration import TorProxyConfig

    assert DEFAULT_DATA["kill_switch_enabled"] is False
    assert TorProxyConfig().kill_switch_enabled is False

    data = dict(DEFAULT_DATA)
    data["kill_switch_enabled"] = 1
    with pytest.raises(AppConfigError, match="kill_switch_enabled"):
        AppConfig._validate(data)

    with pytest.raises(ConfigurationError, match="Boolean"):
        TorProxyConfig(kill_switch_enabled=1)


def test_kill_switch_preference_survives_typed_legacy_migration():
    migrated = migrate_legacy_config({"kill_switch_enabled": True})
    assert migrated["kill_switch_enabled"] is True
    assert TorProxyConfig(**migrated).kill_switch_enabled is True



def test_config_store_persists_the_kill_switch_preference(tmp_path):
    path = tmp_path / "config.json"
    store = ConfigStore(path)
    store.save(TorProxyConfig(kill_switch_enabled=True))

    loaded = store.load()
    assert loaded.kill_switch_enabled is True
    assert json.loads(path.read_text(encoding="utf-8"))["kill_switch_enabled"] is True
