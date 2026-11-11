from __future__ import annotations

from copy import deepcopy

import pytest

from config import Config, ConfigError, DEFAULT_DATA


def _profile(**updates):
    value = {
        "id": "sample-service",
        "display_name": "Sample site",
        "local_host": "127.0.0.1",
        "local_port": 8080,
        "onion_port": 80,
        "persistent": True,
        "access_mode": "public",
        "auto_start": True,
        "service_id": "",
    }
    value.update(updates)
    return value


def test_config_accepts_loopback_only_onion_service_metadata():
    data = deepcopy(DEFAULT_DATA)
    data["onion_hosting_services"] = [_profile()]
    Config._validate(data)


@pytest.mark.parametrize("host", ["localhost", "0.0.0.0", "192.168.1.15", "example.com"])
def test_config_rejects_non_loopback_onion_targets(host):
    data = deepcopy(DEFAULT_DATA)
    data["onion_hosting_services"] = [_profile(local_host=host)]
    with pytest.raises(ConfigError, match="loopback"):
        Config._validate(data)


@pytest.mark.parametrize(
    "secret_field",
    ["private_key", "client_private_key", "tor_private_key", "private_key_base64"],
)
def test_config_rejects_private_key_material_in_onion_metadata(secret_field):
    data = deepcopy(DEFAULT_DATA)
    data["onion_hosting_services"] = [_profile(**{secret_field: "never-save-this"})]
    with pytest.raises(ConfigError, match="private key material"):
        Config._validate(data)


def test_private_service_config_keeps_only_public_client_key():
    data = deepcopy(DEFAULT_DATA)
    data["onion_hosting_services"] = [
        _profile(
            access_mode="private",
            client_public_key="a" * 52,
            service_id="b" * 56,
        )
    ]
    Config._validate(data)
