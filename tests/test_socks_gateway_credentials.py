from __future__ import annotations

import os

import pytest

from torproxy.socks_gateway_credentials import (
    SocksGatewayCredentialError,
    generate_socks_gateway_credentials,
    read_socks_gateway_credentials,
    write_socks_gateway_credentials,
)


def test_socks_gateway_credentials_are_stored_separately_with_restrictive_permissions(tmp_path):
    directories = type("Directories", (), {"data": tmp_path / "user-data"})()
    generated = generate_socks_gateway_credentials()
    write_socks_gateway_credentials(generated["username"], generated["password"], directories)

    assert read_socks_gateway_credentials(directories) == generated
    path = tmp_path / "user-data" / "tor-gateway" / "credentials.json"
    if os.name != "nt":
        assert path.parent.stat().st_mode & 0o777 == 0o700
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    ("username", "password"),
    [("", "secret"), ("user", ""), ("", ""), ("u" * 256, "password")],
)
def test_socks_gateway_credentials_require_valid_username_and_password(tmp_path, username, password):
    directories = type("Directories", (), {"data": tmp_path / "data"})()
    with pytest.raises(SocksGatewayCredentialError):
        write_socks_gateway_credentials(username, password, directories)


def test_corrupt_socks_gateway_credentials_fail_closed(tmp_path):
    directories = type("Directories", (), {"data": tmp_path / "data"})()
    path = tmp_path / "data" / "tor-gateway" / "credentials.json"
    path.parent.mkdir(parents=True)
    path.write_text("{broken", encoding="utf-8")
    with pytest.raises(SocksGatewayCredentialError, match="damaged"):
        read_socks_gateway_credentials(directories)
