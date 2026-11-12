from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from torproxy.service_credentials import (
    ServiceCredentialError,
    credentials_path,
    delete_upstream_credentials,
    read_upstream_credentials,
    write_upstream_credentials,
)


def test_credentials_are_saved_separately_with_restrictive_permissions(tmp_path):
    directories = SimpleNamespace(data=tmp_path / "data")
    write_upstream_credentials("work", "proxy-user", "proxy-secret", directories)

    path = credentials_path("work", directories)
    assert path.is_file()
    assert path.name == "work.json"
    assert read_upstream_credentials("work", directories) == {
        "upstream_proxy_username": "proxy-user",
        "upstream_proxy_password": "proxy-secret",
    }
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700


def test_missing_credentials_are_empty_and_delete_is_idempotent(tmp_path):
    directories = SimpleNamespace(data=tmp_path / "data")
    assert read_upstream_credentials("new", directories) == {
        "upstream_proxy_username": "",
        "upstream_proxy_password": "",
    }
    delete_upstream_credentials("new", directories)
    write_upstream_credentials("new", "user", "pass", directories)
    delete_upstream_credentials("new", directories)
    delete_upstream_credentials("new", directories)
    assert read_upstream_credentials("new", directories)["upstream_proxy_password"] == ""


@pytest.mark.parametrize(
    ("username", "password"),
    [("user", ""), ("", "pass"), ("u\nser", "pass"), ("x" * 256, "pass")],
)
def test_invalid_credentials_are_rejected(tmp_path, username, password):
    directories = SimpleNamespace(data=tmp_path / "data")
    with pytest.raises(ServiceCredentialError):
        write_upstream_credentials("work", username, password, directories)


def test_invalid_profile_id_cannot_escape_credentials_directory(tmp_path):
    directories = SimpleNamespace(data=tmp_path / "data")
    with pytest.raises(ServiceCredentialError):
        credentials_path("../outside", directories)


def test_corrupt_credential_file_fails_closed(tmp_path):
    directories = SimpleNamespace(data=tmp_path / "data")
    path = credentials_path("work", directories)
    path.parent.mkdir(parents=True)
    path.write_text("{invalid", encoding="utf-8")
    with pytest.raises(ServiceCredentialError, match="damaged"):
        read_upstream_credentials("work", directories)
