from torproxy.tor_manager import TorManager, TorSettings


def test_tor_settings_can_disable_socks_for_developer_runtime(tmp_path):
    settings = TorSettings(
        executable=tmp_path / "tor",
        socks_port=0,
        control_port=19051,
        dns_port=None,
        data_directory=tmp_path / "developer-tor",
        log_path=tmp_path / "logs" / "developer-tor.log",
    )
    torrc = TorManager(settings).render_torrc()

    assert "SocksPort 0" in torrc
    assert "SocksPort 127.0.0.1:" not in torrc
    assert "ControlPort 127.0.0.1:19051" in torrc
    assert "CookieAuthentication 1" in torrc


def test_tor_settings_reject_invalid_nonzero_socks_port(tmp_path):
    import pytest

    from torproxy.tor_manager import TorManagerError

    with pytest.raises(TorManagerError):
        TorSettings(
            executable=tmp_path / "tor",
            socks_port=70000,
            control_port=19051,
            data_directory=tmp_path / "developer-tor",
        )
