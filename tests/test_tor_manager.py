import pytest

from torproxy.tor_manager import TorManager, TorManagerError, TorSettings, TorState


def test_tor_configuration_restricts_listeners_and_enables_cookie_auth(tmp_path):
    executable = tmp_path / "tor"
    executable.write_text("fake")
    data = tmp_path / "state" / "tor"
    manager = TorManager(TorSettings(executable=executable, socks_port=19050, control_port=19051,
                                     data_directory=data))
    torrc = manager.render_torrc()
    assert "SocksPort 127.0.0.1:19050" in torrc
    assert "ControlPort 127.0.0.1:19051" in torrc
    assert "CookieAuthentication 1" in torrc
    assert "CookieAuthFile " in torrc
    assert "0.0.0.0" not in torrc


def test_duplicate_ports_are_rejected(tmp_path):
    with pytest.raises(TorManagerError, match="distinct"):
        TorSettings(executable=tmp_path / "tor", socks_port=9050, control_port=9050)


def test_invalid_bridge_syntax_is_rejected():
    with pytest.raises(TorManagerError, match="supported bridge record"):
        TorManager._parse_bridges("custom-transport bridge.example:443")


def test_valid_bridge_record_keeps_transport_arguments():
    parsed = TorManager._parse_bridges("obfs4 192.0.2.4:443 ABCDEF cert=abc")
    assert parsed == [("obfs4", "obfs4 192.0.2.4:443 ABCDEF cert=abc")]


def test_stop_without_owned_process_is_idempotent():
    manager = TorManager(TorSettings(executable="/missing/tor", data_directory="/tmp/torproxy-test-state"))
    manager.stop()
    assert manager.state is TorState.STOPPED



def test_early_startup_exit_reports_recent_tor_log_details(tmp_path):
    manager = TorManager(
        TorSettings(
            executable=tmp_path / "tor",
            socks_port=19050,
            control_port=19051,
            data_directory=tmp_path / "state" / "tor",
        )
    )
    manager.log_path = tmp_path / "logs" / "tor.log"
    manager.log_path.parent.mkdir(parents=True)
    manager.log_path.write_text(
        "old detail that should fall outside the bounded tail\n"
        "[warn] Opening Control listener failed\n"
        "[err] Could not bind to 127.0.0.1:19051: Address already in use\n",
        encoding="utf-8",
    )

    detail = manager._recent_tor_log_detail(max_lines=2)
    assert "Tor log" in detail
    assert "Opening Control listener failed" in detail
    assert "Address already in use" in detail
    assert "old detail that should fall outside the bounded tail" not in detail


def test_tor_config_validation_errors_keep_multiple_output_lines(tmp_path):
    output = "[warn] Reading config file\n[err] Invalid value for ControlPort\n"
    detail = TorManager._summarize_process_output(output, max_lines=2)
    assert "Reading config file" in detail
    assert "Invalid value for ControlPort" in detail
