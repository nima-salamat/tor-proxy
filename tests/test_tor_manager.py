import pytest

import torproxy.tor_manager as tor_manager_module
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


def test_tor_manager_splits_inline_records_using_the_shared_parser():
    parsed = TorManager._parse_bridges(
        "Bridge obfs4 192.0.2.4:443 ABCDEF cert=abc "
        "Bridge snowflake 198.51.100.4:443 fingerprint=def"
    )
    assert parsed == [
        ("obfs4", "obfs4 192.0.2.4:443 ABCDEF cert=abc"),
        ("snowflake", "snowflake 198.51.100.4:443 fingerprint=def"),
    ]


def test_bridge_torrc_registers_lyrebird_transports_in_one_directive(tmp_path):
    executable = tmp_path / "tor" / "tor.exe"
    executable.parent.mkdir(parents=True)
    executable.write_text("fake tor", encoding="utf-8")
    transport_dir = executable.parent / "pluggable_transports"
    transport_dir.mkdir()
    (transport_dir / "lyrebird.exe").write_text("fake transport", encoding="utf-8")
    manager = TorManager(
        TorSettings(
            executable=executable,
            socks_port=19650,
            control_port=19651,
            bridges_enabled=True,
            bridges="webtunnel 192.0.2.10:443 ABCDEF url=https://bridge.example/ ver=0.0.1",
            data_directory=tmp_path / "state",
        )
    )
    torrc = manager.render_torrc()
    plugin_lines = [line for line in torrc.splitlines() if line.startswith("ClientTransportPlugin ")]
    assert plugin_lines == [
        "ClientTransportPlugin meek_lite,obfs4,snowflake,webtunnel exec "
        + TorManager._torrc_quote(transport_dir / "lyrebird.exe")
    ]
    assert 'Bridge webtunnel 192.0.2.10:443 ABCDEF url=https://bridge.example/ ver=0.0.1' in torrc


def test_bootstrap_progress_parser_reads_tor_log_notice_formats():
    assert TorManager._parse_bootstrap_log_line(
        "[notice] Bootstrapped 0% (starting): Starting"
    ) == (0, "Starting")
    assert TorManager._parse_bootstrap_log_line(
        '[notice] Bootstrapped 10% (conn_done): Connected to a relay'
    ) == (10, "Connected to a relay")
    assert TorManager._parse_bootstrap_log_line(
        'NOTICE BOOTSTRAP PROGRESS=12 TAG=conn_done SUMMARY="Connected to a relay"'
    ) == (12, "Connected to a relay")
    assert TorManager._parse_bootstrap_log_line("[warn] Bridge connection failed") is None


def test_bridge_settings_can_override_tor_log_path(tmp_path):
    log_path = tmp_path / "probe.log"
    manager = TorManager(
        TorSettings(
            executable=tmp_path / "tor",
            data_directory=tmp_path / "state",
            log_path=log_path,
        )
    )
    assert manager.log_path == log_path


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
    manager._log_start_offset = 0

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



def test_data_directory_lock_prevents_two_managers_from_claiming_same_directory(tmp_path):
    data_directory = tmp_path / "tor-state"
    settings = TorSettings(
        executable=tmp_path / "tor",
        socks_port=19150,
        control_port=19151,
        data_directory=data_directory,
    )
    first = TorManager(settings)
    second = TorManager(settings)

    first._acquire_data_directory_lock()
    try:
        with pytest.raises(TorManagerError, match="already owns data directory"):
            second._acquire_data_directory_lock()
    finally:
        first._release_data_directory_lock()

    # A clean release makes the directory available for the next connection.
    second._acquire_data_directory_lock()
    second._release_data_directory_lock()


def test_data_directory_lock_reports_other_process_and_cleans_up_after_stop(tmp_path, monkeypatch):
    manager = TorManager(
        TorSettings(
            executable=tmp_path / "tor",
            socks_port=19250,
            control_port=19251,
            data_directory=tmp_path / "tor-state",
        )
    )
    manager._acquire_data_directory_lock()
    manager.stop()
    another = TorManager(manager.settings)
    another._acquire_data_directory_lock()
    another._release_data_directory_lock()



def test_stale_tor_cleanup_targets_only_process_using_exact_managed_torrc(tmp_path, monkeypatch):
    manager = TorManager(
        TorSettings(
            executable=tmp_path / "bundles" / "tor.exe",
            socks_port=19350,
            control_port=19351,
            data_directory=tmp_path / "managed" / "tor-state",
        )
    )

    class FakeProcess:
        def __init__(self, pid, name, cmdline):
            self.pid = pid
            self.info = {"pid": pid, "name": name, "cmdline": cmdline}
            self.terminated = False
            self.killed = False

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.killed = True

    stale = FakeProcess(
        4567,
        "tor.exe",
        [str(manager.settings.executable), "-f", str(manager.torrc_path)],
    )
    unrelated = FakeProcess(
        4568,
        "tor.exe",
        [str(manager.settings.executable), "-f", str(tmp_path / "other-torrc")],
    )
    monkeypatch.setattr(tor_manager_module.psutil, "process_iter", lambda _attrs: [stale, unrelated])
    monkeypatch.setattr(
        tor_manager_module.psutil,
        "wait_procs",
        lambda processes, timeout: (list(processes), []),
    )

    manager._stop_stale_managed_tor_processes()

    assert stale.terminated is True
    assert stale.killed is False
    assert unrelated.terminated is False
    assert unrelated.killed is False
