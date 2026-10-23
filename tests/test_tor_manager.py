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
    parsed = TorManager._parse_bridges("obfs4 192.0.2.4:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=abc")
    assert parsed == [("obfs4", "obfs4 192.0.2.4:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=abc")]


def test_tor_manager_splits_inline_records_using_the_shared_parser():
    parsed = TorManager._parse_bridges(
        "Bridge obfs4 192.0.2.4:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=abc "
        "Bridge snowflake 198.51.100.4:443 fingerprint=A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
    )
    assert parsed == [
        ("obfs4", "obfs4 192.0.2.4:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=abc"),
        ("snowflake", "snowflake 198.51.100.4:443 fingerprint=A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"),
    ]


def test_bridge_torrc_infers_missing_webtunnel_label_from_url_and_ver(tmp_path):
    executable = tmp_path / "tor" / "tor.exe"
    executable.parent.mkdir(parents=True)
    executable.write_text("fake tor", encoding="utf-8")
    transport_dir = executable.parent / "pluggable_transports"
    transport_dir.mkdir()
    (transport_dir / "lyrebird.exe").write_text("fake transport", encoding="utf-8")
    fingerprint = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
    endpoint = "[2001:db8::12]:443"
    manager = TorManager(
        TorSettings(
            executable=executable,
            bridges_enabled=True,
            bridges=f'{endpoint} {fingerprint} url=https://bridge.example/secret ver=0.0.1',
            data_directory=tmp_path / "state",
        )
    )

    bridge_lines = [
        line for line in manager.render_torrc().splitlines()
        if line.startswith("Bridge ")
    ]
    assert bridge_lines == [
        f"Bridge webtunnel {endpoint} {fingerprint} url=https://bridge.example/secret ver=0.0.1"
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
            bridges="webtunnel 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 url=https://bridge.example/ ver=0.0.1",
            data_directory=tmp_path / "state",
        )
    )
    torrc = manager.render_torrc()
    plugin_lines = [line for line in torrc.splitlines() if line.startswith("ClientTransportPlugin ")]
    assert plugin_lines == [
        "ClientTransportPlugin meek_lite,obfs4,snowflake,webtunnel exec "
        + str(transport_dir / "lyrebird.exe")
    ]
    assert 'Bridge webtunnel 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 url=https://bridge.example/ ver=0.0.1' in torrc


def test_quoted_ipv6_webtunnel_bridge_is_normalized_for_torrc(tmp_path):
    raw = 'Bridge webtunnel "[2001:db8:fe46:edd5:2139:2d5b:b732:854a]:443" A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 url=https://bridge.example/ ver=0.0.1'
    parsed = TorManager._parse_bridges(raw)
    assert parsed == [
        ("webtunnel", "webtunnel [2001:db8:fe46:edd5:2139:2d5b:b732:854a]:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 url=https://bridge.example/ ver=0.0.1")
    ]

    executable = tmp_path / "tor" / "tor.exe"
    executable.parent.mkdir(parents=True)
    executable.write_text("fake tor", encoding="utf-8")
    transport_dir = executable.parent / "pluggable_transports"
    transport_dir.mkdir()
    (transport_dir / "lyrebird.exe").write_text("fake transport", encoding="utf-8")
    manager = TorManager(
        TorSettings(
            executable=executable,
            bridges_enabled=True,
            bridges=raw,
            data_directory=tmp_path / "state",
        )
    )
    bridge_lines = [
        line for line in manager.render_torrc().splitlines()
        if line.startswith("Bridge ")
    ]
    assert bridge_lines == [
        "Bridge webtunnel [2001:db8:fe46:edd5:2139:2d5b:b732:854a]:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 url=https://bridge.example/ ver=0.0.1"
    ]
    assert '"[2001:db8:fe46:edd5:2139:2d5b:b732:854a]:443"' not in bridge_lines[0]


def test_plain_ipv6_bridge_does_not_require_lyrebird(tmp_path):
    executable = tmp_path / "tor" / "tor.exe"
    executable.parent.mkdir(parents=True)
    executable.write_text("fake tor", encoding="utf-8")
    raw = 'Bridge "[2001:db8::12]:443" A1B2C3D4E5F60718293A4B5C6D7E8F9012345678'
    manager = TorManager(
        TorSettings(
            executable=executable,
            bridges_enabled=True,
            bridges=raw,
            data_directory=tmp_path / "state",
        )
    )

    torrc = manager.render_torrc()
    assert "UseBridges 1" in torrc
    assert "ClientTransportPlugin " not in torrc
    assert "Bridge [2001:db8::12]:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" in torrc


def test_mixed_inline_bridges_are_rendered_on_separate_torrc_lines(tmp_path):
    executable = tmp_path / "tor" / "tor.exe"
    executable.parent.mkdir(parents=True)
    executable.write_text("fake tor", encoding="utf-8")
    transport_dir = executable.parent / "pluggable_transports"
    transport_dir.mkdir()
    (transport_dir / "lyrebird.exe").write_text("fake transport", encoding="utf-8")
    manager = TorManager(
        TorSettings(
            executable=executable,
            bridges_enabled=True,
            bridges=(
                "obfs4 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=abc "
                'Bridge "[2001:db8::12]:443" A1B2C3D4E5F60718293A4B5C6D7E8F9012345678'
            ),
            data_directory=tmp_path / "state",
        )
    )
    bridge_lines = [
        line for line in manager.render_torrc().splitlines()
        if line.startswith("Bridge ")
    ]
    assert bridge_lines == [
        "Bridge obfs4 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=abc",
        "Bridge [2001:db8::12]:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
    ]


def test_client_transport_plugin_path_is_not_torrc_quoted(tmp_path):
    path = tmp_path / "lyrebird.exe"
    assert TorManager._transport_exec_path(path) == str(path)
    assert not TorManager._transport_exec_path(path).startswith('"')
    assert not TorManager._transport_exec_path(path).endswith('"')


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


def test_bridge_config_validation_error_uses_manager_settings_not_undefined_name(tmp_path):
    from types import SimpleNamespace

    executable = tmp_path / "tor.exe"
    executable.write_text("fake tor", encoding="utf-8")
    settings = TorSettings(
        executable=executable,
        bridges_enabled=True,
        bridges='Bridge "[2001:db8::12]:443" A1B2C3D4E5F60718293A4B5C6D7E8F9012345678',
        data_directory=tmp_path / "state",
        socks_port=19750,
        control_port=19751,
    )

    def fake_run(command, **_kwargs):
        assert "--verify-config" in command
        return SimpleNamespace(
            returncode=1,
            stdout=(
                '[warn] Bridge line did not parse.\n'
                '[err] Reading config failed--see warnings above.\n'
            ),
        )

    manager = TorManager(settings, run_factory=fake_run)
    with pytest.raises(TorManagerError, match="Tor rejected one of the configured Bridge records"):
        manager.start()


def test_bridge_input_shape_diagnostic_hides_bridge_secrets():
    fingerprint = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
    source = (
        "webtunnel 192.0.2.10:443 " + fingerprint +
        " url=https://bridge.example/secret ver=0.0.1"
    )
    summary = TorManager._bridge_input_shape_diagnostics(source)
    assert "item 1 (webtunnel)" in summary
    assert "bare-token length=40 hex=True" in summary
    assert "url,ver" in summary
    assert fingerprint not in summary
    assert "192.0.2.10" not in summary
    assert "/secret" not in summary


def test_bridge_digest_length_error_has_specific_actionable_message(tmp_path):
    from types import SimpleNamespace

    executable = tmp_path / "tor.exe"
    executable.write_text("fake tor", encoding="utf-8")
    settings = TorSettings(
        executable=executable,
        bridges_enabled=True,
        bridges=(
            "webtunnel 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 "
            "url=https://bridge.example/ ver=0.0.1"
        ),
        data_directory=tmp_path / "state",
        socks_port=19760,
        control_port=19761,
    )

    def fake_run(_command, **_kwargs):
        return SimpleNamespace(
            returncode=1,
            stdout="[warn] Key digest for Bridge is wrong length.\\n"
                   "[err] Bridge line did not parse.\\n",
        )

    manager = TorManager(settings, run_factory=fake_run)
    with pytest.raises(TorManagerError, match="identity fingerprint because its digest has the wrong length"):
        manager.start()


def test_tor_config_validation_errors_keep_multiple_output_lines(tmp_path):
    output = "[warn] Reading config file\n[err] Invalid value for ControlPort\n"
    detail = TorManager._summarize_process_output(output, max_lines=2)
    assert "Reading config file" in detail
    assert "Invalid value for ControlPort" in detail



def test_bridge_config_validation_error_does_not_raise_name_error(tmp_path, monkeypatch):
    from types import SimpleNamespace

    executable = tmp_path / "tor" / "tor.exe"
    executable.parent.mkdir(parents=True)
    executable.write_text("fake tor", encoding="utf-8")
    transport_dir = executable.parent / "pluggable_transports"
    transport_dir.mkdir()
    (transport_dir / "lyrebird.exe").write_text("fake transport", encoding="utf-8")

    manager = TorManager(
        TorSettings(
            executable=executable,
            socks_port=19750,
            control_port=19751,
            bridges_enabled=True,
            bridges="webtunnel 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 url=https://bridge.example/ ver=0.0.1",
            data_directory=tmp_path / "state",
            log_path=tmp_path / "logs" / "tor.log",
        ),
        run_factory=lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout=(
                '[warn] "[2001:db8::10]:443" is not a k=v value.\\n'
                "[warn] Bridge line did not parse.\\n"
            ),
        ),
    )
    monkeypatch.setattr(manager, "_stop_stale_managed_tor_processes", lambda: None)

    with pytest.raises(TorManagerError, match="IPv6 endpoints must be written"):
        manager.start()

    assert "NameError" not in (manager.last_error or "")


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
