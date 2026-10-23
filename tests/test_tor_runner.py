from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import tor
import torproxy.bridge_health as bridge_health_module
from torproxy.bridge_health import BridgeHealthResult
from torproxy.tor_manager import TorSettings


FINGERPRINTS = (
    "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
    "B1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
    "C1C2C3D4E5F60718293A4B5C6D7E8F9012345678",
)
BRIDGES = tuple(
    f"webtunnel 192.0.2.{index}:443 {fingerprint} url=https://bridge.example/ ver=0.0.1"
    for index, fingerprint in enumerate(FINGERPRINTS, start=10)
)


def _runner(monkeypatch, tmp_path, bridge_text):
    config = {
        "tor_path": None,
        "MaxCircuitDirtiness": 600,
        "NewCircuitPeriod": 60,
        "auto_prune_bridges": True,
        "bridges": bridge_text,
    }
    monkeypatch.setattr(tor, "CONFIG", config)
    monkeypatch.setattr(tor, "_find_executable", lambda _candidate: (None, None))
    runner = tor.TorRunner(19450, 19451, None)
    runner.bridge = True
    runner.bridges = bridge_text
    return runner, config


def _manager(tmp_path, bridge_text):
    return SimpleNamespace(
        settings=TorSettings(
            executable=Path(tmp_path) / "tor.exe",
            socks_port=19450,
            control_port=19451,
            bridges_enabled=True,
            bridges=bridge_text,
            data_directory=Path(tmp_path) / "tor-state",
        )
    )



def test_startup_timeout_rechecks_bridges_and_retries_once_if_cleanup_succeeds(monkeypatch, tmp_path):
    from torproxy.tor_manager import TorManagerError

    bridge_text = "\n".join(BRIDGES)
    runner, _config = _runner(monkeypatch, tmp_path, bridge_text)
    logs = []
    runner.log_message.connect(logs.append)
    attempts = []

    class FakeManager:
        def __init__(self, should_fail):
            self.should_fail = should_fail
            self.process = SimpleNamespace()
            self.settings = SimpleNamespace(bridges=bridge_text)

        def start(self, on_status=None):
            attempts.append(self)
            if self.should_fail:
                raise TorManagerError("Tor did not become ready within 120s.")

        def _recent_tor_log_detail(self, max_lines=30):
            return (
                "Managed proxy \"C:\\\\TorProxy\\\\lyrebird.exe\": Error dialing: "
                "dial tcp 192.0.2.10:443: connectex: connection refused"
            )

    failed_manager = FakeManager(should_fail=True)
    replacement_manager = FakeManager(should_fail=False)
    monkeypatch.setattr(
        runner,
        "_auto_prune_bridges_before_start",
        lambda manager: replacement_manager if manager is failed_manager else manager,
    )

    result = runner._start_with_bridge_recovery(failed_manager)

    assert result is replacement_manager
    assert attempts == [failed_manager, replacement_manager]
    assert runner.manager is replacement_manager
    assert any("Rechecking configured bridges" in message for message in logs)
    assert any("Retrying Tor startup once" in message for message in logs)


def test_global_tls_runtime_error_does_not_trigger_bridge_cleanup_retry(monkeypatch, tmp_path):
    from torproxy.tor_manager import TorManagerError

    bridge_text = "\n".join(BRIDGES)
    runner, _config = _runner(monkeypatch, tmp_path, bridge_text)

    class FakeManager:
        settings = SimpleNamespace(bridges=bridge_text)

        def start(self, on_status=None):
            raise TorManagerError(
                "Lyrebird TLS runtime error: CurvePreferences includes unsupported curve"
            )

        def _recent_tor_log_detail(self, max_lines=30):
            return "tls: CurvePreferences includes unsupported curve"

    runner._auto_prune_bridges_before_start = lambda _manager: (_ for _ in ()).throw(
        AssertionError("global transport errors must not trigger bridge pruning")
    )

    with pytest.raises(TorManagerError, match="CurvePreferences includes unsupported curve"):
        runner._start_with_bridge_recovery(FakeManager())


def test_global_lyrebird_issue_skips_pruning_but_does_not_abort_normal_startup(monkeypatch, tmp_path):
    bridge_text = "\n".join(BRIDGES)
    runner, config = _runner(monkeypatch, tmp_path, bridge_text)
    manager = _manager(tmp_path, bridge_text)
    logs = []
    runner.log_message.connect(logs.append)

    parsed_records = tuple(tor.TorManager._parse_bridges(bridge_text)[i][1] for i in range(3))
    monkeypatch.setattr(
        bridge_health_module,
        "check_bridges",
        lambda *_args, **_kwargs: BridgeHealthResult(
            original=parsed_records,
            working=(),
            failed=(),
            inconclusive=parsed_records,
            issues=("transport_runtime_incompatible",),
        ),
    )

    result = runner._auto_prune_bridges_before_start(manager)

    assert result is manager
    assert config["bridges"] == bridge_text
    assert any("Automatic cleanup was skipped" in message for message in logs)
    assert any("Continuing with Tor's normal startup" in message for message in logs)


def test_with_one_working_bridge_only_confirmed_failures_are_pruned(monkeypatch, tmp_path):
    bridge_text = "\n".join(BRIDGES)
    runner, config = _runner(monkeypatch, tmp_path, bridge_text)
    manager = _manager(tmp_path, bridge_text)
    parsed_records = tuple(record for _kind, record in tor.TorManager._parse_bridges(bridge_text))
    retained = (parsed_records[0], parsed_records[2])
    next_manager = _manager(tmp_path, "\n".join(retained))
    monkeypatch.setattr(runner, "_make_manager", lambda: next_manager)
    monkeypatch.setattr(
        bridge_health_module,
        "check_bridges",
        lambda *_args, **_kwargs: BridgeHealthResult(
            original=parsed_records,
            working=(parsed_records[0],),
            failed=(parsed_records[1],),
            inconclusive=(parsed_records[2],),
            issues=("transport_runtime_incompatible",),
        ),
    )

    result = runner._auto_prune_bridges_before_start(manager)

    assert result is next_manager
    assert config["bridges"] == "\n".join(retained)
    assert runner.bridges == "\n".join(retained)
