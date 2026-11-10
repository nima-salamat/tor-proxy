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


def test_early_exit_with_explicit_bridge_dial_failure_rechecks_bridges(monkeypatch, tmp_path):
    from torproxy.tor_manager import TorManagerError

    bridge_text = "\n".join(BRIDGES)
    runner, _config = _runner(monkeypatch, tmp_path, bridge_text)
    manager = SimpleNamespace(
        _recent_tor_log_detail=lambda max_lines=30: (
            'Managed proxy "C:\\\\TorProxy\\\\lyrebird.exe": Error dialing: '
            "dial tcp 198.51.100.8:443: connectex: connection refused"
        )
    )

    assert runner._should_recheck_bridges_after_start_failure(
        manager,
        TorManagerError("Tor exited unexpectedly during startup (exit code 1)."),
    )


def test_early_exit_without_bridge_specific_dial_failure_skips_recheck(monkeypatch, tmp_path):
    from torproxy.tor_manager import TorManagerError

    bridge_text = "\n".join(BRIDGES)
    runner, _config = _runner(monkeypatch, tmp_path, bridge_text)
    manager = SimpleNamespace(
        _recent_tor_log_detail=lambda max_lines=30: "Tor exited due to an invalid local configuration."
    )

    assert not runner._should_recheck_bridges_after_start_failure(
        manager,
        TorManagerError("Tor exited unexpectedly during startup (exit code 1)."),
    )


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


def test_tor_runner_identity_uses_its_managed_tor_controller(monkeypatch, tmp_path):
    runner, _config = _runner(monkeypatch, tmp_path, "\n".join(BRIDGES))
    manager = SimpleNamespace(request_new_identity=lambda: 7.5)
    runner.manager = manager
    runner.state = "READY"

    assert runner.request_new_identity() == 7.5


def test_tor_runner_stop_does_not_claim_stopped_while_supervisor_is_alive(monkeypatch, tmp_path):
    from torproxy.tor_manager import TorManagerError

    runner, _config = _runner(monkeypatch, tmp_path, "\n".join(BRIDGES))

    class LiveThread:
        def is_alive(self):
            return True

        def join(self, timeout=None):
            pass

    manager = SimpleNamespace(
        stop=lambda: None,
        process=None,
    )
    runner.manager = manager
    runner.thread = LiveThread()

    with pytest.raises(TorManagerError, match="supervisor/process is still active"):
        runner.stop()

    assert runner.state == "FAILED"
    assert runner.thread is not None


def test_http_proxy_keeps_service_reference_when_server_thread_does_not_stop():
    runner = tor.Runner(19480, 19481, app_window=None)

    class FakeServer:
        def shutdown(self):
            pass

        def server_close(self):
            pass

    class LiveThread:
        def join(self, timeout=None):
            pass

        def is_alive(self):
            return True

    server = FakeServer()
    runner.server = server
    runner.thread = LiveThread()

    with pytest.raises(RuntimeError, match="HTTP listener is still active"):
        runner.stop()

    assert runner.server is server
    assert runner.thread is not None


def _ready_fake_backend(port: int):
    return SimpleNamespace(
        state="ready",
        process=SimpleNamespace(poll=lambda: None),
        settings=SimpleNamespace(socks_port=port),
        get_active_bridge_fingerprints=lambda: (),
    )


def test_primary_pool_routes_only_to_network_verified_tor_instances(monkeypatch, tmp_path):
    from torproxy.health import TorProbeResult

    runner, _config = _runner(monkeypatch, tmp_path, "")
    first = _ready_fake_backend(19460)
    second = _ready_fake_backend(19461)
    runner._backend_managers = [first, second]
    runner._backend_statuses = {0: "READY", 1: "READY"}
    runner._backend_health = {
        0: {"healthy": False, "latency_ms": None, "consecutive_failures": 0},
        1: {"healthy": False, "latency_ms": None, "consecutive_failures": 0},
    }

    monkeypatch.setattr(
        tor,
        "probe_tor_socks",
        lambda port, timeout=8.0: TorProbeResult(
            port == 19460,
            latency_ms=125.0 if port == 19460 else None,
            detail="probe result",
        ),
    )

    assert runner._healthy_managers() == []
    assert runner._probe_ready_backends() is True
    assert runner._healthy_managers() == [first]
    assert runner._ready_backend_endpoints() == [("127.0.0.1", 19460, 125.0)]


def test_primary_pool_withdraws_a_previously_healthy_worker_after_two_failed_probes(
    monkeypatch, tmp_path
):
    from torproxy.health import TorProbeResult

    runner, _config = _runner(monkeypatch, tmp_path, "")
    backend = _ready_fake_backend(19462)
    runner._backend_managers = [backend]
    runner._backend_statuses = {0: "READY"}
    runner._backend_health = {
        0: {
            "healthy": True,
            "latency_ms": 100.0,
            "consecutive_failures": 0,
        }
    }
    monkeypatch.setattr(
        tor,
        "probe_tor_socks",
        lambda *_args, **_kwargs: TorProbeResult(False, detail="network unavailable"),
    )

    assert runner._probe_ready_backends() is True
    assert runner._healthy_managers() == [backend]
    assert runner._probe_ready_backends() is False
    assert runner._healthy_managers() == []


def test_primary_pool_does_not_report_connected_before_tor_check_passes(
    monkeypatch, tmp_path
):
    from torproxy.tor_manager import TorState

    runner, _config = _runner(monkeypatch, tmp_path, "")
    backend = _ready_fake_backend(19463)
    runner.manager = backend
    runner._backend_managers = [backend]
    runner._backend_statuses = {0: "STARTING"}
    runner._backend_health = {
        0: {
            "healthy": False,
            "latency_ms": None,
            "consecutive_failures": 0,
        }
    }
    runner.app_window = SimpleNamespace(data=SimpleNamespace(value="0%"))

    runner._on_worker_status(
        0,
        backend,
        TorState.READY,
        100,
        "Tor bootstrap completed.",
    )

    assert runner.state == "BOOTSTRAPPING"
    assert runner.app_window.data.value == "Verifying Tor network access…"
    assert runner._healthy_managers() == []


def test_primary_pool_health_snapshot_identifies_each_instance(monkeypatch, tmp_path):
    runner, _config = _runner(monkeypatch, tmp_path, "")
    runner._backend_managers = [
        _ready_fake_backend(19464),
        _ready_fake_backend(19465),
    ]
    runner._backend_statuses = {0: "READY", 1: "FAILED"}
    runner._backend_health = {
        0: {
            "healthy": True,
            "latency_ms": 83.0,
            "consecutive_failures": 0,
        },
        1: {
            "healthy": False,
            "latency_ms": None,
            "consecutive_failures": 2,
        },
    }

    snapshot = runner.pool_health_snapshot

    assert snapshot["ready_instances"] == 1
    assert snapshot["total_instances"] == 2
    assert snapshot["instances"][0]["state"] == "healthy"
    assert snapshot["instances"][0]["latency_ms"] == 83.0
    assert snapshot["instances"][1]["state"] == "failed"
