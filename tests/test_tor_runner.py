from __future__ import annotations

from pathlib import Path
import socket
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
        "webtunnel_sni_imitation": "",
        "webtunnel_use_default_tls": True,
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


@pytest.mark.parametrize(
    "diagnostic",
    (
        "remote error: tls: illegal parameter",
        "tls: illegal parameter",
        "unrecognized reply",
    ),
)
def test_peer_tls_handshake_failure_does_not_trigger_bridge_cleanup(monkeypatch, tmp_path, diagnostic):
    from torproxy.tor_manager import TorManagerError

    bridge_text = "\\n".join(BRIDGES)
    runner, _config = _runner(monkeypatch, tmp_path, bridge_text)
    manager = SimpleNamespace(
        _recent_tor_log_detail=lambda max_lines=30: "Managed proxy: Error dialing: " + diagnostic
    )
    assert not runner._should_recheck_bridges_after_start_failure(
        manager,
        TorManagerError("Tor did not become ready within 180s."),
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

    managers = [
        next_manager,
        SimpleNamespace(settings=SimpleNamespace(bridges="")),
    ]
    distribution = runner._apply_bridge_distribution(managers)
    assert distribution is not None
    assigned = set().union(*(set(item.settings.bridges.splitlines()) for item in managers))
    assert assigned == set(retained)
    assert BRIDGES[1] not in assigned
    assert distribution.shared_groups == 1
    assert all(parsed_records[0] in item.settings.bridges.splitlines() for item in managers)


def test_primary_bridge_pool_is_split_evenly_without_cross_instance_overlap(monkeypatch, tmp_path):
    from types import SimpleNamespace

    bridge_text = "\n".join(
        f"obfs4 192.0.2.{index}:443 {index:040X}"
        for index in range(10, 30)
    )
    runner, _config = _runner(monkeypatch, tmp_path, bridge_text)
    managers = [
        SimpleNamespace(settings=SimpleNamespace(bridges=bridge_text))
        for _index in range(4)
    ]

    distribution = runner._apply_bridge_distribution(managers)

    assert distribution is not None
    assert distribution.unique_records == 20
    assert distribution.unique_groups == 20
    assert distribution.shared_groups == 0
    assert distribution.instance_record_counts == (5, 5, 5, 5)
    assigned = [set(item.settings.bridges.splitlines()) for item in managers]
    assert all(len(items) == 5 for items in assigned)
    for left in range(len(assigned)):
        for right in range(left + 1, len(assigned)):
            assert assigned[left].isdisjoint(assigned[right])
    assert set().union(*assigned) == set(bridge_text.splitlines())


def test_primary_bridge_pool_reuses_groups_only_when_there_are_too_few(monkeypatch, tmp_path):
    bridge_text = "\n".join(BRIDGES[:2])
    runner, _config = _runner(monkeypatch, tmp_path, bridge_text)
    managers = [
        SimpleNamespace(settings=SimpleNamespace(bridges=bridge_text))
        for _index in range(4)
    ]

    distribution = runner._apply_bridge_distribution(managers)

    assert distribution is not None
    assert distribution.shared_groups == 2
    assigned = [set(item.settings.bridges.splitlines()) for item in managers]
    assert [len(items) for items in assigned] == [1, 1, 1, 1]
    assert assigned[0] == assigned[2]
    assert assigned[1] == assigned[3]


def test_duplicate_and_same_fingerprint_bridge_records_are_kept_in_one_group(monkeypatch, tmp_path):
    first = f"obfs4 192.0.2.10:443 {FINGERPRINTS[0]}"
    alternate = f"webtunnel 192.0.2.11:443 {FINGERPRINTS[0]} url=https://bridge.example/ ver=0.0.1"
    other = f"obfs4 192.0.2.12:443 {FINGERPRINTS[1]}"
    bridge_text = "\n".join((first, first, alternate, other))
    runner, _config = _runner(monkeypatch, tmp_path, bridge_text)
    managers = [
        SimpleNamespace(settings=SimpleNamespace(bridges=bridge_text))
        for _index in range(2)
    ]

    distribution = runner._apply_bridge_distribution(managers)

    assert distribution is not None
    assert distribution.unique_records == 3
    assert distribution.unique_groups == 2
    assert distribution.shared_groups == 0
    assert set(managers[0].settings.bridges.splitlines()) == {first, alternate}
    assert managers[1].settings.bridges.splitlines() == [other]


def test_restarted_primary_worker_keeps_its_original_bridge_shard(monkeypatch, tmp_path):
    from types import SimpleNamespace

    bridge_text = "\n".join(BRIDGES)
    runner, _config = _runner(monkeypatch, tmp_path, bridge_text)
    original_managers = [
        SimpleNamespace(settings=SimpleNamespace(bridges=bridge_text))
        for _index in range(3)
    ]
    distribution = runner._apply_bridge_distribution(original_managers)
    assert distribution is not None

    replacement = SimpleNamespace(settings=SimpleNamespace(bridges=bridge_text))
    runner._apply_bridge_assignment(replacement, 1)

    assert replacement.settings.bridges == distribution.bridge_texts[1]
    assert replacement.settings.bridges != bridge_text


def test_primary_bridge_pool_can_reuse_a_single_bridge_for_every_instance(monkeypatch, tmp_path):
    bridge_text = "\n".join((BRIDGES[0], BRIDGES[0], BRIDGES[0]))
    runner, _config = _runner(monkeypatch, tmp_path, bridge_text)
    managers = [
        SimpleNamespace(settings=SimpleNamespace(bridges=bridge_text))
        for _index in range(4)
    ]

    distribution = runner._apply_bridge_distribution(managers)

    assert distribution is not None
    assert distribution.unique_records == 1
    assert distribution.unique_groups == 1
    assert distribution.shared_groups == 1
    assert all(item.settings.bridges.splitlines() == [BRIDGES[0]] for item in managers)


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


def test_http_proxy_bind_preference_restarts_listener_between_loopback_and_lan(monkeypatch):
    monkeypatch.setattr(
        tor,
        "CONFIG",
        {
            "http_proxy_enabled": True,
            "http_proxy_bind_all_interfaces": False,
        },
    )
    runner = tor.Runner(0, 19480, app_window=None)
    runner._started = True
    runner.http_enabled = True
    try:
        message = runner.set_http_bind_all_interfaces(True)
        assert runner.server.server_address[0] == "0.0.0.0"
        assert "no proxy authentication" in message
        assert runner.is_running

        message = runner.set_http_bind_all_interfaces(False)
        assert runner.server.server_address[0] == "127.0.0.1"
        assert "restricted to this device" in message
        assert runner.is_running
    finally:
        runner.stop()


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
    # Until Tor Check returns, READY workers remain eligible as Tor-only fallbacks.
    assert runner._ready_backend_endpoints() == [
        ("127.0.0.1", 19460, None),
        ("127.0.0.1", 19461, None),
    ]
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
    # A failed external Tor Check withdraws the verified status, not the live
    # Tor process itself. New requests can still test the actual destination.
    assert runner._ready_backend_endpoints() == [("127.0.0.1", 19462, None)]


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
    assert runner._ready_backend_endpoints() == [("127.0.0.1", 19463, None)]


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



def test_http_proxy_runner_respects_disabled_preference_and_can_start_live(monkeypatch):
    import threading
    import tor

    class FakeServer:
        def __init__(self, *_args, **_kwargs):
            self.stopped = threading.Event()

        def serve_forever(self):
            self.stopped.wait()

        def shutdown(self):
            self.stopped.set()

        def server_close(self):
            pass

    monkeypatch.setattr(tor, "CONFIG", {"http_proxy_enabled": False})
    monkeypatch.setattr(tor, "ThreadedHTTPServer", FakeServer)
    monkeypatch.setattr(tor, "worker_data_usage_tracker", lambda stop_event: stop_event.wait(0.25))
    runner = tor.Runner(18888, 19050, None)
    runner.start()

    assert runner.server is None
    assert runner.is_running is False

    result = runner.set_http_enabled(True)
    assert "listening" in result
    assert runner.is_running is True

    runner.set_http_enabled(False)
    assert runner.is_running is False
    assert runner.server is None
    runner.stop()





def test_bridge_usage_shutdown_publish_does_not_query_closing_control_ports(monkeypatch, tmp_path):
    runner, _config = _runner(monkeypatch, tmp_path, BRIDGES[0])
    runner.bridge = True
    calls = []
    backend = _ready_fake_backend(19468)
    backend.get_active_bridge_fingerprints = lambda: calls.append("control-query") or ()
    runner._backend_managers = [backend]
    runner._backend_statuses = {0: "READY"}
    runner._backend_health = {
        0: {"healthy": True, "latency_ms": 70.0, "consecutive_failures": 0}
    }
    runner._stopping.set()

    runner._publish_bridge_usage()

    assert calls == []


def test_primary_pool_health_snapshot_exposes_gateway_active_load_and_capacity(monkeypatch, tmp_path):
    runner, _config = _runner(monkeypatch, tmp_path, "")
    backend = _ready_fake_backend(19466)
    runner._backend_managers = [backend]
    runner._backend_statuses = {0: "READY"}
    runner._backend_health = {
        0: {"healthy": True, "latency_ms": 72.0, "consecutive_failures": 0}
    }
    runner._gateway = SimpleNamespace(
        backend_metrics={
            ("127.0.0.1", 19466): {
                "active": 3,
                "failures": 2,
                "cooldown_until": 0.0,
            }
        },
        session_metrics={
            "active_sessions": 3,
            "max_sessions": 256,
            "rejected_sessions": 1,
        },
    )

    snapshot = runner.pool_health_snapshot

    assert snapshot["instances"][0]["active_connections"] == 3
    assert snapshot["instances"][0]["gateway_failures"] == 2
    assert snapshot["gateway"] == {
        "active_sessions": 3,
        "max_sessions": 256,
        "rejected_sessions": 1,
    }


def test_bridge_fingerprint_control_port_queries_are_throttled(monkeypatch, tmp_path):
    runner, _config = _runner(monkeypatch, tmp_path, BRIDGES[0])
    runner.bridge = True
    calls = []

    backend = _ready_fake_backend(19467)
    backend.get_active_bridge_fingerprints = lambda: calls.append("query") or ()
    runner._backend_managers = [backend]
    runner._backend_statuses = {0: "READY"}
    runner._backend_health = {
        0: {"healthy": True, "latency_ms": 70.0, "consecutive_failures": 0}
    }
    runner._bridge_fingerprints_initialized = True
    runner._last_bridge_fingerprint_refresh = tor.time.monotonic()
    runner._cached_active_bridge_fingerprints = set()

    runner._publish_bridge_usage()
    assert calls == []

    runner._last_bridge_fingerprint_refresh -= 10.0
    runner._publish_bridge_usage()
    runner._publish_bridge_usage()
    assert calls == ["query"]



def test_primary_pool_fallback_excludes_workers_whose_process_is_not_alive(monkeypatch, tmp_path):
    runner, _config = _runner(monkeypatch, tmp_path, "")
    live = _ready_fake_backend(19469)
    dead = _ready_fake_backend(19470)
    dead.process.poll = lambda: 1
    runner._backend_managers = [live, dead]
    runner._backend_statuses = {0: "READY", 1: "READY"}
    runner._backend_health = {
        0: {"healthy": False, "latency_ms": None, "consecutive_failures": 2},
        1: {"healthy": False, "latency_ms": None, "consecutive_failures": 2},
    }

    assert runner._ready_backend_endpoints() == [("127.0.0.1", 19469, None)]



def test_internal_worker_dns_port_allocation_retries_udp_conflicts(monkeypatch):
    allocated_stream_ports = iter((62001, 62002))
    socket_calls = []

    class FakeSocket:
        def __init__(self, _family, socket_type):
            self.socket_type = socket_type
            self.port = None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def bind(self, address):
            _host, requested_port = address
            socket_calls.append((self.socket_type, requested_port))
            if self.socket_type == tor.socket.SOCK_STREAM and requested_port == 0:
                self.port = next(allocated_stream_ports)
                return
            self.port = requested_port
            if self.socket_type == tor.socket.SOCK_DGRAM and requested_port == 62001:
                raise OSError("UDP port is already in use")

        def getsockname(self):
            return ("127.0.0.1", self.port)

    monkeypatch.setattr(tor.socket, "socket", FakeSocket)
    reserved = set()

    selected = tor.TorRunner._allocate_local_port(reserved, udp=True)

    assert selected == 62002
    assert reserved == {62002}
    assert socket_calls == [
        (tor.socket.SOCK_STREAM, 0),
        (tor.socket.SOCK_DGRAM, 62001),
        (tor.socket.SOCK_STREAM, 0),
        (tor.socket.SOCK_DGRAM, 62002),
    ]



def test_main_socks_gateway_port_is_separate_from_random_tor_worker_ports(monkeypatch, tmp_path):
    runner, _config = _runner(monkeypatch, tmp_path, "")
    runner.path_set = True
    runner.tor_path = str(tmp_path / "tor.exe")
    runner.geoip_path = None
    runner.geoip6_path = None

    directories = SimpleNamespace(data=tmp_path / "app-data", logs=tmp_path / "logs")
    monkeypatch.setattr(tor, "user_directories", lambda: directories)
    monkeypatch.setattr(
        tor,
        "TorManager",
        lambda settings: SimpleNamespace(settings=settings),
    )

    managers = [runner._make_manager(index) for index in range(3)]
    worker_ports = [manager.settings.socks_port for manager in managers]

    assert len(set(worker_ports)) == 3
    assert all(1 <= port <= 65535 for port in worker_ports)
    assert runner.socks_port not in worker_ports
    assert runner.control_port not in worker_ports
    assert all(manager.settings.control_port != runner.socks_port for manager in managers)


def test_main_socks_gateway_reconfigures_without_restarting_tor_workers(monkeypatch, tmp_path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    runner, config = _runner(monkeypatch, tmp_path, "")
    config["tor_socks_bind_all_interfaces"] = False
    config["tor_path"] = None
    config["primary_tor_instances"] = 2
    runner.socks_port = port
    runner._gateway_access_config = ("127.0.0.1", "", "")
    gateway = runner._build_socks_gateway(runner._gateway_access_config)
    gateway.start()
    runner._gateway = gateway

    monkeypatch.setattr(
        tor,
        "read_socks_gateway_credentials",
        lambda: {"username": "lan-user", "password": "lan-password"},
    )
    try:
        config["tor_socks_bind_all_interfaces"] = True
        enabled_message = runner.reconfigure_socks_gateway()
        assert runner._gateway.host == "0.0.0.0"
        assert runner._gateway.port == port
        assert runner._gateway.running
        assert "authenticate" in enabled_message

        config["tor_socks_bind_all_interfaces"] = False
        disabled_message = runner.reconfigure_socks_gateway()
        assert runner._gateway.host == "127.0.0.1"
        assert runner._gateway.port == port
        assert runner._gateway.running
        assert "restricted" in disabled_message
    finally:
        runner._gateway.stop()
