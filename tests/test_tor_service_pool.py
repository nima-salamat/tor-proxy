from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from torproxy.service_pool import TorServicePool, TorServicePoolError
from torproxy.tor_manager import TorSettings


class FakeManager:
    def __init__(self, settings):
        self.settings = settings
        self.state = "stopped"
        self.process = None

    def start(self):
        self.state = "ready"

    def stop(self):
        self.state = "stopped"


def _settings(tmp_path: Path, socks: int = 21050, control: int = 21051, dns: int | None = None):
    return TorSettings(
        executable=tmp_path / "tor.exe",
        socks_port=socks,
        control_port=control,
        dns_port=dns,
    )


def _pool(tmp_path: Path, *, manager_factory=FakeManager, reserved_ports=(), reserved_paths=(), max_workers=4):
    directories = SimpleNamespace(data=tmp_path / "app-data", logs=tmp_path / "app-logs")
    return TorServicePool(
        manager_factory=manager_factory,
        reserved_ports=reserved_ports,
        reserved_paths=reserved_paths,
        max_workers=max_workers,
        directories=directories,
    )


def test_registered_services_receive_unique_directories_and_logs(tmp_path):
    pool = _pool(tmp_path)
    pool.register("personal", _settings(tmp_path, 21050, 21051, 21052))
    pool.register("work", _settings(tmp_path, 21150, 21151, 21152))

    personal = pool.settings_for("personal")
    work = pool.settings_for("work")

    assert personal.data_directory != work.data_directory
    assert personal.log_path != work.log_path
    assert personal.data_directory.name == "personal"
    assert work.data_directory.name == "work"


def test_listener_ports_are_reserved_across_services(tmp_path):
    pool = _pool(tmp_path)
    pool.register("one", _settings(tmp_path, 21050, 21051))

    with pytest.raises(TorServicePoolError, match="reuses listener port"):
        pool.register("two", _settings(tmp_path, 21051, 21052))


def test_reserved_application_ports_are_rejected(tmp_path):
    pool = _pool(tmp_path, reserved_ports=(10818,))

    with pytest.raises(TorServicePoolError, match="reserved application listener"):
        pool.register("one", _settings(tmp_path, 10818, 21051))


def test_overlapping_data_directories_are_rejected(tmp_path):
    pool = _pool(tmp_path)
    first = _settings(tmp_path)
    first = TorSettings(
        executable=first.executable,
        socks_port=21050,
        control_port=21051,
        data_directory=tmp_path / "shared-state",
    )
    pool.register("one", first)
    second = TorSettings(
        executable=tmp_path / "tor.exe",
        socks_port=21150,
        control_port=21151,
        data_directory=tmp_path / "shared-state" / "nested",
    )

    with pytest.raises(TorServicePoolError, match="overlaps"):
        pool.register("two", second)


def test_all_services_start_concurrently(tmp_path):
    barrier = threading.Barrier(3)
    active_lock = threading.Lock()
    active = 0
    peak_active = 0

    class ConcurrentManager(FakeManager):
        def start(self):
            nonlocal active, peak_active
            with active_lock:
                active += 1
                peak_active = max(peak_active, active)
            try:
                barrier.wait(timeout=3)
                self.state = "ready"
            finally:
                with active_lock:
                    active -= 1

    pool = _pool(tmp_path, manager_factory=ConcurrentManager, max_workers=3)
    for index in range(3):
        pool.register(f"service-{index}", _settings(tmp_path, 22000 + index * 10, 22001 + index * 10))

    results = pool.start_all()

    assert results == {"service-0": None, "service-1": None, "service-2": None}
    assert peak_active == 3
    assert all(item["state"] == "ready" for item in pool.status().values())


def test_stop_all_isolates_failures_per_service(tmp_path):
    class OneFailingManager(FakeManager):
        def stop(self):
            if self.settings.socks_port == 23050:
                raise RuntimeError("synthetic stop failure")
            self.state = "stopped"

    pool = _pool(tmp_path, manager_factory=OneFailingManager, max_workers=2)
    pool.register("first", _settings(tmp_path, 23050, 23051))
    pool.register("second", _settings(tmp_path, 23150, 23151))
    pool.get("first").state = "ready"
    pool.get("second").state = "ready"

    results = pool.stop_all()

    assert results["first"].startswith("RuntimeError:")
    assert results["second"] is None


def test_active_service_cannot_be_unregistered_until_stopped(tmp_path):
    pool = _pool(tmp_path)
    manager = pool.register("active", _settings(tmp_path))
    manager.state = "ready"

    with pytest.raises(TorServicePoolError, match="still active"):
        pool.unregister("active")

    pool.stop_service("active")
    pool.unregister("active")
    assert pool.service_ids == ()


def test_service_ids_reject_path_traversal_and_unsafe_characters(tmp_path):
    pool = _pool(tmp_path)

    with pytest.raises(TorServicePoolError, match="Service IDs"):
        pool.register("../escape", _settings(tmp_path))


def test_a_service_log_file_must_be_outside_its_own_data_directory(tmp_path):
    pool = _pool(tmp_path)
    settings = TorSettings(
        executable=tmp_path / "tor.exe",
        socks_port=24050,
        control_port=24051,
        data_directory=tmp_path / "state",
        log_path=tmp_path / "state" / "tor.log",
    )

    with pytest.raises(TorServicePoolError, match="log file outside its DataDirectory"):
        pool.register("one", settings)


def test_service_cannot_be_unregistered_while_its_data_lock_is_held(tmp_path):
    pool = _pool(tmp_path)
    manager = pool.register("locked", _settings(tmp_path))
    manager._data_directory_lock_handle = object()

    with pytest.raises(TorServicePoolError, match="still active"):
        pool.unregister("locked")


def test_service_pool_worker_limit_can_be_updated_safely(tmp_path):
    pool = _pool(tmp_path, max_workers=2)

    assert pool.max_workers == 2
    pool.set_max_workers(7)
    assert pool.max_workers == 7

    with pytest.raises(TorServicePoolError, match="between 1 and 8"):
        pool.set_max_workers(9)


def test_service_pool_worker_limit_cannot_change_during_an_operation(tmp_path):
    pool = _pool(tmp_path)
    pool.register("active", _settings(tmp_path))
    pool._services["active"].active_calls = 1

    with pytest.raises(TorServicePoolError, match="operation is running"):
        pool.set_max_workers(2)


def test_service_data_directories_cannot_overlap_primary_tor_paths(tmp_path):
    primary_state = tmp_path / "primary-tor-state"
    pool = _pool(tmp_path, reserved_paths=(primary_state,))
    settings = TorSettings(
        executable=tmp_path / "tor.exe",
        socks_port=25050,
        control_port=25051,
        data_directory=primary_state / "nested-profile",
    )

    with pytest.raises(TorServicePoolError, match="reserved primary Tor state or log path"):
        pool.register("unsafe", settings)
