from __future__ import annotations

import threading

from torproxy.bridge_health import BridgeProbeOutcome, check_bridges
from torproxy.tor_manager import TorSettings

BRIDGES = (
    "obfs4 192.0.2.10:443 FINGERPRINT10",
    "obfs4 192.0.2.11:443 FINGERPRINT11",
    "obfs4 192.0.2.12:443 FINGERPRINT12",
)


def _settings(tmp_path, bridges=BRIDGES):
    return TorSettings(
        executable=tmp_path / "tor",
        socks_port=19450,
        control_port=19451,
        bridges_enabled=True,
        bridges="\n".join(bridges),
        data_directory=tmp_path / "state" / "tor",
    )


def test_bridge_cleanup_removes_only_failed_records_when_another_is_verified(tmp_path):
    settings = _settings(tmp_path)
    outcomes = {
        BRIDGES[0]: True,
        BRIDGES[1]: False,
        BRIDGES[2]: None,
    }
    progress = []

    def fake_probe(_settings, record, _timeout, _excluded, _claimed, _lock, _cancel):
        return outcomes[record]

    result = check_bridges(settings, max_workers=1, probe=fake_probe,
                           on_result=lambda done, total, _record, state: progress.append((done, total, state)))

    assert result.working == (BRIDGES[0],)
    assert result.failed == (BRIDGES[1],)
    assert result.inconclusive == (BRIDGES[2],)
    assert result.retained == (BRIDGES[0], BRIDGES[2])
    assert result.removed == (BRIDGES[1],)
    assert result.should_prune is True
    assert sorted(state for _done, _total, state in progress) == ["failed", "inconclusive", "working"]


def test_all_failed_bridges_are_preserved_without_a_confirmed_working_bridge(tmp_path):
    settings = _settings(tmp_path)
    result = check_bridges(
        settings,
        max_workers=1,
        probe=lambda *_args: False,
    )

    assert result.working == ()
    assert result.failed == BRIDGES
    assert result.retained == BRIDGES
    assert result.removed == ()
    assert result.should_prune is False


def test_duplicate_records_are_checked_once_and_deduplicated_in_saved_list(tmp_path):
    original = (BRIDGES[0], BRIDGES[0], BRIDGES[1])
    settings = _settings(tmp_path, original)
    call_counts = {}

    def fake_probe(_settings, record, _timeout, _excluded, _claimed, _lock, _cancel):
        call_counts[record] = call_counts.get(record, 0) + 1
        return True

    result = check_bridges(settings, max_workers=2, probe=fake_probe)

    assert call_counts == {BRIDGES[0]: 1, BRIDGES[1]: 1}
    assert result.retained == (BRIDGES[0], BRIDGES[1])
    assert result.should_prune is False


def test_missing_transport_is_reported_as_local_issue_not_bridge_failure(tmp_path):
    settings = _settings(tmp_path)
    progress = []

    result = check_bridges(
        settings,
        max_workers=1,
        probe=lambda *_args: BridgeProbeOutcome(None, "missing_transport:webtunnel"),
        on_result=lambda done, total, _record, status: progress.append((done, total, status)),
    )

    assert result.working == ()
    assert result.failed == ()
    assert result.inconclusive == BRIDGES
    assert result.retained == BRIDGES
    assert result.should_prune is False
    assert result.issues == ("missing_transport:webtunnel",)
    assert progress == [
        (1, 3, "infrastructure"),
        (2, 3, "infrastructure"),
        (3, 3, "infrastructure"),
    ]


def test_transport_executable_launch_failure_is_not_a_dead_bridge(tmp_path):
    result = check_bridges(
        _settings(tmp_path),
        max_workers=1,
        probe=lambda *_args: BridgeProbeOutcome(None, "transport_launch_failed"),
    )

    assert result.working == ()
    assert result.failed == ()
    assert result.inconclusive == BRIDGES
    assert result.retained == BRIDGES
    assert result.should_prune is False
    assert result.issues == ("transport_launch_failed",)


def test_cancelled_check_preserves_original_bridge_list_and_does_not_probe(tmp_path):
    settings = _settings(tmp_path)
    cancelled = threading.Event()
    cancelled.set()
    calls = []

    result = check_bridges(
        settings,
        cancel_event=cancelled,
        probe=lambda *_args: calls.append(True) or True,
    )

    assert calls == []
    assert result.retained == BRIDGES
    assert result.should_prune is False
