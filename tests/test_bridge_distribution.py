from __future__ import annotations

import pytest

from torproxy.bridge_distribution import distribute_bridge_records


def _bridge(index: int, fingerprint: str | None = None) -> str:
    identity = fingerprint or f"{index:040X}"
    return f"obfs4 192.0.2.{index}:443 {identity}"


def test_twenty_unique_bridges_are_evenly_split_across_four_workers():
    records = [_bridge(index) for index in range(10, 30)]

    result = distribute_bridge_records("\n".join(records), 4)

    assert result.unique_records == 20
    assert result.unique_groups == 20
    assert result.shared_groups == 0
    assert result.instance_record_counts == (5, 5, 5, 5)
    assert set().union(*(set(worker) for worker in result.assignments)) == set(records)
    for left in range(4):
        for right in range(left + 1, 4):
            assert set(result.assignments[left]).isdisjoint(result.assignments[right])


def test_uneven_bridge_count_is_balanced_without_dropping_records():
    records = [_bridge(index) for index in range(10, 20)]

    result = distribute_bridge_records("\n".join(records), 4)

    assert result.instance_record_counts == (3, 3, 2, 2)
    assert result.unique_records == 10
    assert result.shared_groups == 0
    assert sum(result.instance_record_counts) == len(records)


def test_fewer_bridge_groups_than_workers_reuses_groups_deterministically():
    records = [_bridge(10), _bridge(11)]

    result = distribute_bridge_records("\n".join(records), 4)

    assert result.instance_record_counts == (1, 1, 1, 1)
    assert result.shared_groups == 2
    assert result.assignments[0] == result.assignments[2]
    assert result.assignments[1] == result.assignments[3]


def test_duplicate_records_are_removed_before_distribution():
    record = _bridge(10)

    result = distribute_bridge_records("\n".join((record, record, record)), 3)

    assert result.unique_records == 1
    assert result.unique_groups == 1
    assert result.shared_groups == 1
    assert result.assignments == ((record,), (record,), (record,))


def test_alternate_records_with_one_fingerprint_stay_in_the_same_worker_group():
    fingerprint = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
    first = f"obfs4 192.0.2.10:443 {fingerprint}"
    second = f"obfs4 192.0.2.11:443 {fingerprint}"
    third = _bridge(12)

    result = distribute_bridge_records("\n".join((first, second, third)), 2)

    assert result.unique_records == 3
    assert result.unique_groups == 2
    assert result.shared_groups == 0
    assert set(result.assignments[0]) == {first, second}
    assert result.assignments[1] == (third,)


def test_empty_bridge_pool_returns_empty_assignment_for_each_worker():
    result = distribute_bridge_records("", 4)

    assert result.assignments == ((), (), (), ())
    assert result.unique_records == 0
    assert result.shared_groups == 0


def test_invalid_bridge_records_are_not_silently_dropped():
    with pytest.raises(ValueError, match="invalid bridge list"):
        distribute_bridge_records("this is not a bridge", 2)


@pytest.mark.parametrize("count", [0, -1, 33, True, 1.5])
def test_worker_count_must_be_a_supported_integer(count):
    with pytest.raises(ValueError, match="instance_count"):
        distribute_bridge_records(_bridge(10), count)

def test_verified_bridge_groups_are_seeded_into_every_worker():
    records = [_bridge(index) for index in range(10, 16)]

    result = distribute_bridge_records(
        "\n".join(records),
        4,
        preferred_records=(records[0], records[1]),
    )

    assert result.unique_groups == 6
    assert result.shared_groups == 2
    assert all(
        records[index] in worker
        for worker, index in zip(result.assignments, (0, 1, 0, 1), strict=True)
    )
    assert set().union(*(set(worker) for worker in result.assignments)) == set(records)


def test_sufficient_verified_groups_are_not_shared():
    records = [_bridge(index) for index in range(10, 17)]

    result = distribute_bridge_records(
        "\n".join(records),
        4,
        preferred_records=records[:4],
    )

    assert result.shared_groups == 0
    assert all(records[index] in worker for index, worker in enumerate(result.assignments))


def test_bridge_shards_balance_record_count_when_fingerprints_have_multiple_lines():
    fingerprint = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
    variants = [
        f"obfs4 192.0.2.{index}:443 {fingerprint}"
        for index in (10, 11, 12)
    ]
    independent = [_bridge(index) for index in (20, 21, 22)]

    result = distribute_bridge_records("\\n".join(variants + independent), 2)

    assert result.unique_groups == 4
    assert result.shared_groups == 0
    assert result.instance_record_counts == (3, 3)
    assert set(result.assignments[0]).isdisjoint(result.assignments[1])
