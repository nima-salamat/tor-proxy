"""Deterministically distribute bridge identities across isolated Tor workers.

The bridge list remains a single user-managed pool. This module only decides
which records each Tor process receives; C Tor remains responsible for bridge
and guard selection within an individual process.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .bridges import bridge_identity_fingerprint, parse_bridge_text


@dataclass(frozen=True)
class BridgeDistribution:
    """Bridge records assigned to each Tor worker and a safe aggregate summary."""

    assignments: tuple[tuple[str, ...], ...]
    unique_records: int
    unique_groups: int
    shared_groups: int

    @property
    def bridge_texts(self) -> tuple[str, ...]:
        """Return one newline-separated bridge list per worker."""
        return tuple("\n".join(records) for records in self.assignments)

    @property
    def instance_record_counts(self) -> tuple[int, ...]:
        return tuple(len(records) for records in self.assignments)


def distribute_bridge_records(
    bridge_text: str,
    instance_count: int,
    *,
    preferred_records: Iterable[str] = (),
) -> BridgeDistribution:
    """Split normalized bridge records into balanced, deterministic worker groups.

    Records with the same explicit relay fingerprint stay together. This keeps
    alternate transport/configuration records for one known bridge identity in
    the same Tor process. Records without an explicit fingerprint are grouped
    only when their complete canonical records are identical.

    If preflight checks verified some bridge records, one verified identity
    group is seeded into every worker when possible. Remaining groups are
    balanced without overlap. If there are fewer verified groups than workers,
    those known-working groups are shared deliberately. Without verified
    records, the entire pool is balanced round-robin; when the pool is smaller
    than the worker count, its groups are repeated so no worker is empty.
    """
    if type(instance_count) is not int or not 1 <= instance_count <= 32:
        raise ValueError("instance_count must be an integer between 1 and 32.")

    parsed = parse_bridge_text(bridge_text)
    if parsed.invalid_records:
        details = "; ".join(parsed.errors[:3])
        if len(parsed.errors) > 3:
            details += f"; plus {len(parsed.errors) - 3} more invalid record(s)"
        raise ValueError(
            f"Cannot distribute an invalid bridge list. {details}"
        )

    # parse_bridge_text performs canonical normalization and exact-record
    # de-duplication while preserving the user's first-seen order.
    records = parsed.records
    if not records:
        return BridgeDistribution(
            assignments=tuple(() for _ in range(instance_count)),
            unique_records=0,
            unique_groups=0,
            shared_groups=0,
        )

    grouped: dict[tuple[str, str], list[str]] = {}
    for record in records:
        fingerprint = bridge_identity_fingerprint(record)
        key = (
            ("fingerprint", fingerprint.casefold())
            if fingerprint
            else ("record", record.casefold())
        )
        grouped.setdefault(key, []).append(record)

    groups = list(grouped.values())
    assignments: list[list[str]] = [[] for _ in range(instance_count)]
    record_loads = [0] * instance_count
    preferred = {str(record).casefold() for record in preferred_records if str(record).strip()}
    preferred_indices = [
        index
        for index, group in enumerate(groups)
        if any(record.casefold() in preferred for record in group)
    ]

    if preferred_indices:
        # Give every process a known-working bridge group when at least one
        # was verified. If fewer such groups exist than workers, reuse them
        # intentionally and expose that overlap in the summary.
        for worker_index in range(instance_count):
            group_index = preferred_indices[worker_index % len(preferred_indices)]
            assignments[worker_index].extend(groups[group_index])
            record_loads[worker_index] += len(groups[group_index])

        preferred_set = set(preferred_indices)
        remaining_indices = [
            index for index in range(len(groups)) if index not in preferred_set
        ]
        for group_index in remaining_indices:
            worker_index = min(
                range(instance_count),
                key=lambda index: (record_loads[index], index),
            )
            assignments[worker_index].extend(groups[group_index])
            record_loads[worker_index] += len(groups[group_index])
    elif len(groups) < instance_count:
        # A small bridge pool must not leave workers with an empty Bridge list.
        for worker_index in range(instance_count):
            group_index = worker_index % len(groups)
            assignments[worker_index].extend(groups[group_index])
            record_loads[worker_index] += len(groups[group_index])
    else:
        # Keep each fingerprint group together, but balance the actual number
        # of bridge records assigned to each worker rather than group count.
        for group in groups:
            worker_index = min(
                range(instance_count),
                key=lambda index: (record_loads[index], index),
            )
            assignments[worker_index].extend(group)
            record_loads[worker_index] += len(group)

    group_usage = [0] * len(groups)
    for worker in assignments:
        assigned_keys = set()
        for record in worker:
            fingerprint = bridge_identity_fingerprint(record)
            assigned_keys.add(
                ("fingerprint", fingerprint.casefold())
                if fingerprint
                else ("record", record.casefold())
            )
        for group_index, key in enumerate(grouped):
            if key in assigned_keys:
                group_usage[group_index] += 1

    shared_groups = sum(1 for uses in group_usage if uses > 1)
    return BridgeDistribution(
        assignments=tuple(tuple(worker) for worker in assignments),
        unique_records=len(records),
        unique_groups=len(groups),
        shared_groups=shared_groups,
    )
