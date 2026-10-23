"""Bounded, byte-offset based helpers for reading a live log file."""
from __future__ import annotations

from pathlib import Path

READ_CHUNK_SIZE = 16 * 1024


def _line_records(
    data: bytes,
    absolute_start: int,
    *,
    drop_partial_first: bool,
) -> list[tuple[int, str]]:
    """Split UTF-8 log bytes into lines while retaining each line's file offset."""
    parts = data.split(b"\n")
    positions: list[int] = []
    position = absolute_start
    for part in parts:
        positions.append(position)
        position += len(part) + 1

    if data.endswith(b"\n") and parts:
        parts.pop()
        positions.pop()
    if drop_partial_first and parts:
        parts.pop(0)
        positions.pop(0)

    return [
        (line_offset, raw.rstrip(b"\r").decode("utf-8", errors="replace"))
        for line_offset, raw in zip(positions, parts)
        if raw
    ]


def read_log_tail(path: Path, line_count: int) -> tuple[list[tuple[int, str]], int, int]:
    """Return a bounded tail, its first line offset, and the current file size."""
    try:
        size = path.stat().st_size
        cursor = size
        chunks: list[bytes] = []
        newline_count = 0
        while cursor > 0 and newline_count <= line_count:
            take = min(READ_CHUNK_SIZE, cursor)
            cursor -= take
            with path.open("rb") as handle:
                handle.seek(cursor)
                chunk = handle.read(take)
            chunks.insert(0, chunk)
            newline_count += chunk.count(b"\n")
        data = b"".join(chunks)
        lines = _line_records(data, cursor, drop_partial_first=cursor > 0)
        visible = lines[-max(1, int(line_count)):]
        first_offset = visible[0][0] if visible else size
        return visible, first_offset, size
    except FileNotFoundError:
        return [], 0, 0


def read_log_page_before(
    path: Path,
    before_offset: int,
    line_count: int = 500,
) -> tuple[list[tuple[int, str]], int]:
    """Read a page immediately older than an existing line offset."""
    try:
        size = path.stat().st_size
        cursor = min(max(0, int(before_offset)), size)
        chunks: list[bytes] = []
        newline_count = 0
        while cursor > 0 and newline_count <= line_count:
            take = min(READ_CHUNK_SIZE, cursor)
            cursor -= take
            with path.open("rb") as handle:
                handle.seek(cursor)
                chunk = handle.read(take)
            chunks.insert(0, chunk)
            newline_count += chunk.count(b"\n")
        data = b"".join(chunks)
        lines = _line_records(data, cursor, drop_partial_first=cursor > 0)
        page = lines[-max(1, int(line_count)):]
        start_offset = page[0][0] if page else cursor
        return page, start_offset
    except FileNotFoundError:
        return [], 0
