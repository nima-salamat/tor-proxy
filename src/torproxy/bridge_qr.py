"""Pure helpers for validating/importing bridge lines decoded from QR payloads."""
from __future__ import annotations

import json
import re
from collections.abc import Iterable


_BRIDGE_METHODS = (
    "obfs4",
    "obfs3",
    "obfs2",
    "scramblesuit",
    "meek_lite",
    "snowflake",
    "webtunnel",
    "fte",
    "vanilla",
)
_BRIDGE_LINE_RE = re.compile(
    r"^(?:(?:" + "|".join(_BRIDGE_METHODS) + r")\s+)?"
    r"(?P<host>\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+):(?P<port>\d{1,5})(?:\s+.*)?$",
    re.IGNORECASE,
)


def bridge_import_actions(existing_text: str) -> tuple[bool, bool, bool]:
    """Return (show_import, show_replace, show_add) for the current text field."""
    has_existing = bool(str(existing_text or "").strip())
    return not has_existing, has_existing, has_existing


def merge_bridge_lines(existing_text: str, imported_lines: Iterable[str]) -> list[str]:
    """Append new bridge lines without deleting or duplicating existing entries."""
    merged = [line.strip() for line in str(existing_text or "").splitlines() if line.strip()]
    seen = {line.casefold() for line in merged}
    for line in imported_lines:
        candidate = str(line).strip()
        if candidate and candidate.casefold() not in seen:
            merged.append(candidate)
            seen.add(candidate.casefold())
    return merged


def parse_bridge_payload(payload: str) -> list[str]:
    """Decode common Tor QR payload shapes and reject unrelated QR codes."""
    raw = str(payload or "").strip()
    if not raw:
        return []

    value: object = raw
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        pass

    if isinstance(value, dict):
        for key in ("bridges", "bridge", "bridge_lines", "lines", "data"):
            if key in value:
                value = value[key]
                break

    if isinstance(value, str):
        candidates: Iterable[object] = value.splitlines()
    elif isinstance(value, (tuple, list)):
        candidates = value
    else:
        return []

    lines: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        for part in candidate.splitlines():
            line = part.strip()
            if not line or line.startswith("#"):
                continue
            line = re.sub(r"^Bridge\s+", "", line, flags=re.IGNORECASE).strip()
            match = _BRIDGE_LINE_RE.fullmatch(line)
            if match is None:
                continue
            try:
                port = int(match.group("port"))
            except ValueError:
                continue
            if not 1 <= port <= 65535:
                continue
            if line not in seen:
                seen.add(line)
                lines.append(line)
    return lines
