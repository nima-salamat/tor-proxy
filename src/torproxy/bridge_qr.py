"""Compatibility helpers for importing Tor bridge records from QR payloads."""
from __future__ import annotations

import json
from collections.abc import Iterable

from .bridges import parse_bridge_text


def bridge_import_actions(existing_text: str) -> tuple[bool, bool, bool]:
    """Return (show_import, show_replace, show_add) for the current text field."""
    has_existing = bool(str(existing_text or "").strip())
    return not has_existing, has_existing, has_existing


def merge_bridge_lines(existing_text: str, imported_lines: Iterable[str]) -> list[str]:
    """Append canonical bridge records without deleting or duplicating entries."""
    existing = parse_bridge_text(str(existing_text or ""))
    if existing.invalid_records:
        # Never silently discard content already typed by the user. Leave it as
        # entered, then append normalized QR records not already present.
        merged = [line.strip() for line in str(existing_text or "").splitlines() if line.strip()]
    else:
        merged = list(existing.records)

    seen = {line.casefold() for line in merged}
    incoming = parse_bridge_text("\n".join(str(item) for item in imported_lines))
    for candidate in incoming.records:
        key = candidate.casefold()
        if key not in seen:
            merged.append(candidate)
            seen.add(key)
    return merged


def parse_bridge_payload(payload: str) -> list[str]:
    """Decode common Tor QR payload shapes into the exact bridge format TorProxy accepts."""
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
        text = value
    elif isinstance(value, (tuple, list)):
        text = "\n".join(item for item in value if isinstance(item, str))
    else:
        return []

    # Ignore unrelated QR payload fragments, but always return normalized
    # complete records; Settings and Tor's torrc generator share this parser.
    return list(parse_bridge_text(text).records)
