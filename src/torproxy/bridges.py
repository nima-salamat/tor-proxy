"""Shared normalization and validation for user-supplied Tor bridge records.

The same parser is used by paste input, QR import, bridge cards and torrc
generation so the UI never advertises a record that the runtime rejects.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


SUPPORTED_BRIDGE_TRANSPORTS = ("obfs4", "snowflake", "webtunnel", "meek_lite")
_TRANSPORT_PATTERN = "|".join(re.escape(name) for name in SUPPORTED_BRIDGE_TRANSPORTS)
# A second transport label followed by a valid-looking literal authority marks
# a new record even when a clipboard source has collapsed all lines into one.
_BRIDGE_START = re.compile(
    rf"(?i)(?<!\S)(?:Bridge\s+)?(?:{_TRANSPORT_PATTERN})\s+"
    r"(?=(?:\[[0-9a-f:.]+\]|(?:\d{1,3}\.){3}\d{1,3}):\d{1,5}(?:\s|$))"
)
_IPV4_AUTHORITY = re.compile(r"^(?P<host>[^:\s]+):(?P<port>\d{1,5})$")
_IPV6_AUTHORITY = re.compile(r"^\[(?P<host>[^\]]+)\]:(?P<port>\d{1,5})$")
_COMMENT_OR_HEADER = re.compile(
    r"(?i)^(?:here are (?:your )?bridge lines:?|bridge addresses?:?|your bridges:?|"
    r"tor bridge configuration:?|bridge configuration:?|begin bridge list:?|end bridge list:?)$"
)


@dataclass(frozen=True)
class BridgeTextParseResult:
    """Canonical bridge records and chunks that could not be interpreted safely."""

    records: tuple[str, ...]
    invalid_records: tuple[str, ...]


def normalize_bridge_record(value: str) -> str:
    """Validate and canonicalize one complete supported bridge record."""
    line = " ".join(str(value or "").strip().split())
    line = re.sub(r"(?i)^Bridge\s+", "", line).strip()
    if not line or "\x00" in line or "\n" in line or "\r" in line:
        raise ValueError("A bridge must be a single non-empty record.")

    fields = line.split()
    if len(fields) < 2:
        raise ValueError("A bridge needs a supported transport and address:port.")
    transport = fields[0].casefold()
    if transport not in SUPPORTED_BRIDGE_TRANSPORTS:
        raise ValueError("Supported bridge transports are obfs4, snowflake, webtunnel and meek_lite.")

    authority = fields[1]
    ipv6_match = _IPV6_AUTHORITY.fullmatch(authority)
    if ipv6_match:
        try:
            ipaddress.IPv6Address(ipv6_match.group("host"))
        except ValueError as exc:
            raise ValueError("The bridge contains an invalid IPv6 address.") from exc
        port = int(ipv6_match.group("port"))
        host = f"[{ipv6_match.group('host')}]"
    else:
        ipv4_match = _IPV4_AUTHORITY.fullmatch(authority)
        if ipv4_match is None:
            raise ValueError("Bridge addresses must be IPv4:port or bracketed IPv6:port.")
        try:
            host = str(ipaddress.IPv4Address(ipv4_match.group("host")))
        except ValueError as exc:
            raise ValueError("The bridge contains an invalid IPv4 address.") from exc
        port = int(ipv4_match.group("port"))

    if not 1 <= port <= 65535:
        raise ValueError("Bridge ports must be between 1 and 65535.")

    remainder = " ".join(fields[2:])
    return f"{transport} {host}:{port}" + (f" {remainder}" if remainder else "")


def _candidate_chunks(text: str) -> list[str]:
    chunks: list[str] = []
    for raw_line in str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw_line.strip()
        if not line or line.startswith("#") or _COMMENT_OR_HEADER.fullmatch(line):
            continue
        # Also accept copied lists prefixed with a bullet or an ordinal number.
        line = re.sub(r"^(?:[-*•]\s*|\d{1,3}[.)]\s*)", "", line).strip()
        starts = list(_BRIDGE_START.finditer(line))
        if not starts:
            chunks.append(line.strip(" \t,;"))
            continue

        prefix = line[: starts[0].start()].strip(" \t,;")
        if prefix and not _COMMENT_OR_HEADER.fullmatch(prefix):
            chunks.append(prefix)
        for index, match in enumerate(starts):
            stop = starts[index + 1].start() if index + 1 < len(starts) else len(line)
            candidate = line[match.start():stop].strip(" \t,;")
            if candidate:
                chunks.append(candidate)
    return chunks


def parse_bridge_text(text: str) -> BridgeTextParseResult:
    """Parse text containing line-separated or concatenated bridge records.

    Records are whitespace-normalized, have any Torrc Bridge prefix removed,
    use a lowercase transport label, and are deduplicated while keeping their
    first-seen order. Unsupported or malformed chunks are reported, not silently
    converted into a partial configuration.
    """
    records: list[str] = []
    invalid: list[str] = []
    seen: set[str] = set()
    for candidate in _candidate_chunks(text):
        try:
            normalized = normalize_bridge_record(candidate)
        except (TypeError, ValueError):
            invalid.append(candidate)
            continue
        key = normalized.casefold()
        if key not in seen:
            seen.add(key)
            records.append(normalized)
    return BridgeTextParseResult(tuple(records), tuple(invalid))


def normalize_bridge_text(text: str) -> str:
    """Return canonical newline-separated text, raising if any chunk is invalid."""
    result = parse_bridge_text(text)
    if result.invalid_records:
        raise ValueError(
            f"{len(result.invalid_records)} bridge item(s) could not be recognized. "
            "Use one complete obfs4, snowflake, webtunnel or meek_lite record per line."
        )
    return "\n".join(result.records)
