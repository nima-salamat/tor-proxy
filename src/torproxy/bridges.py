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
# Consume the authority token as well as the optional PT name. Recognize
# both PT bridge records ("obfs4 [IPv6]:443 ...") and ordinary bridge
# records ("Bridge [IPv6]:443 ..."). Consuming the authority prevents a
# second overlapping match at the same endpoint, while still splitting
# concatenated records and keeping bare IPv6 authorities out of prior args.
_BRIDGE_START = re.compile(
    rf"(?i)(?<!\S)(?:Bridge\s+)?(?:(?:{_TRANSPORT_PATTERN})\s+)?"
    r"[\"']?(?:\[[0-9a-f:.]+\]|(?:\d{1,3}\.){3}\d{1,3}):\d{1,5}[\"']?(?=\s|$)"
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
    errors: tuple[str, ...] = ()


def _canonical_authority(value: str) -> str | None:
    """Canonicalize a standalone IPv4:port or bracketed IPv6:port token."""
    token = value.strip().strip("\"'")
    ipv6 = _IPV6_AUTHORITY.fullmatch(token)
    if ipv6:
        try:
            address = ipaddress.IPv6Address(ipv6.group("host")).compressed.casefold()
            port = int(ipv6.group("port"))
        except ValueError:
            return None
        return f"[{address}]:{port}" if 1 <= port <= 65535 else None
    ipv4 = _IPV4_AUTHORITY.fullmatch(token)
    if ipv4:
        try:
            address = str(ipaddress.IPv4Address(ipv4.group("host")))
            port = int(ipv4.group("port"))
        except ValueError:
            return None
        return f"{address}:{port}" if 1 <= port <= 65535 else None
    return None


def normalize_bridge_record(value: str) -> str:
    """Validate and canonicalize one Tor Bridge record, with or without a PT."""
    line = " ".join(str(value or "").strip().split())
    # Some clipboard exports surround IPv6 authorities with quotes. Tor's
    # Bridge grammar expects [IPv6]:port as a bare token.
    if len(line) >= 2 and line[0] == line[-1] and line[0] in {"\"", "'"}:
        line = line[1:-1].strip()
    line = re.sub(r"(?i)^Bridge\s+", "", line).strip()
    if not line or "\x00" in line or "\n" in line or "\r" in line:
        raise ValueError("A bridge must be a single non-empty record.")

    fields = line.split()
    if not fields:
        raise ValueError("A bridge must contain an address and port.")

    first = fields[0].casefold()
    has_transport = first in SUPPORTED_BRIDGE_TRANSPORTS
    if has_transport:
        if len(fields) < 2:
            raise ValueError("A bridge needs a transport and address:port.")
        transport = first
        authority = fields[1].strip("\"'")
        remainder_fields = fields[2:]
    else:
        transport = ""
        authority = fields[0].strip("\"'")
        remainder_fields = fields[1:]

    ipv6_match = _IPV6_AUTHORITY.fullmatch(authority)
    if ipv6_match:
        try:
            host = f"[{ipaddress.IPv6Address(ipv6_match.group('host')).compressed}]"
        except ValueError as exc:
            raise ValueError("The bridge contains an invalid IPv6 address.") from exc
        port = int(ipv6_match.group("port"))
    else:
        ipv4_match = _IPV4_AUTHORITY.fullmatch(authority)
        if ipv4_match is None:
            raise ValueError(
                "Bridge addresses must be IPv4:port or bracketed IPv6:port, optionally preceded by a supported transport."
            )
        try:
            host = str(ipaddress.IPv4Address(ipv4_match.group("host")))
        except ValueError as exc:
            raise ValueError("The bridge contains an invalid IPv4 address.") from exc
        port = int(ipv4_match.group("port"))

    if not 1 <= port <= 65535:
        raise ValueError("Bridge ports must be between 1 and 65535.")

    primary_authority = _canonical_authority(f"{host}:{port}")

    # Tor's Bridge grammar takes a 40-hex-character identity fingerprint as
    # one token. Clipboard sources sometimes display it as ten groups of four;
    # normalize that presentation instead of passing a short digest to torrc.
    if (
        len(remainder_fields) >= 10
        and all(re.fullmatch(r"[0-9a-fA-F]{4}", item.strip("\"'")) for item in remainder_fields[:10])
    ):
        remainder_fields = ["".join(item.strip("\"'") for item in remainder_fields[:10])] + remainder_fields[10:]

    bare_tokens = [(index, token) for index, token in enumerate(remainder_fields) if "=" not in token]
    if bare_tokens:
        index, fingerprint = bare_tokens[0]
        fingerprint = fingerprint.strip("\"'")
        if index != 0 or not re.fullmatch(r"[0-9a-fA-F]{40}", fingerprint):
            raise ValueError(
                "The bridge fingerprint must be exactly 40 hexadecimal characters. "
                "Copy the complete bridge line; do not use a nickname, partial fingerprint, or hashed fingerprint."
            )
        remainder_fields[0] = fingerprint
        if len(bare_tokens) > 1:
            raise ValueError(
                "Unexpected extra text after the bridge fingerprint. Bridge options must use key=value format."
            )

    clean_remainder: list[str] = []
    for token in remainder_fields:
        extra_authority = _canonical_authority(token)
        if extra_authority is not None:
            # A duplicate endpoint is common when bridge text has been copied
            # with an address repeated in the parameter tail. Drop it only when
            # it is exactly the same endpoint; otherwise do not guess intent.
            if extra_authority == primary_authority:
                continue
            raise ValueError(
                "This bridge record contains a second, different address:port after its main endpoint. "
                "Keep one complete bridge record per line."
            )
        if len(token) >= 2 and token[0] == token[-1] and token[0] in {"\"", "'"}:
            token = token[1:-1]
        clean_remainder.append(token)

    remainder = " ".join(clean_remainder)
    normalized = f"{transport} {host}:{port}" if transport else f"{host}:{port}"
    return normalized + (f" {remainder}" if remainder else "")


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
    errors: list[str] = []
    seen: set[str] = set()
    for index, candidate in enumerate(_candidate_chunks(text), start=1):
        try:
            normalized = normalize_bridge_record(candidate)
        except (TypeError, ValueError) as exc:
            invalid.append(candidate)
            errors.append(f"Item {index}: {exc}")
            continue
        key = normalized.casefold()
        if key not in seen:
            seen.add(key)
            records.append(normalized)
    return BridgeTextParseResult(tuple(records), tuple(invalid), tuple(errors))


def normalize_bridge_text(text: str) -> str:
    """Return canonical newline-separated text, raising if any chunk is invalid."""
    result = parse_bridge_text(text)
    if result.invalid_records:
        raise ValueError(
            f"{len(result.invalid_records)} bridge item(s) could not be recognized. "
            "Use one complete obfs4, snowflake, webtunnel or meek_lite record per line."
        )
    return "\n".join(result.records)
