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
    # A bare authority is only a record start when it has the explicit torrc
    # "Bridge" prefix. Otherwise it is also the endpoint token of the record
    # immediately before it and would create an overlapping false record.
    rf"(?i)(?<!\S)(?:Bridge\s+(?:(?:{_TRANSPORT_PATTERN})\s+)?|(?:{_TRANSPORT_PATTERN})\s+)"
    r"[\"']?(?:\[[0-9a-f:.]+\]|(?:\d{1,3}\.){3}\d{1,3}):\d{1,5}[\"']?(?=\s|$)"
)
_IPV4_AUTHORITY = re.compile(r"^(?P<host>[^:\s]+):(?P<port>\d{1,5})$")
_IPV6_AUTHORITY = re.compile(r"^\[(?P<host>[^\]]+)\]:(?P<port>\d{1,5})$")
_COMMENT_OR_HEADER = re.compile(
    r"(?i)^(?:here are (?:your )?bridge lines:?|bridge addresses?:?|your bridges:?|"
    r"tor bridge configuration:?|bridge configuration:?|begin bridge list:?|end bridge list:?)$"
)


def normalize_sni_hostname(value: str) -> str:
    """Normalize a user-supplied SNI hostname without accepting a URL or IP literal."""
    if not isinstance(value, str):
        raise ValueError("SNI must be a DNS hostname, not a URL.")
    raw = value.strip().rstrip(".")
    if not raw:
        return ""
    if any(char in raw for char in (":", "/", "\\", "@", "?", "#", ",", "\r", "\n", "\t", " ")):
        raise ValueError("SNI must be a hostname only (for example, www.example.com).")
    try:
        ipaddress.ip_address(raw.strip("[]"))
    except ValueError:
        pass
    else:
        raise ValueError("SNI imitation must be a DNS hostname, not an IP address.")
    try:
        hostname = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("SNI hostname contains an invalid internationalized domain name.") from exc
    if len(hostname) > 253:
        raise ValueError("SNI hostname is too long.")
    labels = hostname.split(".")
    if len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("SNI must be a valid fully qualified DNS hostname (for example, www.example.com).")
    return hostname


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

        # WebTunnel bridge lines are identifiable by their required url= and
        # ver= options. If a clipboard paste dropped only the leading
        # "webtunnel" token, restore it instead of letting Tor concatenate
        # those options into the identity fingerprint (causing
        # "Key digest for Bridge is wrong length").
        option_names = {
            token.split("=", 1)[0].casefold()
            for token in remainder_fields
            if "=" in token
        }
        if {"url", "ver"}.issubset(option_names):
            transport = "webtunnel"
        elif option_names:
            raise ValueError(
                "This bridge has transport options but no transport label. "
                "For WebTunnel, include 'webtunnel' before the address, or provide both url= and ver= so it can be detected."
            )

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

    # Remove a duplicated copy of the main endpoint before validating the
    # positional fingerprint. A second, different endpoint is an input error.
    filtered_remainder: list[str] = []
    for token in remainder_fields:
        extra_authority = _canonical_authority(token)
        if extra_authority == primary_authority:
            continue
        if extra_authority is not None:
            raise ValueError(
                "This bridge record contains a second, different address:port after its main endpoint. "
                "Keep one complete bridge record per line."
            )
        filtered_remainder.append(token)
    remainder_fields = filtered_remainder

    # Tor's Bridge grammar takes a 40-hex-character identity fingerprint as
    # one token. Clipboard sources sometimes group it with spaces in different
    # chunk sizes; join only an all-hex sequence that totals exactly 40 chars.
    first_option = next(
        (index for index, token in enumerate(remainder_fields) if "=" in token),
        len(remainder_fields),
    )
    fingerprint_chunks = remainder_fields[:first_option]
    if (
        len(fingerprint_chunks) > 1
        and all(re.fullmatch(r"[0-9a-fA-F]{1,40}", item.strip("\"'")) for item in fingerprint_chunks)
        and sum(len(item.strip("\"'")) for item in fingerprint_chunks) == 40
    ):
        remainder_fields = [
            "".join(item.strip("\"'") for item in fingerprint_chunks),
            *remainder_fields[first_option:],
        ]

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
        if token.casefold().startswith("fingerprint="):
            supplied_fingerprint = token.split("=", 1)[1]
            if not re.fullmatch(r"[0-9a-fA-F]{40}", supplied_fingerprint):
                raise ValueError(
                    "The fingerprint= bridge option must contain exactly 40 hexadecimal characters."
                )
        if token.casefold().startswith("sni-imitation="):
            supplied_sni = token.split("=", 1)[1]
            normalized_sni = normalize_sni_hostname(supplied_sni)
            if not normalized_sni:
                raise ValueError("The sni-imitation= bridge option cannot be empty.")
            token = "sni-imitation=" + normalized_sni
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


def bridge_identity_fingerprint(record: str) -> str | None:
    """Return a bridge identity fingerprint when the record explicitly provides one.

    The optional Snowflake `fingerprint=` transport setting is not the relay
    identity, so it must not be used to claim that a circuit is using this bridge.
    """
    parsed = normalize_bridge_record(record)
    fields = parsed.split()
    if fields and fields[0].casefold() in SUPPORTED_BRIDGE_TRANSPORTS:
        authority_index = 1
    else:
        authority_index = 0
    remainder = fields[authority_index + 1:]
    for token in remainder:
        if "=" in token:
            break
        value = token.strip("\"'").upper()
        if re.fullmatch(r"[0-9A-F]{40}", value):
            return value
        return None
    return None


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
        detail = "; ".join(result.errors[:3])
        if len(result.errors) > 3:
            detail += f"; plus {len(result.errors) - 3} more item(s)"
        raise ValueError(
            f"{len(result.invalid_records)} bridge item(s) could not be recognized. "
            f"{detail} "
            "Use one complete bridge record per line."
        )
    return "\n".join(result.records)
