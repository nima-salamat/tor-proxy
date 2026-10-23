from __future__ import annotations

import pytest

from torproxy.bridges import normalize_bridge_record, parse_bridge_text


IPV6 = "[2001:db8:fe46:edd5:2139:2d5b:b732:854a]:443"


def test_quoted_ipv6_endpoint_is_unquoted_and_canonicalized():
    record = f'Bridge webtunnel "{IPV6}" A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 url=https://bridge.example/ ver=0.0.1'

    assert normalize_bridge_record(record) == (
        f"webtunnel {IPV6} A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 url=https://bridge.example/ ver=0.0.1"
    )


def test_identical_second_endpoint_is_removed_from_bridge_parameter_tail():
    record = (
        f'webtunnel {IPV6} "{IPV6}" A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 '
        "url=https://bridge.example/ ver=0.0.1"
    )

    assert normalize_bridge_record(record) == (
        f"webtunnel {IPV6} A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 url=https://bridge.example/ ver=0.0.1"
    )


def test_second_different_endpoint_is_rejected_instead_of_written_to_torrc():
    record = (
        f"webtunnel {IPV6} [2001:db8::99]:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 "
        "url=https://bridge.example/ ver=0.0.1"
    )

    with pytest.raises(ValueError, match="second, different address:port"):
        normalize_bridge_record(record)


def test_parser_reports_second_endpoint_as_invalid_without_mutating_saved_records():
    parsed = parse_bridge_text(
        f"webtunnel {IPV6} A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 url=https://bridge.example/ ver=0.0.1\n"
        f"webtunnel {IPV6} [2001:db8::99]:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 url=https://other.example/"
    )

    assert parsed.records == (
        f"webtunnel {IPV6} A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 url=https://bridge.example/ ver=0.0.1",
    )
    assert len(parsed.invalid_records) == 1
    assert "second, different address:port" in parsed.invalid_records[0] or "second" in parsed.invalid_records[0]


def test_bare_ipv6_bridge_without_transport_remains_supported():
    assert normalize_bridge_record(f'"{IPV6}"') == IPV6


def test_webtunnel_transport_is_inferred_when_url_and_ver_are_present():
    fingerprint = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
    raw = f'{IPV6} {fingerprint} url=https://bridge.example/secret ver=0.0.1'

    assert normalize_bridge_record(raw) == (
        f"webtunnel {IPV6} {fingerprint} url=https://bridge.example/secret ver=0.0.1"
    )


def test_missing_transport_with_other_options_is_rejected():
    fingerprint = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
    raw = f'{IPV6} {fingerprint} url=https://bridge.example/secret'

    with pytest.raises(ValueError, match="transport options but no transport label"):
        normalize_bridge_record(raw)


def test_short_identity_fingerprint_is_rejected_with_clear_error():
    with pytest.raises(ValueError, match="exactly 40 hexadecimal characters"):
        normalize_bridge_record(f"webtunnel {IPV6} ABCDEF url=https://bridge.example/ ver=0.0.1")


def test_spaced_fingerprint_is_normalized_to_one_digest():
    groups = "A1B2 C3D4 E5F6 0718 293A 4B5C 6D7E 8F90 1234 5678"
    assert normalize_bridge_record(f"webtunnel {IPV6} {groups} url=https://bridge.example/ ver=0.0.1") == (
        f"webtunnel {IPV6} A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 url=https://bridge.example/ ver=0.0.1"
    )


def test_short_fingerprint_option_is_rejected():
    with pytest.raises(ValueError, match="fingerprint= bridge option must contain exactly 40 hexadecimal characters"):
        normalize_bridge_record("snowflake 192.0.2.10:443 fingerprint=abc url=https://bridge.example/")


def test_fingerprint_grouped_in_eight_character_chunks_is_normalized():
    groups = "A1B2C3D4 E5F60718 293A4B5C 6D7E8F90 12345678"
    assert normalize_bridge_record(f"webtunnel {IPV6} {groups} url=https://bridge.example/ ver=0.0.1") == (
        f"webtunnel {IPV6} A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 "
        "url=https://bridge.example/ ver=0.0.1"
    )


def test_parser_returns_indexed_reason_for_invalid_fingerprint():
    result = parse_bridge_text(f"webtunnel {IPV6} ABCDEF url=https://bridge.example/ ver=0.0.1")
    assert result.records == ()
    assert result.invalid_records
    assert result.errors == (
        "Item 1: The bridge fingerprint must be exactly 40 hexadecimal characters. "
        "Copy the complete bridge line; do not use a nickname, partial fingerprint, or hashed fingerprint.",
    )
