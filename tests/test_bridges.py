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
    assert normalize_bridge_record(f'"{IPV6}" A1B2C3D4E5F60718293A4B5C6D7E8F9012345678') == f"{IPV6} A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
