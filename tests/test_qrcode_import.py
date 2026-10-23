from __future__ import annotations

import json
from pathlib import Path

from torproxy.bridges import parse_bridge_text
from torproxy.bridge_qr import (
    bridge_import_actions,
    merge_bridge_lines,
    parse_bridge_payload,
)


def test_bridge_qr_accepts_json_array_and_deduplicates_lines():
    bridges = [
        "obfs4 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=abc iat-mode=0",
        "webtunnel 198.51.100.11:443 url=https://bridges.example.org/",
    ]
    payload = json.dumps(bridges + [bridges[0]])

    assert parse_bridge_payload(payload) == bridges


def test_bridge_qr_accepts_torrc_prefix_and_multiline_text():
    payload = """Bridge obfs4 192.0.2.12:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=abc iat-mode=0
# comment
snowflake 198.51.100.12:443 fingerprint=A1B2C3D4E5F60718293A4B5C6D7E8F9012345678
not a bridge
"""
    assert parse_bridge_payload(payload) == [
        "obfs4 192.0.2.12:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=abc iat-mode=0",
        "snowflake 198.51.100.12:443 fingerprint=A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
    ]


def test_bridge_qr_accepts_json_object_shapes():
    payload = json.dumps({"type": "tor-bridges", "bridges": ["obfs4 198.51.100.9:9001 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"]})
    assert parse_bridge_payload(payload) == ["obfs4 198.51.100.9:9001 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"]


def test_bridge_qr_rejects_unrelated_or_invalid_payloads():
    assert parse_bridge_payload("https://example.org") == []
    assert parse_bridge_payload('{"url": "https://example.org"}') == []
    assert parse_bridge_payload("obfs4 relay.example.org:99999 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678") == []
    assert parse_bridge_payload("") == []


def test_bridge_qr_ignores_malformed_lines_but_keeps_valid_bridges():
    payload = """obfs4 203.0.113.2:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=x
obfs4 not-a-host A1B2C3D4E5F60718293A4B5C6D7E8F9012345678
webtunnel [2001:db8::12]:8443 url=https://bridge.example.net/ front=cdn.example.org
"""
    assert parse_bridge_payload(payload) == [
        "obfs4 203.0.113.2:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=x",
        "webtunnel [2001:db8::12]:8443 url=https://bridge.example.net/ front=cdn.example.org",
    ]



def test_bridge_action_choices_depend_on_existing_settings_text():
    assert bridge_import_actions("") == (True, False, False)
    assert bridge_import_actions("  \n  ") == (True, False, False)
    assert bridge_import_actions("obfs4 192.0.2.4:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678") == (False, True, True)


def test_add_bridge_lines_preserves_existing_entries_and_avoids_duplicates():
    existing = "obfs4 192.0.2.4:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678\nwebtunnel 198.51.100.12:443 url=x"
    incoming = [
        "OBFS4 192.0.2.4:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
        "snowflake 198.51.100.4:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
    ]
    assert merge_bridge_lines(existing, incoming) == [
        "obfs4 192.0.2.4:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
        "webtunnel 198.51.100.12:443 url=x",
        "snowflake 198.51.100.4:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
    ]




def test_pasted_single_line_bridge_list_is_split_and_canonicalized():
    pasted = (
        "Bridge OBFS4 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=abc   "
        "snowflake 198.51.100.12:443 fingerprint=A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 "
        "WEBTUNNEL [2001:db8::12]:8443 url=https://bridge.example.net/"
    )
    parsed = parse_bridge_text(pasted)
    assert parsed.invalid_records == ()
    assert parsed.records == (
        "obfs4 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=abc",
        "snowflake 198.51.100.12:443 fingerprint=A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
        "webtunnel [2001:db8::12]:8443 url=https://bridge.example.net/",
    )


def test_bridge_parser_deduplicates_and_reports_unrecognized_chunks():
    pasted = (
        "obfs4 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 "
        "obfs4 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678\n"
        "invalid-content"
    )
    parsed = parse_bridge_text(pasted)
    assert parsed.records == ("obfs4 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",)
    assert parsed.invalid_records == ("invalid-content",)


def test_qr_payload_uses_same_supported_transports_as_tor_runtime():
    payload = """
obfs4 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678
meek_lite 198.51.100.10:8443 front=cdn.example.org
webtunnel bridge.example.org:443 url=https://bridge.example.org/
"""
    assert parse_bridge_payload(payload) == [
        "obfs4 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
        "meek_lite 198.51.100.10:8443 front=cdn.example.org",
    ]


def test_inline_paste_splits_transport_and_plain_ipv6_bridge_records():
    pasted = (
        "obfs4 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=abc "
        'Bridge "[2001:db8:fe46:edd5:2139:2d5b:b732:854a]:443" A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 '
        "webtunnel 198.51.100.12:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 url=https://bridge.example/"
    )
    parsed = parse_bridge_text(pasted)
    assert parsed.invalid_records == ()
    assert parsed.records == (
        "obfs4 192.0.2.10:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 cert=abc",
        "[2001:db8:fe46:edd5:2139:2d5b:b732:854a]:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
        "webtunnel 198.51.100.12:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 url=https://bridge.example/",
    )


def test_plain_ipv6_bridge_record_without_transport_is_normalized():
    parsed = parse_bridge_text('Bridge "[2001:db8::12]:443" A1B2C3D4E5F60718293A4B5C6D7E8F9012345678')
    assert parsed.invalid_records == ()
    assert parsed.records == ("[2001:db8::12]:443 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",)


def test_qr_scanner_button_callbacks_exist_for_application_startup():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/qrcode_widget.py").read_text(encoding="utf-8")

    # The Import/Replace/Add buttons bind these callbacks during __init__, so
    # the methods must be present before SettingsWindow can be constructed.
    assert "callback=self.import_bridges" in source
    assert "callback=self.replace_bridges" in source
    assert "callback=self.add_bridges" in source
    assert "def import_bridges(self):" in source
    assert "def replace_bridges(self):" in source
    assert "def add_bridges(self):" in source
    assert "def _apply_detected_bridges(self, mode: str):" in source
