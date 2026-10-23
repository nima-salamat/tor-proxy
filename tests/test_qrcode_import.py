from __future__ import annotations

import json

from torproxy.bridge_qr import (
    bridge_import_actions,
    merge_bridge_lines,
    parse_bridge_payload,
)


def test_bridge_qr_accepts_json_array_and_deduplicates_lines():
    bridges = [
        "obfs4 192.0.2.10:443 AABBCCDDEEFF cert=abc iat-mode=0",
        "webtunnel bridges.example.org:443 url=https://bridges.example.org/",
    ]
    payload = json.dumps(bridges + [bridges[0]])

    assert parse_bridge_payload(payload) == bridges


def test_bridge_qr_accepts_torrc_prefix_and_multiline_text():
    payload = """Bridge obfs4 192.0.2.12:443 AABB cert=abc iat-mode=0
# comment
snowflake snowflake.example.org:443 fingerprint=abc
not a bridge
"""
    assert parse_bridge_payload(payload) == [
        "obfs4 192.0.2.12:443 AABB cert=abc iat-mode=0",
        "snowflake snowflake.example.org:443 fingerprint=abc",
    ]


def test_bridge_qr_accepts_json_object_shapes():
    payload = json.dumps({"type": "tor-bridges", "bridges": ["obfs4 198.51.100.9:9001 fingerprint"]})
    assert parse_bridge_payload(payload) == ["obfs4 198.51.100.9:9001 fingerprint"]


def test_bridge_qr_rejects_unrelated_or_invalid_payloads():
    assert parse_bridge_payload("https://example.org") == []
    assert parse_bridge_payload('{"url": "https://example.org"}') == []
    assert parse_bridge_payload("obfs4 relay.example.org:99999 fingerprint") == []
    assert parse_bridge_payload("") == []


def test_bridge_qr_ignores_malformed_lines_but_keeps_valid_bridges():
    payload = """obfs4 203.0.113.2:443 fingerprint cert=x
obfs4 not-a-host fingerprint
meek_lite bridge.example.net:8443 front=cdn.example.org
"""
    assert parse_bridge_payload(payload) == [
        "obfs4 203.0.113.2:443 fingerprint cert=x",
        "meek_lite bridge.example.net:8443 front=cdn.example.org",
    ]



def test_bridge_action_choices_depend_on_existing_settings_text():
    assert bridge_import_actions("") == (True, False, False)
    assert bridge_import_actions("  \n  ") == (True, False, False)
    assert bridge_import_actions("obfs4 192.0.2.4:443 fingerprint") == (False, True, True)


def test_add_bridge_lines_preserves_existing_entries_and_avoids_duplicates():
    existing = "obfs4 192.0.2.4:443 fingerprint\nwebtunnel bridge.example.org:443 url=x"
    incoming = [
        "OBFS4 192.0.2.4:443 FINGERPRINT",
        "snowflake 198.51.100.4:443 fingerprint",
    ]
    assert merge_bridge_lines(existing, incoming) == [
        "obfs4 192.0.2.4:443 fingerprint",
        "webtunnel bridge.example.org:443 url=x",
        "snowflake 198.51.100.4:443 fingerprint",
    ]
