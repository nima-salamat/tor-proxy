from __future__ import annotations

import json

from ui_.window.qrcode_widget import parse_bridge_payload


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
