import pytest

from torproxy.host_rules import HostRule, HostRuleError, HostRules, MatchMode, normalize_hostname


def test_domain_rule_matches_root_and_subdomains_only_on_label_boundary():
    rule = HostRule.parse("Example.COM.")
    assert rule.matches("example.com")
    assert rule.matches("api.example.com")
    assert not rule.matches("notexample.com")


def test_wildcard_matches_only_subdomains():
    rule = HostRule.parse("*.example.com")
    assert rule.mode is MatchMode.SUBDOMAINS_ONLY
    assert rule.matches("api.example.com")
    assert not rule.matches("example.com")


def test_exact_rule_is_explicit():
    rule = HostRule.parse("=example.com")
    assert rule.matches("example.com")
    assert not rule.matches("api.example.com")


def test_tld_wildcard_matches_any_hostname_ending_in_suffix_at_any_depth():
    rule = HostRule.parse("*.IR")
    assert str(rule) == "*.ir"
    assert rule.matches("example.ir")
    assert rule.matches("api.example.ir")
    assert rule.matches("deep.api.example.ir")
    assert not rule.matches("ir")
    assert not rule.matches("example.iran")
    assert not rule.matches("notir")


def test_subdomain_wildcard_does_not_match_the_base_domain_or_similar_suffix():
    rule = HostRule.parse("*.x.com")
    assert rule.matches("api.x.com")
    assert rule.matches("deep.api.x.com")
    assert not rule.matches("x.com")
    assert not rule.matches("notx.com")


@pytest.mark.parametrize(
    ("pattern", "matched", "unmatched"),
    [
        (
            "*-api.something.com",
            "v2-api.something.com",
            ["api.something.com", "v2-api.other.com", "deep.v2-api.something.com"],
        ),
        (
            "api-*.something.com",
            "api-v2.something.com",
            ["api.something.com", "api-v2.other.com", "deep.api-v2.something.com"],
        ),
        (
            "api.*.example.com",
            "api.eu.example.com",
            ["api.example.com", "api.eu.example.org", "api.eu.extra.example.com"],
        ),
        (
            "*.api.*.com",
            "v1.api.eu.com",
            ["api.eu.com", "v1.api.eu.net", "v1.api.deep.eu.com"],
        ),
        (
            "UPPER-*.BÜCHER.example",
            "upper-v2.xn--bcher-kva.example",
            ["lower-v2.xn--bcher-kva.example", "upper-v2.bücher.example.net"],
        ),
    ],
)
def test_label_globs_match_only_the_intended_hostname_pattern(pattern, matched, unmatched):
    rule = HostRule.parse(pattern)
    assert rule.mode is MatchMode.GLOB
    assert rule.matches(matched)
    for hostname in unmatched:
        assert not rule.matches(hostname)


def test_legacy_leading_wildcard_shorthand_is_preserved():
    rule = HostRule.parse("*example.org")
    assert str(rule) == "*.example.org"
    assert rule.matches("api.example.org")
    assert not rule.matches("example.org")
    assert not rule.matches("badexample.org")


def test_idna_and_ip_literals_are_normalized():
    assert normalize_hostname("BÜCHER.example") == "xn--bcher-kva.example"
    assert normalize_hostname("[2001:db8::1]") == "2001:db8::1"
    assert normalize_hostname("192.0.2.1") == "192.0.2.1"


@pytest.mark.parametrize("bad", ["", "https://example.com", "user@example.com", "example.com:443",
                                  "bad host.com", "a..b", "-bad.com", "example.com/path"])
def test_invalid_rules_are_rejected(bad):
    with pytest.raises(HostRuleError):
        HostRule.parse(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "*-bad_.example.com",
        "api-*-.example.com",
        "foo..*.example.com",
        "sub.*.example.com/path",
        "bü*cher.example.com",
        "=*.example.com",
        "foo.?.example.com",
    ],
)
def test_invalid_glob_patterns_are_rejected(bad):
    with pytest.raises(HostRuleError):
        HostRule.parse(bad)


def test_rule_collection_is_immutable_and_deduplicated():
    original = HostRules.from_values(["example.com", "EXAMPLE.com.", "*.example.com"])
    updated = original.add("other.example")
    assert original.as_list() == ["example.com", "*.example.com"]
    assert updated.matches("api.other.example")
    assert updated.remove("example.com").as_list() == ["*.example.com", "other.example"]
