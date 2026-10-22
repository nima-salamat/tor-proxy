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


def test_idna_and_ip_literals_are_normalized():
    assert normalize_hostname("BÜCHER.example") == "xn--bcher-kva.example"
    assert normalize_hostname("[2001:db8::1]") == "2001:db8::1"
    assert normalize_hostname("192.0.2.1") == "192.0.2.1"


@pytest.mark.parametrize("bad", ["", "https://example.com", "user@example.com", "example.com:443",
                                  "bad host.com", "a..b", "-bad.com", "example.com/path"])
def test_invalid_rules_are_rejected(bad):
    with pytest.raises(HostRuleError):
        HostRule.parse(bad)


def test_rule_collection_is_immutable_and_deduplicated():
    original = HostRules.from_values(["example.com", "EXAMPLE.com.", "*.example.com"])
    updated = original.add("other.example")
    assert original.as_list() == ["example.com", "*.example.com"]
    assert updated.matches("api.other.example")
    assert updated.remove("example.com").as_list() == ["*.example.com", "other.example"]
