"""Validated, immutable host matching shared by HTTP and CONNECT requests."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum


class HostRuleError(ValueError):
    """Raised when a host rule is malformed or ambiguous."""


class MatchMode(str, Enum):
    EXACT = "exact"
    DOMAIN_AND_SUBDOMAINS = "domain-and-subdomains"
    SUBDOMAINS_ONLY = "subdomains-only"
    GLOB = "glob"


def normalize_hostname(value: str) -> str:
    if not isinstance(value, str):
        raise HostRuleError("Host must be a string.")
    raw = value.strip()
    if not raw or len(raw) > 1024:
        raise HostRuleError("Host is empty or too long.")
    if any(char in raw for char in ("/", "\\", "@", "?", "#", "%")):
        raise HostRuleError("Enter a hostname or IP address, not a URL or authority.")
    if any(char.isspace() for char in raw):
        raise HostRuleError("Hostnames cannot contain whitespace.")

    bracketed = raw.startswith("[") and raw.endswith("]")
    if bracketed:
        inner = raw[1:-1]
        try:
            return ipaddress.IPv6Address(inner).compressed.lower()
        except ValueError as exc:
            raise HostRuleError("Bracketed hosts must be valid IPv6 literals.") from exc
    try:
        return ipaddress.ip_address(raw).compressed.lower()
    except ValueError:
        pass

    if ":" in raw:
        raise HostRuleError("A rule must not include a port; IPv6 addresses must be valid literals.")
    if raw.endswith("."):
        raw = raw[:-1]
    if not raw or raw.endswith(".") or len(raw) > 253:
        raise HostRuleError("Invalid hostname length.")
    try:
        ascii_name = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise HostRuleError("Hostname is not valid IDNA.") from exc

    labels = ascii_name.split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise HostRuleError("Hostname contains an empty or overlong label.")
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
    if any(not label_pattern.fullmatch(label) for label in labels):
        raise HostRuleError("Hostname contains an invalid label.")
    return ascii_name


def _normalize_glob_pattern(value: str) -> str:
    """Normalize a DNS glob while keeping '*' limited to one hostname label."""
    raw = value.strip()
    if not raw or len(raw) > 1024:
        raise HostRuleError("Host pattern is empty or too long.")
    if any(char in raw for char in ("/", "\\", "@", "?", "#", "%")):
        raise HostRuleError("Enter a hostname pattern, not a URL or authority.")
    if any(char.isspace() for char in raw):
        raise HostRuleError("Host patterns cannot contain whitespace.")
    if raw.endswith("."):
        raw = raw[:-1]
    if not raw or raw.endswith(".") or len(raw) > 253:
        raise HostRuleError("Invalid hostname pattern length.")

    normalized_labels: list[str] = []
    for label in raw.split("."):
        if not label or len(label) > 63:
            raise HostRuleError("Host pattern contains an empty or overlong label.")
        if "*" not in label:
            normalized_labels.append(normalize_hostname(label))
            continue

        # Partial-label wildcarding is defined on ASCII/IDNA labels. Whole
        # internationalized labels remain supported in the other label slots.
        if not label.isascii():
            raise HostRuleError(
                "Wildcards inside an internationalized label must use its ASCII/IDNA form."
            )
        try:
            normalize_hostname(label.replace("*", "a"))
        except HostRuleError as exc:
            raise HostRuleError(f"Invalid wildcard label: {label!r}.") from exc
        normalized_labels.append(label.lower())

    pattern = ".".join(normalized_labels)
    if len(pattern) > 253:
        raise HostRuleError("Host pattern exceeds the maximum hostname length.")
    return pattern


def _matches_glob_label(pattern: str, candidate: str) -> bool:
    """Match one DNS label with '*' using a bounded, non-regex glob matcher."""
    pattern_index = 0
    candidate_index = 0
    last_star = -1
    retry_index = 0

    while candidate_index < len(candidate):
        if (
            pattern_index < len(pattern)
            and pattern[pattern_index] == candidate[candidate_index]
        ):
            pattern_index += 1
            candidate_index += 1
        elif pattern_index < len(pattern) and pattern[pattern_index] == "*":
            last_star = pattern_index
            pattern_index += 1
            retry_index = candidate_index
        elif last_star >= 0:
            pattern_index = last_star + 1
            retry_index += 1
            candidate_index = retry_index
        else:
            return False

    while pattern_index < len(pattern) and pattern[pattern_index] == "*":
        pattern_index += 1
    return pattern_index == len(pattern)


@dataclass(frozen=True)
class HostRule:
    host: str
    mode: MatchMode = MatchMode.DOMAIN_AND_SUBDOMAINS

    @classmethod
    def parse(cls, value: str) -> HostRule:
        if not isinstance(value, str):
            raise HostRuleError("Rule must be a string.")
        raw = value.strip()
        if not raw or len(raw) > 1024:
            raise HostRuleError("Rule is empty or too long.")
        if raw.startswith("="):
            if "*" in raw:
                raise HostRuleError("Exact-host rules cannot contain wildcards.")
            return cls(normalize_hostname(raw[1:]), MatchMode.EXACT)
        if raw.startswith("*.") and "*" not in raw[2:]:
            # This suffix form intentionally spans any subdomain depth.
            suffix = raw[2:]
            if not suffix or suffix.startswith(".") or suffix.endswith("."):
                raise HostRuleError("Wildcard rules must name exactly one valid suffix.")
            return cls(normalize_hostname(suffix), MatchMode.SUBDOMAINS_ONLY)
        if raw.startswith("*") and "*" not in raw[1:]:
            # Preserve the historical '*example.org' shorthand for subdomains only.
            # If the suffix is not itself a hostname (e.g. '-api.example.org'),
            # treat the input as a label glob instead.
            suffix = raw[1:]
            if suffix:
                try:
                    normalized_suffix = normalize_hostname(suffix)
                except HostRuleError:
                    pass
                else:
                    return cls(normalized_suffix, MatchMode.SUBDOMAINS_ONLY)
        if "*" in raw:
            return cls(_normalize_glob_pattern(raw), MatchMode.GLOB)
        return cls(normalize_hostname(raw), MatchMode.DOMAIN_AND_SUBDOMAINS)

    def matches(self, hostname: str) -> bool:
        try:
            candidate = normalize_hostname(hostname)
        except HostRuleError:
            return False
        if self.mode is MatchMode.EXACT:
            return candidate == self.host
        if self.mode is MatchMode.SUBDOMAINS_ONLY:
            return candidate.endswith("." + self.host)
        if self.mode is MatchMode.GLOB:
            pattern_labels = self.host.split(".")
            candidate_labels = candidate.split(".")
            return len(pattern_labels) == len(candidate_labels) and all(
                _matches_glob_label(pattern, label)
                for pattern, label in zip(pattern_labels, candidate_labels)
            )
        return candidate == self.host or candidate.endswith("." + self.host)

    def __str__(self) -> str:
        if self.mode is MatchMode.EXACT:
            return "=" + self.host
        if self.mode is MatchMode.SUBDOMAINS_ONLY:
            return "*." + self.host
        return self.host


@dataclass(frozen=True)
class HostRules:
    """A snapshot of rules; mutations create a new instance for thread safety."""
    rules: tuple[HostRule, ...] = ()

    @classmethod
    def from_values(cls, values: list[str] | tuple[str, ...]) -> HostRules:
        parsed: list[HostRule] = []
        seen: set[tuple[str, MatchMode]] = set()
        for value in values:
            rule = HostRule.parse(value)
            key = (rule.host, rule.mode)
            if key not in seen:
                seen.add(key)
                parsed.append(rule)
        return cls(tuple(parsed))

    def matches(self, hostname: str) -> bool:
        return any(rule.matches(hostname) for rule in self.rules)

    def add(self, value: str) -> HostRules:
        rule = HostRule.parse(value)
        if rule in self.rules:
            return self
        return HostRules(self.rules + (rule,))

    def remove(self, value: str) -> HostRules:
        rule = HostRule.parse(value)
        return HostRules(tuple(existing for existing in self.rules if existing != rule))

    def as_list(self) -> list[str]:
        return [str(rule) for rule in self.rules]
